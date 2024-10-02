use crate::{
    errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult, ExternCrateErrorKind},
    filtering::{self, FilteringConfig}, redis_mod, resolver::{self, SortedRecords}
};

use std::sync::Arc;
use hickory_resolver::{IntoName, TokioAsyncResolver};
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    proto::op::{Header, ResponseCode, OpCode, MessageType},
    authority::MessageResponseBuilder
};
use hickory_proto::rr::RecordType;
use arc_swap::ArcSwapAny;
use redis::aio::ConnectionManager;
use tracing::{error, warn};
use async_trait::async_trait;

pub const TTL_1H: u32 = 3600;

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> ResponseInfo {
        match self.try_handle_request(request, response.clone()).await {
            // Successfully request info returned to the subscriber to be displayed
            Ok(response_info) => response_info,
            Err(err) => {
                let builder = MessageResponseBuilder::from_message_request(request);

                let mut header = Header::response_from_request(request.header());
                header.set_authoritative(false);
                header.set_recursion_available(true);

                let request_info = request.request_info();
                let msg_stats = format!("{}: request:{} src:{}://{} QUERY:{} | ",
                    self.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                );
                match err.kind() {
                    DnsBlrsErrorKind::InvalidOpCode => {
                        warn!("{msg_stats}An 'InvalidOpCode' error occured");
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidMessageType => {
                        warn!("{msg_stats}An 'InvalidMessageType' error occured");
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidRule => {
                        error!("{msg_stats}A rule seems to be broken");
                        header.set_response_code(ResponseCode::ServFail);
                    },
                    DnsBlrsErrorKind::ExternCrateError(extern_crate_errorkind) => {
                        match extern_crate_errorkind {
                            ExternCrateErrorKind::Resolver(err) =>
                                error!("{msg_stats}A resolver had an error: {err}"),
                            ExternCrateErrorKind::Redis(err) =>
                                error!("{msg_stats}An error occured while fetching from Redis: {err}"),
                            ExternCrateErrorKind::IO(err) => 
                                error!("{msg_stats}Could not send response: {err}"),
                            ExternCrateErrorKind::SystemTime(err) =>
                                error!("{msg_stats}A 'SystemTimeError' occured: {err}"),
                            ExternCrateErrorKind::Proto(err) =>
                                error!("{msg_stats}A 'ProtoError' occured: {err}")
                        }
                        header.set_response_code(ResponseCode::ServFail);
                    },
                    _ => unreachable!("Unfinished implementation of new error kind")
                }

                let message = builder.build(header, &[], &[], &[], &[]);
                response.send_response(message).await.expect("Could not send the error response")
            }
        }
    }
}

pub struct Handler {
    pub daemon_id: String,
    pub redis_manager: ConnectionManager,
    pub filtering_config: Arc<ArcSwapAny<Arc<FilteringConfig>>>,
    pub resolver: Arc<TokioAsyncResolver>
}
impl Handler {
    /// Will try to handle a request on a designated thread
    async fn try_handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> DnsBlrsResult<ResponseInfo> {
        if request.op_code() != OpCode::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidOpCode))
        }
        if request.message_type() != MessageType::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidMessageType))
        }

        let mut builder = MessageResponseBuilder::from_message_request(request);    
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);

        let query = request.query();
        let query_name = query.name().into_name()
            .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Proto(err))))?;
        let query_type = query.query_type();
        let request_src_ip = request.request_info().src.ip();
        let wants_dnssec = request.edns().map_or(false, |edns| {
            builder.edns(edns.clone());
            edns.dnssec_ok()
        });

        // Copies from the thread-safe handler
        let mut redis_manager = self.redis_manager.clone();
        let filtering_config = self.filtering_config.clone().load();
        let filtering_config = filtering_config.as_ref();
        let resolver = self.resolver.clone();
        let resolver = resolver.as_ref();
        let daemon_id = self.daemon_id.as_ref();

        // Write stats about the source IP
        redis_mod::write_stats_request(&mut redis_manager, daemon_id, request_src_ip).await?;

        // Filters the domain name if the request is of RecordType A or AAAA
        let sorted_records: SortedRecords = match filtering_config.is_filtering {
            true => {
                let filtering_data = filtering_config.data.as_ref().expect("'filtering_data' should never be 'None' here");
                let sinks = filtering_data.sinks;
                let filters = &filtering_data.filters;
                match query_type {
                    RecordType::A | RecordType::AAAA => {
                        filtering::filter(daemon_id, query_name, query_type, request_src_ip, sinks, filters, wants_dnssec, resolver, &mut header, &mut redis_manager).await?
                    },
                    _ => filtering::filter_resolution(daemon_id, query_name, query_type, sinks, wants_dnssec, resolver, &mut header, &mut redis_manager).await?
                }
            },
            false => resolver::resolve(resolver, &query_name, query_type, wants_dnssec, &mut header).await?
        };

        let message = builder.build(header,
            sorted_records.answer.iter(),
            sorted_records.name_servers.iter(),
            sorted_records.soas.iter(),
            sorted_records.additional.iter()
        );
        response.send_response(message).await
            .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::IO(err))))
    }
}
