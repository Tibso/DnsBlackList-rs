use crate::{
    errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult, ExternCrateErrorKind},
    filtering::{self, FilteringConf}, resolver::{self, Records}
};

use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
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
                    DnsBlrsErrorKind::IncompleteConf => {
                        error!("{msg_stats}The daemon conf is incomplete");
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

                let msg = builder.build(header, [], [], [], []);
                response.send_response(msg).await.expect("Could not send the error response")
            }
        }
    }
}

pub struct Handler {
    pub daemon_id: String,
    pub redis_mngr: ConnectionManager,
    pub filtering_conf: Arc<ArcSwapAny<Arc<FilteringConf>>>,
    pub resolver: Arc<TokioAsyncResolver>
}
impl Handler {
    /// Try to handle a request on a designated thread
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
        let builder_header = (&mut builder, &mut header);

        // #[feature(stats)]
        // // Write stats about the source IP
        // redis_mod::write_stats_request(&mut redis_manager, daemon_id, request_src_ip).await?;

        let filtering_conf = self.filtering_conf.clone().load();
        // Filters the domain name if the request is of RecordType A or AAAA
        let response_records: Records = {
            if filtering_conf.is_filtering {
                match request.query().query_type() {
                    RecordType::A | RecordType::AAAA => {
                        if let Some(records) = filtering::filter_domain(self, request).await? {
                            if records.answer.is_empty() {
                                header.set_response_code(ResponseCode::NXDomain);
                            }
                            records
                        } else {
                            let mut records = resolver::resolve(self, request, builder_header).await?;
                            if filtering::have_blacklisted_ip(self, request, &records).await? {
                                header.set_response_code(ResponseCode::NXDomain);
                                records.answer.clear();
                            }
                            records
                        }
                    },
                    _ => {
                        let mut records = resolver::resolve(self, request, builder_header).await?;
                        if filtering::have_blacklisted_ip(self, request, &records).await? {
                            header.set_response_code(ResponseCode::NXDomain);
                            records.answer.clear();
                        }
                        records
                    }
                }
            } else {
                resolver::resolve(self, request, builder_header).await?
            }
        };

        let msg = builder.build(header,
            response_records.answer.iter(),
            response_records.name_servers.iter(),
            response_records.soas.iter(),
            response_records.additional.iter()
        );
        response.send_response(msg).await
            .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::IO(err))))
    }
}
