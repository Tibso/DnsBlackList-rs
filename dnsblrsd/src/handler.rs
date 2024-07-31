use crate::{
    structs::{Config, DnsBlrsResult, DnsBlrsErrorKind, ExternCrateErrorKind, DnsBlrsError},
    resolver, filtering, DAEMON_ID, redis_mod
};

use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    proto::op::{Header, ResponseCode, OpCode, MessageType},
    authority::MessageResponseBuilder
};
use hickory_proto::rr::RecordType;
use arc_swap::ArcSwap;
use tracing::{error, warn};
use async_trait::async_trait;

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> ResponseInfo {
        match self.handle_request(request, response.clone()).await {
            // The successfully request's info is returned to the subscriber to be displayed
            Ok(info) => info,
            Err(err) => {
                let builder = MessageResponseBuilder::from_message_request(request);

                let mut header = Header::response_from_request(request.header());
                header.set_authoritative(false);
                header.set_recursion_available(true);

                let daemon_id = DAEMON_ID.get().expect("Could not fetch daemon_id");

                let request_info = request.request_info();
                let msg_stats = format!("{daemon_id}: request:{} src:{}://{} QUERY:{} | ",
                    request.id(), request_info.protocol, request_info.src, request_info.query
                );
                match err.kind() {
                    DnsBlrsErrorKind::InvalidOpCode => {
                        warn!("{msg_stats}An \"InvalidOpCode\" error occured");
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidMessageType => {
                        warn!("{msg_stats}An \"InvalidMessageType\" error occured");
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::RequestRefused => {
                        error!("{msg_stats}A resolver's request was refused by a forwarder");
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidRule => {
                        error!("{msg_stats}A rule seems to be broken");
                        header.set_response_code(ResponseCode::ServFail);
                    },
                    DnsBlrsErrorKind::NotImpl => {
                        warn!("{msg_stats}This \"query_type\" is not implemented");
                        header.set_response_code(ResponseCode::NotImp);
                    }
                    DnsBlrsErrorKind::LogicError => {
                        warn!("{msg_stats}A logic error occured");
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
                                error!("{msg_stats}A \"SystemTimeError\" occured: {err}"),
                            ExternCrateErrorKind::Proto(err) =>
                                error!("{msg_stats}A \"ProtoError\" occured: {err}")
                        }
                        header.set_response_code(ResponseCode::ServFail);
                    }
                    _ => unreachable!("Unfinished implementation of new error kind")
                }

                let message = builder.build(header, &[], &[], &[], &[]);
                response.send_response(message).await.expect("Could not send the error response")
            }
        }
    }
}

pub struct Handler {
    pub redis_manager: redis::aio::ConnectionManager,
    pub arc_config: Arc<ArcSwap<Config>>,
    pub arc_resolver: Arc<TokioAsyncResolver>
}
impl Handler {
    /// Will run to handle a request on a designated thread
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> DnsBlrsResult<ResponseInfo> {
        // Filters out unwanted query and message types
        if request.op_code() != OpCode::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidOpCode))
        }
        if request.message_type() != MessageType::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidMessageType))
        }

        let builder = MessageResponseBuilder::from_message_request(request);

        // Creates a new header based on the request's header
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);

        // Borrows the configuration from the thread-safe variable
        let config = self.arc_config.load();
        // Copies the resolver out of the thread-safe variable
        let resolver = self.arc_resolver.as_ref().clone();
        let mut redis_manager = self.redis_manager.clone();
        
        // Write general stats about the source IP
        redis_mod::write_stats_query(&mut redis_manager, request.request_info().src.ip()).await?;

        // Filters the domain name if the request is of RecordType A or AAAA
        let records = if config.is_filtering {
            match request.query().query_type() {
                RecordType::A => filtering::filter(request, &config, &mut redis_manager, resolver).await?,
                RecordType::AAAA => filtering::filter(request, &config, &mut redis_manager, resolver).await?,
                _ => resolver::get_records(request, resolver).await?
            }
        } else {
            resolver::get_records(request, resolver).await?
        };

        let message = builder.build(header, &records, &[], &[], &[]);
        response.send_response(message).await
            .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::IO(err))))
    }
}
