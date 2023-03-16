use crate::{
    enums_structs::{Config, DnsLrResult, DnsLrErrorKind, ExternCrateErrorKind, DnsLrError},
    resolver_mod,
    matching,
    CONFILE
};

use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};
use trust_dns_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    proto::op::{Header, ResponseCode, OpCode, MessageType},
    authority::MessageResponseBuilder
};
use trust_dns_proto::rr::RecordType;

use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::{error, warn};

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    )
    -> ResponseInfo {
        match self.do_handle_request(request, response.clone()).await {
            Ok(info) => info,
            Err(err) => {
                let builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());

                let request_info = request.request_info();
                match err.kind() {
                    DnsLrErrorKind::InvalidOpCode => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} InvalidOpCode received",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsLrErrorKind::InvalidMessageType => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} InvalidMessageType received",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsLrErrorKind::InvalidArpaAddress => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} InvalidArpAddress received",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::FormErr);
                    },
                    DnsLrErrorKind::RequestRefused => {
                        error!("{}: request:{} src:{}://{} QUERY:{} A resolver's request was refused by forwarder",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsLrErrorKind::ExternCrateError(dnslrerrorkind) => {
                        match dnslrerrorkind {
                            ExternCrateErrorKind::ResolverError(tmp_err) =>
                                error!("{}: request:{} src:{}://{} QUERY:{} A resolver had an error: {}",
                                    CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query, tmp_err
                                ),
                            ExternCrateErrorKind::RedisError(tmp_err) =>
                                error!("{}: request:{} src:{}://{} QUERY:{} An error occured while fetching from Redis: {}",
                                    CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query, tmp_err
                                ),
                            ExternCrateErrorKind::IOError(tmp_err) => 
                                error!("{}: request:{} src:{}://{} QUERY:{} Could not send response: {}",
                                    CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query, tmp_err
                                ),
                        }
                        header.set_response_code(ResponseCode::ServFail);
                    }
                    _ => unreachable!()
                }
                let message = builder.build(header, &[], &[], &[], &[]);
                response.send_response(message).await.expect("Could not send the error response")
            }
        }
    }
}

pub struct Handler {
    pub redis_manager: redis::aio::ConnectionManager,
    pub config: Arc<ArcSwap<Config>>,
    pub resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
}
impl Handler {
    async fn do_handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    )
    -> DnsLrResult<ResponseInfo> {
        if request.op_code() != OpCode::Query {
            return Err(DnsLrError::from(DnsLrErrorKind::InvalidOpCode))
        }

        if request.message_type() != MessageType::Query {
            return Err(DnsLrError::from(DnsLrErrorKind::InvalidMessageType))
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);

        let config = self.config.load();

        let answers = match config.is_filtering {
            true => match request.query().query_type() {
                RecordType::A => matching::filter(
                    request,
                    config,
                    self.redis_manager.clone(),
                    self.resolver.clone()
                ).await?,
                RecordType::AAAA => matching::filter(
                    request,
                    config,
                    self.redis_manager.clone(),
                    self.resolver.clone()
                ).await?,
                _ => resolver_mod::get_answers(
                    request,
                    self.resolver.clone()
                ).await? 
            },
            false => resolver_mod::get_answers(
                request,
                self.resolver.clone()
            ).await?
        };

        let message = builder.build(header, answers.iter(), &[], &[], &[]);
        return match response.send_response(message).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::IOError(err))))
        }
    }
}
