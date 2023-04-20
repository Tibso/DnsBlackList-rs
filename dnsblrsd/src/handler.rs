use crate::{
    structs::{Config, DnsBlrsResult, DnsBlrsErrorKind, ExternCrateErrorKind, DnsBlrsError},
    resolver, filtering, CONFILE, redis_mod
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
use async_trait::async_trait;

#[async_trait]
/// Implements the TrustDns RequestHandler trait for the handler
impl RequestHandler for Handler {
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    )
    -> ResponseInfo {
        // Attempts to handle the request
        match self.handle_request(request, response.clone()).await {
            // The request was served succesfully
            // The request's info is returned to the subscriber to be displayed
            Ok(info) => info,

            // An error occured while serving the request
            // The error was propagated throughout the functions to here
            Err(err) => {
                // Creates the message response builder based on the request
                let builder = MessageResponseBuilder::from_message_request(request);

                // Creates a new header based on the request's header
                let mut header = Header::response_from_request(request.header());
                // Configures the header to specify this response is not authoritative
                header.set_authoritative(false);
                // Configures the header to specify recursion is available on this server
                header.set_recursion_available(true);

                // Each error type is handled differently
                // Each error has a custom error log
                // The new header's response code is set to the appropriate ResponseCode
                let request_info = request.request_info();
                match err.kind() {
                    DnsBlrsErrorKind::InvalidOpCode => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} An \"InvalidOpCode\" error occured",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidMessageType => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} An \"InvalidMessageType\" error occured",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidArpaAddress => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} An \"InvalidArpAddress\" error occured",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::FormErr);
                    },
                    DnsBlrsErrorKind::RequestRefused => {
                        error!("{}: request:{} src:{}://{} QUERY:{} A resolver's request was refused by a forwarder",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::Refused);
                    },
                    DnsBlrsErrorKind::InvalidRule => {
                        error!("{}: request:{} src:{}://{} QUERY:{} A rule seems to be broken",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::ServFail);
                    },
                    DnsBlrsErrorKind::NotImpl => {
                        warn!("{}: request:{} src:{}://{} QUERY:{} This \"query_type\" is not implemented",
                            CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query
                        );
                        header.set_response_code(ResponseCode::NotImp);
                    },
                    DnsBlrsErrorKind::ExternCrateError(dns_blrs_errorkind) => {
                        // These errors are from external crates
                        match dns_blrs_errorkind {
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
                            ExternCrateErrorKind::SystemTimeError(tmp_err) =>
                                error!("{}: request:{} src:{}://{} QUERY:{} A \"SystemTimeError\" occured: {}",
                                CONFILE.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query, tmp_err
                                )
                        }
                        header.set_response_code(ResponseCode::ServFail);
                    }
                    _ => unreachable!()
                }

                // Message response is built to send to appropriate error
                let message = builder.build(header, &[], &[], &[], &[]);
                response.send_response(message).await.expect("Could not send the error response")
            }
        }
    }
}

pub struct Handler {
    pub redis_manager: redis::aio::ConnectionManager,
    pub arc_config: Arc<ArcSwap<Config>>,
    pub arc_resolver: Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>
}
impl Handler {
    /// Handles the request
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    )
    -> DnsBlrsResult<ResponseInfo> {
        // Each new request triggers this code on a designated thread

        // Filters out unwanted query types
        if request.op_code() != OpCode::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidOpCode))
        }

        // Filters out unwanted message types
        if request.message_type() != MessageType::Query {
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidMessageType))
        }

        // Creates the message response builder based on the request
        let builder = MessageResponseBuilder::from_message_request(request);

        // Creates a new header based on the request's header
        let mut header = Header::response_from_request(request.header());
        // Configures the header to specify this response is not authoritative
        header.set_authoritative(false);
        // Configures the header to specify recursion is available on this server
        header.set_recursion_available(true);

        // Borrows the configuration from the thread-safe variable
        let config = self.arc_config.load();

        // Copies the resolver out of the thread-safe variable
        let resolver = self.arc_resolver.as_ref().clone();

        // Copies the Redis connection manager
        let mut redis_manager = self.redis_manager.clone();
        
        // Write statistics about the source IP
        redis_mod::write_stats(&mut redis_manager, request.request_info().src.ip(), false).await?;

        // Fetches the answer from the appropriate functions
        // Filters the domain name if the request is of RecordType A or AAAA
        let records = match config.is_filtering {
            true => match request.query().query_type() {
                RecordType::A => filtering::filter(request, &config, &mut redis_manager, resolver).await?,
                RecordType::AAAA => filtering::filter(request, &config, &mut redis_manager, resolver).await?,
                _ => resolver::get_records(request, resolver).await? 
            },
            false => resolver::get_records(request, resolver).await?
        };

        // Message response is built to send the response
        let message = builder.build(header, &records, &[], &[], &[]);
        // Attempts to send the response
        match response.send_response(message).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::IOError(err))))
        }
    }
}
