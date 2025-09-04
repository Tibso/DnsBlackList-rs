use crate::{config::Service, errors::{DnsBlrsError, DnsBlrsResult}, filtering, resolver};

use std::{net::SocketAddr, sync::Arc};
use hickory_proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    proto::op::{Header, ResponseCode, OpCode, MessageType},
    authority::MessageResponseBuilder
};
use redis::aio::ConnectionManager;
use tracing::{error, warn};
use async_trait::async_trait;

pub struct Handler {
    pub resolver: Arc<TokioAsyncResolver>,
    pub redis_mngr: ConnectionManager,
    pub services: Vec<Service>
}
impl Handler {
    /// Finds the filters for the given socket address
    pub fn find_filters(&self, socket_addr: SocketAddr) -> Option<Vec<String>> {
        self.services.iter()
            .find(|service| service.binds.iter().any(|bind| bind.socket_address == socket_addr))
            .map(|service| service.filters.clone())
    }

    /// Try to handle a request on a designated thread
    async fn try_handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> DnsBlrsResult<ResponseInfo> {
        let op_code = request.op_code();
        if op_code != OpCode::Query {
            return Err(DnsBlrsError::InvalidOpCode(op_code.into()))
        }
        let message_type = request.message_type();
        if message_type != MessageType::Query {
            return Err(DnsBlrsError::MessageTypeNotQuery)
        }

        let mut builder = MessageResponseBuilder::from_message_request(request);
        let wants_dnssec = request.edns().is_some_and(|edns| {
            builder.edns(edns.clone());
            edns.dnssec_ok()
        });
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);

        // #[feature(stats)]
        // // Write stats about the source IP
        // redis_mod::write_stats_request(&mut redis_manager, daemon_id, request_src_ip).await?;

        let resolver = self.resolver.clone();
        let mut records = resolver::resolve(&resolver, request, wants_dnssec, &mut header).await?;

        let query_type = request.query().query_type();
        if matches!(query_type, RecordType::A | RecordType::AAAA)
            && (filtering::is_domain_blacklisted(self, request).await?
            || filtering::have_blacklisted_ip(self, request, &records).await?)
        {
            header.set_response_code(ResponseCode::NXDomain);
            records.answer.clear();
            records.name_servers.clear();
            records.additional.clear();
        }

        let msg = builder.build(header,
            records.answer.iter(),
            records.name_servers.iter(),
            records.soas.iter(),
            records.additional.iter()
        );
        response.send_response(msg).await
            .map_err(DnsBlrsError::IO)
    }
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request <R: ResponseHandler> (
        &self,
        request: &Request,
        mut response: R
    ) -> ResponseInfo {
        match self.try_handle_request(request, response.clone()).await {
            // Successfully request info returned to the subscriber to be displayed
            Err(e) => {
                let builder = MessageResponseBuilder::from_message_request(request);

                let mut header = Header::response_from_request(request.header());
                header.set_authoritative(false);
                header.set_recursion_available(true);

                let request_info = request.request_info();
                let msg_stats = format!("request:{} src:{}://{} QUERY:{}",
                    request.id(), request_info.protocol, request_info.src, request_info.query
                );
                if matches!(e, DnsBlrsError::InvalidOpCode(_) | DnsBlrsError::MessageTypeNotQuery) {
                    warn!("{msg_stats} | {e}");
                    header.set_response_code(ResponseCode::Refused);
                } else {
                    error!("{msg_stats} | {e}");
                    header.set_response_code(ResponseCode::ServFail);
                }

                let msg = builder.build(header, [], [], [], []);
                response.send_response(msg).await.expect("Could not send the error response")
            },
            Ok(response_info) => response_info
        }
    }
}
