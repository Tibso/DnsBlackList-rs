use crate::enums_structs::{Config, WrappedErrors, ErrorKind, DnsLrResult};
use crate::resolver_mod;
use crate::matching;

use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};
use trust_dns_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    proto::op::{Header, ResponseCode, OpCode, MessageType},
    authority::MessageResponseBuilder
};
use trust_dns_proto::rr::{Record, RecordType};

use tracing::error;

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
            Err(error) => {
                error!("RequestHandler error: {}", error);

                let builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());
                header.set_response_code(ResponseCode::ServFail);
                let message = builder.build(header, &[], &[], &[], &[]);
                
                response.send_response(message).await.expect("Could not send the ServFail")
            }
        }
    }
}

pub struct Handler {
    pub redis_manager: redis::aio::ConnectionManager,
    pub config: Config,
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
            return Err(WrappedErrors::DNSlrError(ErrorKind::InvalidOpCode))
        }

        if request.message_type() != MessageType::Query {
            return Err(WrappedErrors::DNSlrError(ErrorKind::InvalidMessageType))
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);

        let answers: Vec<Record>;
        match self.config.is_filtering {
            true => (answers, header) = match request.query().query_type() {
                RecordType::A => matching::filter(
                    request.query(),
                    header,
                    &self.config,
                    self.redis_manager.clone(),
                    self.resolver.clone()
                ).await?,
                RecordType::AAAA => matching::filter(
                    request.query(),
                    header, 
                    &self.config,
                    self.redis_manager.clone(),
                    self.resolver.clone()
                ).await?,
                _ => resolver_mod::get_answers(
                    request.query(),
                    header,
                    self.resolver.clone()
                ).await?
            },
            false => (answers, header) = resolver_mod::get_answers(
                request.query(),
                header,
                self.resolver.clone()
            ).await?
        }


        let message = builder.build(header, answers.iter(), &[], &[], &[]);
        return match response.send_response(message).await {
            Ok(ok) => Ok(ok),
            Err(error) => Err(WrappedErrors::IOError(error))
        }
    }
}
