use crate::handler_mod::CustomError;

use trust_dns_client::{
    op::{LowerQuery, Header, ResponseCode},
    rr::RecordType,
};
use trust_dns_proto::rr::Record;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol},
    TokioAsyncResolver,
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    IntoName,
    error::{ResolveErrorKind, ResolveError},
    lookup::Lookup
};
use std::{
    net::SocketAddr
};

pub fn build_resolver (
    sockets: Vec<SocketAddr>
)
-> AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>> {
    let mut resolver_config = ResolverConfig::new();
    resolver_config.domain();

    for socket in sockets {
        let ns_udp = NameServerConfig::new(socket, Protocol::Udp);
        resolver_config.add_name_server(ns_udp);
        let ns_tcp = NameServerConfig::new(socket, Protocol::Tcp);
        resolver_config.add_name_server(ns_tcp)
    }
    
    let mut resolver_opts: ResolverOpts = ResolverOpts::default();
    resolver_opts.num_concurrent_reqs = 0;
    let resolver = TokioAsyncResolver::tokio(
        resolver_config,
        resolver_opts
    ).unwrap();

    println!("Resolver built");
    return resolver
}

pub async fn get_answers (
    query: &LowerQuery,
    mut header: Header,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> Result<(Vec<Record>, Header), CustomError> {    
    let mut answers: Vec<Record> =  Vec::new();
    let name = query.name().into_name().unwrap();

    let wrapped: Result<Lookup, ResolveError>;
    match query.query_type() {
        RecordType::A => wrapped = resolver.lookup(name.clone(), RecordType::A).await,
        RecordType::AAAA => wrapped = resolver.lookup(name.clone(), RecordType::AAAA).await,
        RecordType::TXT => wrapped = resolver.lookup(name.clone(), RecordType::TXT).await,
        RecordType::SRV => wrapped = resolver.lookup(name.clone(), RecordType::SRV).await,
        RecordType::MX => wrapped = resolver.lookup(name.clone(), RecordType::MX).await,
        RecordType::PTR => {
            let ip = name.clone().parse_arpa_name().unwrap().addr();

            match resolver.reverse_lookup(ip).await {
                Ok(ok) => {
                    for record in ok.as_lookup().records() {
                    answers.push(record.clone())
                    }
                    return Ok((answers, header))
                },
                Err(error) => {
                    match error.kind() {
                        ResolveErrorKind::NoRecordsFound {..} => return Ok((vec![], header)),
                        _ => return Err(CustomError::ResolverError(error))
                    }
                }
            }
        },
        _ => {
            answers = vec![];
            header.set_response_code(ResponseCode::NotImp);
            return Ok((answers, header))
        }
    };

    match wrapped {
        Ok(ok) => {
            for record in ok.records() {
            answers.push(record.clone())
            }
            return Ok((answers, header))
        },
        Err(error) => {
            match error.kind() {
                ResolveErrorKind::NoRecordsFound {..} => return Ok((vec![], header)),
                _ => return Err(CustomError::ResolverError(error))
            }
        }
    }
}
