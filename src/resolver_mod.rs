use crate::enums_structs::{Config, WrappedErrors, DnsLrResult};

use tracing::info;
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

pub fn build_resolver (
    config: &Config
)
-> AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>> {
    let mut resolver_config = ResolverConfig::new();
    resolver_config.domain();

    for socket in config.forwarders.clone().into_iter() {
        let ns_udp = NameServerConfig::new(socket, Protocol::Udp);
        resolver_config.add_name_server(ns_udp);
        let ns_tcp = NameServerConfig::new(socket, Protocol::Tcp);
        resolver_config.add_name_server(ns_tcp);
    }
    
    let mut resolver_opts: ResolverOpts = ResolverOpts::default();
    resolver_opts.num_concurrent_reqs = 0;
    let resolver = TokioAsyncResolver::tokio(
        resolver_config,
        resolver_opts
    ).unwrap();

    info!("{}: Resolver built", config.daemon_id);
    return resolver
}

pub async fn get_answers (
    query: &LowerQuery,
    mut header: Header,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> DnsLrResult<(Vec<Record>, Header)> {    
    let mut answers: Vec<Record> =  Vec::new();
    let name = query.name().into_name().unwrap();

    let wrapped: Result<Lookup, ResolveError>;
    match query.query_type() {
        RecordType::A => wrapped = resolver.lookup(name, RecordType::A).await,
        RecordType::AAAA => wrapped = resolver.lookup(name, RecordType::AAAA).await,
        RecordType::TXT => wrapped = resolver.lookup(name, RecordType::TXT).await,
        RecordType::SRV => wrapped = resolver.lookup(name, RecordType::SRV).await,
        RecordType::MX => wrapped = resolver.lookup(name, RecordType::MX).await,
        RecordType::PTR => {
            let Ok(ip) = name.parse_arpa_name() else {
                return Err(WrappedErrors::DNSlrError(crate::enums_structs::ErrorKind::InvalidArpaAddress))
            };
            
            let ip = ip.addr();
            return match resolver.reverse_lookup(ip).await {
                Ok(ok) => {
                    for record in ok.as_lookup().records() {
                    answers.push(record.clone())
                    }
                    Ok((answers, header))
                },
                Err(error) => {
                    match error.kind() {
                        ResolveErrorKind::NoRecordsFound {..} => Ok((vec![], header)),
                        _ => Err(WrappedErrors::ResolverError(error))
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

    return match wrapped {
        Ok(ok) => {
            for record in ok.records() {
            answers.push(record.clone())
            }
            Ok((answers, header))
        },
        Err(error) => {
            match error.kind() {
                ResolveErrorKind::NoRecordsFound {..} => Ok((vec![], header)),
                _ => Err(WrappedErrors::ResolverError(error))
            }
        }
    }
}
