use crate::{
    CONFILE,
    structs::{Config, DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind, ExternCrateErrorKind}
};

use hickory_client::{
    op::ResponseCode,
    rr::RecordType,
};
use hickory_proto::rr::Record;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol},
    TokioAsyncResolver,
    IntoName,
    error::{ResolveErrorKind, ResolveError},
    lookup::Lookup
};
use hickory_server::server::Request;

use tracing::info;

/// Builds the resolver that will forward the requests to other DNS servers
pub fn build_resolver (
    config: &Config
)
-> TokioAsyncResolver {
    let mut resolver_config = ResolverConfig::new();
    // Local domain is set as resolver's domain
    resolver_config.domain();

    for socket in config.forwarders.clone() {
        let ns_udp = NameServerConfig::new(socket, Protocol::Udp);
        resolver_config.add_name_server(ns_udp);
        let ns_tcp = NameServerConfig::new(socket, Protocol::Tcp);
        resolver_config.add_name_server(ns_tcp);
    }
    
    // Default values of the resolver are used
    let mut resolver_opts: ResolverOpts = ResolverOpts::default();
    
    // We do not want the resolver to send concurrent queries,
    // as it would increase network load for little to no speed benefit
    resolver_opts.num_concurrent_reqs = 0;

    let resolver = TokioAsyncResolver::tokio(
        resolver_config,
        resolver_opts
    );

    info!("{}: Resolver built", CONFILE.daemon_id);
    resolver
}

/// Uses the resolver to retrieve the correct records
pub async fn get_records (
    request: &Request,
    resolver: TokioAsyncResolver
)
-> DnsBlrsResult<Vec<Record>> {
    let mut records: Vec<Record> =  vec![];

    let name = request.query().name().into_name().unwrap();

    // The result variable of the resolver queries is defined here to increase its scope,
    // so all the results can be handled later
    let wrapped: Result<Lookup, ResolveError>;
    match request.query().query_type() {
        RecordType::A => wrapped = resolver.lookup(name, RecordType::A).await,
        RecordType::AAAA => wrapped = resolver.lookup(name, RecordType::AAAA).await,
        RecordType::TXT => wrapped = resolver.lookup(name, RecordType::TXT).await,
        RecordType::SRV => wrapped = resolver.lookup(name, RecordType::SRV).await,
        RecordType::MX => wrapped = resolver.lookup(name, RecordType::MX).await,
        RecordType::PTR => {
            // PTR queries results need to be handled separetely,
            // as the result is of a different type

            let Ok(ip) = name.parse_arpa_name() else {
                return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidArpaAddress))
            };
            
            // Subnet address is converted to an IP
            let ip = ip.addr();
            return match resolver.reverse_lookup(ip).await {
                Ok(ok) => {
                    for record in ok.as_lookup().records() {
                        records.push(record.clone())
                    }
                    Ok(records)
                },
                Err(err) => {
                    match err.kind() {
                        ResolveErrorKind::NoRecordsFound {response_code: ResponseCode::Refused, ..}
                            => Err(DnsBlrsError::from(DnsBlrsErrorKind::RequestRefused)),
                        ResolveErrorKind::NoRecordsFound {..}
                            => Ok(records),
                        _ => Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::ResolverError(err))))
                    }
                }
            }
        },
        _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::NotImpl))
    };

    // The result of the resolver queries are handled here
    match wrapped {
        Ok(ok) => {
            for record in ok.records() {
                records.push(record.clone())
            }
            Ok(records)
        },
        Err(err) => {
            match err.kind() {
                ResolveErrorKind::NoRecordsFound {response_code: ResponseCode::Refused, ..}
                    => Err(DnsBlrsError::from(DnsBlrsErrorKind::RequestRefused)),
                // If no record was found, returns the empty answer
                ResolveErrorKind::NoRecordsFound {..}
                    => Ok(records),
                _ => Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::ResolverError(err))))
            }
        }
    }
}
