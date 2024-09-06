use crate::errors::{DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind, ExternCrateErrorKind};

use std::net::SocketAddr;
use hickory_client::{op::ResponseCode, rr::RecordType};
use hickory_proto::{op::LowerQuery, rr::{RData, Record}};
use hickory_resolver::{
    IntoName, TokioAsyncResolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind}
};
use tracing::info;

/// Builds the resolver that will forward the requests to other DNS servers
pub fn build(
    daemon_id: &str,
    forwarders: Vec<SocketAddr>
) -> TokioAsyncResolver {
    let mut resolver_config = ResolverConfig::new();
    // Local domain is set as resolver's domain
    resolver_config.domain();

    for socket_addr in forwarders {
        let ns_udp = NameServerConfig::new(socket_addr, Protocol::Udp);
        resolver_config.add_name_server(ns_udp);
        let ns_tcp = NameServerConfig::new(socket_addr, Protocol::Tcp);
        resolver_config.add_name_server(ns_tcp);
    }
    
    let mut resolver_opts: ResolverOpts = ResolverOpts::default();
    // We do not want the resolver to send concurrent queries,
    // as it would increase network load for little to no speed benefit
    resolver_opts.num_concurrent_reqs = 0;
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

    info!("{daemon_id}: Resolver built");
    resolver
}

/// Handles the resolver errors
fn resolve_err_kind(err: ResolveError)
-> DnsBlrsResult<()> {
    match err.kind() {
        ResolveErrorKind::NoRecordsFound {response_code: ResponseCode::Refused, ..}
            => Err(DnsBlrsError::from(DnsBlrsErrorKind::RequestRefused)),
        ResolveErrorKind::NoRecordsFound {..}
            => Ok(()),
        _ => Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Resolver(err))))
    }
}

/// Uses the resolver to retrieve the correct records
pub async fn get_records(
    query: &LowerQuery,
    resolver: &TokioAsyncResolver
) -> DnsBlrsResult<Vec<Record>> {
    let mut records: Vec<Record> = vec![];

    let name = query.name().into_name()
        .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Proto(err))))?;

    match query.query_type() {
        RecordType::A => if let Ok(lookup) = resolver.ipv4_lookup(name.clone()).await
            .map_err(resolve_err_kind) {
                for a in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::A(a)));
                }
            },
        RecordType::AAAA => if let Ok(lookup) = resolver.ipv6_lookup(name.clone()).await
            .map_err(resolve_err_kind) {
                for aaaa in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::AAAA(aaaa)));
                }
            },
        RecordType::TXT => if let Ok(lookup) = resolver.txt_lookup(name.clone()).await
            .map_err(resolve_err_kind) {
                for txt in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::TXT(txt)));
                }
            },
        RecordType::SRV => if let Ok(lookup) = resolver.srv_lookup(name.clone()).await
            .map_err(resolve_err_kind) {
                for srv in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::SRV(srv)));
                }
            },
        RecordType::MX => if let Ok(lookup) = resolver.mx_lookup(name.clone()).await
            .map_err(resolve_err_kind) {
                for mx in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::MX(mx)));
                }
            },
        RecordType::PTR => {
            let ip = name.parse_arpa_name() 
                .map_err(|err| DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Proto(err))))?
                .addr();

            if let Ok(lookup) = resolver.reverse_lookup(ip).await
            .map_err(resolve_err_kind) {
                for ptr in lookup {
                    records.push(Record::from_rdata(name.clone(), 3600, RData::PTR(ptr)));
                }
            }
        },
        _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::NotImpl))
    };

    Ok(records)
}
