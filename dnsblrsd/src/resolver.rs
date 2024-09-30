use crate::{errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult, ExternCrateErrorKind}, handler::TTL_1H};

use std::net::SocketAddr;
use hickory_proto::{error::ProtoErrorKind, op::{Header, ResponseCode}, rr::{Record, RecordData, RecordType}};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Name, TokioAsyncResolver
};

/// Builds the resolver that will forward the requests to other DNS servers
pub fn build(forwarders: Vec<SocketAddr>)
-> TokioAsyncResolver {
    let mut resolver_config = ResolverConfig::new();

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
    // Preserve intermediate records such as CNAME records
    resolver_opts.preserve_intermediates = true;
    // Enable EDNS for larger records
    resolver_opts.edns0 = true;

    TokioAsyncResolver::tokio(resolver_config, resolver_opts)
}

/// Resolves the query
pub async fn resolve(
    resolver: &TokioAsyncResolver,
    query_name: &Name,
    query_type: RecordType,
    wants_dnssec: bool,
    header: &mut Header
) -> DnsBlrsResult<(Vec<Record>, Vec<Record>, Vec<Record>, Vec<Record>)> {
    let mut answer = Vec::new();
    let mut name_servers = Vec::new();
    let mut soas: Vec<Record> = Vec::new();
    let mut additional = Vec::new();

    match resolver.lookup(query_name.clone(), query_type, wants_dnssec).await {
        Err(err) => match err.proto() {
            Some(proto_err) => match proto_err.kind() {
                ProtoErrorKind::NoRecordsFound { response_code: ResponseCode::Refused, .. }
                    => { header.set_response_code(ResponseCode::Refused); },
                ProtoErrorKind::NoRecordsFound { response_code: ResponseCode::NXDomain, .. }
                    => { header.set_response_code(ResponseCode::NXDomain); },
                ProtoErrorKind::NoRecordsFound { soa, .. }
                    => {
                        header.set_response_code(ResponseCode::NoError);
                        if soa.is_some() {
                            let soa = soa.clone().expect("Should always be 'Some'");
                            soas.push(
                                Record::from_rdata(query_name.clone(), TTL_1H, soa.into_data().into_rdata())
                            );
                        }
                    },
                _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Proto(proto_err.clone()))))
            },
            _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Resolver(err))))
        },
        Ok(lookup) => {
            let mut cname = Name::new();
            let records = lookup.records();
            for record in records {
                let record_type = record.record_type();
                match record_type {
                    RecordType::SOA => {
                        match query_type {
                            RecordType::SOA => answer.push(record.clone()),
                            _ => soas.push(record.clone())
                        }
                    },
                    RecordType::NS => {
                        match query_type {
                            RecordType::NS => answer.push(record.clone()),
                            _ => name_servers.push(record.clone())
                        }
                    },
                    RecordType::RRSIG => {
                        let data_type_covered = record.data().clone()
                            .into_dnssec().expect("Record data has to be DNSSECRData")
                            .into_rrsig().expect("DNSSECRData has to be RRSIG")
                            .type_covered();

                        if (data_type_covered == query_type) && (*record.name() == *query_name) {
                            answer.push(record.clone());
                            continue
                        }
                        match data_type_covered {
                            RecordType::SOA | RecordType::DS
                            if *record.name() == *query_name
                                => soas.push(record.clone()),
                            RecordType::NS
                            if *record.name() == *query_name
                                => name_servers.push(record.clone()),
                            _ => additional.push(record.clone())
                        }
                    },
                    RecordType::CNAME => {
                        cname = record.data().clone()
                            .into_cname().expect("Record data has to be CNAME")
                            .to_lowercase();
                        answer.push(record.clone())
                    },
                    _ => {
                        if (record_type == query_type && *record.name() == *query_name)
                            || (record_type == query_type && *record.name() == cname) {
                                answer.push(record.clone())
                        } else {
                            additional.push(record.clone())
                        }
                    }
                }
            }
        }
    }
    Ok((answer, name_servers, soas, additional))
}
