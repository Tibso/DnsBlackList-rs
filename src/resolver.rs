use crate::{errors::{DnsBlrsError, DnsBlrsResult}, handler::TTL_1H};

use std::{net::SocketAddr, sync::Arc};
use hickory_proto::{
    op::{Header, ResponseCode}, rr::{Record, RecordData, RecordType},
    xfer::Protocol, ProtoErrorKind};
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    Name, TokioResolver
};
use hickory_server::server::Request;

/// Builds the resolver that will forward the requests to other DNS servers
pub fn build(forwarders: Vec<SocketAddr>) -> TokioResolver {
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
    // Enable Extended DNS
    resolver_opts.edns0 = true;
    // Enable DNSSEC validation
    resolver_opts.validate = true;

    TokioResolver::builder_with_config(resolver_config, )
}

pub struct Records {
    pub answer: Vec<Record>,
    pub name_servers: Vec<Record>,
    pub soas: Vec<Record>,
    pub additional: Vec<Record>
}
impl Records {
    pub fn new() -> Self {
        Self {
            answer: Vec::new(),
            name_servers: Vec::new(),
            soas: Vec::new(),
            additional: Vec::new()
        }
    }
}
impl Default for Records {
    fn default() -> Self {
        Records::new()
    }
}

/// Resolves the query
pub async fn resolve(
    resolver: &Arc<TokioResolver>,
    request: &Request,
    wants_dnssec: bool,
    header: &mut Header
) -> DnsBlrsResult<Records> {
    let (query_name, qtype) = {
        let query = request.query();
        (query.name(), query.query_type())
    };

    let mut sorted_records = Records::new();
    match resolver.lookup(query_name, qtype, wants_dnssec).await {
        Err(e) => match e.proto() {
            Some(proto_err) => match proto_err.kind() {
                ProtoErrorKind::NoRecordsFound { response_code: ResponseCode::Refused, .. }
                    => { header.set_response_code(ResponseCode::Refused); },
                ProtoErrorKind::NoRecordsFound { response_code: ResponseCode::NotImp, .. }
                    => { header.set_response_code(ResponseCode::NotImp); },
                ProtoErrorKind::NoRecordsFound { response_code, soa, ns, .. }
                    => {
                        match response_code {
                            ResponseCode::NXDomain => { header.set_response_code(ResponseCode::NXDomain); },
                            ResponseCode::NoError => { header.set_response_code(ResponseCode::NoError); },
                            _ => return Err(DnsBlrsError::Proto(proto_err.clone()))
                        }
                        if let Some(soa) = soa {
                            sorted_records.soas.push(Record::from_rdata(query_name.into(), TTL_1H, soa.clone().into_data().into_rdata()));
                        }
                        if let Some(ns_datas) = ns {
                            for ns_data in ns_datas.as_ref() {
                                sorted_records.name_servers.push(Record::from_rdata(query_name.into(), TTL_1H, ns_data.ns.clone().into_data().into_rdata()));
                                sorted_records.additional.extend_from_slice(&ns_data.glue);
                            }
                        }
                    },
                _ => return Err(DnsBlrsError::Proto(proto_err.clone()))
            },
            _ => return Err(DnsBlrsError::Resolver(e.clone()))
        },
        Ok(lookup) => {
            header.set_response_code(ResponseCode::NoError);
            sort_records(lookup.records(), query_name, qtype, &mut sorted_records);
        }
    }
    Ok(sorted_records)
}

/// Sorts the records in their respective section
pub fn sort_records (
    records: &[Record],
    query_name: &Name,
    qtype: RecordType,
    sorted_records: &mut Records
) {
    let answer = &mut sorted_records.answer;
    let name_servers = &mut sorted_records.name_servers;
    let soas = &mut sorted_records.soas;
    let additional = &mut sorted_records.additional;
    let mut cname = Name::new();

    for record in records {
        let record_type = record.record_type();
        match record_type {
            RecordType::SOA => {
                match qtype {
                    RecordType::SOA => answer.push(record.clone()),
                    _ => soas.push(record.clone())
                }
            },
            RecordType::NS => {
                match qtype {
                    RecordType::NS => answer.push(record.clone()),
                    _ => name_servers.push(record.clone())
                }
            },
            RecordType::RRSIG => {
                let data_type_covered = record.data().clone()
                    .into_dnssec().unwrap()
                    .into_rrsig().unwrap()
                    .type_covered();

                if data_type_covered == qtype && *record.name() == *query_name {
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
                    .into_cname().unwrap()
                    .to_lowercase();
                answer.push(record.clone())
            },
            _ => {
                if (*record.name() == *query_name || *record.name() == cname) && record_type == qtype {
                        answer.push(record.clone())
                } else {
                    additional.push(record.clone())
                }
            }
        }
    }
}
