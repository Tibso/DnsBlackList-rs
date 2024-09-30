use crate::{
    errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult},
    handler::TTL_1H,
    redis_mod, resolver
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use hickory_resolver::{Name, TokioAsyncResolver};
use hickory_proto::{op::Header, rr::{rdata, RData, RecordType, Record}};
use redis::AsyncCommands;
use serde::Deserialize;
//use tracing::debug;

#[derive(Deserialize, Clone)]
/// Running filtering config
pub struct FilteringConfig {
    pub is_filtering: bool,
    pub data: Option<Data>
}
#[derive(Deserialize, Clone)]
/// Data used for filtering
pub struct Data {
    pub filters: Vec<String>,
    pub sinks: (Ipv4Addr, Ipv6Addr)
}

/// Filters out requests based on its requested domain
pub async fn filter(
    daemon_id: &str,
    query_name: Name,
    query_type: RecordType,
    request_src_ip: IpAddr,
    sinks: (Ipv4Addr, Ipv6Addr),
    filters: &Vec<String>,
    wants_dnssec: bool,
    resolver: &TokioAsyncResolver,
    header: &mut Header,
    redis_manager: &mut redis::aio::ConnectionManager
) -> DnsBlrsResult<(Vec<Record>, Vec<Record>, Vec<Record>, Vec<Record>)> {
    let name_string = {
        let mut name = query_name.to_string();
        // Because it is a root domain name, we remove the trailing dot from the String
        name.pop();
        name
    };

    let names: Vec<&str> = name_string.split('.').collect();
    let name_count = names.len();
    
    // The domain name is rearranged into different orders
    // which were found to match known domain names faster
    let filter_5: [u8; 5] = [3, 4, 2, 5, 1];
    let mut order: Vec<u8> = vec![];
    match name_count {
        1 => order.push(1),
        2 => order.extend([2, 1]),
        3 => order.extend([3, 2, 1]),
        4 => order.extend([3, 4, 2, 1]),
        5 => order.extend(filter_5),
        _ => order.extend(filter_5.into_iter().chain(6..=name_count as u8))
    }

    let (sink_v4, sink_v6) = sinks;

    for index in order {
        // The domain name is reconstructed based on each iteration of order
        let domain = names[name_count - (index as usize)..name_count].join(".");

        for filter in filters {
            let rule = format!("DBL;R;{filter};{domain}");
            let rule = rule.as_str();

            // Attempts to find a matching rule
            let rule_val: Option<String> = redis_manager.hget(rule, query_type.to_string().as_str()).await?;
            let Some(rule_val) = rule_val else {
                continue
            };
            // Checks if the rule is enabled
            if ! redis_manager.hget(rule, "enabled").await? {
                continue
            }

            //debug!("{daemon_id}: request:{} \"{domain}\" has matched \"{filter}\" for record type: \"{record_type}\"", request.id());

            // If value is 1, the sinks are used to lie
            let rdata: RData = {
                if rule_val == "1" {
                    match query_type {
                        RecordType::A => RData::A(rdata::a::A(sink_v4)),
                        RecordType::AAAA => RData::AAAA(rdata::aaaa::AAAA(sink_v6)),
                        _ => unreachable!("Record type should have already been filtered out")
                    }
                } else {
                    // The rule seems to have custom IPs to respond with
                    match rule_val.parse::<IpAddr>() {
                        Ok(IpAddr::V4(ipv4)) => RData::A(rdata::a::A(ipv4)),
                        Ok(IpAddr::V6(ipv6)) => RData::AAAA(rdata::aaaa::AAAA(ipv6)),
                        Err(_) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
                    }
                }
            };

            // Write statistics about the source IP
            redis_mod::write_stats_match(redis_manager, daemon_id, request_src_ip, rule).await?;

            return Ok((vec![Record::from_rdata(query_name, TTL_1H, rdata)], vec![], vec![], vec![]))
        }
    }

    // If no rule was found, the resolver is used to fetch the correct answers
    Ok(filter_resolution(daemon_id, query_name, query_type, sinks, wants_dnssec, resolver, header, redis_manager).await?)
}

/// Resolves the query while filtering out blacklisted IPs
pub async fn filter_resolution(
    daemon_id: &str,
    query_name: Name,
    query_type: RecordType,
    sinks: (Ipv4Addr, Ipv6Addr),
    wants_dnssec: bool,
    resolver: &TokioAsyncResolver,
    header: &mut Header,
    redis_manager: &mut redis::aio::ConnectionManager
) -> DnsBlrsResult<(Vec<Record>, Vec<Record>, Vec<Record>, Vec<Record>)> {
    let (mut answer, name_servers, soa, additional) = resolver::resolve(resolver, &query_name, query_type, wants_dnssec, header).await?;
    if answer.is_empty() {
        return Ok((answer, name_servers, soa, additional))
    }

    // If a record is blacklisted, replace it with the sink
    for record in &answer {
        let Some(ip) = record.data().ip_addr() else {
            continue
        };
        if ! redis_manager.sismember(format!("DBL;blocked-ips;{daemon_id}").as_str(), ip.to_string().as_str()).await? {
            continue
        }

        answer.clear();
        let (sink_v4, sink_v6) = sinks;
        let rdata: RData = match query_type {
            RecordType::A => RData::A(rdata::a::A(sink_v4)),
            RecordType::AAAA => RData::AAAA(rdata::aaaa::AAAA(sink_v6)),
            _ => unreachable!("Record type should have already been filtered out")
        };
        answer.push(Record::from_rdata(query_name, TTL_1H, rdata));
        return Ok((answer, name_servers, soa, additional))
    }

    Ok((answer, name_servers, soa, additional))
}