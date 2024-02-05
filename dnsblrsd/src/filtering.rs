use tracing::info;
use arc_swap::Guard;

use hickory_client::rr::{RData, RecordType, Record};
use hickory_server::server::Request;
use hickory_resolver::TokioAsyncResolver;
use hickory_proto::rr::rdata;

use std::{sync::Arc, net::IpAddr};

use crate::{
    structs::{DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind},
    Config, resolver, redis_mod, CONFILE
};

/// Filters out requests based on its requested domain
pub async fn filter (
    request: &Request,
    config: &Guard<Arc<Config>>,
    redis_manager: &mut redis::aio::ConnectionManager,
    resolver: TokioAsyncResolver
)
-> DnsBlrsResult<Vec<Record>> {
    let record_type = request.query().query_type();

    let mut domain_name = request.query().name().to_string();
    // Because it is a root domain name, we remove the trailing dot from the String
    domain_name.pop();

    let names: Vec<&str> = domain_name.split('.').collect();
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
        _ => order.extend(filter_5.into_iter().chain(6..=u8::try_from(name_count).map_err(|_| DnsBlrsError::from(DnsBlrsErrorKind::LogicError))?))
    }

    // "blackholes" and "filters" are cloned
    // out of the configuration to be used on this thread
    let (blackhole_ipv4, blackhole_ipv6) = config.blackholes.unwrap();
    let filters = config.filters.clone().unwrap();

    for index in order {
        // The domain name is reconstructed based on each iteration of order
        let domain = names[name_count - (index as usize)..name_count].join(".");

        for filter in &filters {
            let rule = format!("DBL;R;{filter};{domain}");

            // Attempts to find a rule with the provided filter and domain name
            let rule_val = redis_mod::hget(redis_manager, rule.as_str(), record_type.to_string().as_str()).await?;

            if let Some(rule_val) = rule_val {
                let enabled = redis_mod::hget(redis_manager, rule.as_str(), "enabled").await?;
                if enabled.is_some_and(|enabled| enabled != "1") {
                    continue
                }

                info!("{}: request:{} \"{domain}\" has matched \"{filter}\" for record type: \"{record_type}\"",
                    CONFILE.daemon_id, request.id()
                );

                // If found value is "1", the blackholes are used to lie to the request
                let rdata: RData = if rule_val == "1" {
                    match record_type {
                        RecordType::A => RData::A(rdata::a::A(blackhole_ipv4)),
                        RecordType::AAAA => RData::AAAA(rdata::aaaa::AAAA(blackhole_ipv6)),
                        _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
                    }
                } else {
                    // The rule seems to have custom IPs to respond with
                    match rule_val.parse::<IpAddr>() {
                        Ok(IpAddr::V4(ipv4)) => RData::A(rdata::a::A(ipv4)),
                        Ok(IpAddr::V6(ipv6)) => RData::AAAA(rdata::aaaa::AAAA(ipv6)),
                        Err(_) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
                    }
                };

                // Write statistics about the source IP
                redis_mod::write_stats(redis_manager, request.request_info().src.ip(), true).await?;

                return Ok(vec![Record::from_rdata(request.query().name().into(), 3600, rdata)])
            }
        }
    }

    // If no rule was found, the resolver is used to fetch the correct answers
    let mut records = resolver::get_records(request, resolver).await?;
    if records.is_empty() {
        return Ok(records)
    }

    match record_type {
        RecordType::A => {
            // If a record is blacklisted, replace it with the blackhole
            for record in &records {
                if let Some(rdata) = record.data() {
                    if let Some(ip) = rdata.ip_addr() {
                        if redis_mod::sismember(redis_manager, format!("DBL;blocked-ips;{}", CONFILE.daemon_id).as_str(), ip.to_string().as_str()).await? {
                            records.clear();
                            records.push(Record::from_rdata(request.query().name().into(), 3600, RData::A(rdata::a::A(blackhole_ipv4))));
        
                            return Ok(records)
                        }
                    } else {
                        return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
                    }
                } else {
                    return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
                }
            }
        },
        RecordType::AAAA => {
            for record in &records {
                if let Some(rdata) = record.data() {
                    if let Some(ip) = rdata.ip_addr() {
                        if redis_mod::sismember(redis_manager, format!("DBL;blocked-ips;{}", CONFILE.daemon_id).as_str(), ip.to_string().as_str()).await? {
                            records.clear();
                            records.push(Record::from_rdata(request.query().name().into(), 3600, RData::AAAA(rdata::aaaa::AAAA(blackhole_ipv6))));

                            return Ok(records)
                        }
                    } else {
                        return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
                    }
                } else {
                    return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
                }
            }
        },
        _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::LogicError))
    }

    Ok(records)
}
