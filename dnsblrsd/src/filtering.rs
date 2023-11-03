use crate::{
    structs::{DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind},
    Config, resolver, redis_mod, CONFILE
};

use hickory_client::rr::{RData, RecordType, Record};
use hickory_server::server::Request;
use hickory_resolver::TokioAsyncResolver;
use hickory_proto::rr::rdata;

use tracing::info;
use smallvec::{SmallVec, smallvec};
use arc_swap::Guard;
use std::{sync::Arc, net::IpAddr};

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

    // Splits the domain name by using the dots and collect the iterator to a vector
    // The SmallVec type is an optimized vector type which lives in the stack
    // but the vector is moved to the heap when the vector gets bigger
    // than the specified stack size
    let names: SmallVec<[&str; 5]>  = domain_name.split('.').collect();
    let name_count = names.len();
    
    // The domain name is rearranged into different orders
    // which were found to match known domain names faster
    let filter_5: [u8; 5] = [3, 4, 2, 5, 1];
    let mut order: SmallVec<[u8; 5]> = smallvec![];
    match name_count {
        1 => order.push(1),
        2 => order.extend([2, 1]),
        3 => order.extend([3, 2, 1]),
        4 => order.extend([3, 4, 2, 1]),
        5 => order.extend(filter_5),
        _ => order.extend(filter_5.into_iter().chain(6..=name_count as u8))
    }

    // "blackhole_ips" and "matchclasses" are cloned
    // out of the configuration to be used on this thread
    let (blackhole_ipv4, blackhole_ipv6) = config.blackhole_ips.unwrap();
    let matchclasses = config.matchclasses.clone().unwrap();

    for index in order {
        // The domain name is reconstructed based on each iteration of order
        let mut domain_to_check = names[name_count - (index as usize)..name_count].join(".");
        // Because we are matching root domain names, we have to put the trailing dot back in place
        domain_to_check.push('.');

        for matchclass in &matchclasses {
            let rule = format!("{}:{}", matchclass, domain_to_check);

            // Attempts to find a rule with the provided matchclass and domain name
            let rule = redis_mod::hget(redis_manager, rule, record_type.to_string()).await?;

            if rule != "Nil" {
                info!("{}: request:{} \"{}\" has matched \"{}\" for record type: \"{}\"",
                    CONFILE.daemon_id, request.id(), domain_to_check, matchclass, record_type
                );

                // If found value is "1", the default blackhole_ips are used to lie to the request
                let rdata: RData = if rule == "1" {
                    match record_type {
                        RecordType::A => RData::A(rdata::a::A(blackhole_ipv4)),
                        RecordType::AAAA => RData::AAAA(rdata::aaaa::AAAA(blackhole_ipv6)),
                        _ => unreachable!()
                    }
                } else {
                    // The rule seems to have custom IPs to respond with
                    match rule.parse::<IpAddr>() {
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
    };

    // If no rule was found, the resolver is used to fetch the correct answers
    let mut records = resolver::get_records(request, resolver).await?;
    if records.is_empty() {
        return Ok(records)
    }

    match record_type {
        RecordType::A => {
            // If a record is blacklisted, replace it with "blackhole_ips"
            for record in &records {
                let ip: IpAddr = record.data().unwrap().ip_addr().unwrap();

                if redis_mod::sismember(redis_manager, format!("dnsblrs:blocked_ips_v4:{}", CONFILE.daemon_id), ip.to_string()).await? {
                    records.clear();
                    records.push(Record::from_rdata(request.query().name().into(), 3600, RData::A(rdata::a::A(blackhole_ipv4))));

                    return Ok(records)
                }
            }
        },
        RecordType::AAAA => {
            for record in &records {
                let ip: IpAddr = record.data().unwrap().ip_addr().unwrap();

                if redis_mod::sismember(redis_manager, format!("dnsblrs:blocked_ips_v6:{}", CONFILE.daemon_id), ip.to_string()).await? {
                    records.clear();
                    records.push(Record::from_rdata(request.query().name().into(), 3600, RData::AAAA(rdata::aaaa::AAAA(blackhole_ipv6))));

                    return Ok(records)
                }
            }
        },
        _ => unreachable!()
    }

    Ok(records)
}
