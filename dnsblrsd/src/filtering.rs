use crate::{
    structs::{DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind},
    Config, resolver, redis_mod, CONFILE
};

use trust_dns_client::rr::{RData, RecordType, Record};
use trust_dns_server::server::Request;
use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};

use tracing::info;
use smallvec::{SmallVec, smallvec};
use arc_swap::Guard;
use std::{sync::Arc, net::IpAddr};

/// Filters out requests based on its requested domain
pub async fn filter (
    request: &Request,
    config: &Guard<Arc<Config>>,
    redis_manager: &mut redis::aio::ConnectionManager,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> DnsBlrsResult<Vec<Record>> {
    // Stores the record_type of the request
    let record_type = request.query().query_type();

    // Converts the domain name to string
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

    // The number of names from the domain name to match is iterated onto
    for index in order {
        // The domain name is reconstructed based on the index of each iteration of order
        let mut domain_to_check = names[name_count - (index as usize)..name_count].join(".");
        // Because we are matching root domain names, we have to put back the trailing dot
        domain_to_check.push('.');

        // "matchclasses" is converted to an iterable and is iterated onto
        // to attempt to match one of the matchclasses to the domain name
        for matchclass in &matchclasses {
            let full_matchclass = format!("{}:{}", matchclass, domain_to_check);

            // Attempts to find a rule with the provided matchclass and domain name
            // If an error occurs, it is propagated up in the stack
            let rule = redis_mod::hget(redis_manager, full_matchclass, record_type.to_string()).await?;

            // If the rule exists
            if rule != "Nil" {
                info!("{}: request:{} \"{}\" has matched \"{}\" for record type: \"{}\"",
                    CONFILE.daemon_id, request.id(), domain_to_check, matchclass, record_type
                );

                // If found value is "1", the default blackhole_ips are used to lie to the request
                let rdata: RData = if rule == "1" {
                    // "rdata" is filled with the default blackhole_ip for the corresponding RecordType
                    match record_type {
                        RecordType::A => RData::A(blackhole_ipv4),
                        RecordType::AAAA => RData::AAAA(blackhole_ipv6),
                        // Because the other types were filtered out before, this part of the code is unreachable
                        // This macro indicates it to the compiler
                        _ => unreachable!()
                    }
                } else {
                    // The rule seems to have custom IPs to respond with
                    // If found value is an IP, "rdata" is filled with the IP of the corresponding RecordType
                    match rule.parse::<IpAddr>() {
                        Ok(IpAddr::V4(ipv4)) => RData::A(ipv4),
                        Ok(IpAddr::V6(ipv6)) => RData::AAAA(ipv6),
                        // An error occured, the rule must be broken
                        Err(_) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
                    }
                };

                // Write statistics about the source IP
                redis_mod::write_stats(redis_manager, request.request_info().src.ip(), true).await?;

                // Returns the answer to the calling function
                return Ok(vec![Record::from_rdata(request.query().name().into(), 3600, rdata)])
            }
        }
    };

    // If no rule was found, the resolver is used to fetch the correct answers
    let mut records = resolver::get_records(request, resolver).await?;
    // Do not check records if there is none
    if records.is_empty() {
        return Ok(records)
    }

    match record_type {
        RecordType::A => {
            // If a record is blacklisted, replace it with "blackhole_ips"
            for record in &records {
                // "ip" is extracted from the record's data
                let ip: IpAddr = record.data().unwrap().to_ip_addr().unwrap();

                // If the record is blacklisted, returns the corresponding "blackhole_ip"
                if redis_mod::sismember(redis_manager, format!("dnsblrs:blocked_ips_v4:{}", CONFILE.daemon_id), ip.to_string()).await? {
                    // Clears the previous records
                    records.clear();
                    // Stores the new record
                    records.push(Record::from_rdata(request.query().name().into(), 3600, RData::A(blackhole_ipv4)));

                    return Ok(records)
                }
            }
        },
        RecordType::AAAA => {
            for record in &records {
                let ip: IpAddr = record.data().unwrap().to_ip_addr().unwrap();

                if redis_mod::sismember(redis_manager, format!("dnsblrs:blocked_ips_v6:{}", CONFILE.daemon_id), ip.to_string()).await? {
                    records.clear();
                    records.push(Record::from_rdata(request.query().name().into(), 3600, RData::AAAA(blackhole_ipv6)));

                    return Ok(records)
                }
            }
        },
        _ => unreachable!()
    }

    Ok(records)
}
