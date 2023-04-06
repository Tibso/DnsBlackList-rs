use crate::{
    structs::{DnsLrResult, DnsLrError, DnsLrErrorKind},
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
    config: Guard<Arc<Config>>,
    mut redis_manager: redis::aio::ConnectionManager,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> DnsLrResult<Vec<Record>> {
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
        for matchclass in matchclasses.iter() {
            let full_matchclass = format!("{}:{}", matchclass, domain_to_check);

            // Attempt to find a rule with the provided matchclass and domain name
            match redis_mod::hget(&mut redis_manager, full_matchclass, request.query().query_type().to_string()).await {
                // The Redis query was succesfully processed
                Ok(ok) => {
                    // If the rule exists
                    if ok != "Nil" {
                        info!("{}: request:{} \"{}\" has matched \"{}\" for record type: \"{}\"",
                            CONFILE.daemon_id, request.id(), domain_to_check, matchclass, request.query().query_type()
                        );

                        let rdata: RData;
                        // If found value is "1", the default blackhole_ips are used to lie to the request
                        if ok == "1" {
                            // "rdata" is filled with the default blackhole_ip for the corresponding RecordType
                            rdata = match request.query().query_type() {
                                RecordType::A => RData::A(blackhole_ipv4),
                                RecordType::AAAA => RData::AAAA(blackhole_ipv6),
                                // Because the other types were filtered out before, this part of the code is unreachable
                                // This macro indicates it to the compiler
                                _ => unreachable!()
                            };
                        } else {
                            // The rule seems to have custom IPs to respond with
                            // If found value is an IP, "rdata" is filled with the IP of the corresponding RecordType
                            rdata = match ok.parse::<IpAddr>() {
                                Ok(IpAddr::V4(ipv4)) => RData::A(ipv4),
                                Ok(IpAddr::V6(ipv6)) => RData::AAAA(ipv6),
                                // An error occured, the rule must be broken
                                Err(_) => return Err(DnsLrError::from(DnsLrErrorKind::InvalidRule))
                            }
                        } 

                        // Write statistics about the source IP
                        redis_mod::write_stats(&mut redis_manager, request.request_info().src.ip(), true).await?;
    
                        // Returns the answer to the calling function
                        return Ok(vec![Record::from_rdata(request.query().name().into(), 3600, rdata)])
                    }
                },
                // The Redis query encountered an error, it is propagated up in the stack
                Err(err) => return Err(err)
            };
        }
    }

    // If no rule was found, the resolver is used to fetch the correct answers
    resolver::get_answers(request, resolver).await
}
