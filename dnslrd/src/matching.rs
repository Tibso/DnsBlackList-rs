use crate::{
    Config,
    structs::{DnsLrResult, DnsLrError, DnsLrErrorKind},
    resolver,
    redis_mod,
    CONFILE
};

use trust_dns_client::{
    rr::{RData, RecordType, Record}
    };
use trust_dns_server::server::Request;
use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};

use tracing::info;
use smallvec::{SmallVec, smallvec};
use arc_swap::Guard;
use std::{sync::Arc, net::IpAddr};

pub async fn filter (
    request: &Request,
    config: Guard<Arc<Config>>,
    mut redis_manager: redis::aio::ConnectionManager,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> DnsLrResult<Vec<Record>> {
    let mut domain_name = request.query().name().to_string();
    domain_name.pop();
    let names = domain_name.split('.');

    let name_count = names.clone().count();
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

    let (blackhole_ipv4, blackhole_ipv6) = config.blackhole_ips.unwrap();
    let matchclasses = config.matchclasses.clone().unwrap();

    let record_type = match request.query().query_type() {
        RecordType::A => "A", 
        RecordType::AAAA => "AAAA",
        _ => unreachable!()
    };

    let names: SmallVec<[&str; 5]> = names.collect();
    for index in order {
        let mut domain_to_check = names[name_count - (index as usize)..name_count].join(".");
        domain_to_check.push('.');

        for matchclass in matchclasses.iter() {
            let full_matchclass = format!("{}:{}", matchclass, domain_to_check);

            match redis_mod::hget(&mut redis_manager, full_matchclass, record_type.to_owned()).await {
                Ok(ok) => {
                    if ok != "Nil" {
                        info!("{}: request:{} \"{}\" has matched \"{}\"", CONFILE.daemon_id, request.id(), domain_to_check, matchclass);

                        let rdata: RData;
                        if ok == "1" {
                            rdata = match record_type {
                                "A" => RData::A(blackhole_ipv4),
                                "AAAA" => RData::AAAA(blackhole_ipv6),
                                _ => unreachable!()
                            };
                        } else {
                            rdata = match ok.parse::<IpAddr>() {
                                Ok(IpAddr::V4(ipv4)) => RData::A(ipv4),
                                Ok(IpAddr::V6(ipv6)) => RData::AAAA(ipv6),
                                Err(_) => return Err(DnsLrError::from(DnsLrErrorKind::InvalidRule))
                            }
                        } 

                        redis_mod::write_stats(&mut redis_manager, request.request_info().src.ip(), true).await?;
    
                        return Ok(vec![Record::from_rdata(request.query().name().into(), 3600, rdata)])
                    }
                },
                Err(err) => return Err(err)
            };
        }
    }

    return resolver::get_answers(request, resolver).await
}
