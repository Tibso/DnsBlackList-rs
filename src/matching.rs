use crate::Config;
use crate::enums_structs::DnsLrResult;
use crate::resolver_mod;
use crate::redis_mod;

use trust_dns_client::{
    rr::{RData, RecordType, Record},
    op::Header
    };
use trust_dns_server::server::Request;
use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};

use tracing::info;
use smallvec::{SmallVec, ToSmallVec, smallvec};
use arc_swap::Guard;
use std::sync::Arc;

pub async fn filter (
    request: &Request,
    header: Header,
    config: Guard<Arc<Config>>,
    mut redis_manager: redis::aio::ConnectionManager,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> DnsLrResult<(Vec<Record>, Header)> {
    let mut domain_name = request.query().name().to_string();
    domain_name.pop();
    let names = domain_name.split('.');

    let name_count = names.clone().count();
    let filter_5: [u8; 5] = [3, 4, 2, 5, 1];
    let mut order: SmallVec<[u8; 5]> = smallvec![];
    match name_count {
        1 => order = smallvec![1],
        2 => order = smallvec![2, 1],
        3 => order = smallvec![3, 2, 1],
        4 => order = smallvec![3, 4, 2, 1],
        5 => order = filter_5.to_smallvec(),
        _ => {
            order.extend(1..=name_count as u8);
            order = filter_5.to_smallvec();
            for index in 6..=name_count {
                order.push(index as u8);
            }
        }
    }

    let (blackhole_ipv4, blackhole_ipv6) = config.blackhole_ips.unwrap();
    let matchclasses = config.matchclasses.clone().unwrap();

    let names: SmallVec<[&str; 5]> = names.collect();
    for index in order {
        let mut domain_to_check = names[name_count - (index as usize)..name_count].join(".");
        domain_to_check.push('.');

        for matchclass in matchclasses.iter() {
            match redis_mod::exists(
                &mut redis_manager,
                format!("{}:{}", matchclass, domain_to_check),
                request.query().query_type()
            ).await {
                Ok(ok) => {
                    if ok {
                        //answer IPs that respond a reset
                        info!("{}: Request n°{}: {} has matched {}", config.daemon_id, request.id(), domain_to_check, matchclass);

                        let rdata = match request.query().query_type() {
                            RecordType::A => RData::A(blackhole_ipv4),
                            RecordType::AAAA => RData::AAAA(blackhole_ipv6),
                            _ => unreachable!()
                        };
                        return Ok((vec![Record::from_rdata(request.query().name().into(), 3600, rdata)], header))
                    };
                },
                Err(error) => return Err(error)
            };
        }
    }

    return resolver_mod::get_answers(request, header, resolver).await
}
