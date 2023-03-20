use crate::{
    Config,
    enums_structs::DnsLrResult,
    resolver_mod,
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
use std::sync::Arc;

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
        _ => {
            order.extend(filter_5);
            order.extend(6..=name_count as u8);
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
                        info!("{}: request:{} {} has matched {}", CONFILE.daemon_id, request.id(), domain_to_check, matchclass);

                        let rdata = match request.query().query_type() {
                            RecordType::A => RData::A(blackhole_ipv4),
                            RecordType::AAAA => RData::AAAA(blackhole_ipv6),
                            _ => unreachable!()
                        };
                        return Ok(vec![Record::from_rdata(request.query().name().into(), 3600, rdata)])
                    };
                },
                Err(err) => return Err(err)
            };
        }
    }

    return resolver_mod::get_answers(request, resolver).await
}
