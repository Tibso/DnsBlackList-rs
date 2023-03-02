use crate::handler_mod::CustomError;
use crate::resolver_mod;
use crate::redis_mod;

use trust_dns_client::op::{Header, LowerQuery};
use trust_dns_client::rr::{RData, RecordType, Record};
use trust_dns_resolver::{
    AsyncResolver,
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}
};
use std::net::{Ipv4Addr, Ipv6Addr};
use smallvec::{SmallVec, ToSmallVec, smallvec};

pub async fn filter (
    query: &LowerQuery,
    header: Header,
    matchclasses: Vec<String>,
    blacklist_ips: (Ipv4Addr, Ipv6Addr),
    redis_manager: redis::aio::ConnectionManager,
    resolver: AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>
)
-> Result<(Vec<Record>, Header), CustomError> {
    let domain_name = query.name().to_string();
    let names = domain_name.split(".");

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
            order.extend(1..name_count as u8);
            order = filter_5.to_smallvec();
            for index in 6..name_count {
                order.push(index as u8)
            }
        }
    }

    let (blacklist_ipv4, blacklist_ipv6) = blacklist_ips;

    let names: SmallVec<[&str; 5]> = names.collect();
    for index in order {
        let mut domain_to_check = names[name_count - (index as usize)..name_count].join(".");
        domain_to_check.push('.');

        for matchclass in matchclasses.clone() {
            match redis_mod::exists(
                &redis_manager,
                format!("{}:{}", matchclass, domain_to_check),
                query.query_type()
            ).await {
                Ok(ok) => {
                    if ok {
                        //answer IPs that respond a reset
                        let rdata = match query.query_type() {
                            RecordType::A => RData::A(blacklist_ipv4),
                            RecordType::AAAA => RData::AAAA(blacklist_ipv6),
                            _ => panic!()
                        };
                        return Ok((vec![Record::from_rdata(query.name().into(), 3600, rdata)], header))
                    };
                },
                Err(error) => return Err(CustomError::RedisError(error))
            };
        }
    }

    return resolver_mod::get_answers(query, header, resolver.clone()).await

}
