use crate::{
    handler::Handler,
    errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult},
    resolver::Records
};

use hickory_server::server::Request;
use redis::pipe;
use serde::Deserialize;
use tracing::info;

#[derive(Deserialize, Clone)]
/// Conf used for filtering
pub struct FilteringConf {
    pub is_filtering: bool,
    pub filters: Option<Vec<String>>
}

/// Filters out requests based on its requested domain
pub async fn filter_domain (
    handler: &Handler,
    request: &Request
) -> DnsBlrsResult<Option<Records>> {
    let Some(filters) = handler.filtering_conf.load().filters.clone() else {
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::IncompleteConf))
    };
    let query = request.query();
    let mut redis_mngr = handler.redis_mngr.clone();
    let request_info = request.request_info();

    let mut request_domain = query.name().to_string();
    // Because it is a root domain name, we remove the trailing dot
    request_domain.pop();
    let parts: Vec<&str> = request_domain.split('.').collect();
    let parts_len = parts.len();
    
    let mut pipe = pipe();
    let mut search_domain_parts = Vec::with_capacity(parts_len);
    for filter in filters {
        for i in (0..parts_len).rev() {
            search_domain_parts.insert(0, parts[i]);
            let rule = format!("DBL;RD;{filter};{}", search_domain_parts.join("."));
            pipe.hget(rule, "enabled");
        }
        search_domain_parts.clear();
    }
    let results: Vec<Option<u8>> = pipe.query_async(&mut redis_mngr).await?;
    for result in results.into_iter().flatten() {
        info!("{}: request:{} src:{}://{} QUERY:{} | Blacklisted \"{request_domain}\" found",
            handler.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query);
        match result {
            1 => return Ok(Some(Records::new())),
            0 => continue,
            _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
        }
    }
    Ok(None)
    
    // #[cfg(feature = "qtypes")]
    // let rule_val: Option<String> = redis_mngr.hget(rule, query.query_type().to_string()).await?;
    // let Some(rule_val) = rule_val else {
    //     continue
    // };

    // info!("{}: request:{} \"{domain}\" has matched \"{filter}\" for qtype: \"{}\"",
    //     handler.daemon_id, request.id(), query.query_type());
    
    // #[cfg(feature = "stats")]
    // // Write statistics about the source IP
    // redis_mod::write_stats_match(redis_manager, daemon_id, request_src_ip, rule).await?;

    // #[cfg(feature = "custom_ips")]
    // // If value is 1 respond NXDomain, otherwise respond custom IP
    // if rule_val == "1" {
    //     header.set_response_code(ResponseCode::NXDomain);
    //     return Ok(ResponseRecords::new())
    // } else {
    //     let rdata = match rule_val.parse::<IpAddr>() {
    //         Ok(IpAddr::V4(ipv4)) => RData::A(rdata::a::A(ipv4)),
    //         Ok(IpAddr::V6(ipv6)) => RData::AAAA(rdata::aaaa::AAAA(ipv6)),
    //         Err(_) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
    //     };
    //     let mut response_records = ResponseRecords::new();
    //     response_records.answer.push(Record::from_rdata(query_name, TTL_1H, rdata));
    //     return Ok(response_records)
    // }
}

/// Checks if there is a blacklisted IP in the answer section of the DNS response
pub async fn have_blacklisted_ip (
    handler: &Handler,
    request: &Request,
    records: &Records
) -> DnsBlrsResult<bool> {
    let Some(filters) = handler.filtering_conf.load().filters.clone() else {
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::IncompleteConf))
    };
    let mut redis_mngr = handler.redis_mngr.clone();
    let request_info = request.request_info();

    let mut pipe = pipe();
    for record in &records.answer {
        let Some(ip) = record.data().ip_addr() else {
            continue
        };
        let ip_string = ip.to_string();

        for filter in &filters {
            let rule = format!("DBL;RI;{filter};{ip_string}");
            pipe.hget(rule, "enabled");
        }
    }
    let results: Vec<Option<u8>> = pipe.query_async(&mut redis_mngr).await?;
    for result in results.into_iter().flatten() {
        info!("{}: request:{} src:{}://{} QUERY:{} | A blacklisted IP was found when resolving \"{}\"",
            handler.daemon_id, request.id(), request_info.protocol, request_info.src, request_info.query, request.query().name());
        match result {
            1 => return Ok(true),
            0 => continue,
            _ => return Err(DnsBlrsError::from(DnsBlrsErrorKind::InvalidRule))
        }
    }
    Ok(false)
}
