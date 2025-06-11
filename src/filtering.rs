use crate::{errors::DnsBlrsResult, handler::Handler, resolver::Records};

use hickory_server::server::Request;
use redis::pipe;
use tracing::info;

/// Checks if the requested domain is blacklisted
pub async fn is_domain_blacklisted(
    handler: &Handler,
    request: &Request
) -> DnsBlrsResult<bool> {
    let query = request.query();
    let request_info = request.request_info();
    let mut redis_mngr = handler.redis_mngr.clone();

    let mut request_domain = query.name().to_string();
    // Because it is a root domain name, we remove the trailing dot
    request_domain.pop();
    let parts: Vec<&str> = request_domain.split('.').collect();
    let parts_len = parts.len();
    
    let mut pipe = pipe();
    let mut search_domain_parts = Vec::with_capacity(parts_len);
    for filter in &handler.filters {
        for i in (0..parts_len).rev() {
            search_domain_parts.insert(0, parts[i]);
            let rule = format!("DBL;RD;{filter};{}", search_domain_parts.join("."));
            pipe.hget(rule, "enabled");
        }
        search_domain_parts.clear();
    }
    let results: Vec<Option<u8>> = pipe.query_async(&mut redis_mngr).await?;
    if results.into_iter().flatten().any(|x| x == 1) {
        info!("request:{} src:{}://{} QUERY:{} | Blacklisted \"{request_domain}\" found",
            request.id(), request_info.protocol, request_info.src, request_info.query);
        return Ok(true);
    }
    Ok(false)
}
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

/// Checks if there is a blacklisted IP in the answer section of the DNS response
pub async fn have_blacklisted_ip(
    handler: &Handler,
    request: &Request,
    records: &Records
) -> DnsBlrsResult<bool> {
    let request_info = request.request_info();
    let mut redis_mngr = handler.redis_mngr.clone();

    let mut pipe = pipe();
    for record in &records.answer {
        let Some(ip) = record.data().ip_addr() else {
            continue
        };
        let ip_string = ip.to_string();

        for filter in &handler.filters {
            let rule = format!("DBL;RI;{filter};{ip_string}");
            pipe.hget(rule, "enabled");
        }
    }
    let results: Vec<Option<u8>> = pipe.query_async(&mut redis_mngr).await?;
    if results.into_iter().flatten().any(|x| x == 1) {
        info!("request:{} src:{}://{} QUERY:{} | A blacklisted IP was found when resolving \"{}\"",
            request.id(), request_info.protocol, request_info.src, request_info.query, request.query().name());
        return Ok(true);
    }
    Ok(false)
}
