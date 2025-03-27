use std::{
    fs::File, io::{BufRead, BufReader}, net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::PathBuf, process::ExitCode
};
use redis::{Commands, Connection, RedisResult, pipe};

use super::{is_valid_domain, get_date, time_abrv_to_secs};

/// Disable rules that match a pattern
pub fn disable (
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = con.scan_match(format!("DBL;RD;{filter};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
    } else {
        let mut disabled_cnt = 0usize;
        for key in keys {
            let () = con.hset(key, "enabled", "0")?;
            disabled_cnt += 1;
        }
        println!("{disabled_cnt} rule(s) were disabled");
    }
    Ok(ExitCode::SUCCESS)
}

/// Enable rules that match a pattern
pub fn enable (
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = con.scan_match(format!("DBL;RD;{filter};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
    } else {
        let mut enabled_cnt = 0usize;
        for key in keys {
            let () = con.hset(key, "enabled", "1")?;
            enabled_cnt += 1;
        }
        println!("{enabled_cnt} rule(s) were enabled");
    }
    Ok(ExitCode::SUCCESS)
}

/// Add a new domain rule
pub fn add_domain (
    con: &mut Connection,
    filter: &str,
    src: &str,
    domain: &str,
    ttl: &str,
    ip1: Option<String>,
    ip2: Option<String>
) -> RedisResult<ExitCode> {
    if ! is_valid_domain(domain) {
        println!("ERR: Given domain is invalid");
        return Ok(ExitCode::from(65))
    }
    let Some(secs_to_expiry) = time_abrv_to_secs(ttl) else {
        println!("ERR: Given TTL is not properly formatted or is too big");
        return Ok(ExitCode::from(65))
    };
   
    let mut pipe = pipe();
    let key = format!("DBL;RD;{filter};{domain}");
    let fields = [("enabled","1"),("date",&get_date()),("src",src)];
    match (ip1, ip2) {
        (None, None) => {
            println!("No IP provided, adding domain rule for both v4 and v6");
            pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],("A","1"),("AAAA","1")]);
        },
        (Some(ip1), Some(ip2)) => {
            match (ip1.as_str(), ip2.as_str()) {
                ("A", "AAAA") | ("AAAA", "A") => {
                    pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],("A","1"),("AAAA","1")]);
                },
                ("A", ip) | (ip, "A") => {
                    if ip.parse::<Ipv6Addr>().is_err() {
                        println!("ERR: IP parsed was not IPv6");
                        return Ok(ExitCode::from(65));
                    }
                    pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],("A","1"),("AAAA",ip)]);
                },
                ("AAAA", ip) | (ip, "AAAA") => {
                    if ip.parse::<Ipv4Addr>().is_err() {
                        println!("ERR: IP parsed was not IPv4");
                        return Ok(ExitCode::from(65));
                    }
                    pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],("A",ip),("AAAA","1")]);
                },
                _ => {
                    if let (Ok(ip1), Ok(ip2)) = (ip1.parse::<IpAddr>(), ip2.parse::<IpAddr>()) {
                        match (ip1, ip2) {
                            (IpAddr::V4(ipv4), IpAddr::V6(ipv6)) | (IpAddr::V6(ipv6), IpAddr::V4(ipv4)) => {
                                pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],("A",&ipv4.to_string()),("AAAA",&ipv6.to_string())]);
                            },
                            _ => {
                                println!("ERR: Provided IPs cannot both be v4 or v6");
                                return Ok(ExitCode::from(65));
                            }
                        }
                    } else {
                        println!("ERR: Could not parse provided IPs");
                        return Ok(ExitCode::from(65));
                    }
                }
            }
        },
        (Some(ip), None) => {
            if matches!(ip.as_str(), "A" | "AAAA") {
                pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],(&ip,"1")]);
            } else if let Ok(ip) = ip.parse::<IpAddr>() {
                let ip_field: (&str,&str) = match ip {
                    IpAddr::V4(ipv4) => ("A",&ipv4.to_string()),
                    IpAddr::V6(ipv6) => ("AAAA",&ipv6.to_string()),
                };
                pipe.hset_multiple(&key, &[fields[0],fields[1],fields[2],ip_field]);
            } else {
                println!("ERR: Could not parse provided IP");
                return Ok(ExitCode::from(65));
            }
        },
        _ => unreachable!(),
    }

    pipe.expire(key, secs_to_expiry)
        .exec(con)?;
    println!("Domain rule added");
    Ok(ExitCode::SUCCESS)
}

/// Delete a domain rule or only one IP version
pub fn remove_domain (
    con: &mut Connection,
    filter: &str,
    domain: &str,
    ip_ver: Option<u8>
) -> RedisResult<ExitCode> {
    if ! is_valid_domain(domain) {
        println!("ERR: Given domain is invalid");
        return Ok(ExitCode::from(65))
    }

    let key = format!("DBL;RD;{filter};{domain}");
    let del_cnt: usize = match ip_ver {
        None => {
            println!("No IP version provided, deleting domain rule");
            con.del(key)?
        },
        Some(ip_ver) => {
            let q_type = match ip_ver {
                4 => "A",
                6 => "AAAA",
                _ => {
                    println!("ERR: Given IP version is invalid");
                    return Ok(ExitCode::from(65))
                }
            };
            con.hdel(key, q_type)?
        }
    };
    match del_cnt {
        1 => println!("Rule deleted"),
        _ => println!("Nothing deleted, are you sure this rule exists?")
    }
    Ok(ExitCode::SUCCESS)
}

/// Add IP rules
pub fn add_ips (
    con: &mut Connection,
    src: &str,
    filter: &str,
    ttl: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    if ips.iter().any(|ip| ip.parse::<IpAddr>().is_err()) {
        println!("ERR: An IP is invalid");
        return Ok(ExitCode::from(65))
    }
    let Some(secs_to_expiry) = time_abrv_to_secs(ttl) else {
        println!("ERR: Given TTL is not properly formatted or is too big");
        return Ok(ExitCode::from(65))
    };

    let mut pipe = pipe();
    let keys: Vec<String> = ips.iter().map(|ip| format!("DBL;RI;{filter};{ip}")).collect();
    for key in keys {
        pipe.hset_multiple(&key, &[("enabled","1"),("date",&get_date()),("src",src)])
            .expire(key, secs_to_expiry);
    }
    pipe.exec(con)?;
    println!("IP(s) added");
    Ok(ExitCode::SUCCESS)
}

/// Remove IP rules
pub fn remove_ips (
    con: &mut Connection,
    filter: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    if ips.iter().any(|ip| ip.parse::<IpAddr>().is_err()) {
        println!("ERR: An IP is invalid");
        return Ok(ExitCode::from(65))
    }

    let keys: Vec<String> = ips.iter().map(|ip| format!("DBL;RI;{filter};{ip}")).collect();
    let del_cnt: usize = con.del(keys)?;
    println!("{del_cnt} IP rule(s) removed");
    Ok(ExitCode::SUCCESS)
}

/// Feed a list to a filter
pub fn feed_filter (
    con: &mut Connection,
    path_to_list: &PathBuf,
    src: &str,
    filter: &str,
    ttl: &str // formatted like 1y, 2M, 3d
) -> RedisResult<ExitCode> {
    let file = File::open(path_to_list)?;

    let date = get_date();
    let Some(secs_to_expiry) = time_abrv_to_secs(ttl) else {
        println!("ERR: Given TTL is not properly formatted or is too big");
        return Ok(ExitCode::from(65))
    };
    let fields = [("enabled","1"),("date",&date),("src",src)];

    let mut item_cnt = 0usize;
    let mut add_cnt = 0usize;
    let reader = BufReader::new(file);
    for bytes in reader.split(b'\n') {
        let Ok(bytes) = bytes else {
            println!("ERR: Could not buffer file content: Bad EOF/IO");
            break
        };
        item_cnt += 1;

        if ! bytes.is_ascii() {
            continue
        }
        let Ok(item) = core::str::from_utf8(&bytes) else {
            continue // not fastest conversion but safe and has ascii optimizations -- forbid unsafe
        };

        if item.parse::<IpAddr>().is_ok() {
            let key = format!("DBL;RI;{filter};{item}");
            if pipe()
                .hset_multiple(&key, &fields)
                .expire(&key, secs_to_expiry)
                .exec(con).is_ok()
            {
                add_cnt += 1;
            } 
        } else if is_valid_domain(item) {
            let key = format!("DBL;RD;{filter};{item}");
            if pipe()
                .hset_multiple(&key, &fields)
                .expire(&key, secs_to_expiry)
                .exec(con).is_ok()
            {
                add_cnt += 1;
            } 
        }
    }

    println!("{item_cnt} item(s) read\n{} item(s) were invalid\n{add_cnt} rule(s) added", item_cnt - add_cnt);
    Ok(ExitCode::SUCCESS)
}

/// Search for rules using a pattern
pub fn search (
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let scan_string = format!("DBL;R[D-I];{filter};{pattern}");
    let keys: Vec<String> = con.scan_match(&scan_string)?.collect();
    if keys.is_empty() {
        println!("No match for: {scan_string}");
    } else {
        for key in keys {
            let values: Vec<String> = con.hgetall(key.clone())?;
            println!("{key}\n{values:?}");
        }
    }
    Ok(ExitCode::SUCCESS)
}
