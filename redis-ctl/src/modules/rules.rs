use std::{
    fs, io::{BufRead, BufReader, Cursor}, net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::PathBuf, process::ExitCode
};
use redis::{Commands, Connection, RedisResult, pipe};
use serde::Deserialize;

use super::{is_valid_domain, get_date, time_abrv_to_secs};

#[derive(Deserialize)]
struct SourcesLists {
    name: String,
    lists: Vec<List>
}
#[derive(Deserialize)]
struct List {
    filter: String,
    urls: Vec<String>
}

/// Disable rules that match a pattern
pub fn disable(
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = con.scan_match(format!("DBL;D;{filter};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
    } else {
        let mut disabled_acc: u64 = 0;
        for key in keys {
            let () = con.hset(key, "enabled", "0")?;
            disabled_acc += 1;
        }
        println!("{disabled_acc} rule(s) were disabled");
    }
    Ok(ExitCode::SUCCESS)
}

/// Enable rules that match a pattern
pub fn enable(
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = con.scan_match(format!("DBL;D;{filter};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
    } else {
        let mut enabled_acc: u64 = 0;
        for key in keys {
            let () = con.hset(key, "enabled", "1")?;
            enabled_acc += 1;
        }
        println!("{enabled_acc} rule(s) were enabled");
    }
    Ok(ExitCode::SUCCESS)
}

/// Add a new domain rule
pub fn add_domain(
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
    let key = format!("DBL;D;{filter};{domain}");
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
pub fn remove_domain(
    con: &mut Connection,
    filter: &str,
    domain: &str,
    ip_ver: Option<u8>
) -> RedisResult<ExitCode> {
    if ! is_valid_domain(domain) {
        println!("ERR: Given domain is invalid");
        return Ok(ExitCode::from(65))
    }

    let key = format!("DBL;D;{filter};{domain}");
    let del_cnt: u64 = match ip_ver {
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
pub fn add_ips(
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
    let keys: Vec<String> = ips.iter().map(|ip| format!("DBL;I;{filter};{ip}")).collect();
    for key in keys {
        pipe.hset_multiple(&key, &[("enabled","1"),("date",&get_date()),("src",src)])
            .expire(key, secs_to_expiry);
    }
    pipe.exec(con)?;
    println!("IP(s) added");
    Ok(ExitCode::SUCCESS)
}

/// Remove IP rules
pub fn remove_ips(
    con: &mut Connection,
    filter: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    if ips.iter().any(|ip| ip.parse::<IpAddr>().is_err()) {
        println!("ERR: An IP is invalid");
        return Ok(ExitCode::from(65))
    }

    let keys: Vec<String> = ips.iter().map(|ip| format!("DBL;I;{filter};{ip}")).collect();
    let del_cnt: u64 = con.del(keys)?;
    println!("{del_cnt} IP rule(s) removed");
    Ok(ExitCode::SUCCESS)
}

fn feed_from_reader<R: BufRead>(
    con: &mut Connection,
    reader: R,
    src: &str,
    filter: &str,
    ttl: &str
) -> RedisResult<ExitCode> {
    let date = get_date();
    let Some(secs_to_expiry) = time_abrv_to_secs(ttl) else {
        println!("ERR: Given TTL is not properly formatted or is too big");
        return Ok(ExitCode::from(65))
    };
    let fields = [("enabled","1"),("date",&date),("src",src)];

    let mut item_acc: u64 = 0;
    let mut add_acc: u64 = 0;

    for bytes in reader.split(b'\n') {
        let Ok(bytes) = bytes else {
            println!("ERR: Could not buffer file content: Bad EOF/IO");
            break
        };
        item_acc += 1;

        if ! bytes.is_ascii() {
            continue
        }
        let Ok(item) = core::str::from_utf8(&bytes) else {
            continue // not fastest conversion but safe and has ascii optimizations -- forbid unsafe
        };

        if item.parse::<IpAddr>().is_ok() {
            let key = format!("DBL;I;{filter};{item}");
            if pipe()
                .hset_multiple(&key, &fields)
                .expire(&key, secs_to_expiry)
                .exec(con).is_ok()
            {
                add_acc += 1;
            } 
        } else if is_valid_domain(item) {
            let key = format!("DBL;D;{filter};{item}");
            if pipe()
                .hset_multiple(&key, &fields)
                .expire(&key, secs_to_expiry)
                .exec(con).is_ok()
            {
                add_acc += 1;
            } 
        }
    }
    println!("{item_acc} item(s) read\n{} item(s) were invalid\n{add_acc} rule(s) added", item_acc - add_acc);
    Ok(ExitCode::SUCCESS)
}

/// Feed the blacklist using a list of blacklist sources such as in the `blacklist_sources.json` file
pub fn feed_from_downloads(
    con: &mut Connection,
    path_to_file: &PathBuf,
    ttl: &str
) -> RedisResult<ExitCode> {
    let data = match fs::read_to_string(path_to_file) {
        Err(e) => {
            println!("Error reading \"{path_to_file:?}\": {e}");
            return Ok(ExitCode::from(66)) // EX_NOINPUT
        },
        Ok(data) => data
    };

    let srcs_list: Vec<SourcesLists> = match serde_json::from_str(&data) {
        Err(e) => {
            println!("Error deserializing \"{path_to_file:?}\" data: {e}");
            return Ok(ExitCode::from(65)) // EX_DATAERR
        },
        Ok(srcs_list) => srcs_list
    };

    let http_client = reqwest::blocking::Client::new();
    for src in srcs_list {
        for list in src.lists {
            for url in list.urls {
                println!("Trying: {url}");
                let resp = match http_client.get(&url).send() {
                    Err(e) => {
                        println!("Error retrieving data: {e}\nSkipping...");
                        continue
                    },
                    Ok(resp) => resp
                };
                
                if ! resp.status().is_success() {
                    println!("Error {}: Request was not successful\nSkipping...", resp.status());
                    continue
                }

                let Ok(text) = resp.text() else {
                    println!("Retrieved data is not utf-8\nSkipping...");
                    continue
                };

                let reader = BufReader::new(Cursor::new(text.as_bytes()));
                feed_from_reader(con, reader, &src.name, &list.filter, ttl)?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Feed a list to a filter
pub fn feed_filter(
    con: &mut Connection,
    path_to_file: &PathBuf,
    src: &str,
    filter: &str,
    ttl: &str // formatted like 1y, 2M, 3d
) -> RedisResult<ExitCode> {
    let file = fs::File::open(path_to_file)?;
    let reader = BufReader::new(file);
    feed_from_reader(con, reader, src, filter, ttl)?;
    Ok(ExitCode::SUCCESS)
}

/// Search for rules using a pattern
pub fn search(
    con: &mut Connection,
    filter: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let scan_string = format!("DBL;[D-I];{filter};{pattern}");
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
