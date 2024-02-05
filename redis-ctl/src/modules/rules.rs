use redis::{Connection, RedisResult};

use std::{
    process::ExitCode,
    net::{IpAddr, Ipv4Addr, Ipv6Addr}
};

use crate::{
    modules::get_datetime,
    redis_mod
};

/// Disable rules that match a pattern
pub fn disable (
    mut connection: Connection,
    filter: &str,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL;R;{filter};{pattern}"))?;

    let mut disabled_count = 0u32;
    for key in keys {
        redis_mod::exec(&mut connection, "hset",
            &vec![key.clone(), "enabled".to_owned(), "0".to_owned()])?;

        let hash_value = redis_mod::exec(&mut connection, "hget",
            &vec![key.clone(), "enabled".to_owned()])?;
        if hash_value == 0 {
            disabled_count += 1;
        }
    }

    println!("Disabled {disabled_count} rule(s)");

    Ok(ExitCode::SUCCESS)
}

/// Enable rules that match a pattern
pub fn enable (
    mut connection: Connection,
    filter: &str,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL;R;{filter};{pattern}"))?;

    let mut enabled_count = 0u32;
    for key in keys {
        redis_mod::exec(&mut connection, "hset",
            &vec![key.clone(), "enabled".to_owned(), "1".to_owned()])?;

        let hash_value = redis_mod::exec(&mut connection, "hget",
            &vec![key.clone(), "enabled".to_owned()])?;
        if hash_value == 1 {
            enabled_count += 1;
        }
    }

    println!("Enabled {enabled_count} rule(s)");

    Ok(ExitCode::SUCCESS)
}

/// Adds a new rule
pub fn add (
    mut connection: Connection,
    filter: &str,
    source: &str,
    domain: &str,
    ip1: Option<String>,
    ip2: Option<String>
)
-> RedisResult<ExitCode> {
    let (year, month, day) = get_datetime::get_datetime();
    let mut args: Vec<String> = vec![format!("DBL;R;{filter};{domain}"),
        "enabled".to_owned(), "1".to_owned(),
        "date".to_owned(), format!("{year}{month}{day}"),
        "source".to_owned(), source.to_owned()];

    match (ip1, ip2) {
        (None, None) => {
            println!("IP not provided, adding default rules for both v4 and v6");
            args.extend(["A".to_owned(), "1".to_owned(), "AAAA".to_owned(), "1".to_owned()]);
        },
        (Some(ip1), Some(ip2)) => {
            match (ip1.as_str(), ip2.as_str()) {
                ("A", "AAAA") | ("AAAA", "A") => args.extend([ip1, "1".to_owned(), ip2, "1".to_owned()]),
                ("A", ip) | (ip, "A") => {
                    if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                        args.extend(["A".to_owned(), "1".to_owned(), "AAAA".to_owned(), ipv6.to_string()])
                    } else {
                        println!("IP parsed was not Ipv6!");
                        return Ok(ExitCode::from(65))
                    }
                },
                ("AAAA", ip) | (ip, "AAAA") => {
                    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                        args.extend(["AAAA".to_owned(), "1".to_owned(), "A".to_owned(), ipv4.to_string()])
                    } else {
                        println!("IP parsed was not Ipv4!");
                        return Ok(ExitCode::from(65))
                    }
                },
                _ => {
                    if let (Ok(ip1), Ok(ip2)) = (ip1.parse::<IpAddr>(), ip2.parse::<IpAddr>()) {
                        match (ip1, ip2) {
                            (IpAddr::V4(ipv4), IpAddr::V6(ipv6)) | (IpAddr::V6(ipv6), IpAddr::V4(ipv4))
                                => args.extend(["A".to_owned(), ipv4.to_string(), "AAAA".to_owned(), ipv6.to_string()]),
                            _ => {
                                println!("Provided IPs cannot both be v4 or v6!");
                                return Ok(ExitCode::from(65))
                            }
                        }
                    } else {
                        println!("Could not parse provided IPs!");
                        return Ok(ExitCode::from(65))
                    }
                }
            }
        },
        (Some(ip), None) => {
            match ip.as_str() {
                "A" => args.extend([ip, "1".to_owned()]),
                "AAAA" => args.extend([ip, "1".to_owned()]),
                _ => if let Ok(ip) = ip.parse::<IpAddr>() {
                        match ip {
                            IpAddr::V4(ipv4) => args.extend(["A".to_owned(), ipv4.to_string()]),
                            IpAddr::V6(ipv6) => args.extend(["AAAA".to_owned(), ipv6.to_string()])
                        }
                    } else {
                        println!("Could not parse the provided IP!");
                        return Ok(ExitCode::from(65))
                    }
            }
        },
        _ => unreachable!()
    }

    let count = redis_mod::exec(&mut connection, "hset", &args)?;
    if count != 0 {
        println!("The rule was added to the blacklist");
    } else {
        println!("Could not add the rule to the blacklist!");
    }

    Ok(ExitCode::SUCCESS)
}

/// Deletes a rule or one query type
pub fn delete (
    mut connection: Connection,
    filter: &str,
    domain: &str,
    q_type: Option<String>
)
-> RedisResult<ExitCode> {
    let cmd: &str;
    let mut args: Vec<String> = vec![format!("DBL;R;{filter};{domain}")];
    if q_type.is_none() {
        println!("Record type not provided, deleting rule for both v4 and v6");
        cmd = "del";
    } else {
        cmd = "hdel";

        let q_type_string = q_type.unwrap();
        match q_type_string.as_str() {
            "A" => args.extend([q_type_string]),
            "AAAA" => args.extend([q_type_string]),
            _ => {
                println!("Could not parse the provided query type!");
                return Ok(ExitCode::from(65))
            }
        }
    }

    let count = redis_mod::exec(&mut connection, cmd, &args)?;
    if count == 1 {
        println!("The rule was deleted from the blacklist");
    } else {
        println!("Could not delete the rule from the blacklist!");
    }

    Ok(ExitCode::SUCCESS)
}

/// Searches for rules using a pattern
pub fn search (
    mut connection: Connection,
    filter: &str,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL;R;{filter};{pattern}"))?;

    if keys.is_empty() {
        println!("No match for: {pattern}");
        return Ok(ExitCode::SUCCESS)
    }

    for key in keys {
        let values = redis_mod::fetch(&mut connection, "hgetall", &vec![key.clone()])?;

        let key_cp = key.clone();
        let splits: Vec<&str> = key_cp.split(';').collect();

        println!("{}\n{values:?}\n", splits[3]);
    }

    Ok(ExitCode::SUCCESS)
}
