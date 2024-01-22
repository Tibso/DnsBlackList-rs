use redis::{Connection, RedisResult};

use std::{
    process::ExitCode,
    net::{Ipv4Addr, Ipv6Addr}
};

use crate::{
    modules::get_datetime,
    redis_mod
};

/// Disable rules that match a pattern
pub fn disable (
    mut connection: Connection,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL:R:{pattern}"))?;

    let mut disabled_count = 0u32;
    for key in keys {
        disabled_count += redis_mod::exec(&mut connection, "hset",
            &vec![key.clone(), "enabled".to_owned(), "0".to_owned()])?;
    }

    println!("{disabled_count} rules were disabled.");    

    Ok(ExitCode::SUCCESS)
}

/// Enable rules that match a pattern
pub fn enable (
    mut connection: Connection,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL:R:{pattern}"))?;

    let mut enabled_count = 0u32;
    for key in keys {
        enabled_count += redis_mod::exec(&mut connection, "hset",
            &vec![key.clone(), "enabled".to_owned(), "1".to_owned()])?;
    }
    println!("{enabled_count} rules were enabled.");

    Ok(ExitCode::SUCCESS)
}

/// Adds a new rule
pub fn set (
    mut connection: Connection,
    filter: &str,
    source: &str,
    domain: &str,
    ips: Option<Vec<String>>
)
-> RedisResult<ExitCode> {
    let (year, month, day) = get_datetime::get_datetime();
    let mut args: Vec<String> = vec![format!("DBL:R:{filter}:{domain}"),
        "enabled".to_owned(), "1".to_owned(),
        "date".to_owned(), format!("{year}{month}{day}"),
        "source".to_owned(), source.to_owned()];

    if ips.is_none() {
        println!("IP not provided, adding default rules for both v4 and v6!");
        args.extend(["A".to_owned(), "1".to_owned(),
            "AAAA".to_owned(), "1".to_owned()]);
    } else {
        let ips = ips.unwrap();
        if ips.len() > 2 {
            println!("Incorrect amount of IPs were given!");
            return Ok(ExitCode::from(2))
        }

        let mut have_v4 = false;
        let mut have_v6 = false;
        for ip in ips {
            if ! have_v4 {
                if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                    args.extend(["A".to_owned(), ipv4.to_string()]);
                    have_v4 = true;
                    continue
                }
            }
            if ! have_v6 {
                if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                    args.extend(["AAAA".to_owned(), ipv6.to_string()]);
                    have_v6 = true;
                } else {
                    println!("Parsing error on IPs!");
                    return Ok(ExitCode::from(65))
                }
            }
        }
    }

    let mut add_count = 0u8;
    let count = redis_mod::exec(&mut connection, "hset", &args)?;
    if count != 0 {
        add_count += 1;
    }
    
    println!("{add_count} rules were added to Redis.");

    Ok(ExitCode::SUCCESS)
}

/// Deletes a rule
pub fn delete (
    mut connection: Connection,
    filter: &str,
    domain: &str,
    ip: Option<String>
)
-> RedisResult<ExitCode> {
    let cmd: &str;
    let mut args: Vec<String> = vec![format!("DBL:R:{filter}:{domain}")];
    if ip.is_none() {
        println!("IP not provided, deleting default rules for both v4 and v6!");
        cmd = "del";
    } else {
        let ip = ip.unwrap();

        cmd = "hdel";
        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            args.extend(["A".to_owned(), ipv4.to_string()]);
        } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
            args.extend(["AAAA".to_owned(), ipv6.to_string()]);
        } else {
            println!("Parsing error on IPs!");
            return Ok(ExitCode::from(65))
        }
    }

    let del_count = redis_mod::exec(&mut connection, cmd, &args)?;
    println!("{del_count} rule was deleted from Redis.");

    Ok(ExitCode::SUCCESS)
}

/// Searches for the existence of a rule
pub fn search (
    mut connection: Connection,
    filter: &str,
    domain: &str
)
-> RedisResult<ExitCode> {
    let args = vec![format!("DBl:R:{filter}:{domain}")];
    let exists = redis_mod::exec(&mut connection, "exists", &args)?;

    if exists == 1 {
        println!("The given rule exists.");
    } else {
        println!("The given rule does not exists.");
    }

    Ok(ExitCode::SUCCESS)
}
