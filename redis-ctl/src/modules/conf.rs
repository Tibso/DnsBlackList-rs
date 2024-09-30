use crate::VERSION;

use std::{process::ExitCode, net::IpAddr};
use redis::{Commands, Connection, RedisResult};

/// Displays the daemon conf and 'redis-ctl' version
pub fn show (
    connection: &mut Connection,
    daemon_id: &str,
    redis_address: &str
) -> RedisResult<ExitCode> {
    println!("'redis-ctl' version {VERSION}\n");
    println!("Confile {{\n    \"daemon_id\": \"{daemon_id}\"");
    println!("    \"redis_address\": \"{redis_address}\"\n}}\n");

    let binds: Vec<String> = connection.smembers(format!("DBL;binds;{daemon_id}"))?;
    if binds.is_empty() {
        println!("No bind is configured\n");
    } else {
        println!("Binds {binds:#?}\n");
    }

    let forwarders: Vec<String> = connection.smembers(format!("DBL;forwarders;{daemon_id}"))?;
    if forwarders.is_empty() {
        println!("No forwarder is configured\n");
    } else {
        println!("Forwarders {forwarders:#?}\n");
    }

    let filters: Vec<String> = connection.smembers(format!("DBL;filters;{daemon_id}"))?;
    if filters.is_empty() {
        println!("No filter is configured\n");
    } else {
        println!("Filters {filters:#?}\n");
    }

    let sinks: Vec<String> = connection.smembers(format!("DBL;sinks;{daemon_id}"))?;
    if sinks.is_empty() {
        println!("No sinks are configured\n");
    } else {
        println!("Sinks {sinks:#?}\n");
    }

    Ok(ExitCode::SUCCESS)
}

/// Reconfigures the sinks of the daemon conf
pub fn set_sinks (
    connection: &mut Connection,
    daemon_id: &str,
    sinks: Vec<String>
) -> RedisResult<ExitCode> {
    if sinks.len() != 2 {
        println!("2 sinks must be provided");
        return Ok(ExitCode::from(2))
    }

    let () = connection.del(format!("DBL;sinks;{daemon_id}"))?;

    let add_count: u8 = connection.sadd(format!("DBL;sinks;{daemon_id}"), sinks)?;
    println!("{add_count} sinks added to the daemon conf");
        
    Ok(ExitCode::SUCCESS)
}

/// Adds blocked IPs to the daemon conf
pub fn add_blocked_ips (
    connection: &mut Connection,
    daemon_id: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    for ip in &ips {
        if let Err(err) = ip.parse::<IpAddr>() {
            println!("Parsing error on '{ip}' : {err}");
            return Ok(ExitCode::from(65))
        }
    }

    let add_count: usize = connection.sadd(format!("DBL;blocked-ips;{daemon_id}"), ips)?;
    println!("{add_count} IP(s) added to the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

/// Removes blocked IPs from the daemon conf
pub fn remove_blocked_ips (
    connection: &mut Connection,
    daemon_id: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    for ip in &ips {
        if let Err(err) = ip.parse::<IpAddr>() {
            println!("Parsing error on '{ip}' : {err}");
            return Ok(ExitCode::from(65))
        }
    }

    let del_count: usize = connection.srem(format!("DBL;blocked-ips;{daemon_id}"), ips)?;
    println!("{del_count} IP(s) removed from the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the daemon conf
pub fn add_binds (
    connection: &mut Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: u32 = connection.sadd(format!("DBL;binds;{daemon_id}"), binds)?;
    println!("{add_count} bind(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes binds from the daemon conf
pub fn remove_binds (
    connection: &mut Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    let del_count: u32 = connection.srem(format!("DBL;binds;{daemon_id}"), binds)?;
    println!("{del_count} bind(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Add new forwarders to the daemon conf
pub fn add_forwarders (
    connection: &mut Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: usize = connection.sadd(format!("DBL;forwarders;{daemon_id}"), forwarders)?;
    println!("{add_count} forwarder(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes forwarders from the daemon conf
pub fn remove_forwarders (
    connection: &mut Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    let del_count: usize = connection.srem(format!("DBL;forwarders;{daemon_id}"), forwarders)?;
    println!("{del_count} forwarder(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Adds filters to the daemon conf
pub fn add_filters (
    connection: &mut Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: usize = connection.sadd(format!("DBL;filters;{daemon_id}"), filters)?;
    println!("{add_count} filter(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes filters from the daemon conf
pub fn remove_filters (
    connection: &mut Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    let del_count: usize = connection.srem(format!("DBL;filters;{daemon_id}"), filters)?;
    println!("{del_count} filter(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}
