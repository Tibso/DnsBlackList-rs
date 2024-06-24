use crate::Confile;

use std::{
    process::ExitCode,
    net::IpAddr
};
use redis::{Commands, Connection, RedisResult};

/// Displays the daemon's configuration
pub fn show (
    mut connection: Connection,
    confile: &Confile
) -> RedisResult<ExitCode> {
    println!("{confile:#?}");

    let binds: Vec<String> = connection.smembers(format!("DBL;binds;{}", confile.daemon_id))?;
    if binds.is_empty() {
        println!("No bind is configured!");
    } else {
        println!("Binds {binds:#?}");
    }

    let forwarders: Vec<String> = connection.smembers(format!("DBL;forwarders;{}", confile.daemon_id))?;
    if forwarders.is_empty() {
        println!("No forwarder is configured!");
    } else {
        println!("Forwarders {forwarders:#?}");
    }

    let filters: Vec<String> = connection.smembers(format!("DBL;filters;{}", confile.daemon_id))?;
    if filters.is_empty() {
        println!("No filter is configured!");
    } else {
        println!("Filters {filters:#?}");
    }

    let blackholes: Vec<String> = connection.smembers(format!("DBL;blackholes;{}", confile.daemon_id))?;
    if blackholes.is_empty() {
        println!("No blackholes are configured!");
    } else {
        println!("Blackholes {blackholes:#?}");
    }

    Ok(ExitCode::SUCCESS)
}

/// Reconfigures the blackholes of the daemon's configuration
pub fn set_blackholes (
    mut connection: Connection,
    daemon_id: &str,
    blackhole_ips: Vec<String>
) -> RedisResult<ExitCode> {
    if blackhole_ips.len() != 2 {
        println!("2 blackholes must be provided!");
        return Ok(ExitCode::from(2))
    }

    connection.del(format!("DBL;blackholes;{daemon_id}"))?;

    let add_count: u8 = connection.sadd(format!("DBL;blackholes;{daemon_id}"), blackhole_ips)?;
    println!("Added {add_count} blackhole(s) to the daemon's configuration");
        
    Ok(ExitCode::SUCCESS)
}

/// Adds blocked IPs to the daemon's configuration
pub fn add_blocked_ips (
    mut connection: Connection,
    daemon_id: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    for ip in &ips {
        if let Err(err) = ip.parse::<IpAddr>() {
            println!("Parsing error on '{ip}' : {err}");
            return Ok(ExitCode::from(65))
        }
    }

    let add_count: u64 = connection.sadd(format!("DBL;blocked-ips;{daemon_id}"), ips)?;
    println!("Added {add_count} IP(s) to the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_blocked_ips (
    mut connection: Connection,
    daemon_id: &str,
    ips: Vec<String>
) -> RedisResult<ExitCode> {
    for ip in &ips {
        if let Err(err) = ip.parse::<IpAddr>() {
            println!("Parsing error on '{ip}' : {err}");
            return Ok(ExitCode::from(65))
        }
    }

    let del_count: u64 = connection.srem(format!("DBL;blocked-ips;{daemon_id}"), ips)?;
    println!("Removed {del_count} IP(s) from the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the daemon's configuration
pub fn add_binds (
    mut connection: Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: u32 = connection.sadd(format!("DBL;binds;{daemon_id}"), binds)?;
    println!("Added {add_count} bind(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_binds (
    mut connection: Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    let del_count: u32 = connection.srem(format!("DBL;binds;{daemon_id}"), binds)?;
    println!("Removed {del_count} bind(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Add new forwarders to the daemon's configuration
pub fn add_forwarders (
    mut connection: Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: u64 = connection.sadd(format!("DBL;forwarders;{daemon_id}"), forwarders)?;
    println!("Added {add_count} forwarder(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_forwarders (
    mut connection: Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    let del_count: u64 = connection.srem(format!("DBL;forwarders;{daemon_id}"), forwarders)?;
    println!("Removed {del_count} forwarder(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Adds filters to the daemon's configuration
pub fn add_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    let add_count: u64 = connection.sadd(format!("DBL;filters;{daemon_id}"), filters)?;
    println!("Added {add_count} filter(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Removes filters from the daemon's configuration
pub fn remove_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    let remove_count: u64 = connection.srem(format!("DBL;filters;{daemon_id}"), filters)?;
    println!("Removed {remove_count} filter(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}
