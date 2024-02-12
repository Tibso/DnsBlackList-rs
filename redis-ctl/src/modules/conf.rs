use crate::{Confile, redis_mod};


use std::{
    process::ExitCode,
    net::IpAddr
};
use redis::{Connection, RedisResult};

/// Displays the daemon's configuration
pub fn show (
    mut connection: Connection,
    confile: &Confile
)
-> RedisResult<ExitCode> {
    println!("{confile:#?}");

    let binds = redis_mod::fetch(&mut connection, "smembers", vec![format!("DBL;binds;{}", confile.daemon_id)])?;
    if binds.is_empty() {
        println!("No bind is configured!");
    } else {
        println!("Binds {binds:#?}");
    }

    let forwarders = redis_mod::fetch(&mut connection, "smembers", vec![format!("DBL;forwarders;{}", confile.daemon_id)])?;
    if forwarders.is_empty() {
        println!("No forwarder is configured!");
    } else {
        println!("Forwarders {forwarders:#?}");
    }

    let filters = redis_mod::fetch(&mut connection, "smembers", vec![format!("DBL;filters;{}", confile.daemon_id)])?;
    if filters.is_empty() {
        println!("No filter is configured!");
    } else {
        println!("Filters {filters:#?}");
    }

    let blackholes = redis_mod::fetch(&mut connection, "smembers", vec![format!("DBL;blackholes;{}", confile.daemon_id)])?;
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
)
-> RedisResult<ExitCode> {
    if blackhole_ips.len() != 2 {
        println!("2 blackholes must be provided!");
        return Ok(ExitCode::from(2))
    }

    redis_mod::exec(&mut connection, "del", vec![format!("DBL;blackholes;{daemon_id}")])?;

    let mut args = vec![format!("DBL;blackholes;{daemon_id}")];
    args.extend(blackhole_ips);

    let add_count = redis_mod::exec(&mut connection, "sadd", args)?;
    println!("Added {add_count} blackhole(s) to the daemon's configuration");
        
    Ok(ExitCode::SUCCESS)
}

/// Adds blocked IPs to the daemon's configuration
pub fn add_blocked_ips (
    mut connection: Connection,
    daemon_id: &str,
    ips: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args: Vec<String> = vec![format!("DBL;blocked-ips;{daemon_id}")];

    for ip in ips {
        if let Ok(ip) = ip.parse::<IpAddr>() {
            args.extend([ip.to_string()]);
        } else {
            println!("Parsing error on IPs!");
            return Ok(ExitCode::from(65))
        }
    }

    let add_count = redis_mod::exec(&mut connection, "sadd", args)?;
    println!("Added {add_count} IP(s) to the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_blocked_ips (
    mut connection: Connection,
    daemon_id: &str,
    ips: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args: Vec<String> = vec![format!("DBL;blocked-ips;{daemon_id}")];

    for ip in ips {
        if let Ok(ip) = ip.parse::<IpAddr>() {
            args.extend([ip.to_string()]);
        } else {
            println!("Parsing error on IPs!");
            return Ok(ExitCode::from(65))
        }
    }

    let del_count = redis_mod::exec(&mut connection, "srem", args)?;
    println!("Removed {del_count} IP(s) from the IP blacklist");

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the daemon's configuration
pub fn add_binds (
    mut connection: Connection,
    daemon_id: &str,
    binds: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;binds;{daemon_id}")];
    args.extend(binds);

    let add_count = redis_mod::exec(&mut connection, "sadd", args)?;
    println!("Added {add_count} bind(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_binds (
    mut connection: Connection,
    daemon_id: &str,
    binds: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;binds;{daemon_id}")];
    args.extend(binds);

    let del_count = redis_mod::exec(&mut connection, "srem", args)?;
    println!("Removed {del_count} bind(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Add new forwarders to the daemon's configuration
pub fn add_forwarders (
    mut connection: Connection,
    daemon_id: &str,
    forwarders: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;forwarders;{daemon_id}")];
    args.extend(forwarders);

    let add_count = redis_mod::exec(&mut connection, "sadd", args)?;
    println!("Added {add_count} forwarder(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

pub fn remove_forwarders (
    mut connection: Connection,
    daemon_id: &str,
    forwarders: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;forwarders;{daemon_id}")];
    args.extend(forwarders);

    let del_count = redis_mod::exec(&mut connection, "srem", args)?;
    println!("Removed {del_count} forwarder(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Adds filters to the daemon's configuration
pub fn add_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;filters;{daemon_id}")];
    args.extend(filters);

    let add_count = redis_mod::exec(&mut connection, "sadd", args)?;
    println!("Added {add_count} filter(s) to the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}

/// Removes filters from the daemon's configuration
pub fn remove_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL;filters;{daemon_id}")];
    args.extend(filters);

    let remove_count = redis_mod::exec(&mut connection, "srem", args)?;
    println!("Removed {remove_count} filter(s) from the daemon's configuration");

    Ok(ExitCode::SUCCESS)
}
