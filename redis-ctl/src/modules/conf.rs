use redis::{Connection, RedisResult};

use std::{
    process::ExitCode,
    net::{Ipv4Addr, Ipv6Addr}
};

use crate::{Confile, redis_mod};

/// Displays the daemon's configuration
pub fn show (
    mut connection: Connection,
    confile: &Confile
)
-> RedisResult<ExitCode> {
    println!("{confile:#?}");

    let binds = redis_mod::fetch(&mut connection, "smembers", &vec![format!("DBL:binds:{}", confile.daemon_id)])?;
    if binds.is_empty() {
        println!("No bind is configured!");
    } else {
        println!("Binds {binds:#?}");
    }

    let forwarders = redis_mod::fetch(&mut connection, "smembers", &vec![format!("DBL:forwarders:{}", confile.daemon_id)])?;
    if forwarders.is_empty() {
        println!("No forwarder is configured!");
    } else {
        println!("Forwarders {forwarders:#?}");
    }

    let filters = redis_mod::fetch(&mut connection, "smembers", &vec![format!("DBL:filters:{}", confile.daemon_id)])?;
    if filters.is_empty() {
        println!("No filter is configured!");
    } else {
        println!("Filters {filters:#?}");
    }

    let blackholes = redis_mod::fetch(&mut connection, "smembers", &vec![format!("DBL:blackholes:{}", confile.daemon_id)])?;
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

    redis_mod::exec(&mut connection, "del", &vec![format!("DBL:blackholes:{daemon_id}")])?;

    let mut args = vec![format!("DBL:blackholes:{daemon_id}")];
    args.extend(blackhole_ips);

    let add_count = redis_mod::exec(&mut connection, "sadd", &args)?;
    println!("{add_count} blackholes were added to the configuration.");
        
    Ok(ExitCode::SUCCESS)
}

/// Adds blocked IPs to the daemon's configuration
pub fn add_blocked_ips (
    mut connection: Connection,
    daemon_id: &str,
    ips: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args: Vec<String> = vec![format!("DBL:blocked-ips:{daemon_id}")];

    for ip in ips {
        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            args.extend([ipv4.to_string()]);
        } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
            args.extend([ipv6.to_string()]);
        } else {
            println!("Parsing error on IPs!");
            return Ok(ExitCode::from(65))
        }
    }

    let add_count = redis_mod::exec(&mut connection, "sadd", &args)?;
    println!("{add_count} IPs were added to the IP blacklist.");

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the daemon's configuration
pub fn add_binds (
    mut connection: Connection,
    daemon_id: &str,
    binds: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL:binds:{daemon_id}")];
    args.extend(binds);

    let add_count = redis_mod::exec(&mut connection, "sadd", &args)?;
    println!("{add_count} binds were added to the configuration.");

    Ok(ExitCode::SUCCESS)
}

/// Clear a parameter from the daemon's configuration
pub fn clear_parameter (
    mut connection: Connection,
    daemon_id: &str,
    parameter: &str
)
-> RedisResult<ExitCode> {
    let del_count = redis_mod::exec(&mut connection, "del", &vec![format!("DBL:{parameter}:{daemon_id}")])?;
    if del_count != 1 {
        println!("Parameter not found!");
    }
    println!("Parameter was cleared.");

    Ok(ExitCode::SUCCESS)
}

/// Add new forwarders to the daemon's configuration
pub fn add_forwarders (
    mut connection: Connection,
    daemon_id: &str,
    forwarders: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL:forwarders:{daemon_id}")];
    args.extend(forwarders);

    let add_count = redis_mod::exec(&mut connection, "sadd", &args)?;
    println!("{add_count} forwarders were added to the configuration.");

    Ok(ExitCode::SUCCESS)
}

/// Adds filters to the daemon's configuration
pub fn add_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL:filters:{daemon_id}")];
    args.extend(filters);

    let add_count = redis_mod::exec(&mut connection, "sadd", &args)?;
    println!("{add_count} matchclass types were added to the daemon's configuration.");

    Ok(ExitCode::SUCCESS)
}

/// Removes filters from the daemon's configuration
pub fn remove_filters (
    mut connection: Connection,
    daemon_id: &str,
    filters: Vec<String>
)
-> RedisResult<ExitCode> {
    let mut args = vec![format!("DBL:filters:{daemon_id}")];
    args.extend(filters);

    let remove_count = redis_mod::exec(&mut connection, "srem", &args)?;
    println!("{remove_count} matchclass types were removed from the daemon's configuration.");

    Ok(ExitCode::SUCCESS)
}
