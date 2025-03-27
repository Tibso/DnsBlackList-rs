use crate::VERSION;

use std::process::ExitCode;
use redis::{Commands, Connection, RedisResult};

/// Displays the daemon conf and 'redis-ctl' version
pub fn show (
    con: &mut Connection,
    daemon_id: &str,
    redis_address: &str
) -> RedisResult<ExitCode> {
    println!("'redis-ctl' version {VERSION}\n\nConfile {{\n  \"daemon_id\": \"{daemon_id}\"\n  \"redis_address\": \"{redis_address}\"\n}}\n");

    let binds: Vec<String> = con.smembers(format!("DBL;C;binds;{daemon_id}"))?;
    if binds.is_empty() {
        println!("No bind is configured\n");
    } else {
        println!("Binds {binds:#?}\n");
    }

    let forwarders: Vec<String> = con.smembers(format!("DBL;C;forwarders;{daemon_id}"))?;
    if forwarders.is_empty() {
        println!("No forwarder is configured\n");
    } else {
        println!("Forwarders {forwarders:#?}\n");
    }

    let filters: Vec<String> = con.smembers(format!("DBL;C;filters;{daemon_id}"))?;
    if filters.is_empty() {
        println!("No filter is configured\n");
    } else {
        println!("Filters {filters:#?}\n");
    }

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the daemon conf
pub fn add_binds (
    con: &mut Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    if binds.is_empty() {
        println!("No bind was given");
        return Ok(ExitCode::from(2))
    }
    let add_cnt: u32 = con.sadd(format!("DBL;C;binds;{daemon_id}"), binds)?;
    println!("{add_cnt} bind(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes binds from the daemon conf
pub fn remove_binds (
    con: &mut Connection,
    daemon_id: &str,
    binds: Vec<String>
) -> RedisResult<ExitCode> {
    if binds.is_empty() {
        println!("No bind was given");
        return Ok(ExitCode::from(2))
    }
    let del_cnt: u32 = con.srem(format!("DBL;C;binds;{daemon_id}"), binds)?;
    println!("{del_cnt} bind(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Add new forwarders to the daemon conf
pub fn add_forwarders (
    con: &mut Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    if forwarders.is_empty() {
        println!("No forwarder was given");
        return Ok(ExitCode::from(2))
    }
    let add_cnt: usize = con.sadd(format!("DBL;C;forwarders;{daemon_id}"), forwarders)?;
    println!("{add_cnt} forwarder(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes forwarders from the daemon conf
pub fn remove_forwarders (
    con: &mut Connection,
    daemon_id: &str,
    forwarders: Vec<String>
) -> RedisResult<ExitCode> {
    if forwarders.is_empty() {
        println!("No forwarder was given");
        return Ok(ExitCode::from(2))
    }
    let del_cnt: usize = con.srem(format!("DBL;C;forwarders;{daemon_id}"), forwarders)?;
    println!("{del_cnt} forwarder(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Adds filters to the daemon conf
pub fn add_filters (
    con: &mut Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    if filters.is_empty() {
        println!("No filter was given");
        return Ok(ExitCode::from(2))
    }
    let add_cnt: usize = con.sadd(format!("DBL;C;filters;{daemon_id}"), filters)?;
    println!("{add_cnt} filter(s) added to the daemon conf");

    Ok(ExitCode::SUCCESS)
}

/// Removes filters from the daemon conf
pub fn remove_filters (
    con: &mut Connection,
    daemon_id: &str,
    filters: Vec<String>
) -> RedisResult<ExitCode> {
    if filters.is_empty() {
        println!("No filter was given");
        return Ok(ExitCode::from(2))
    }
    let del_cnt: usize = con.srem(format!("DBL;C;filters;{daemon_id}"), filters)?;
    println!("{del_cnt} filter(s) removed from the daemon conf");

    Ok(ExitCode::SUCCESS)
}
