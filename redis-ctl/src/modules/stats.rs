use redis::{cmd, Commands, Connection, RedisResult};

use std::process::ExitCode;

/// Deletes all stats that match an IP pattern
pub fn clear (
    mut connection: Connection,
    daemon_id: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = connection.scan_match(format!("DBL;R;stats;{daemon_id};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
        return Ok(ExitCode::SUCCESS)
    }

    let del_count: u64 = cmd("del").arg(keys)
        .query(&mut connection)?;
    println!("{del_count} stat(s) deleted");

    Ok(ExitCode::SUCCESS)
}

/// Displays all stats that match an IP pattern
pub fn show (
    mut connection: Connection,
    daemon_id: &str,
    pattern: &str
) -> RedisResult<ExitCode> {
    let keys: Vec<String> = connection.scan_match(format!("DBL;R;stats;{daemon_id};{pattern}"))?.collect();
    if keys.is_empty() {
        println!("No match for: {pattern}");
        return Ok(ExitCode::SUCCESS)
    }

    for key in keys {
        let values = connection.hgetall(key.clone())?;
        let splits: Vec<&str> = key.split(';').collect();
        println!("{}\n{values:?}\n", splits[3]);
    }

    Ok(ExitCode::SUCCESS)
}
