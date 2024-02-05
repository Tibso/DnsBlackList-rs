use redis::{Connection, RedisResult};

use std::process::ExitCode;

use crate::redis_mod;

/// Deletes all stats that match an IP pattern
pub fn clear (
    mut connection: Connection,
    daemon_id: &str,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL;stats;{daemon_id};{pattern}"))?;

    let del_count = redis_mod::exec(&mut connection, "del", &keys)?;
    println!("Deleted {del_count} stat(s)");

    Ok(ExitCode::SUCCESS)
}

/// Displays all stats that match an IP pattern
pub fn show (
    mut connection: Connection,
    daemon_id: &str,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL;stats;{daemon_id};{pattern}"))?;

    if keys.is_empty() {
        println!("No match for: {pattern}");
        return Ok(ExitCode::SUCCESS)
    }

    for key in keys {
        let values = redis_mod::fetch(&mut connection, "hgetall", &vec![key.clone()])?;

        let splits: Vec<&str> = key.split(';').collect();

        println!("{}\n{values:?}\n", splits[3]);
    }

    Ok(ExitCode::SUCCESS)
}
