use redis::{Connection, RedisResult};

use std::process::ExitCode;

use crate::redis_mod;

/// Deletes all stats that match an IP pattern
pub fn clear (
    mut connection: Connection,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL:stats:{pattern}"))?;

    let del_count = redis_mod::exec(&mut connection, "del", &keys)?;
    println!("{del_count} stats were deleted.");

    Ok(ExitCode::SUCCESS)
}

/// Displays all stats that match an IP pattern
pub fn show (
    mut connection: Connection,
    pattern: &str
)
-> RedisResult<ExitCode> {
    let keys = redis_mod::get_keys(&mut connection, &format!("DBL:stats:{pattern}"))?;

    for key in keys {
        let values = redis_mod::fetch(&mut connection, "hgetall", &vec![key.clone()])?;

        let split: Vec<&str> = key.split(':').collect();

        print!("Stats for IP: \"{}\":\n{values:#?}\n", split[2]);
    }

    Ok(ExitCode::SUCCESS)
}
