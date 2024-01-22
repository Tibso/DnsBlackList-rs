use redis::{Connection, RedisResult, cmd};

use crate::redis_mod;

/// Executes a command to Redis
/// 
/// Retrieve the amount of items that were successfully manipulated
pub fn exec (
    connection: &mut Connection,
    command: &str,
    args: &Vec<String>
)
-> RedisResult<u32> {
    cmd(command).arg(args).query(connection)
}

/// Fetches items from Redis
/// 
/// Returns a vector of the items
pub fn fetch (
    connection: &mut Connection,
    command: &str,
    args: &Vec<String>
)
-> RedisResult<Vec<String>> {
    cmd(command).arg(args).query(connection)
}

/// Copies keys from Redis
/// 
/// Returns a tuple containing the cursor then the keys
pub fn scan (
    connection: &mut Connection,
    cursor: u32,
    pattern: &str
)
-> RedisResult<(u32, Vec<String>)> {
    cmd("scan")
        .arg(cursor)
        .arg("count").arg(10000)
        .arg("match").arg(pattern)
        .query(connection)
}

/// Retrieves keys from Redis in a non-blocking fashion
pub fn get_keys (
    connection: &mut Connection,
    pattern: &str
)
-> RedisResult<Vec<String>> {
    let mut retrieved_keys: Vec<String> = vec![];
    let mut cursor = 0u32;
    loop {
        let keys: Vec<String>;
        (cursor, keys) = redis_mod::scan(connection, cursor, pattern)?;
        if cursor == 0 {
            break
        }
        if keys.is_empty() {
            continue
        }

        for key in keys {
            retrieved_keys.push(key);
        }
    }

    Ok(retrieved_keys)
}

/* 
/// Fetches the type of a key in Redis
/// 
/// Returns the type as String
pub fn get_type (
    connection: &mut Connection,
    key: &str
)
-> RedisResult<String> {
    cmd("type").arg(key).query(connection)
}
*/