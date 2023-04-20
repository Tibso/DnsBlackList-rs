use redis::{Cmd, FromRedisValue, ConnectionLike, Connection, RedisResult};

/// Sets a value of a field in a hash in Redis
pub fn hset (
    connection: &mut Connection,
    hash: String,
    field: &str,
    value: String
)
-> RedisResult<usize> {
    // This Redis command sets a value of a field in a hash if it does not already exist
    // The command returns the number of values added in a serialized "Value"
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HSET")
        .arg(hash)
        .arg(field)
        .arg(value)
    )?;
    // Deserializes "Value"
    let add_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns 1 if the field was successfully added
    Ok(add_count)
}

/// Deletes hashes from Redis
pub fn del_vec (
    connection: &mut Connection,
    hashes: Vec<String>
)
-> RedisResult<usize> {
    // This Redis command deletes hashes if they exists
    // The command takes a vector as input
    let ser_answer = connection.req_command(Cmd::new()
        .arg("DEL")
        .arg(hashes))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns the amount of hashes deleted
    Ok(del_count)
}

/// Deletes the field of a hash from Redis
pub fn hdel (
    connection: &mut Connection,
    hash: String,
    field: &str
)
-> RedisResult<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HDEl")
        .arg(hash)
        .arg(field))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns 1 if the field was successfully deleted
    Ok(del_count)
}

/// Fetches all the keys of a hash from Redis
pub fn get_keys (
    connection: &mut Connection,
    command: &str,
    hash: String
)
-> RedisResult<Vec<String>> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg(command)
        .arg(hash))?;
    let deser_answer = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns a vector of strings
    Ok(deser_answer)
}
