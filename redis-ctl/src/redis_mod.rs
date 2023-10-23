use redis::{Cmd, from_redis_value, ConnectionLike, Connection, RedisResult};

/// Sets a value of a field in a hash in Redis
/// 
/// Returns "true" if the field was successfully added
pub fn hset (
    connection: &mut Connection,
    hash: String,
    key: &str,
    value: String
)
-> RedisResult<bool> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("hset")
        .arg(hash)
        .arg(key)
        .arg(value))?;
    let result = from_redis_value(&ser_value)?;

    Ok(result)
}

/// Deletes a key from Redis
/// 
/// Returns "true" if the key was successfully deleted
pub fn del (
    connection: &mut Connection,
    key: String
)
-> RedisResult<bool> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("del")
        .arg(key))?;
    let result = from_redis_value(&ser_value)?;

    Ok(result)
}

/// Deletes keys from Redis using a vector of keys as input
/// 
/// Returns the number of keys that were deleted
pub fn del_vec (
    connection: &mut Connection,
    keys: Vec<String>
)
-> RedisResult<usize> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("del")
        .arg(keys))?;
    let del_count = from_redis_value(&ser_value)?;

    Ok(del_count)
}

/// Deletes the field of a hash from Redis
/// 
/// Returns "true" if the field was successfully deleted
pub fn hdel (
    connection: &mut Connection,
    hash: String,
    field: &str
)
-> RedisResult<bool> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("hdel")
        .arg(hash)
        .arg(field))?;
    let result = from_redis_value(&ser_value)?;

    Ok(result)
}

/// Fetches all the elements of a key from Redis
/// 
/// This functions encompasses the commands "keys", "hgetall" and "smembers"
/// as this function works for regular keys, hashes and sets
/// 
/// Returns a vector of the elements
pub fn get_elements (
    connection: &mut Connection,
    command: &str,
    key: String
)
-> RedisResult<Vec<String>> {
    let ser_value = connection.req_command(Cmd::new()
        .arg(command)
        .arg(key))?;
    let deser_value = from_redis_value(&ser_value)?;

    Ok(deser_value)
}

/// Adds a vector of members to a set in Redis
/// 
/// Returns the number of members that were added to the set
pub fn sadd_vec (
    connection: &mut Connection,
    set: String,
    members: Vec<String>
)
-> RedisResult<usize> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("sadd")
        .arg(set)
        .arg(members))?;
    let add_count = from_redis_value(&ser_value)?;

    Ok(add_count)
}

/// Adds a member to a set in Redis
/// 
/// Returns "true" if the member was successfully added to the set
pub fn sadd (
    connection: &mut Connection,
    set: String,
    member: String
)
-> RedisResult<bool> {
    let ser_value = connection.req_command(Cmd::new()
        .arg("sadd")
        .arg(set)
        .arg(member))?;
    let result = from_redis_value(&ser_value)?;

    Ok(result)
}
