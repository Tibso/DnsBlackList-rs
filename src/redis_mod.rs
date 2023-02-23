use redis::{
    RedisError,
    aio::{ConnectionManager, ConnectionLike}
};

pub async fn redis_exists (
    manager: &ConnectionManager,
    fullmatch: String,
    is_v4: bool
) -> Result<bool, RedisError> {
    let qtype = match is_v4 {
        true => "A",
        false => "AAAA"
    };

    let serialized_answer = manager.clone().req_packed_command(
        redis::Cmd::new()
            .arg("EXISTS")
            .arg(fullmatch)
            .arg(qtype))
            .await?;
    
    let deserialized = redis::FromRedisValue::from_redis_value(&serialized_answer)?;
    return Ok(deserialized)
}

pub async fn redis_get (
    manager: &ConnectionManager,
    kind: &str,
    daemon_id: &String
) -> Result<Vec<String>, RedisError> {
    let serialized_answer = manager.clone().req_packed_command(
        redis::Cmd::new()
            .arg("HKEYS")
            .arg(format!("{}_{}", kind, daemon_id)))
            .await?;

    let deserialized = redis::FromRedisValue::from_redis_value(&serialized_answer)?;
    return Ok(deserialized)
}
