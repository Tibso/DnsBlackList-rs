use tracing::info;

use redis::{
    aio::{ConnectionManager, ConnectionLike},
    Client, FromRedisValue, cmd
};

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH}
};

use crate::{structs::DnsBlrsResult, CONFILE};

/// Builds the Redis connection manager
pub async fn build_manager()
-> DnsBlrsResult<ConnectionManager> {
    // A client is built and probes the Redis server to check its availability
    let client = Client::open(format!("redis://{}/", &CONFILE.redis_address))?;

    // This manager allows the connection to be cloned and used simultaneously across different threads
    let manager = client.get_connection_manager().await?;

    info!("{}: Redis connection manager built", CONFILE.daemon_id);

    Ok(manager)
}

/// Fetches the value of a field in a hash from Redis 
pub async fn hget (
    manager: &mut ConnectionManager,
    hash: &str,
    field: &str
)
-> DnsBlrsResult<Option<String>> {
    let ser_answer = manager.req_packed_command(cmd("hget").arg(hash).arg(field)).await?;
    let deser_answer: Option<String> = FromRedisValue::from_redis_value(&ser_answer)?;
    
    Ok(deser_answer)
}

/// Fetches all the members of a set from Redis
pub async fn smembers (
    manager: &mut ConnectionManager,
    set: &str
)
-> DnsBlrsResult<Vec<String>> {
    let ser_answer = manager.req_packed_command(cmd("smembers").arg(set)).await?;
    let deser_answer: Vec<String> = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(deser_answer)
}

/// Checks if a member exists in a set from Redis
pub async fn sismember (
    manager: &mut ConnectionManager,
    set: &str,
    member: &str
)
-> DnsBlrsResult<bool> {
    let ser_answer = manager.req_packed_command(cmd("sismember").arg(set).arg(member)).await?;
    let deser_answer: bool = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(deser_answer)
}

/// Writes stats on Redis about the IP of the request
pub async fn write_stats (
    manager: &mut ConnectionManager,
    ip : IpAddr,
    is_match: bool
)
-> DnsBlrsResult<()> {
    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let set_key: &str;
    let incr_key: &str;
    // The key to increment to on Redis depends on whether or not a rule was matched
    if is_match {
        set_key = "last_match";
        incr_key = "match_count";
    } else {
        set_key = "last_seen";
        incr_key = "query_count";
    }

    let ip_string = ip.to_string();

    // This Redis command sets the time at which a rule was matched by the IP or the last time the IP was seen
    manager.req_packed_command(cmd("hset")
        .arg(format!("DBL;stats;{};{ip_string}", CONFILE.daemon_id))
        .arg(set_key)
        .arg(time_epoch)
    ).await?;

    // This Redis command increments by 1 the number of matches or requests of the IP
    manager.req_packed_command(cmd("hincrby")
        .arg(format!("DBL;stats;{};{ip_string}", CONFILE.daemon_id))
        .arg(incr_key)
        .arg(1)
    ).await?;

    Ok(())
}
