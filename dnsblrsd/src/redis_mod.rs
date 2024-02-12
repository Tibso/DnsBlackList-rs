use crate::{structs::DnsBlrsResult, CONFILE};

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH}
};
use redis::{aio::ConnectionManager, cmd, pipe, Client, FromRedisValue};
use tracing::info;

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
    hash: String,
    field: &str
)
-> DnsBlrsResult<Option<String>> {
    let ser_answer = manager.send_packed_command(cmd("hget").arg(hash).arg(field)).await?;
    Ok(FromRedisValue::from_redis_value(&ser_answer)?)
}

/// Fetches all the members of a set from Redis
pub async fn smembers (
    manager: &mut ConnectionManager,
    set: String
)
-> DnsBlrsResult<Vec<String>> {
    let ser_answer = manager.send_packed_command(cmd("smembers").arg(set)).await?;
    Ok(FromRedisValue::from_redis_value(&ser_answer)?)
}

/// Checks if a member exists in a set from Redis
pub async fn sismember (
    manager: &mut ConnectionManager,
    set: String,
    member: String
)
-> DnsBlrsResult<bool> {
    let ser_answer = manager.send_packed_command(cmd("sismember").arg(set).arg(member)).await?;
    Ok(FromRedisValue::from_redis_value(&ser_answer)?)
}

/// Prepares stats
fn prepare_stats (
    ip: String
)
-> DnsBlrsResult<(u64, String)> {
    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let stats_key = format!("DBL;stats;{};{ip}", CONFILE.daemon_id);

    Ok((time_epoch, stats_key))
}
/// Writes basic stats about a query
pub async fn write_stats_query (
    manager: &mut ConnectionManager,
    ip: IpAddr
)
-> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(ip.to_string())?;
    
    let mut cmd_last_seen = cmd("hset");
    cmd_last_seen.arg(stats_key.clone()).arg("last_seen").arg(time_epoch);
    let mut cmd_query_count = cmd("hincrby");
    cmd_query_count.arg(stats_key).arg("query_count").arg(1);

    manager.send_packed_commands(
        pipe()
        .add_command(cmd_last_seen).ignore()
        .add_command(cmd_query_count).ignore(),
        0, 0).await?;
    
    Ok(())
}
/// Writes stats about a matched rule
pub async fn write_stats_match (
    manager: &mut ConnectionManager,
    ip: IpAddr,
    rule: String
)
-> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(ip.to_string())?;

    let mut cmd_last_match = cmd("hset");
    cmd_last_match.arg(stats_key).arg("last_match").arg(time_epoch);
    let mut cmd_match_count = cmd("hincrby");
    cmd_match_count.arg(rule).arg("match_count").arg(1);

    manager.send_packed_commands(
        pipe()
        .add_command(cmd_last_match).ignore()
        .add_command(cmd_match_count).ignore(),
        0, 0).await?;

    Ok(())
}
