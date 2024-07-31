use crate::{DAEMON_ID, structs::DnsBlrsResult};

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH}
};
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;

/// Builds the Redis connection manager
pub async fn build_manager(redis_address: &str)
-> DnsBlrsResult<ConnectionManager> {
    let daemon_id = DAEMON_ID.get().expect("Could not fetch daemon_id");

    // A client is built and probes the Redis server to check its availability
    let client = Client::open(format!("redis://{redis_address}/"))?;

    // This manager allows the connection to be cloned and used simultaneously across different threads
    let manager = client.get_connection_manager().await?;
    info!("{daemon_id}: Redis connection manager built");

    Ok(manager)
}

/// Prepares stats
fn prepare_stats(ip: &str)
-> DnsBlrsResult<(u64, String)> {
    let daemon_id = DAEMON_ID.get().expect("Could not fetch daemon_id");

    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let stats_key = format!("DBL;stats;{daemon_id};{ip}");

    Ok((time_epoch, stats_key))
}
/// Writes basic stats about a query
pub async fn write_stats_query(
    manager: &mut ConnectionManager,
    ip: IpAddr
) -> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(&ip.to_string())?;

    manager.hset(stats_key.clone(), "last_seen", time_epoch).await?;
    manager.hincr(stats_key, "query_count", 1).await?;

//    manager.send_packed_commands(
//        pipe()
//        .cmd("hset").arg(stats_key.clone()).arg("last_seen").arg(time_epoch).ignore()
//        .cmd("hincrby").arg(stats_key).arg("query_count").arg(1).ignore(),
//        0, 0).await?;

    Ok(())
}
/// Writes stats about a matched rule
pub async fn write_stats_match(
    manager: &mut ConnectionManager,
    ip: IpAddr,
    rule: String
) -> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(&ip.to_string())?;

    manager.hset(stats_key, "last_match", time_epoch).await?;
    manager.hincr(rule, "match_count", 1).await?;

//    manager.send_packed_commands(
//        pipe()
//        .cmd("hset").arg(stats_key).arg("last_match").arg(time_epoch).ignore()
//        .cmd("hincrby").arg(rule).arg("match_count").arg(1).ignore(),
//        0, 0).await?;

    Ok(())
}
