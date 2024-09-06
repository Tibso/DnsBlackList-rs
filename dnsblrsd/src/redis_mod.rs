use crate::errors::DnsBlrsResult;

use std::{net::IpAddr, time::{SystemTime, UNIX_EPOCH}};
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tracing::info;

/// Builds the Redis connection manager
pub async fn build_manager(
    daemon_id: &str,
    redis_address: &str
) -> DnsBlrsResult<ConnectionManager> {
    // A client is built and probes the Redis server to check its availability
    let client = Client::open(format!("redis://{redis_address}/"))?;

    // This manager allows the connection to be cloned and used simultaneously across different threads
    let manager = client.get_connection_manager().await?;
    info!("{daemon_id}: Redis connection manager built");

    Ok(manager)
}

/// Prepares stats
fn prepare_stats(
    daemon_id: &str,
    ip: &str
) -> DnsBlrsResult<(u64, String)> {
    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let stats_key = format!("DBL;stats;{daemon_id};{ip}");

    Ok((time_epoch, stats_key))
}

/// Writes basic stats about a request
pub async fn write_stats_request(
    manager: &mut ConnectionManager,
    daemon_id: &str,
    ip: IpAddr
) -> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(daemon_id, ip.to_string().as_str())?;

    let () = manager.hset(stats_key.clone(), "last_seen", time_epoch).await?;
    let () = manager.hincr(stats_key, "query_count", 1).await?;

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
    daemon_id: &str,
    ip: IpAddr,
    rule: &str
) -> DnsBlrsResult<()> {
    let (time_epoch, stats_key) = prepare_stats(daemon_id, ip.to_string().as_str())?;

    let () = manager.hset(stats_key, "last_match", time_epoch).await?;
    let () = manager.hincr(rule, "match_count", 1).await?;

//    manager.send_packed_commands(
//        pipe()
//        .cmd("hset").arg(stats_key).arg("last_match").arg(time_epoch).ignore()
//        .cmd("hincrby").arg(rule).arg("match_count").arg(1).ignore(),
//        0, 0).await?;

    Ok(())
}
