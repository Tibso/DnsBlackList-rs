use redis::{
    RedisError,
    aio::{ConnectionManager, ConnectionLike},
    Client
};
use std::net::SocketAddr;

pub async fn build_redis (
    address: String,
    daemon_id: &String
)
-> (ConnectionManager, Vec<String>, Vec<SocketAddr>, Vec<String>) {
    let client = Client::open(format!("redis://{}/", address)).expect("Error probing the Redis server");
    println!("Redis server probe successful");
    let manager = client.get_tokio_connection_manager().await.expect("Error initiating the connection manager");
    println!("Connection to Redis successful");

    let matchclasses = get(&manager, "matchclasses", daemon_id).await.expect("Error fetching matchclasses from Redis");
    let matchclasses_count = matchclasses.clone().iter().count();
    println!("Received {} matchclasse(s)", matchclasses_count);

    let ser_forwarders = get(&manager, "forwarders", daemon_id).await.expect("Error fetching forwarders from Redis");
    let forwarders_count = ser_forwarders.clone().iter().count();
    println!("Received forwarder list");

    let mut deser_forwarders: Vec<SocketAddr> = Vec::new();
    let mut valid_forwarder_count: u8 = 0;
    for forwarder in ser_forwarders {
        deser_forwarders.push(
            match forwarder.parse::<SocketAddr>() {
                Ok(ok) => ok,
                Err(_) => continue
            }
        );
        valid_forwarder_count += 1
    }
    println!("{} out of {} forwarder(s) are valid", valid_forwarder_count, forwarders_count);

    let binds = get(&manager, "binds", daemon_id).await.expect("Error fetching binds from Redis");
    println!("Received bind list");

    return (manager, matchclasses, deser_forwarders, binds)
}

pub async fn exists (
    manager: &ConnectionManager,
    fullmatch: String,
    is_v4: bool
)
-> Result<bool, RedisError> {
    let qtype = match is_v4 {
        true => "A",
        false => "AAAA"
    };

    let ser_answer = manager.clone().req_packed_command(
        redis::Cmd::new()
            .arg("EXISTS")
            .arg(fullmatch)
            .arg(qtype))
            .await?;
    
    let deser_answer = redis::FromRedisValue::from_redis_value(&ser_answer)?;
    return Ok(deser_answer)
}

pub async fn get (
    manager: &ConnectionManager,
    kind: &str,
    daemon_id: &String
)
-> Result<Vec<String>, RedisError> {
    let ser_answer = manager.clone().req_packed_command(
        redis::Cmd::new()
            .arg("HKEYS")
            .arg(format!("{}_{}", kind, daemon_id)))
            .await?;

    let deser_answer = redis::FromRedisValue::from_redis_value(&ser_answer)?;
    return Ok(deser_answer)
}
