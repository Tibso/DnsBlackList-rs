use crate::{
    structs::{DnsBlrsResult, DnsBlrsError, DnsBlrsErrorKind, ExternCrateErrorKind,},
    CONFILE
};

use redis::{
    aio::{ConnectionManager, ConnectionLike},
    Client, Cmd, FromRedisValue, Value
};

use tracing::{info, error};
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH}
};

/// Builds the Redis connection manager
pub async fn build_manager ()
-> DnsBlrsResult<ConnectionManager> {
    // The Redis server address is obtained from the configuration file constant 

    // A client is built and probes the Redis server to check its availability
    let client = match Client::open(format!("redis://{}/", &CONFILE.redis_address)) {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}: Error probing the Redis server: {:?}", CONFILE.daemon_id, err);
            // Changes error to properly handle exitcode upstack
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildManagerError))
        }
    };

    // The manager is created from the previous Client
    // The manager wraps a multiplexed connection
    // This type of connection allows the manager to be cloned and used simultaneously across different threads
    let manager = match client.get_tokio_connection_manager().await {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}: Error creating the connection manager: {:?}", CONFILE.daemon_id, err);
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildManagerError))
        }
    };

    info!("{}: Redis connection manager built", CONFILE.daemon_id);

    Ok(manager)
}

/// Fetches the value of a field in a hash from Redis 
pub async fn hget (
    manager: &mut ConnectionManager,
    hash: String,
    field: String
)
-> DnsBlrsResult<String> {
    // This Redis command fetches the value of a field in a hash in a serialized "Value"
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HGET")
        .arg(hash)
        .arg(field)
    ).await {
        Ok(ok) => ok,
        // If an error occurs, we propagate the error up in the stack for proper error handling
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    // Because the received type from Redis is serialized,
    // we have to deserialize it to use the value in our code
    let deser_answer: String;
    // If the received value is not Null, the requested field exists and the value is deserialized
    if ser_answer != Value::Nil {
        match FromRedisValue::from_redis_value(&ser_answer) {
            Ok(ok) => deser_answer = ok,
            Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
        };
    } else {
        // If the value is Null, "Nil" is returned to the calling function to indicate that the requested field doesn't exist
        deser_answer = "Nil".to_owned()
    }
    
    Ok(deser_answer)
}

/// Fetches all the members of a set from Redis
pub async fn smembers (
    manager: &mut ConnectionManager,
    set: String
)
-> DnsBlrsResult<Vec<String>> {
    // This Redis command fetches all the members of a set in a serialized "Value"
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("smembers")
        .arg(set)
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    // The serialized "Value" is deserialized into a vector
    let deser_answer: Vec<String> = match FromRedisValue::from_redis_value(&ser_answer) {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    Ok(deser_answer)
}

/// Checks if a member exists in a set from Redis
pub async fn sismember (
    manager: &mut ConnectionManager,
    set: String,
    member: String
)
-> DnsBlrsResult<bool> {
    // This Redis command checks whether the member if part of the set
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("sismember")
        .arg(set)
        .arg(member)
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };
    
    // The serialized "Value" is deserialized into a boolean
    let deser_answer: bool = match FromRedisValue::from_redis_value(&ser_answer) {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    Ok(deser_answer)
}

/*
/// Fetches all the keys of a hash from Redis 
pub async fn hkeys (
    manager: &mut ConnectionManager,
    matchclass_kind: &str
)
-> DnsBlrsResult<Vec<String>> {
    // This Redis command fetches all the keys of a hash in a serialized "Value"
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HKEYS")
        .arg(format!("{}:{}", matchclass_kind, CONFILE.daemon_id))
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    // The serialized "Value" is deserialized into a vector
    let deser_answer: Vec<String> = match FromRedisValue::from_redis_value(&ser_answer) {
        Ok(ok) => ok,
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    Ok(deser_answer)
}
*/

/// Writes stats on Redis about the IP of the request
pub async fn write_stats (
    manager: &mut ConnectionManager,
    ip : IpAddr,
    is_match: bool
)
-> DnsBlrsResult<()> {
    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(ok) => ok.as_secs(),
        Err(err) => return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::SystemTimeError(err))))
    };

    let set_key: &str;
    let incr_key: &str;
    // The key to increment to on Redis depends on whether or not a rule was matched
    match is_match {
        false => {
            set_key = "last_seen";
            incr_key = "query_count"
        },
        true => {
            set_key = "last_match";
            incr_key = "match_count"
        }
    }

    // If the IP is v6, we wrap [] around it for better readability
    let ip_string = if ip.is_ipv6() {
        format!("[{}]", ip)
    } else {
        ip.to_string()
    };

    // This Redis command sets the time at which a rule was matched by the IP or the last time the IP was seen
    if let Err(err) = manager.req_packed_command(Cmd::new()
        .arg("HSET")
        .arg(format!("stats:{}:{}", CONFILE.daemon_id, ip_string))
        .arg(set_key)
        .arg(time_epoch)
    ).await {
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    }

    // This Redis command increments by 1 the number of matches or requests of the IP
    if let Err(err) = manager.req_packed_command(Cmd::new()
        .arg("HINCRBY")
        .arg(format!("stats:{}:{}", CONFILE.daemon_id, ip_string))
        .arg(incr_key)
        .arg(1)
    ).await {
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    }

    Ok(())
}
