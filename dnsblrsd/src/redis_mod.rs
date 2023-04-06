use crate::{
    structs::{Config, DnsLrResult, DnsLrError, DnsLrErrorKind, ExternCrateErrorKind,},
    CONFILE
};

use redis::{
    aio::{ConnectionManager, ConnectionLike},
    Client, Cmd, FromRedisValue, Value
};

use tracing::{info, error, warn};
use std::{
    net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr},
    time::{SystemTime, UNIX_EPOCH}
};


/// Fetches the value of a field in a hash from Redis 
pub async fn hget (
    manager: &mut ConnectionManager,
    hash: String,
    field: String
)
-> DnsLrResult<String> {
    // This Redis command fetches the value of a field in a hash in a serialized "Value"
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HGET")
        .arg(hash)
        .arg(field)
    ).await {
        Ok(ok) => ok,
        // If an error occurs, we propagate the error up in the stack for proper error handling
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    // Because the received type from Redis is serialized,
    // we have to deserialize it to use the value in our code
    let deser_answer: String;
    // If the received value is not Null, the requested field exists and the value is deserialized
    if ser_answer != Value::Nil {
        match FromRedisValue::from_redis_value(&ser_answer) {
            Ok(ok) => deser_answer = ok,
            Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
        };
    } else {
        // If the value is Null, "Nil" is returned to the calling function to indicate that the requested field doesn't exist
        deser_answer = "Nil".to_owned()
    }
    
    Ok(deser_answer)
}

/// Fetches all the keys of a hash from Redis 
pub async fn hkeys (
    manager: &mut ConnectionManager,
    matchclass_kind: &str
)
-> DnsLrResult<Vec<String>> {
    // This Redis command fetches all the keys of a hash in a serialized "Value"
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HKEYS")
        .arg(format!("{}:{}", matchclass_kind, CONFILE.daemon_id))
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    // The serialized "Value" is deserialized into a vector
    let deser_answer: Vec<String>;
    match FromRedisValue::from_redis_value(&ser_answer) {
        Ok(ok) => deser_answer = ok,
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    Ok(deser_answer)
}


/// Builds the Redis connection manager
pub async fn build_manager ()
-> DnsLrResult<ConnectionManager> {
    // The Redis server address is obtained from the configuration file constant 

    // A client is built and probes the Redis server to check its availability
    let client = Client::open(format!("redis://{}/", &CONFILE.redis_address)).expect("Error probing the Redis server");
    info!("{}: Redis server probe successful", &CONFILE.daemon_id);

    // The manager is created from the previous Client
    // The manager wraps a multiplexed connection
    // This type of connection allows the manager to be cloned and used simultaneously across different threads
    let manager = client.get_tokio_connection_manager().await.expect("Error creating the connection manager");
    info!("{}: Redis connection manager built", &CONFILE.daemon_id);

    Ok(manager)
}

/// Builds the server's configuration
pub async fn build_config (
    manager: &mut ConnectionManager
)
-> DnsLrResult<Config> {
    // Initialize the configuration variable with the default values using the Default trait
    let mut config = Config::default();

    // If an error occurs in this function, we make the process panic with "expect"
    // because the server cannot start without its configuration

    // Fetches the blackhole_ips from Redis
    let tmp_blackhole_ips = hkeys(manager, "blackhole_ips").await.expect("Error fetching blackhole_ips");
    let blackhole_ips_count = tmp_blackhole_ips.len();
    // If we haven't received exactly 2 blackhole_ips, there is an issue with the configuration 
    if blackhole_ips_count != 2 {
        warn!("{}: Amount of blackhole_ips received were not 2 (must have v4 and v6)", CONFILE.daemon_id);
        warn!("{}: The server will not filter any request and so will not lie", CONFILE.daemon_id)
    } else {
        // The vector is made into an iterable to parse both IPs
        let mut tmp_blackhole_ips = tmp_blackhole_ips.iter();
        // The blackhole_ips field is filled by the received tuple
        config.blackhole_ips = Some((
            // If they can both be parsed into IPs, they are stored in the configuration variable
            tmp_blackhole_ips.next().unwrap().parse::<Ipv4Addr>().expect("Error parsing blackhole_ipv4"),
            tmp_blackhole_ips.next().unwrap().parse::<Ipv6Addr>().expect("Error parsing blackhole_ipv6")
        ));
        info!("{}: Blackhole_ips received are valid", CONFILE.daemon_id);

        // Fetches the matchclasses from Redis
        let tmp_matchclasses = hkeys(manager, "matchclasses").await.expect("Error fetching matchclasses");
        let matchclasses_count = tmp_matchclasses.len();
        // If no matchclass is received, the server will not filter any request
        if matchclasses_count == 0 {
            warn!("{}: No matchclass received", CONFILE.daemon_id);
            warn!("{}: The server will not filter any request and so will not lie", CONFILE.daemon_id)
        } else {
            // If at least 1 matchclass is received, the server will filter the requests
            config.is_filtering = true;
            // The variable is store in the configuration variable
            config.matchclasses = Some(tmp_matchclasses);

            info!("{}: Received {} matchclasses", CONFILE.daemon_id, matchclasses_count)
        }
    }

    // Fetches the forwarders' sockets from Redis
    let tmp_forwarders = hkeys(manager, "forwarders").await.expect("Error fetching forwarders");
    let forwarders_count = tmp_forwarders.len() as u8;
    // If no forwarder is received, the server cannot start
    if forwarders_count == 0 {
        error!("{}: No forwarder was received", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupForwardersError))
    }
    info!("{}: Received {} forwarders", CONFILE.daemon_id, forwarders_count);

    // The forwarders' sockets are parsed to validate them
    let mut valid_forwarder_count: u8 = 0;
    for forwarder in tmp_forwarders {
        config.forwarders.push(
            match forwarder.parse::<SocketAddr>() {
                Ok(ok) => ok,
                Err(_) => {
                    warn!("{}: forwarder: {} is not valid", CONFILE.daemon_id, forwarder);
                    continue
                }
            }
        );
        valid_forwarder_count += 1
    }
    // If at least 1 forwarder socket is valid, the server can start
    if valid_forwarder_count == forwarders_count {
        info!("{}: all {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count)
    } else if valid_forwarder_count < forwarders_count {
        warn!("{}: {} out of {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count, forwarders_count)
    } else if valid_forwarder_count == 0 {
        error!("{}: No forwarder is valid", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupForwardersError))
    }

    // Fetches the binds from Redis
    config.binds = hkeys(manager, "binds").await.expect("Error fetching binds");
    let bind_count = config.binds.len() as usize;
    // If no bind is received, the server cannot start
    if bind_count == 0 {
        error!("{}: No bind received", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupBindingError))
    }
    info!("{}: Received {} binds", CONFILE.daemon_id, bind_count);

    Ok(config)
}

/// Writes stats on Redis about the IP of the request
pub async fn write_stats (
    manager: &mut ConnectionManager,
    ip : IpAddr,
    is_match: bool
)
-> DnsLrResult<()> {
    // The current time is fetched and converted to EPOCH in seconds
    let time_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(ok) => ok.as_secs(),
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::SystemTimeError(err))))
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

    let ip_string: String;
    // If the IP is v6, we wrap [] around it for better readability
    if ip.is_ipv6() {
        ip_string = format!("[{}]", ip)
    } else {
        ip_string = ip.to_string()
    }

    // This Redis command sets the time at which a rule was matched by the IP or the last time the IP was seen
    if let Err(err) = manager.req_packed_command(Cmd::new()
        .arg("HSET")
        .arg(format!("stats:{}:{}", CONFILE.daemon_id, ip_string))
        .arg(set_key)
        .arg(time_epoch)
    ).await {
        return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    }

    // This Redis command increments by 1 the number of matches or requests of the IP
    if let Err(err) = manager.req_packed_command(Cmd::new()
        .arg("HINCRBY")
        .arg(format!("stats:{}:{}", CONFILE.daemon_id, ip_string))
        .arg(incr_key)
        .arg(1)
    ).await {
        return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    }

    Ok(())
}
