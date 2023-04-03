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

pub async fn build_manager ()
-> DnsLrResult<ConnectionManager> {
    let client = Client::open(format!("redis://{}/", &CONFILE.redis_address)).expect("Error probing the Redis server");
    info!("{}: Redis server probe successful", &CONFILE.daemon_id);

    let manager = client.get_tokio_connection_manager().await.expect("Error creating the connection manager");
    info!("{}: Redis connection manager built", &CONFILE.daemon_id);

    Ok(manager)
}

pub async fn build_config (
    manager: &mut ConnectionManager
)
-> DnsLrResult<Config> {
    let mut config: Config = Default::default();

    let tmp_blackhole_ips = hkeys(manager, "blackhole_ips").await.expect("Error fetching blackhole_ips");
    let blackhole_ips_count = tmp_blackhole_ips.len();
    if blackhole_ips_count != 2 {
        warn!("{}: Amount of blackhole_ips received were not 2 (must have v4 and v6)", CONFILE.daemon_id);
        warn!("{}: The server will not filter any request and so will not lie", CONFILE.daemon_id)
    } else {
        config.blackhole_ips = Some((
            tmp_blackhole_ips[0].parse::<Ipv4Addr>().expect("Error parsing blackhole_ipv4"),
            tmp_blackhole_ips[1].parse::<Ipv6Addr>().expect("Error parsing blackhole_ipv6")
        ));
        info!("{}: Blackhole_ips received are valid", CONFILE.daemon_id);

        let tmp_matchclasses = hkeys(manager, "matchclasses").await.expect("Error fetching matchclasses");
        let matchclasses_count = tmp_matchclasses.len();
        if matchclasses_count == 0 {
            warn!("{}: No matchclass received", CONFILE.daemon_id);
            warn!("{}: The server will not filter any request and so will not lie", CONFILE.daemon_id)
        } else {
            config.is_filtering = true;
            config.matchclasses = Some(tmp_matchclasses);

            info!("{}: Received {} matchclasses", CONFILE.daemon_id, matchclasses_count)
        }
    }

    let ser_forwarders = hkeys(manager, "forwarders").await.expect("Error fetching forwarders");
    let forwarders_count = ser_forwarders.len() as u8;
    if forwarders_count == 0 {
        error!("{}: No forwarder was received", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupForwardersError))
    }
    info!("{}: Received {} forwarders", CONFILE.daemon_id, forwarders_count);

    let mut valid_forwarder_count: u8 = 0;
    for forwarder in ser_forwarders {
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
    if valid_forwarder_count == forwarders_count {
        info!("{}: all {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count)
    } else if valid_forwarder_count < forwarders_count {
        warn!("{}: {} out of {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count, forwarders_count)
    } else if valid_forwarder_count == 0 {
        error!("{}: No forwarder is valid", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupForwardersError))
    }

    config.binds = hkeys(manager, "binds").await.expect("Error fetching binds");
    let bind_count = config.binds.len() as u32;
    if bind_count == 0 {
        error!("{}: No bind received", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupBindingError))
    }
    info!("{}: Received {} binds", CONFILE.daemon_id, bind_count);

    Ok(config)
}

pub async fn hget (
    manager: &mut ConnectionManager,
    hash: String,
    field: String
)
-> DnsLrResult<String> {
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HGET")
        .arg(hash)
        .arg(field)
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    let deser_answer: String;
    if ser_answer != Value::Nil {
        match FromRedisValue::from_redis_value(&ser_answer) {
            Ok(ok) => deser_answer = ok,
            Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
        };
    } else {
        deser_answer = "Nil".to_owned()
    }
    
    Ok(deser_answer)
}

pub async fn hkeys (
    manager: &mut ConnectionManager,
    matchclass_kind: &str
)
-> DnsLrResult<Vec<String>> {
    let ser_answer = match manager.req_packed_command(Cmd::new()
        .arg("HKEYS")
        .arg(format!("{}:{}", matchclass_kind, CONFILE.daemon_id))
    ).await {
        Ok(ok) => ok,
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    let deser_answer: Vec<String>;
    match FromRedisValue::from_redis_value(&ser_answer) {
        Ok(ok) => deser_answer = ok,
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    };

    Ok(deser_answer)
}

pub async fn write_stats (
    manager: &mut ConnectionManager,
    ip : IpAddr,
    is_match: bool
)
-> DnsLrResult<()> {
    let time_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(ok) => ok.as_secs(),
        Err(err) => return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::SystemTimeError(err))))
    };

    let set_key: &str;
    let incr_key: &str;
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
    if ip.is_ipv6() {
        ip_string = format!("[{}]", ip)
    } else {
        ip_string = ip.to_string()
    }

    if let Err(err) = manager.req_packed_command(Cmd::new()
        .arg("HSET")
        .arg(format!("stats:{}:{}", CONFILE.daemon_id, ip_string))
        .arg(set_key)
        .arg(time_epoch)
    ).await {
        return Err(DnsLrError::from(DnsLrErrorKind::ExternCrateError(ExternCrateErrorKind::RedisError(err))))
    }

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
