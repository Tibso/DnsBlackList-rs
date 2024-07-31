use crate::{structs::{Config, DnsBlrsResult, Confile, DnsBlrsError, DnsBlrsErrorKind}, Handler};

use std::{fs, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, process::exit, str::FromStr, time::Duration};
use hickory_server::ServerFuture;
use redis::{aio::ConnectionManager, AsyncCommands};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, error, warn};

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads the config file
pub fn read_confile(file_name: &str)
-> Confile {
    let confile: Confile = {
        let data = match fs::read_to_string(file_name) {
            Ok(data) => data,
            Err(err) => {
                error!("Error reading \"dnsblrsd\": {err}");
                exit(78) // CONFIG
            }
        };
        match serde_json::from_str(&data) {
            Ok(confile) => confile,
            Err(err) => {
                error!("Error deserializing \"dnsblrsd.conf\" data: {err}");
                exit(78) // CONFIG
            }
        }
    };

    info!("daemon_id is \"{}\"", confile.daemon_id);
    info!("{}: Redis server: {}", confile.daemon_id, confile.redis_address);
    
    confile
}

/// Checks the config blackhole ips
fn check_blackhole_ips(blackholes: Vec<String>)
-> Option<(Ipv4Addr, Ipv6Addr)> {
    Some(match IpAddr::from_str(blackholes.first().unwrap()).ok()? {
        IpAddr::V4(ipv4) => (ipv4, Ipv6Addr::from_str(blackholes.get(1).unwrap()).ok()?),
        IpAddr::V6(ipv6) => (Ipv4Addr::from_str(blackholes.get(1).unwrap()).ok()?, ipv6)
    })
}

/// Configures forwarders
fn config_forwarders(
    daemon_id: &str,
    recvd_forwarders: Vec<String>
) -> DnsBlrsResult<Vec<SocketAddr>> {
    let recvd_forwarder_cnt = recvd_forwarders.len();
    if recvd_forwarder_cnt == 0 {
        error!("{daemon_id}: Forwarder vector received is empty");
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    }
    info!("{daemon_id}: Received {recvd_forwarder_cnt} forwarders");

    let valid_forwarders: Vec<SocketAddr> = recvd_forwarders.into_iter().filter_map(|socket_addr_strg| {
        socket_addr_strg.parse::<SocketAddr>().map_or_else(
            |err| {
                warn!("{daemon_id}: Forwarder: \"{socket_addr_strg}\" is not valid: {err:?}");
                None
            },
            Some
        )
    }).collect();
    let valid_forwarder_cnt = valid_forwarders.len();

    // At least 1 forwarder socket address must be valid
    if valid_forwarder_cnt == recvd_forwarder_cnt {
        info!("{daemon_id}: All {valid_forwarder_cnt} forwarders are valid");
    } else if valid_forwarder_cnt == 0 {
        error!("{daemon_id}: No forwarder is valid");
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    } else {
        warn!("{daemon_id}: {valid_forwarder_cnt} out of {recvd_forwarder_cnt} forwarders are valid");
    }

    Ok(valid_forwarders)
}

/// Parses config binds
fn parse_binds(
    daemon_id: &str,
    recvd_binds: Vec<String>
) -> DnsBlrsResult<Vec<(String, SocketAddr)>> {
    let recvd_bind_cnt = recvd_binds.len();
    if recvd_bind_cnt == 0 {
        error!("{daemon_id}: No bind received");
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    }
    info!("{daemon_id}: Received {recvd_bind_cnt} binds");

    let mut valid_binds: Vec<(String, SocketAddr)> = Vec::with_capacity(recvd_bind_cnt);
    for bind in recvd_binds {
        let mut splits = bind.split('=');
        let proto = match splits.next() {
            Some(proto) => proto.to_lowercase(),
            None => {
                warn!("{daemon_id}: Bind: \"{bind}\" is not valid");
                continue
            }
        };
        if proto != "tcp" || proto != "udp" {
            warn!("{daemon_id}: Bind: \"{bind}\": Protocol is not valid");
            continue
        }
        let Some(socket_addr_strg) = splits.next() else {
            warn!("{daemon_id}: Bind: \"{bind}\" is not valid");
            continue
        };
        let Ok(socket_addr) = socket_addr_strg.parse::<SocketAddr>() else {
            warn!("{daemon_id}: Bind: \"{bind}\": Socket is not valid");
            continue
        };

        valid_binds.push((proto, socket_addr));
    };

    let valid_bind_cnt = valid_binds.len();
    // At least 1 bind must be valid
    if valid_bind_cnt == recvd_bind_cnt {
        info!("{daemon_id}: All {valid_bind_cnt} binds are valid");
    } else if valid_bind_cnt == 0 {
        error!("{daemon_id}: No bind is valid");
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::SetupBinding))
    } else {
        warn!("{daemon_id}: {valid_bind_cnt} out of {recvd_bind_cnt} total binds are valid");
    }

    Ok(valid_binds)
}

/// Builds server config
pub async fn build(
    daemon_id: &str,
    redis_manager: &mut ConnectionManager
) -> DnsBlrsResult<(Config, Vec<SocketAddr>, Vec<(String, SocketAddr)>)> {
    let mut config = Config::default();

    // Fatal config errors are checked first for early returns

    let recvd_forwarders: Vec<String> = redis_manager.smembers(format!("DBL;forwarders;{daemon_id}")).await
        .map_err(|err| {
            error!("{daemon_id}: Error retrieving forwarders: {err:?}");
            DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig)
        })?;
    let forwarders = config_forwarders(daemon_id, recvd_forwarders)?;

    let recvd_binds: Vec<String> = redis_manager.smembers(format!("DBL;binds;{daemon_id}")).await
        .map_err(|err| {
            error!("{daemon_id}: Error retrieving binds: {err:?}");
            DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig)
        })?;
    let binds = parse_binds(daemon_id, recvd_binds)?;

    // Errors shouldn't be fatal anymore
    // If an error occurs beyond this point, the server will not filter

    let filtering_warn_msg = "The server will not filter any request";
    let blackholes: Vec<String> = match redis_manager.smembers(format!("DBL;blackholes;{daemon_id}")).await {
        Ok(blackholes) => blackholes,
        Err(err) => {
            warn!("{daemon_id}: Error retrieving blackholes: {err:?}");
            warn!("{daemon_id}: {filtering_warn_msg}");
            return Ok((config, forwarders, binds))
        }
    };
    // If we haven't received exactly 2 blackholes, there is an issue with the configuration
    if blackholes.len() != 2 {
        warn!("{daemon_id}: Amount of blackholes received were not 2 (must have v4 and v6)");
        warn!("{daemon_id}: {filtering_warn_msg}");
        return Ok((config, forwarders, binds))
    }
    let Some((blackhole_ipv4, blackhole_ipv6)) = check_blackhole_ips(blackholes) else {
        warn!("{daemon_id}: The blackholes are not properly configured, there must be one IPv4 and one IPv6");
        return Ok((config, forwarders, binds))
    };

    let filters: Vec<String> = match redis_manager.smembers(format!("DBL;filters;{daemon_id}")).await {
        Ok(filters) => filters,
        Err(err) => {
            warn!("{daemon_id}: Error retrieving filters: {err:?}");
            warn!("{daemon_id}: {filtering_warn_msg}");
            return Ok((config, forwarders, binds))
        }
    };
    // If at least 1 filter is received, the server will filter the requests
    let filters_cnt: usize = filters.len();
    if filters_cnt == 0 {
        warn!("{daemon_id}: No filter received");
        warn!("{daemon_id}: {filtering_warn_msg}");
        return Ok((config, forwarders, binds))
    }
    info!("{daemon_id}: Received {filters_cnt} filters");

    config.blackholes = (blackhole_ipv4, blackhole_ipv6);
    config.is_filtering = true;
    config.filters = filters;
    Ok((config, forwarders, binds))
}

/// Setups server binds
pub async fn setup_binds(
    server: &mut ServerFuture<Handler>,
    daemon_id: &str,
    binds: Vec<(String, SocketAddr)>
) -> DnsBlrsResult<()> {
    let bind_cnt = binds.len();
    let mut successful_bind_cnt = 0usize;
    for (proto, socket_addr) in binds {
        match proto.as_str() {
            "udp" => {
                if let Ok(socket) = UdpSocket::bind(socket_addr).await {
                    server.register_socket(socket);
                } else {
                    warn!("{daemon_id}: Failed to bind: \"{socket_addr}\" for UDP");
                }
            },
            "tcp" => {
                if let Ok(listener) = TcpListener::bind(socket_addr).await {
                    server.register_listener(listener, TCP_TIMEOUT);
                } else {
                    warn!("{daemon_id}: Failed to bind: \"{socket_addr}\" for TCP");
                }
            },
            _ => unreachable!("Socket protocol should have been filtered out earlier")
        }
        successful_bind_cnt += 1;
    }

    // At least 1 bind must be set
    if successful_bind_cnt == bind_cnt {
        info!("{daemon_id}: All {successful_bind_cnt} binds were set");
    } else if successful_bind_cnt == 0 {
        error!("{daemon_id}: No bind was set");
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::SetupBinding))
    } else {
        warn!("{daemon_id}: {successful_bind_cnt} out of {bind_cnt} total binds were set");
    }

    Ok(())
}