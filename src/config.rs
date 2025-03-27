use crate::{
    resolver, handler::Handler,
    errors::{DnsBlrsError, DnsBlrsErrorKind, DnsBlrsResult}
};

use std::{fs, process::exit, time::Duration,net::SocketAddr};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::ServerFuture;
use redis::{aio::ConnectionManager, AsyncCommands};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, error, warn};
use serde::Deserialize;

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
/// The initial config file
pub struct Confile {
    pub daemon_id: String,
    pub redis_addr: String
}

/// Reads the config file
pub fn read_confile(file_name: &str)
-> (String, String) {
    let data = match fs::read_to_string(file_name) {
        Ok(data) => data,
        Err(err) => {
            error!("Error reading 'dnsblrsd': {err}");
            exit(78) // CONFIG
        }
    };
    let confile: Confile = match serde_json::from_str(data.as_str()) {
        Ok(confile) => confile,
        Err(err) => {
            error!("Error deserializing 'dnsblrsd.conf' data: {err}");
            exit(78) // CONFIG
        }
    };
    let (daemon_id, redis_addr) = (confile.daemon_id, confile.redis_addr);

    info!("'daemon_id' is '{daemon_id}'");
    info!("{daemon_id}: Redis server: {redis_addr}");
    
    (daemon_id, redis_addr)
}

/// Configures forwarders
fn config_forwarders(
    daemon_id: &str,
    recvd_forwarders: Vec<String>
) -> Option<Vec<SocketAddr>> {
    let recvd_forwarder_cnt = recvd_forwarders.len();
    if recvd_forwarder_cnt == 0 {
        error!("{daemon_id}: No forwarders received");
        return None
    }
    info!("{daemon_id}: Received {recvd_forwarder_cnt} forwarders");

    let valid_forwarders: Vec<SocketAddr> = recvd_forwarders.into_iter().filter_map(|socket_addr_strg| {
        socket_addr_strg.parse::<SocketAddr>().map_or_else(
            |err| {
                warn!("{daemon_id}: Forwarder: '{socket_addr_strg}' is not valid: {err:?}");
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
        return None
    } else {
        warn!("{daemon_id}: {valid_forwarder_cnt} out of {recvd_forwarder_cnt} forwarders are valid");
    }

    Some(valid_forwarders)
}

/// Parses config binds
fn parse_binds(
    daemon_id: &str,
    recvd_binds: Vec<String>
) -> Option<Vec<(String, SocketAddr)>> {
    let recvd_bind_cnt = recvd_binds.len();
    if recvd_bind_cnt == 0 {
        error!("{daemon_id}: No bind received");
        return None
    }
    info!("{daemon_id}: Received {recvd_bind_cnt} binds");

    let mut valid_binds: Vec<(String, SocketAddr)> = Vec::with_capacity(recvd_bind_cnt);
    for bind in recvd_binds {
        let mut splits = bind.split('=');
        let proto = match splits.next() {
            Some(proto) => proto.to_lowercase(),
            None => {
                warn!("{daemon_id}: Bind: '{bind}' is not valid");
                continue
            }
        };
        if proto != "tcp" && proto != "udp" {
            warn!("{daemon_id}: Bind: '{bind}': Protocol is not valid");
            continue
        }
        let Some(socket_addr_strg) = splits.next() else {
            warn!("{daemon_id}: Bind: '{bind}' is not valid");
            continue
        };
        let Ok(socket_addr) = socket_addr_strg.parse::<SocketAddr>() else {
            warn!("{daemon_id}: Bind: '{bind}': Socket is not valid");
            continue
        };

        valid_binds.push((proto, socket_addr));
    }

    let valid_bind_cnt = valid_binds.len();
    // At least 1 bind must be valid
    if valid_bind_cnt == recvd_bind_cnt {
        info!("{daemon_id}: All {valid_bind_cnt} binds are valid");
    } else if valid_bind_cnt == 0 {
        error!("{daemon_id}: No bind is valid");
        return None
    } else {
        warn!("{daemon_id}: {valid_bind_cnt} out of {recvd_bind_cnt} total binds are valid");
    }

    Some(valid_binds)
}

/// Builds the resolver
pub async fn build_resolver(
    daemon_id: &str,
    redis_mngr: &mut ConnectionManager
) -> Option<TokioAsyncResolver> {
    let recvd_forwarders: Vec<String> = match redis_mngr.smembers(format!("DBL;C;forwarders;{daemon_id}")).await {
        Ok(forwarders) => forwarders,
        Err(err) => {
            error!("{daemon_id}: Error retrieving forwarders: {err:?}");
            return None
        }
    };
    let forwarders = config_forwarders(daemon_id, recvd_forwarders)?;

    Some(resolver::build(forwarders))
}

/// Builds the server binds
pub async fn build_binds(
    daemon_id: &str,
    redis_mngr: &mut ConnectionManager
) -> Option<Vec<(String, SocketAddr)>> {
    let recvd_binds: Vec<String> = match redis_mngr.smembers(format!("DBL;C;binds;{daemon_id}")).await {
        Ok(binds) => binds,
        Err(err) => {
            error!("{daemon_id}: Error retrieving binds: {err:?}");
            return None
        }
    };
    let binds = parse_binds(daemon_id, recvd_binds)?;

    Some(binds)
}

/// Setup server filters
pub async fn setup_filters(
    daemon_id: &str,
    redis_mngr: &mut ConnectionManager
) -> Option<Vec<String>> {
    let filters: Vec<String> = match redis_mngr.smembers(format!("DBL;C;filters;{daemon_id}")).await {
        Ok(filters) => filters,
        Err(err) => {
            warn!("{daemon_id}: Error retrieving filters: {err:?}");
            return None
        }
    };
    // If at least 1 filter is received, the server will filter the requests
    let filters_cnt: usize = filters.len();
    if filters_cnt == 0 {
        warn!("{daemon_id}: No filter received");
        return None
    }
    info!("{daemon_id}: Received {filters_cnt} filters");
    info!("{daemon_id}: Filtering data is valid");
    Some(filters)
}

/// Setups server binds
pub async fn setup_binds(
    srv: &mut ServerFuture<Handler>,
    daemon_id: &str,
    binds: Vec<(String, SocketAddr)>
) -> DnsBlrsResult<()> {
    let bind_cnt = binds.len();
    let mut successful_bind_cnt = 0usize;
    for (proto, socket_addr) in binds {
        match proto.as_str() {
            "udp" => {
                if let Ok(socket) = UdpSocket::bind(socket_addr).await {
                    srv.register_socket(socket);
                } else {
                    warn!("{daemon_id}: Failed to bind: '{socket_addr}' for UDP");
                }
            },
            "tcp" => {
                if let Ok(listener) = TcpListener::bind(socket_addr).await {
                    srv.register_listener(listener, TCP_TIMEOUT);
                } else {
                    warn!("{daemon_id}: Failed to bind: '{socket_addr}' for TCP");
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
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::SocketBinding))
    } else {
        warn!("{daemon_id}: {successful_bind_cnt} out of {bind_cnt} total binds were set");
    }

    Ok(())
}
