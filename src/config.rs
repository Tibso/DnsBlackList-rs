use crate::{
    errors::{DnsBlrsError, DnsBlrsResult},
    handler::Handler, misp::MispAPIConf
};

use std::{fs, process::exit, time::Duration,net::SocketAddr};
use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, error, warn};
use serde::Deserialize;
use serde_norway::from_str;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
/// The main configuration structure
pub struct Config {
    pub daemon_id: String,
    pub redis_addr: SocketAddr,
    pub binds: Vec<(BindProtocol, SocketAddr)>,
    pub forwarders: Vec<SocketAddr>,
    pub filters: Vec<String>,
    pub misp_api_conf: Option<MispAPIConf>
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindProtocol {
    Udp,
    Tcp
}

/// Parses the config file into the config structure
pub fn read_confile(filename: &str)-> Config {
    let data = match fs::read_to_string(filename) {
        Ok(data) => data,
        Err(e) => {
            error!("Error reading '{filename}': {e}");
            exit(78) // CONFIG
        }
    };
    match from_str(data.as_str()) {
        Ok(config) => config,
        Err(e) => {
            error!("Error deserializing '{filename}' data: {e}");
            exit(78) // CONFIG
        }
    }
}

/// Setup server binds
pub async fn setup_binds(
    srv: &mut ServerFuture<Handler>,
    binds: Vec<(BindProtocol, SocketAddr)>
) -> DnsBlrsResult<()> {
    let bind_cnt = binds.len();
    let mut successful_bind_acc: usize = 0;
    for (protocol, socket_addr) in binds {
        match protocol {
            BindProtocol::Udp => {
                if let Ok(socket) = UdpSocket::bind(socket_addr).await {
                    srv.register_socket(socket);
                } else {
                    warn!("Failed to bind: '{socket_addr}' for UDP");
                }
            },
            BindProtocol::Tcp => {
                if let Ok(listener) = TcpListener::bind(socket_addr).await {
                    srv.register_listener(listener, TCP_TIMEOUT);
                } else {
                    warn!("Failed to bind: '{socket_addr}' for TCP");
                }
            }
        }
        successful_bind_acc += 1;
    }

    if successful_bind_acc == bind_cnt {
        info!("All {bind_cnt} binds were set");
    } else if successful_bind_acc == 0 {
        error!("No bind was set");
        return Err(DnsBlrsError::SocketBinding)
    } else {
        warn!("{successful_bind_acc} out of {bind_cnt} total binds were set");
    }

    Ok(())
}
