use crate::{
    errors::{DnsBlrsError, DnsBlrsResult},
    handler::Handler, features::misp::MispAPIConf
};

use std::{fs, time::Duration, net::SocketAddr, error::Error};
use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use serde::Deserialize;
use serde_norway::from_str;

pub const CONFILE: &str = "dnsblrsd.conf";
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// The main config structure
#[derive(Deserialize)]
pub struct Config {
    pub redis_addr: SocketAddr,
    pub services: Vec<Service>,
    pub forwarders: Vec<SocketAddr>,
    pub misp_api_conf: Option<MispAPIConf>
}

#[derive(Deserialize, Clone)]
/// Service the server has to serve
pub struct Service {
    pub name: String,
    pub filters: Vec<String>,
    pub binds: Vec<Bind>
}

#[derive(Deserialize, Clone)]
/// Binds the server will attempt to bind to
pub struct Bind {
    pub protocols: Vec<BindProtocol>,
    pub socket_addr: SocketAddr
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum BindProtocol {
    Udp,
    Tcp
}

/// Parses the config file into the main config structure
pub fn read_confile() -> Result<Config, Box<dyn Error>> {
    let data = fs::read_to_string(CONFILE)?;
    from_str(&data).map_err(|e| e.into())
}

/// Setup server binds
pub async fn setup_binds(
    srv: &mut ServerFuture<Handler>,
    services: Vec<Service>,
) -> DnsBlrsResult<()> {
    let (mut total, mut successful): (u32, u32) = (0, 0);

    for service in services {
        for bind in service.binds {
            for bind_protocol in bind.protocols {
                total += 1;
                let socket_addr = bind.socket_addr;

                let result = match bind_protocol {
                    BindProtocol::Udp => UdpSocket::bind(socket_addr).await
                        .map(|s| srv.register_socket(s)),
                    BindProtocol::Tcp => TcpListener::bind(socket_addr).await
                        .map(|l| srv.register_listener(l, TCP_TIMEOUT))
                };

                match result {
                    Ok(_) => successful += 1,
                    Err(e) => {
                        let protocol = format!("{bind_protocol:?}").to_uppercase();
                        warn!("Failed to bind '{socket_addr}' for {protocol}: {e}");
                    }
                }
            }
        }
    }

    match (successful, total) {
        (s, t) if s == t => info!("All {t} binds were set"),
        (0, _) => return Err(DnsBlrsError::SocketBinding),
        (s, t) => warn!("{s} out of {t} binds were set")
    }

    Ok(())
}
