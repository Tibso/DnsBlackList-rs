mod handler_mod;
mod redis_mod;
mod resolver_mod;
mod matching;
mod enums_structs;

use crate::handler_mod::Handler;
use crate::enums_structs::{Config, DnsLrResult, WrappedErrors, ErrorKind, Confile};

use trust_dns_server::ServerFuture;

use tokio::net::{TcpListener, UdpSocket};
use std::{
    time::Duration,
    fs
};
use tracing::{info, error, warn};

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

fn read_config (
    file_name: &str
)
-> Config {
    let confile: Confile = {
        let data = fs::read_to_string(file_name).expect("Error reading config file");
        serde_json::from_str(&data).expect("Error deserializing config file data")
    };

    info!("Daemon_id is {}", confile.daemon_id);
    info!("{}: Redis server: {}", confile.daemon_id, confile.redis_address);
    
    return Config {
        daemon_id: confile.daemon_id,
        redis_address: confile.redis_address,
        forwarders: vec![],
        binds: vec![],
        is_filtering: false,
        blackhole_ips: None,
        matchclasses: None
    };
}

async fn setup_binds (
    server: &mut ServerFuture<Handler>,
    config: &Config
)
-> DnsLrResult<()> {
    let bind_count = config.binds.clone().iter().count() as u32;
    let mut successful_binds_count: u32 = 0;
    for bind in config.binds.clone().into_iter() {
        let splits: Vec<&str> = bind.split("=").collect();

        match splits[0] {
            "UDP" => {
                let Ok(socket) = UdpSocket::bind(splits[1]).await else {
                    warn!("{}: Failed to bind: {}", config.daemon_id, bind);
                    continue
                };
                server.register_socket(socket)
            },
            "TCP" => {
                let Ok(listener) = TcpListener::bind(splits[1]).await else {
                    warn!("{}: Failed to bind: {}", config.daemon_id, bind);
                    continue
                };
                server.register_listener(listener, TCP_TIMEOUT)
            },
            _ => {
                warn!("{}: Failed to bind: {}", config.daemon_id, bind);
                continue
            }
        };
        successful_binds_count += 1
    }
    if successful_binds_count == bind_count {
        info!("{}: all {} binds were set", config.daemon_id, successful_binds_count)
    } else if successful_binds_count < bind_count {
        warn!("{}: {} out of {} total binds were set", config.daemon_id, successful_binds_count, bind_count)
    } else if successful_binds_count == 0 {
        error!("{}: 0 binds were set", config.daemon_id);
        return Err(WrappedErrors::DNSlrError(ErrorKind::SetupBindingError))
    }

    return Ok(())
}

#[tokio::main]
async fn main()
-> DnsLrResult<()> {
    tracing_subscriber::fmt::init();

    let mut config = read_config("dnslr.conf");

    let redis_manager = redis_mod::build_redis(&mut config).await?;

    let resolver = resolver_mod::build_resolver(&config);

    info!("{}: Initializing server...", config.daemon_id);

    let config_binding = config.clone();
    let handler = handler_mod::Handler {
        redis_manager, resolver, config
    };
    let mut server = ServerFuture::new(handler);

    setup_binds(&mut server, &config_binding).await?;

    info!("{}: Server started", config_binding.daemon_id);
    server.block_until_done().await?;

    return Ok(())
}
