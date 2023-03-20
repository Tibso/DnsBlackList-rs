mod handler;
mod redis_mod;
mod resolver;
mod matching;
mod structs;

use crate::{
    handler::Handler,
    structs::{Config, DnsLrResult, Confile, DnsLrError, DnsLrErrorKind}
};

use arc_swap::ArcSwap;
use trust_dns_server::ServerFuture;

use tokio::{
    net::{TcpListener, UdpSocket}
};
use std::{
    time::Duration,
    fs,
    sync::Arc
};
use tracing::{info, error, warn};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::{SIGHUP, SIGUSR1, SIGUSR2};
use futures_util::{
    stream::StreamExt
};
use lazy_static::lazy_static;

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

lazy_static! {
    static ref CONFILE: Confile = read_confile("dnslr.conf");
}

fn read_confile (
    file_name: &str
)
-> Confile {
    let confile: Confile = {
        let data = fs::read_to_string(file_name).expect("Error reading config file");
        serde_json::from_str(&data).expect("Error deserializing config file data")
    };

    info!("Daemon_id is {}", confile.daemon_id);
    info!("{}: Redis server: {}", confile.daemon_id, confile.redis_address);
    
    return confile
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
                    warn!("{}: Failed to bind: {}", CONFILE.daemon_id, bind);
                    continue
                };
                server.register_socket(socket)
            },
            "TCP" => {
                let Ok(listener) = TcpListener::bind(splits[1]).await else {
                    warn!("{}: Failed to bind: {}", CONFILE.daemon_id, bind);
                    continue
                };
                server.register_listener(listener, TCP_TIMEOUT)
            },
            _ => {
                warn!("{}: Failed to bind: {}", CONFILE.daemon_id, bind);
                continue
            }
        };
        successful_binds_count += 1
    }
    if successful_binds_count == bind_count {
        info!("{}: all {} binds were set", CONFILE.daemon_id, successful_binds_count)
    } else if successful_binds_count < bind_count {
        warn!("{}: {} out of {} total binds were set", CONFILE.daemon_id, successful_binds_count, bind_count)
    } else if successful_binds_count == 0 {
        error!("{}: No bind was set", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupBindingError))
    }

    return Ok(())
}

async fn handle_signals (
    mut signals: Signals,
    arc_config: Arc<ArcSwap<Config>>,
    mut redis_manager: redis::aio::ConnectionManager
) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGHUP => {
                info!("Captured SIGHUP");

                let Ok(new_config) = redis_mod::build_config(&mut redis_manager).await else {
                    error!("Could not rebuild the config");
                    continue
                };
                let new_config =  Arc::new(new_config);
                arc_config.store(new_config);
                info!("Config was rebuilt")
            },
            SIGUSR1 => {
                info!("Captured SIGUSR1");
            },
            SIGUSR2 => {
                info!("Captured SIGUSR2");

            },
            _ => unreachable!()
        }
    }
}

#[tokio::main]
async fn main()
-> DnsLrResult<()> {
    let tracing_format = tracing_subscriber::fmt::format().with_target(false).with_thread_ids(true);
    tracing_subscriber::fmt().event_format(tracing_format).init();

    let signals = Signals::new(&[SIGHUP, SIGUSR1, SIGUSR2]).expect("Could not create signal stream");
    let signals_handler = signals.handle();

    let mut redis_manager = redis_mod::build_manager().await?;
    let config = redis_mod::build_config(&mut redis_manager).await?;
    let resolver = resolver::build_resolver(&config);

    info!("{}: Initializing server...", CONFILE.daemon_id);
    let arc_config = Arc::new(ArcSwap::from_pointee(config.clone()));

    let handler = Handler {
        redis_manager: redis_manager.clone(), resolver, config: Arc::clone(&arc_config)
    };
    
    let signals_task = tokio::task::spawn(handle_signals(signals, Arc::clone(&arc_config), redis_manager));

    let mut server = ServerFuture::new(handler);

    setup_binds(&mut server, &config).await?;

    info!("{}: Server started", CONFILE.daemon_id);
    server.block_until_done().await.expect("An error occured when joining server futures");

    signals_handler.close();
    signals_task.await.expect("An error occured when joining signals futures");

    return Ok(())
}
