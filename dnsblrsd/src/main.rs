// This flag ensures any unsafe code will induce a compiler error 
#![forbid(unsafe_code)]

mod handler;
mod redis_mod;
mod resolver;
mod matching;
mod structs;

use crate::{
    handler::Handler,
    structs::{Config, DnsLrResult, Confile, DnsLrError, DnsLrErrorKind}
};

use trust_dns_server::ServerFuture;

use tokio::{
    net::{TcpListener, UdpSocket}
};
use arc_swap::ArcSwap;
use std::{time::Duration, fs, sync::Arc};
use tracing::{info, error, warn};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::{SIGHUP, SIGUSR1, SIGUSR2};
use futures_util::stream::StreamExt;
use lazy_static::lazy_static;

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

// Creates the configuration file constant which is evaluated at runtime
lazy_static! {
    static ref CONFILE: Confile = read_confile("dnsblrsd.conf");
}

/// Reads the configuration file
fn read_confile (
    file_name: &str
)
-> Confile {
    // Fills the configuration file structure from the provided file path
    let confile: Confile = {
        let data = fs::read_to_string(file_name).expect("Error reading config file");
        serde_json::from_str(&data).expect("Error deserializing config file data")
    };

    info!("Daemon_id is \"{}\"", confile.daemon_id);
    info!("{}: Redis server: {}", confile.daemon_id, confile.redis_address);
    
    confile
}

/// Binds the server's ports cloned from the server's configuration
async fn setup_binds (
    server: &mut ServerFuture<Handler>,
    config: &Config
)
-> DnsLrResult<()> {
    let bind_count = config.binds.len() as usize ;
    let mut successful_binds_count = 0usize;

    // Clones the binds vector from the configuration variable
    // The binds vector is then made into an iterable to iterate onto
    for bind in config.binds.clone().into_iter() {
        let mut splits = bind.split('=');

        match splits.next() {
            Some("UDP") => {
                // Attempts to bind an UDP port

                let bind = match splits.next() {
                    Some(bind) => bind,
                    None => {
                        warn!("{}: Failed to read bind: \"{}\"", CONFILE.daemon_id, bind);
                        continue
                    }
                };
                let Ok(socket) = UdpSocket::bind(bind).await else {
                    warn!("{}: Failed to bind: \"{}\"", CONFILE.daemon_id, bind);
                    continue
                };
                server.register_socket(socket)
            },
            Some("TCP") => {
                // Attempts to bind a TCP port

                let bind = match splits.next() {
                    Some(bind) => bind,
                    None => {
                        warn!("{}: Failed to read bind: \"{}\"", CONFILE.daemon_id, bind);
                        continue
                    }
                };
                let Ok(listener) = TcpListener::bind(bind).await else {
                    warn!("{}: Failed to bind: \"{}\"", CONFILE.daemon_id, bind);
                    continue
                };
                server.register_listener(listener, TCP_TIMEOUT)
            },
            _ => {
                warn!("{}: Failed to bind: \"{}\"", CONFILE.daemon_id, bind);
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
        // If no binds were set, returns an error

        error!("{}: No bind was set", CONFILE.daemon_id);
        return Err(DnsLrError::from(DnsLrErrorKind::SetupBindingError))
    }

    Ok(())
}

/// Handles the signals
async fn handle_signals (
    mut signals: Signals,
    arc_config: Arc<ArcSwap<Config>>,
    mut redis_manager: redis::aio::ConnectionManager
) {
    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        match signal {
            SIGHUP => {
                info!("Captured SIGHUP");

                // Rebuilds the server's configuration
                let Ok(new_config) = redis_mod::build_config(&mut redis_manager).await else {
                    error!("Could not rebuild the config");
                    continue
                };

                // Stores the new configuration in the thread-safe variable
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
    // Defines a custom logging format
    let tracing_format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_thread_ids(true)
        .without_time();
    // Sets the logging subscriber with the custom format
    tracing_subscriber::fmt().event_format(tracing_format).init();

    // Prepares the signals handler
    let signals = Signals::new(&[SIGHUP, SIGUSR1, SIGUSR2]).expect("Could not create signal stream");
    let signals_handler = signals.handle();

    // Builds the Redis connection manager
    let mut redis_manager = redis_mod::build_manager().await?;
    // Builds the server's configuration
    let config = redis_mod::build_config(&mut redis_manager).await?;
    // Builds the resolver
    let resolver = resolver::build_resolver(&config);

    info!("{}: Initializing server...", CONFILE.daemon_id);

    // Builds a thread-safe variable that stores the server's configuration
    // The variable is optimized for read-mostly scenarios
    let arc_config = Arc::new(ArcSwap::from_pointee(config.clone()));

    // Builds the server's handler structure
    // This variable is placed into another thread-safe variable by the TrustDns library and is given to each thread
    let handler = Handler {
        redis_manager: redis_manager.clone(), resolver, config: Arc::clone(&arc_config)
    };
    
    // Spawns a task thread that handles the signals
    let signals_task = tokio::task::spawn(handle_signals(signals, Arc::clone(&arc_config), redis_manager));

    // Creates the server's future
    let mut server = ServerFuture::new(handler);

    // Binds the server's ports
    setup_binds(&mut server, &config).await?;

    info!("{}: Server started", CONFILE.daemon_id);
    // Drives the server to completion (indefinite)
    server.block_until_done().await.expect("An error occured when running server future to completion");

    // Code should not be able to reach here

    signals_handler.close();
    // Signals' task is driven to completion
    signals_task.await.expect("An error occured when running signals future to completion");

    Ok(())
}
