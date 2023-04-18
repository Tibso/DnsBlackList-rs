// This flag ensures any unsafe code will induce a compiler error 
#![forbid(unsafe_code)]

mod handler;
mod redis_mod;
mod resolver;
mod matching;
mod structs;

use crate::{
    handler::Handler,
    structs::{Config, DnsBlrsResult, Confile, DnsBlrsError, DnsBlrsErrorKind}
};

use trust_dns_resolver::{AsyncResolver, name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}};
use trust_dns_server::ServerFuture;

use tokio::{
    net::{TcpListener, UdpSocket}
};
use arc_swap::ArcSwap;
use std::{time::Duration, fs, sync::Arc, process::{ExitCode, exit}};
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
    // Fills the configuration file structure from the JSON at the provided file path
    let confile: Confile = {
        // Reads the file into a big String
        let data = match fs::read_to_string(file_name) {
            Ok(ok) => ok,
            Err(err) => {
                println!("Error reading config file: {}", err);
                // Exits with CONFIG exitcode on error
                exit(78)
            }
        };
        // Deserializes the JSON String
        match serde_json::from_str(&data) {
            Ok(ok) => ok,
            Err(err) => {
                println!("Error deserializing config file data: {}", err);
                // Exits with CONFIG exitcode on error
                exit(78)
            }
        }
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
-> DnsBlrsResult<()> {
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
    } else if successful_binds_count == 0 {
        // If no binds were set, returns an error
        error!("{}: No bind was set", CONFILE.daemon_id);
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::SetupBindingError))
    } else if successful_binds_count < bind_count {
        warn!("{}: {} out of {} total binds were set", CONFILE.daemon_id, successful_binds_count, bind_count)
    }

    Ok(())
}

/// Handles the signals
async fn handle_signals (
    mut signals: Signals,
    arc_config: Arc<ArcSwap<Config>>,
    arc_resolver: Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>,
    mut redis_manager: redis::aio::ConnectionManager,
) {
    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        match signal {
            // Receiving a SIGHUP signal causes a reload of the server's configuration
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
            // Receiving a SIGUSR1 signal switches ON/OFF the server's filtering
            SIGUSR1 => {
                info!("Captured SIGUSR1");

                // Copies the configuration stored in the thread-safe variable
                let mut config = arc_config.load_full().as_ref().clone();
                // Switches the boolean
                config.is_filtering = !config.is_filtering;

                if config.is_filtering {
                    info!("The server is now filtering")
                } else {
                    info!("The server is not filtering anymore")
                }
            
                // Stores the modified configuration back into the thread-safe variable
                arc_config.store(Arc::new(config));
            },
            // Receiving a SIGUSR2 signal clears the resolver's cache
            SIGUSR2 => {
                info!("Captured SIGUSR2");

                arc_resolver.clear_cache();
                info!("The resolver's cache was cleared")
            },
            _ => unreachable!()
        }
    }
}

#[tokio::main]
async fn main() 
-> ExitCode {
    // Defines a custom logging format
    let tracing_format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_thread_ids(true)
        .without_time();
    // Sets the logging subscriber with the custom format
    tracing_subscriber::fmt().event_format(tracing_format).init();

    // Prepares the signals handler
    let Ok(signals) = Signals::new(&[SIGHUP, SIGUSR1, SIGUSR2]) else {
        error!("{}: Could not create signal stream", CONFILE.daemon_id);
        // Returns with OSERR exitcode on error
        return ExitCode::from(71)
    };
    let signals_handler = signals.handle();

    // Builds the Redis connection manager
    let mut redis_manager = match redis_mod::build_manager().await {
        Ok(ok) => ok,
        Err(_) => {
            error!("{}: An error occured while building the Redis connection manager", CONFILE.daemon_id);
            // Returns with UNAVAILABLE exitcode on error
            return ExitCode::from(69)
        }
    };
    // Builds the server's configuration
    let config = match redis_mod::build_config(&mut redis_manager).await {
        Ok(ok) => ok,
        Err(_) => {
            error!("{}: An error occured while building server configuration", CONFILE.daemon_id);
            // Returns with CONFIG exitcode on error
            return ExitCode::from(78)
        }
    };
    
    // Builds the resolver
    let resolver = resolver::build_resolver(&config);
    // The resolver is stored into a thread-safe variable
    let arc_resolver = Arc::new(resolver);

    info!("{}: Initializing server...", CONFILE.daemon_id);

    // Builds a thread-safe variable that stores the server's configuration
    // This variable is optimized for read-mostly scenarios
    let arc_config = Arc::new(ArcSwap::from_pointee(config.clone()));

    // Builds the server's handler structure
    // This variable is stored into another thread-safe variable by the TrustDns library and is given to each thread
    let handler = Handler {
        redis_manager: redis_manager.clone(), arc_config: arc_config.clone(), arc_resolver: arc_resolver.clone()
    };
    
    // Spawns a task thread that handles the signals
    let signals_task = tokio::task::spawn(handle_signals(signals, arc_config.clone(), arc_resolver.clone(), redis_manager));

    // Creates the server's future
    let mut server = ServerFuture::new(handler);

    // Binds the server's ports
    if let Err(err) = setup_binds(&mut server, &config).await {
        error!("An error occured while setting up binds: {:?}", err);
        // Returns with OSERR exitcode on error
        return ExitCode::from(71)
    };

    info!("{}: Server started", CONFILE.daemon_id);
    // Drives the server to completion (indefinite)
    if let Err(_) = server.block_until_done().await {
        error!("An error occured when running server future to completion");
        // Returns with SOFTWARE exitcode on error
        return ExitCode::from(70)
    };

    // Code should not be able to reach here

    signals_handler.close();
    // Signals' task is driven to completion
    if let Err(_) = signals_task.await {
        error!("An error occured when running signals future to completion");
        // Returns with SOFTWARE exitcode on error
        return ExitCode::from(70)
    };

    ExitCode::SUCCESS
}
