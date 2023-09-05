// This flag ensures any unsafe code will induce a compiler error 
#![forbid(unsafe_code)]

mod handler;
mod redis_mod;
mod resolver;
mod filtering;
mod structs;

use crate::{
    handler::Handler,
    structs::{Config, DnsBlrsResult, Confile, DnsBlrsError, DnsBlrsErrorKind},
    redis_mod::smembers
};

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_server::ServerFuture;

use redis::aio::ConnectionManager;

use tokio::net::{TcpListener, UdpSocket};
use arc_swap::ArcSwap;
use std::{
    time::Duration, fs, sync::Arc, 
    process::{ExitCode, exit},
    net::{IpAddr, SocketAddr}
};
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

    info!("daemon_id is \"{}\"", confile.daemon_id);
    info!("{}: Redis server: {}", confile.daemon_id, confile.redis_address);
    
    confile
}

/// Builds the server's configuration
async fn build_config (
    redis_manager: &mut ConnectionManager
)
-> DnsBlrsResult<Config> {
    // Initialize the configuration variable with the default values using the Default trait
    let mut config = Config::default();

    // The configuration is retrieved from Redis
    // If an error occurs, the server will not filter
    // Attempts to fetch the blackhole_ips from Redis
    match smembers(redis_manager, format!("dnsblrsd:blackhole_ips:{}", CONFILE.daemon_id)).await {
        Err(err) => warn!("{}: Error retrieving retrieve blackhole_ips: {:?}", CONFILE.daemon_id, err),
        Ok(tmp_blackhole_ips) => {
            // If we haven't received exactly 2 blackhole_ips, there is an issue with the configuration 
            if tmp_blackhole_ips.len() != 2 {
                warn!("{}: Amount of blackhole_ips received were not 2 (must have v4 and v6)", CONFILE.daemon_id);
            } else {
                // Vector is made into an iterable to parse both IPs
                let mut tmp_blackhole_ips = tmp_blackhole_ips.iter();

                // Tries to parse first IP
                match tmp_blackhole_ips.next().unwrap().parse::<IpAddr>() {
                    Err(err) => warn!("{}: Error parsing first blackhole IP: {:?}", CONFILE.daemon_id, err),
                    Ok(ip1) => {
                        // Tries to parse for second IP
                        match tmp_blackhole_ips.next().unwrap().parse::<IpAddr>() {
                            Err(err) => warn!("{}: Error parsing second blackhole IP: {:?}", CONFILE.daemon_id, err),
                            Ok(ip2) => {
                                // There must be one IPv4 and one IPv6
                                match (ip1, ip2) {
                                    | (IpAddr::V4(ipv4), IpAddr::V6(ipv6))
                                    | (IpAddr::V6(ipv6), IpAddr::V4(ipv4))
                                    => {
                                        info!("{}: Blackhole_ips received are valid", CONFILE.daemon_id);

                                        // Fetches the matchclasses from Redis
                                        match smembers(redis_manager, format!("dnsblrsd:matchclasses:{}", CONFILE.daemon_id)).await {
                                            Err(err) => warn!("{}: Error retrieving matchclasses: {:?}", CONFILE.daemon_id, err),
                                            Ok(tmp_matchclasses) => {
                                                let matchclasses_count = tmp_matchclasses.len();
                                                // If no matchclass is received, the server will not filter
                                                if matchclasses_count == 0 {
                                                    warn!("{}: No matchclass received", CONFILE.daemon_id);
                                                } else {
                                                    // If at least 1 matchclass is received, the server will filter the requests
                                                    config.blackhole_ips = Some((ipv4, ipv6));
                                                    config.is_filtering = true;
                                                    config.matchclasses = Some(tmp_matchclasses);

                                                    info!("{}: Received {} matchclasses", CONFILE.daemon_id, matchclasses_count)
                                                }
                                            }
                                        }
                                    },
                                    _ => warn!("The \"blackhole_ips\" are not properly configured, there must be one IPv4 and one IPv6"),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // If filtering is not enabled, displays a warning
    if !config.is_filtering {
        warn!("{}: The server will not filter any request and so will not lie", CONFILE.daemon_id)
    }

    // If an error occurs beyond here, we make return the error
    // because the server cannot start without these next values

    // Attempts to fetch the forwarders' sockets from Redis
    match smembers(redis_manager, format!("dnsblrsd:forwarders:{}", CONFILE.daemon_id)).await {
        Err(err) => {
            error!("{}: Error retrieving forwarders: {:?}", CONFILE.daemon_id, err);
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfigError))
        },
        Ok(tmp_forwarders) => {
            let forwarders_count = tmp_forwarders.len();
            // If no forwarder is received, the server cannot start
            if forwarders_count == 0 {
                error!("{}: No forwarder was received", CONFILE.daemon_id);
                return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfigError))
            }
            info!("{}: Received {} forwarders", CONFILE.daemon_id, forwarders_count);
        
            // The forwarders' sockets are parsed to validate them
            let mut valid_forwarder_count = 0usize;
            for forwarder in tmp_forwarders {
                config.forwarders.push(
                    match forwarder.parse::<SocketAddr>() {
                        Ok(ok) => ok,
                        Err(err) => {
                            warn!("{}: forwarder: {} is not valid: {:?}", CONFILE.daemon_id, forwarder, err);
                            continue
                        }
                    }
                );
                valid_forwarder_count += 1
            }
            // If at least 1 forwarder socket is valid, the server can start
            if valid_forwarder_count == forwarders_count {
                info!("{}: all {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count)
            } else if valid_forwarder_count == 0 {
                error!("{}: No forwarder is valid", CONFILE.daemon_id);
                return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfigError))
            } else if valid_forwarder_count < forwarders_count {
                warn!("{}: {} out of {} forwarders are valid", CONFILE.daemon_id, valid_forwarder_count, forwarders_count)
            }
        }
    }

    // Attempts to fetch the binds from Redis
    match smembers(redis_manager, format!("dnsblrsd:binds:{}", CONFILE.daemon_id)).await {
        Err(err) => {
            error!("{}: Error retrieving binds: {:?}", CONFILE.daemon_id, err);
            return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfigError))
        },
        Ok(binds) => {
            let bind_count = binds.len();
            // If no bind is received, the server cannot start
            if bind_count == 0 {
                error!("{}: No bind received", CONFILE.daemon_id);
                return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfigError))
            }
            config.binds = binds;

            info!("{}: Received {} binds", CONFILE.daemon_id, bind_count);
        }
    }

    Ok(config)
}

/// Binds the server's ports cloned from the server's configuration
async fn setup_binds (
    server: &mut ServerFuture<Handler>,
    config: &Config
)
-> DnsBlrsResult<()> {
    let bind_count = config.binds.len();
    let mut successful_binds_count = 0usize;

    // Clones the binds vector from the configuration variable
    // The binds vector is then made into an iterable to iterate onto
    for bind in &config.binds {
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
    arc_resolver: Arc<TokioAsyncResolver>,
    mut redis_manager: redis::aio::ConnectionManager,
) {
    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        match signal {
            // Receiving a SIGHUP signal causes a reload of the server's configuration
            SIGHUP => {
                info!("Captured SIGHUP");

                // Rebuilds the server's configuration
                let Ok(new_config) = build_config(&mut redis_manager).await else {
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
    let Ok(signals) = Signals::new([SIGHUP, SIGUSR1, SIGUSR2]) else {
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
    let config = match build_config(&mut redis_manager).await {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}: An error occured while building server configuration: {:?}", CONFILE.daemon_id, err);
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
    // This variable is stored into another thread-safe container and is given to each thread
    let handler = Handler {
        redis_manager: redis_manager.clone(), arc_config: Arc::clone(&arc_config), arc_resolver: Arc::clone(&arc_resolver)
    };
    
    // Spawns a task thread that handles the signals
    let signals_task = tokio::task::spawn(handle_signals(signals, Arc::clone(&arc_config), Arc::clone(&arc_resolver), redis_manager));

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
    if let Err(err) = server.block_until_done().await {
        error!("An error occured when running server future to completion: {:?}", err);
        // Returns with SOFTWARE exitcode on error
        return ExitCode::from(70)
    };

    // Code should not be able to reach here

    signals_handler.close();
    // Signals' task is driven to completion
    if let Err(err) = signals_task.await {
        error!("An error occured when running signals future to completion: {:?}", err);
        // Returns with SOFTWARE exitcode on error
        return ExitCode::from(70)
    };

    ExitCode::SUCCESS
}
