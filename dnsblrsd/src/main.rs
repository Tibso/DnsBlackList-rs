// This flag ensures any unsafe code will induce a compiler error 
#![forbid(unsafe_code)]

use tokio::net::{TcpListener, UdpSocket};
use arc_swap::ArcSwap;
use tracing::{info, error, warn};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::{SIGHUP, SIGUSR1, SIGUSR2};
use futures_util::stream::StreamExt;
use lazy_static::lazy_static;

use hickory_resolver::TokioAsyncResolver;
use hickory_server::ServerFuture;

use redis::aio::ConnectionManager;

use std::{
    time::Duration, fs, sync::Arc,
    process::{ExitCode, exit},
    net::{IpAddr, SocketAddr}
};

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
    let confile: Confile = {
        let data = match fs::read_to_string(file_name) {
            Ok(ok) => ok,
            Err(err) => {
                error!("Error reading \"dnsblrsd\": {err}");
                // CONFIG exitcode
                exit(78)
            }
        };

        match serde_json::from_str(&data) {
            Ok(ok) => ok,
            Err(err) => {
                error!("Error deserializing \"dnsblrsd.conf\" data: {err}");
                // CONFIG exitcode
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
    let mut config = Config::default();

    // The configuration is retrieved from Redis
    // If an error occurs, the server will not filter
    
    match smembers(redis_manager, format!("DBL;blackholes;{}", CONFILE.daemon_id).as_str()).await {
        Err(err) => warn!("{}: Error retrieving retrieve blackholes: {err:?}", CONFILE.daemon_id),
        Ok(tmp_blackholes) => {
            // If we haven't received exactly 2 blackholes, there is an issue with the configuration
            if tmp_blackholes.len() != 2 {
                warn!("{}: Amount of blackholes received were not 2 (must have v4 and v6)", CONFILE.daemon_id);
            } else {
                let mut tmp_blackholes = tmp_blackholes.iter();

                match tmp_blackholes.next().unwrap().parse::<IpAddr>() {
                    Err(err) => warn!("{}: Error parsing first blackhole IP: {err:?}", CONFILE.daemon_id),
                    Ok(ip1) => {
                        match tmp_blackholes.next().unwrap().parse::<IpAddr>() {
                            Err(err) => warn!("{}: Error parsing second blackhole IP: {err:?}", CONFILE.daemon_id),
                            Ok(ip2) => {
                                // There must be one IPv4 and one IPv6
                                match (ip1, ip2) {
                                    | (IpAddr::V4(ipv4), IpAddr::V6(ipv6))
                                    | (IpAddr::V6(ipv6), IpAddr::V4(ipv4))
                                    => {
                                        info!("{}: Blackholes received are valid", CONFILE.daemon_id);

                                        match smembers(redis_manager, format!("DBL;filters;{}", CONFILE.daemon_id).as_str()).await {
                                            Err(err) => warn!("{}: Error retrieving filters: {err:?}", CONFILE.daemon_id),
                                            Ok(tmp_filters) => {
                                                let filters_count = tmp_filters.len();
                                                if filters_count == 0 {
                                                    warn!("{}: No filter received", CONFILE.daemon_id);
                                                } else {
                                                    // If at least 1 matchclass is received, the server will filter the requests
                                                    config.blackholes = Some((ipv4, ipv6));
                                                    config.is_filtering = true;
                                                    config.filters = Some(tmp_filters);

                                                    info!("{}: Received {filters_count} filters", CONFILE.daemon_id);
                                                }
                                            }
                                        }
                                    },
                                    _ => warn!("The blackholes are not properly configured, there must be one IPv4 and one IPv6"),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !config.is_filtering {
        warn!("{}: The server will not filter any request because of misconfiguration", CONFILE.daemon_id);
    }

    // If an error occurs beyond here, we return the error
    // because the server cannot start without these next values

    let tmp_forwarders = smembers(redis_manager, format!("DBL;forwarders;{}", CONFILE.daemon_id).as_str()).await
        .map_err(|err| {
            error!("{}: Error retrieving forwarders: {err:?}", CONFILE.daemon_id);
            DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig)
        })?;
    let forwarders_count = u16::try_from(tmp_forwarders.len())
        .map_err(|err| {
            error!("{}: Unexpected integer value: {err}", CONFILE.daemon_id);
            DnsBlrsError::from(DnsBlrsErrorKind::LogicError)
        })?;
    // If no forwarder is received, the server cannot start
    if forwarders_count == 0 {
        error!("{}: No forwarder was received!", CONFILE.daemon_id);
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    }
    info!("{}: Received {forwarders_count} forwarders", CONFILE.daemon_id);

    // The forwarders' sockets are parsed to validate them
    let mut valid_forwarder_count = 0u16;
    for forwarder in tmp_forwarders {
        config.forwarders.push(
            match forwarder.parse::<SocketAddr>() {
                Ok(ok) => ok,
                Err(err) => {
                    warn!("{}: forwarder: {forwarder} is not valid: {err:?}", CONFILE.daemon_id);
                    continue
                }
            }
        );
        valid_forwarder_count += 1;
    }
    // At least 1 forwarder socket must be valid
    if valid_forwarder_count == forwarders_count {
        info!("{}: All {valid_forwarder_count} forwarders are valid", CONFILE.daemon_id);
    } else if valid_forwarder_count == 0 {
        error!("{}: No forwarder is valid!", CONFILE.daemon_id);
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    } else {
        warn!("{}: {valid_forwarder_count} out of {forwarders_count} forwarders are valid", CONFILE.daemon_id);
    }

    let binds = smembers(redis_manager, format!("DBL;binds;{}", CONFILE.daemon_id).as_str()).await
        .map_err(|err| {
            error!("{}: Error retrieving binds: {err:?}", CONFILE.daemon_id);
            DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig)
        })?;

    let bind_count = binds.len();
    if bind_count == 0 {
        error!("{}: No bind received!", CONFILE.daemon_id);
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::BuildConfig))
    }
    config.binds = binds;

    info!("{}: Received {bind_count} binds", CONFILE.daemon_id);

    Ok(config)
}

/// Binds the server's ports cloned from the server's configuration
async fn setup_binds (
    server: &mut ServerFuture<Handler>,
    config: &Config
)
-> DnsBlrsResult<()> {
    let bind_count = u32::try_from(config.binds.len())
        .map_err(|_| DnsBlrsError::from(DnsBlrsErrorKind::LogicError))?;
    let mut successful_binds_count = 0u32;

    for bind in &config.binds {
        let mut splits = bind.split('=');

        match splits.next() {
            Some("UDP") => {
                let Some(bind) = splits.next() else {
                    warn!("{}: Failed to read bind: \"{bind}\"", CONFILE.daemon_id);
                    continue
                };
                let Ok(socket) = UdpSocket::bind(bind).await else {
                    warn!("{}: Failed to bind: \"{bind}\"", CONFILE.daemon_id);
                    continue
                };
                server.register_socket(socket);
            },
            Some("TCP") => {
                let Some(bind) = splits.next() else {
                    warn!("{}: Failed to read bind: \"{bind}\"", CONFILE.daemon_id);
                    continue
                };
                let Ok(listener) = TcpListener::bind(bind).await else {
                    warn!("{}: Failed to bind: \"{bind}\"", CONFILE.daemon_id);
                    continue
                };
                server.register_listener(listener, TCP_TIMEOUT);
            },
            _ => {
                warn!("{}: Failed to bind: \"{bind}\"", CONFILE.daemon_id);
                continue
            }
        };
        successful_binds_count += 1;
    }
    // At least 1 bind must be set
    if successful_binds_count == bind_count {
        info!("{}: All {successful_binds_count} binds were set", CONFILE.daemon_id);
    } else if successful_binds_count == 0 {
        error!("{}: No bind was set", CONFILE.daemon_id);
        return Err(DnsBlrsError::from(DnsBlrsErrorKind::SetupBinding))
    } else {
        warn!("{}: {successful_binds_count} out of {bind_count} total binds were set", CONFILE.daemon_id);
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

                let Ok(new_config) = build_config(&mut redis_manager).await else {
                    error!("{}: Could not rebuild the config!", CONFILE.daemon_id);
                    continue
                };

                // Stores the new configuration in the thread-safe variable
                let new_config =  Arc::new(new_config);
                arc_config.store(new_config);

                info!("Config was rebuilt, binds were not reloaded");
            },
            // Receiving a SIGUSR1 signal switches ON/OFF the server's filtering
            SIGUSR1 => {
                info!("Captured SIGUSR1");

                // Copies the configuration stored in the thread-safe variable
                let mut config = arc_config.load_full().as_ref().clone();

                config.is_filtering = !config.is_filtering;

                if config.is_filtering {
                    info!("The server is now filtering");
                } else {
                    info!("The server is not filtering anymore");
                }
            
                // Stores the modified configuration back into the thread-safe variable
                arc_config.store(Arc::new(config));
            },
            // Receiving a SIGUSR2 signal clears the resolver's cache
            SIGUSR2 => {
                info!("Captured SIGUSR2");

                arc_resolver.clear_cache();
                info!("The resolver's cache was cleared");
            },
            _ => error!("{}: Unexpected signal handled!", CONFILE.daemon_id)
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
    tracing_subscriber::fmt().event_format(tracing_format).init();

    let Ok(signals) = Signals::new([SIGHUP, SIGUSR1, SIGUSR2]) else {
        error!("{}: Could not create signal stream!", CONFILE.daemon_id);
        // OSERR exitcode
        return ExitCode::from(71)
    };
    let signals_handler = signals.handle();

    let Ok(mut redis_manager) = redis_mod::build_manager().await else {
            error!("{}: An error occured while building the Redis connection manager!", CONFILE.daemon_id);
            // UNAVAILABLE exitcode
            return ExitCode::from(69)
        };

    let config = match build_config(&mut redis_manager).await {
        Ok(ok) => ok,
        Err(err) => {
            error!("{}: An error occured while building server configuration: {err:?}", CONFILE.daemon_id);
            // CONFIG exitcode
            return ExitCode::from(78)
        }
    };
    
    let resolver = resolver::build(&config);
    let arc_resolver = Arc::new(resolver);

    info!("{}: Initializing server...", CONFILE.daemon_id);

    // Builds a thread-safe variable that stores the server's configuration
    // This variable is optimized for read-mostly scenarios
    let arc_config = Arc::new(ArcSwap::from_pointee(config.clone()));

    // This variable is stored into another thread-safe container and is given to each thread
    let handler = Handler {
        redis_manager: redis_manager.clone(),
        arc_config: Arc::clone(&arc_config),
        arc_resolver: Arc::clone(&arc_resolver)
    };
    
    let signals_task = tokio::task::spawn(handle_signals(signals, Arc::clone(&arc_config), Arc::clone(&arc_resolver), redis_manager));

    let mut server = ServerFuture::new(handler);

    if let Err(err) = setup_binds(&mut server, &config).await {
        error!("An error occured while setting up binds: {err:?}");
        // OSERR exitcode
        return ExitCode::from(71)
    };

    info!("{}: Server started", CONFILE.daemon_id);
    if let Err(err) = server.block_until_done().await {
        error!("An error occured when running server future to completion: {err:?}");
        // SOFTWARE exitcode
        return ExitCode::from(70)
    };

    // Code should (as of now) not be able to reach here
    // Need to add a graceful shutdown

    signals_handler.close();
    if let Err(err) = signals_task.await {
        error!("An error occured when running signals future to completion: {err:?}");
        // SOFTWARE exitcode
        return ExitCode::from(70)
    };

    ExitCode::SUCCESS
}
