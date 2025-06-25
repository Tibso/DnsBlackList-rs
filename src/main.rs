#![forbid(unsafe_code)]

use dnsblrsd::{config, log, redis_mod, resolver, handler, signals, features::misp, VERSION};

use std::{process::ExitCode, sync::Arc};
use hickory_server::ServerFuture;
use tracing::{error, info};

#[tokio::main]
async fn main()
-> ExitCode {
    log::init_logging();
    info!("Server version: {VERSION}");
    info!("Initializing server...");
   
    let filename = "dnsblrsd.conf";
    let config = match config::read_confile(filename) {
        Err(e) => {
            error!("Error reading or deserializing '{filename}': {e}");
            return ExitCode::from(78) // CONFIG
        },
        Ok(config) => config
    };

    let redis_addr = config.redis_addr.to_string();
    info!("Redis server: {redis_addr}");
    let redis_mngr = match redis_mod::build_manager(&redis_addr).await {
        Err(e) => {
            error!("An error occured when building the Redis connection manager: {e}");
            return ExitCode::from(69) // UNAVAILABLE
        },
        Ok(mngr) => mngr
    };

    let Some(signals) = signals::instantiate() else {
        error!("Could not create signal stream");
        return ExitCode::from(71) // OSERR
    };
    let signals_handler = signals.handle();

    let resolver = resolver::build(config.forwarders);
    info!("Resolver built");
    let resolver = Arc::new(resolver);

    let handler = handler::Handler {
        redis_mngr: redis_mngr.clone(),
        services: config.services.clone(),
        resolver: resolver.clone()
    };

    let mut srv = ServerFuture::new(handler);

    if let Err(e) = config::setup_binds(&mut srv, config.services).await {
        error!("{e}");
        return ExitCode::from(71) // OSERR
    };

    if cfg!(feature = "misp") {
        match config.misp_api_conf {
            None => {
                error!("MISP configuration is missing from the configuration file");
                return ExitCode::from(78) // CONFIG
            },
            Some(misp_api_conf) => { tokio::spawn(misp::update(misp_api_conf, redis_mngr.clone())); }
        }
    }

    let signals_task = tokio::task::spawn(signals::handle(signals, resolver));

    info!("Server started");
    if let Err(e) = srv.block_until_done().await {
        error!("An error occured while driving server future to completion: {e:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    // The code should not reach here because the service gets killed on systemctl stop or restart
    // Need to implement graceful shutdown

    signals_handler.close();
    if let Err(e) = signals_task.await {
        error!("An error occured while driving signals future to completion: {e:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    info!("Graceful shutdown completed");
    ExitCode::SUCCESS
}
