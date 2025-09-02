#![forbid(unsafe_code)]

use dnsblrsd::{config, log, redis_mod, resolver, handler, signals, features::misp, VERSION};

use std::{process::ExitCode, sync::Arc};
use hickory_server::ServerFuture;
use tracing::{error, info};

#[tokio::main]
async fn main() -> ExitCode {
    log::init_logging();
    info!("Server version: {VERSION}");
    info!("Initializing server...");

    let config = match config::init_config() {
        Err(exitcode) => return exitcode,
        Ok(config) => config
    };

    let redis_addr = config.redis_addr;
    info!("Redis server: {redis_addr}");
    info!("Attemping to connect...");
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

    let mut srv = ServerFuture::new(handler::Handler {
        resolver: resolver.clone(),
        redis_mngr: redis_mngr.clone(),
        services: config.services.clone()
    });

    if let Err(e) = config::setup_binds(&mut srv, config.services).await {
        error!("{e}");
        return ExitCode::from(71) // OSERR
    };

    if cfg!(feature = "misp") {
        if let Some(misp_api_conf) = config.misp_api_conf {
            tokio::spawn(misp::update(misp_api_conf, redis_mngr.clone()));
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
