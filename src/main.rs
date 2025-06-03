#![forbid(unsafe_code)]

mod config;
mod errors;
mod redis_mod;
mod signals;
mod handler;
mod resolver;
mod misp;
mod log;

use std::{process::ExitCode, sync::Arc};
use hickory_server::ServerFuture;
use tracing::{error, info};

#[tokio::main]
async fn main()
-> ExitCode {
    let config = config::read_confile("dnsblrsd.conf");
    let (daemon_id, redis_addr) = (config.daemon_id, config.redis_addr.to_string());
    // "Controlled" memory-leak, doesn't feel clean
    let daemon_id: &'static str = Box::leak(Box::from(daemon_id));

    log::init_logging(daemon_id);

    info!("Server version: {}", config::VERSION);
    info!("Initializing server...");
    info!("Redis server: {redis_addr}");

    let redis_mngr = match redis_mod::build_manager(&redis_addr).await {
        Ok(mngr) => mngr,
        Err(e) => {
            error!("An error occured when building the Redis connection manager: {e}");
            return ExitCode::from(69) // UNAVAILABLE
        }
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
        filters: config.filters.clone(),
        resolver: resolver.clone()
    };

    let mut srv = ServerFuture::new(handler);

    if let Err(err) = config::setup_binds(&mut srv, config.binds).await {
        error!("An error occured when setting up binds: {err}");
        return ExitCode::from(71) // OSERR
    };

    if cfg!(feature = "misp") {
        match config.misp_api_conf {
            Some(misp_api_conf) => { tokio::spawn(misp::update(misp_api_conf, redis_mngr.clone())); },
            None => {
                error!("MISP configuration is missing from the confi:qgurationguration file");
                return ExitCode::from(78) // CONFIG
            }
        }
    }

    let signals_task = tokio::task::spawn(signals::handle(signals, resolver));

    info!("Server started");
    if let Err(err) = srv.block_until_done().await {
        error!("An error occured while driving server future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    signals_handler.close();
    if let Err(err) = signals_task.await {
        error!("An error occured while driving signals future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    info!("Graceful shutdown completed");
    ExitCode::SUCCESS
}
