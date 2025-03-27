#![forbid(unsafe_code)]

mod handler;
mod redis_mod;
mod resolver;
mod filtering;
mod errors;
mod config;
mod signals;
mod tests;

use std::{process::ExitCode, sync::Arc};
use hickory_server::ServerFuture;
use arc_swap::ArcSwap;
use tracing::{error, info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main()
-> ExitCode {
    // Defines logging format
    let tracing_format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_thread_ids(true)
        .without_time();
    tracing_subscriber::fmt().event_format(tracing_format).init();

    let (daemon_id, redis_addr) = config::read_confile("dnsblrsd.conf");

    info!("{daemon_id}: Server version: {VERSION}");
    info!("{daemon_id}: Initializing server...");

    let Some(signals) = signals::instantiate() else {
        error!("{daemon_id}: Could not create signal stream");
        return ExitCode::from(71) // OSERR
    };
    let signals_handler = signals.handle();

    let mut redis_mngr = match redis_mod::build_manager(&daemon_id, &redis_addr).await {
        Ok(mngr) => mngr,
        Err(err) => {
            error!("{daemon_id}: An error occured when building the Redis connection manager: {err:?}");
            return ExitCode::from(69) // UNAVAILABLE
        }
    };

    let Some(resolver) = config::build_resolver(&daemon_id, &mut redis_mngr).await else {
        error!("{daemon_id}: An error occured when building the resolver");
        return ExitCode::from(78) // CONFIG
    };
    info!("{daemon_id}: Resolver built");
    let resolver = Arc::new(resolver);

    let mut filtering_conf = filtering::FilteringConf {
        is_filtering: false,
        filters: None  
    };
    match config::setup_filters(&daemon_id, &mut redis_mngr).await {
        Some(filters) => {
            filtering_conf.filters = Some(filters);
            filtering_conf.is_filtering = true;
            info!("{daemon_id}: The server will filter requests");
        },
        None => {
            error!("{daemon_id}: An error occured when setting up filtering");
            warn!("{daemon_id}: The server will not filter requests");
        }
    }

    // Builds a thread-safe variable that stores the server's configuration
    // This variable is optimized for read-mostly scenarios
    let filtering_conf = Arc::new(ArcSwap::from_pointee(filtering_conf));

    // This variable is thread-safe and given to each thread
    let handler = handler::Handler {
        daemon_id: daemon_id.clone(),
        redis_mngr: redis_mngr.clone(),
        filtering_conf: filtering_conf.clone(),
        resolver: resolver.clone()
    };
    
    // Spawns signals task
    let signals_task = tokio::task::spawn(signals::handle(daemon_id.clone(), signals, filtering_conf, resolver, redis_mngr.clone()));

    let mut srv = ServerFuture::new(handler);

    let Some(binds) = config::build_binds(&daemon_id, &mut redis_mngr).await else {
        error!("{daemon_id}: An error occured when building server binds");
        return ExitCode::from(78) // CONFIG
    };

    if let Err(err) = config::setup_binds(&mut srv, &daemon_id, binds).await {
        error!("{daemon_id}: An error occured when setting up binds: {err:?}");
        return ExitCode::from(71) // OSERR
    };

    info!("{daemon_id}: Server started");
    if let Err(err) = srv.block_until_done().await {
        error!("{daemon_id}: An error occured while driving server future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    signals_handler.close();
    if let Err(err) = signals_task.await {
        error!("{daemon_id}: An error occured while driving signals future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    ExitCode::SUCCESS
}
