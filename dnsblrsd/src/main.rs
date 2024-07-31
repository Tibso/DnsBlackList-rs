// This flag ensures any unsafe code will induce a compiler error 
#![forbid(unsafe_code)]

mod handler;
mod redis_mod;
mod resolver;
mod filtering;
mod structs;
mod config;
mod signals;

use crate::{handler::Handler, structs::Config};

use std::{sync::OnceLock, process::ExitCode, sync::Arc};
use hickory_server::ServerFuture;
use arc_swap::ArcSwap;
use tracing::{info, error};

static DAEMON_ID: OnceLock<String> = OnceLock::new();
#[tokio::main]
async fn main()
-> ExitCode {
    // Defines logging format
    let tracing_format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_thread_ids(true)
        .without_time();
    tracing_subscriber::fmt().event_format(tracing_format).init();

    let confile = config::read_confile("dnsblrsd.conf");
    let daemon_id: String = confile.daemon_id;
    // sets global daemon id
    DAEMON_ID.set(daemon_id.clone()).expect("Could not initialize DAEMON_ID");

    let Some(signals) = signals::instantiate() else {
        error!("{daemon_id}: Could not create signal stream");
        return ExitCode::from(71) // OSERR
    };
    let signals_handler = signals.handle();

    let mut redis_manager = match redis_mod::build_manager(&confile.redis_address).await {
        Ok(manager) => manager,
        Err(err) => {
            error!("{daemon_id}: An error occured while building the Redis connection manager: {err:?}");
            return ExitCode::from(69) // UNAVAILABLE
        }
    };

    let (config, forwarders, binds) = match config::build(&daemon_id, &mut redis_manager).await {
        Ok(config) => config,
        Err(err) => {
            error!("{daemon_id}: An error occured while building server configuration: {err:?}");
            return ExitCode::from(78) // CONFIG
        }
    };
    
    let resolver = resolver::build(forwarders);
    let arc_resolver = Arc::new(resolver);

    info!("{daemon_id}: Initializing server...");

    // Builds a thread-safe variable that stores the server's configuration
    // This variable is optimized for read-mostly scenarios
    let arc_config = Arc::new(ArcSwap::from_pointee(config.clone()));

    // This variable is stored into another thread-safe container and is given to each thread
    let handler = Handler {
        redis_manager: redis_manager.clone(),
        arc_config: Arc::clone(&arc_config),
        arc_resolver: Arc::clone(&arc_resolver)
    };
    
    // Spawns signals task
    let signals_task = tokio::task::spawn(signals::handle(signals, Arc::clone(&arc_config), Arc::clone(&arc_resolver), redis_manager));

    let mut server = ServerFuture::new(handler);

    if let Err(err) = config::setup_binds(&mut server, &daemon_id, binds).await {
        error!("{daemon_id}: An error occured while setting up binds: {err:?}");
        return ExitCode::from(71) // OSERR
    };

    info!("{daemon_id}: Server started");
    if let Err(err) = server.block_until_done().await {
        error!("{daemon_id}: An error occured when running server future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    signals_handler.close();
    if let Err(err) = signals_task.await {
        error!("{daemon_id}: An error occured when running signals future to completion: {err:?}");
        return ExitCode::from(70) // SOFTWARE
    };

    ExitCode::SUCCESS
}
