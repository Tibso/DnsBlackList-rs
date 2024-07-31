use crate::{DAEMON_ID, Config, config};

use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
use arc_swap::ArcSwap;
use tracing::{info, error};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::{SIGHUP, SIGUSR1, SIGUSR2};
use futures_util::stream::StreamExt;

pub fn instantiate() -> Option<Signals> {
    Signals::new([SIGHUP, SIGUSR1, SIGUSR2]).ok()
}

pub async fn handle(
    mut signals: Signals,
    arc_config: Arc<ArcSwap<Config>>,
    arc_resolver: Arc<TokioAsyncResolver>,
    mut redis_manager: redis::aio::ConnectionManager,
) {
    let daemon_id = DAEMON_ID.get().expect("Could not fetch daemon_id");

    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        match signal {
            // Receiving a SIGHUP signal reloads server config
            SIGHUP => {
                info!("Captured SIGHUP");

                let Ok((new_config, _, _)) = config::build(daemon_id, &mut redis_manager).await else {
                    error!("{daemon_id}: Could not rebuild the config");
                    continue
                };

                // Stores the new configuration in the thread-safe variable
                let new_config =  Arc::new(new_config);
                arc_config.store(new_config);

                info!("Config was rebuilt, binds were not reloaded");
            },
            // Receiving a SIGUSR1 signal switches ON/OFF filtering
            SIGUSR1 => {
                info!("Captured SIGUSR1");

                // Copies the configuration stored in the thread-safe variable
                let mut config = arc_config.load_full().as_ref().clone();

                config.is_filtering = !config.is_filtering;

                if config.is_filtering {
                    info!("The server is filtering again");
                } else {
                    info!("The server stopped filtering");
                }
            
                // Stores the modified configuration back into the thread-safe variable
                arc_config.store(Arc::new(config));
            },
            // Receiving a SIGUSR2 signal clears the resolver cache
            SIGUSR2 => {
                info!("Captured SIGUSR2");

                arc_resolver.clear_cache();
                info!("The resolver's cache was cleared");
            },
            _ => error!("{daemon_id}: Unexpected signal handled")
        }
    }
}
