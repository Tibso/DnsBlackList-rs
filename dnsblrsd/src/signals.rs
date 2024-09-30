use crate::{config, filtering::FilteringConfig};

use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
use arc_swap::ArcSwapAny;
use tracing::{info, error};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::{SIGHUP, SIGUSR1, SIGUSR2};
use futures_util::stream::StreamExt;

pub fn instantiate() -> Option<Signals> {
    Signals::new([SIGHUP, SIGUSR1, SIGUSR2]).ok()
}

pub async fn handle(
    daemon_id: String,
    mut signals: Signals,
    filtering_config: Arc<ArcSwapAny<Arc<FilteringConfig>>>,
    resolver: Arc<TokioAsyncResolver>,
    mut redis_manager: redis::aio::ConnectionManager
) {
    let daemon_id = daemon_id.as_str();
    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        match signal {
            // SIGHUP refreshes the filtering_data
            SIGHUP => {
                info!("{daemon_id}: Captured SIGHUP");

                let Some(filtering_data) = config::setup_filtering(daemon_id, &mut redis_manager).await else {
                    error!("{daemon_id}: Could not fetch the filtering data");
                    continue
                };

                // Stores the new configuration back in the thread-safe variable
                filtering_config.store(Arc::new(FilteringConfig {
                    is_filtering: true,
                    data: Some(filtering_data)
                }));

                info!("{daemon_id}: Filtering data was refreshed");
            },
            // SIGUSR1 toggles filtering
            SIGUSR1 => {
                info!("{daemon_id}: Captured SIGUSR1");

                // Takes a reference to the thread-safe variable
                let mut tmp_filtering_config = filtering_config.load().as_ref().clone();
                match tmp_filtering_config.is_filtering {
                    true => {
                        tmp_filtering_config.is_filtering = false;
                        info!("{daemon_id}: Server stopped filtering");
                        filtering_config.store(Arc::new(tmp_filtering_config));
                    },
                    false => {
                        if tmp_filtering_config.data.is_some() {
                            tmp_filtering_config.is_filtering = true;
                            info!("{daemon_id}: Server started filtering");
                            filtering_config.store(Arc::new(tmp_filtering_config));
                        } else {
                            let Some(filtering_data) = config::setup_filtering(daemon_id, &mut redis_manager).await else {
                                error!("{daemon_id}: Could not fetch the filtering data");
                                error!("{daemon_id}: Server is not filtering");
                                continue
                            };
                            tmp_filtering_config.data = Some(filtering_data);
                            tmp_filtering_config.is_filtering = true;
                            info!("{daemon_id}: Server started filtering");
                            filtering_config.store(Arc::new(tmp_filtering_config));
                        }
                    }
                }
            },
            // SIGUSR2 clears the resolver cache
            SIGUSR2 => {
                info!("{daemon_id}: Captured SIGUSR2");

                resolver.clear_cache();
                info!("{daemon_id}: The resolver's cache was cleared");
            },
            _ => error!("{daemon_id}: Unimplemented signal received: {signal:?}")
        }
    }
}
