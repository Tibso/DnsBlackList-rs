use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
use tracing::{info, error};
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::SIGHUP;
use futures_util::stream::StreamExt;

pub fn instantiate() -> Option<Signals> {
    Signals::new([SIGHUP]).ok()
}

pub async fn handle(mut signals: Signals, resolver: Arc<TokioAsyncResolver>) {
    // Awaits for a signal to be captured
    while let Some(signal) = signals.next().await {
        //    // SIGUSR2 clears the resolver cache
        if signal == SIGHUP {
            info!("Captured SIGHUP");

            resolver.clear_cache();
            info!("The resolver's cache was cleared");
        } else {
            error!("Unimplemented signal received: {signal:?}")
        }
    }
}

// // SIGUSR1 toggles filtering
// SIGUSR1 => {
//     info!("{daemon_id}: Captured SIGUSR1");
//
//     // Takes a reference to the thread-safe variable
//     let mut tmp_filtering_config = filtering_config.load().as_ref().clone();
//     match tmp_filtering_config.is_filtering {
//         true => {
//             tmp_filtering_config.is_filtering = false;
//             info!("{daemon_id}: Server stopped filtering");
//             filtering_config.store(Arc::new(tmp_filtering_config));
//         },
//         false => {
//             if tmp_filtering_config.filters.is_some() {
//                 tmp_filtering_config.is_filtering = true;
//                 info!("{daemon_id}: Server started filtering");
//                 filtering_config.store(Arc::new(tmp_filtering_config));
//             } else {
//                 let Some(filters) = config::setup_filters(&daemon_id, &mut redis_manager).await else {
//                     error!("{daemon_id}: Could not fetch the filtering data");
//                     error!("{daemon_id}: Server is not filtering");
//                     continue
//                 };
//                 tmp_filtering_config.filters = Some(filters);
//                 tmp_filtering_config.is_filtering = true;
//                 info!("{daemon_id}: Server started filtering");
//                 filtering_config.store(Arc::new(tmp_filtering_config));
//             }
//         }
//     }
// }
