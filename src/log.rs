use std::fmt;
use tracing::Event;
use tracing_subscriber::{
    fmt::{format::{Writer, Format}, FmtContext, FormatFields, FormatEvent},
    registry::LookupSpan
};

pub struct TracingEventFormatter {
    daemon_id: &'static str
}
impl<S, N> FormatEvent<S, N> for TracingEventFormatter
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>
    ) -> fmt::Result {
        write!(writer, "{}", self.daemon_id)?;
        Format::default()
            .with_target(false)
            .with_thread_ids(true)
            .without_time()
            .format_event(ctx, writer, event)
    }
}

/// Defines and initiates logging
pub fn init_logging(daemon_id: &'static str) {
    let formatter = TracingEventFormatter { daemon_id };
    tracing_subscriber::fmt().event_format(formatter).init();
}
