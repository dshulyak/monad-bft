use std::{
    collections::HashMap,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use eyre::Result;
use futures_util::{FutureExt, StreamExt};
use monad_executor::Executor;

use super::{send_metrics, LatencyMetrics, MultiRouterType, RouterEvent};

pub async fn run_workload(
    router: &mut MultiRouterType,
    metrics: &mut LatencyMetrics,
    maybe_otel_meter: &Option<opentelemetry::metrics::Meter>,
    gauge_cache: &mut HashMap<&'static str, opentelemetry::metrics::Gauge<u64>>,
    maybe_metrics_ticker: &mut Option<tokio::time::Interval>,
    process_start: &Instant,
) -> Result<()> {
    use std::time::Duration;

    loop {
        tokio::select! {
            maybe_event = router.next() => {
                if let Some(RouterEvent::Message(event)) = maybe_event {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;
                    let latency_ns = now.saturating_sub(event.message.timestamp);
                    let latency_ms = latency_ns as f64 / 1_000_000.0;

                    metrics.record_received(latency_ns);

                    tracing::debug!(
                        from = ?event.from,
                        latency_ms = latency_ms,
                        message_size = event.message.data.len(),
                        "message received"
                    );
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                tracing::trace!("bootnode heartbeat");
            }
            _ = match maybe_metrics_ticker {
                Some(ticker) => ticker.tick().boxed(),
                None => futures_util::future::pending().boxed(),
            } => {
                if let Some(otel_meter) = maybe_otel_meter.as_ref() {
                    let router_metrics = router.metrics();
                    send_metrics(otel_meter, gauge_cache, metrics, router_metrics, process_start);
                    tracing::debug!("exported metrics");
                }
            }
        }
    }
}
