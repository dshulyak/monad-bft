use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::Result;
use futures_util::{FutureExt, StreamExt};
use monad_executor::Executor;
use monad_executor_glue::RouterCommand;
use monad_types::{Epoch, Round, RouterTarget};
use rand::{thread_rng, Rng};

use super::{send_metrics, LatencyMetrics, MockMessage, MultiRouterType, RouterEvent};
use crate::config::WorkloadConfig;

pub async fn run_workload(
    router: &mut MultiRouterType,
    workload: &WorkloadConfig,
    metrics: &mut LatencyMetrics,
    maybe_otel_meter: &Option<opentelemetry::metrics::Meter>,
    gauge_cache: &mut HashMap<&'static str, opentelemetry::metrics::Gauge<u64>>,
    maybe_metrics_ticker: &mut Option<tokio::time::Interval>,
    process_start: &Instant,
) -> Result<()> {
    let mut rng = thread_rng();
    let mut current_round = Round(1);
    let epoch = Epoch(0);

    router.exec(vec![RouterCommand::UpdateCurrentRound(
        epoch,
        current_round,
    )]);

    let mut round_ticker = tokio::time::interval(Duration::from_millis(100));

    loop {
        let delay_ms = rng.gen_range(0..workload.validator_broadcast_window_ms);
        let next_broadcast = tokio::time::sleep(Duration::from_millis(delay_ms));

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
            _ = round_ticker.tick() => {
                current_round = Round(current_round.0 + 1);
                router.exec(vec![RouterCommand::UpdateCurrentRound(epoch, current_round)]);
                tracing::trace!(?current_round, "advanced round");
            }
            _ = next_broadcast => {
                let size = rng.gen_range(workload.validator_message_size_min..=workload.validator_message_size_max);
                let message = MockMessage::new_with_timestamp(size);

                router.exec(vec![
                    RouterCommand::Publish {
                        target: RouterTarget::Raptorcast(epoch),
                        message: message.clone(),
                    },
                    RouterCommand::PublishToFullNodes {
                        epoch,
                        round: current_round,
                        message,
                    },
                ]);

                metrics.record_sent();

                tracing::info!(
                    message_size = size,
                    round = ?current_round,
                    "sent broadcast message"
                );
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
