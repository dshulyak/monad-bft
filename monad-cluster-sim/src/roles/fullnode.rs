use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::Result;
use futures_util::{FutureExt, StreamExt};
use monad_executor::Executor;
use monad_executor_glue::RouterCommand;
use monad_types::{NodeId, RouterTarget};
use rand::{seq::SliceRandom, thread_rng, Rng};

use super::{send_metrics, LatencyMetrics, MockMessage, MultiRouterType, PubKeyType, RouterEvent};
use crate::config::WorkloadConfig;

pub async fn run_workload(
    router: &mut MultiRouterType,
    workload: &WorkloadConfig,
    known_peers: &[NodeId<PubKeyType>],
    metrics: &mut LatencyMetrics,
    maybe_otel_meter: &Option<opentelemetry::metrics::Meter>,
    gauge_cache: &mut HashMap<&'static str, opentelemetry::metrics::Gauge<u64>>,
    maybe_metrics_ticker: &mut Option<tokio::time::Interval>,
    process_start: &Instant,
) -> Result<()> {
    let mut rng = thread_rng();

    loop {
        let delay_ms = rng.gen_range(0..workload.fullnode_p2p_window_ms);
        let next_p2p = tokio::time::sleep(Duration::from_millis(delay_ms));

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
            _ = next_p2p => {
                if !known_peers.is_empty() {
                    let num_targets = rng.gen_range(workload.fullnode_p2p_targets_min..=workload.fullnode_p2p_targets_max)
                        .min(known_peers.len());

                    let targets: Vec<_> = known_peers
                        .choose_multiple(&mut rng, num_targets)
                        .copied()
                        .collect();

                    for target in targets {
                        let size = rng.gen_range(workload.fullnode_message_size_min..=workload.fullnode_message_size_max);
                        let message = MockMessage::new_with_timestamp(size);

                        router.exec(vec![RouterCommand::Publish {
                            target: RouterTarget::PointToPoint(target),
                            message,
                        }]);

                        metrics.record_sent();

                        tracing::info!(
                            target = ?target,
                            message_size = size,
                            "sent p2p message"
                        );
                    }
                }
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
