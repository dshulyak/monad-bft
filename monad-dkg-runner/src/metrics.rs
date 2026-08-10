use std::sync::Arc;

use monad_executor::{ExecutorMetrics, Gauge};

macro_rules! define_metrics {
    ($($field:ident => $constant:ident($name:literal, $help:literal)),+ $(,)?) => {
        monad_executor::metric_consts! {
            $($constant { name: $name, help: $help })+
        }

        #[derive(Clone)]
        pub(crate) struct DkgRunnerMetrics {
            executor_metrics: Arc<ExecutorMetrics>,
            $(pub(crate) $field: Gauge,)+
        }

        impl DkgRunnerMetrics {
            pub(crate) fn new() -> Self {
                let mut executor_metrics = ExecutorMetrics::with_metric_defs(&[$($constant),+]);
                Self {
                    $($field: executor_metrics.gauge($constant).clone(),)+
                    executor_metrics: Arc::new(executor_metrics),
                }
            }

            pub(crate) fn executor_metrics(&self) -> &ExecutorMetrics {
                self.executor_metrics.as_ref()
            }
        }
    };
}

define_metrics! {
    retained_sessions => RETAINED_SESSIONS("monad.dkg.retained_sessions", "DKG protocol sessions currently retained by the runner"),
    sessions_started => SESSIONS_STARTED("monad.dkg.sessions_started_total", "DKG protocol sessions started since process start"),
    results_finalized => RESULTS_FINALIZED("monad.dkg.results_finalized_total", "DKG result epochs first observed finalized since process start"),
    pending_network_retries => PENDING_NETWORK_RETRIES("monad.dkg.pending_network_retries", "DKG peer deliveries currently scheduled for retry"),
    network_retries => NETWORK_RETRIES("monad.dkg.network_retries_total", "DKG peer delivery retries sent since process start"),
    pending_transactions => PENDING_TRANSACTIONS("monad.dkg.pending_transactions", "DKG contract transactions awaiting finalization"),
    transaction_retries => TRANSACTION_RETRIES("monad.dkg.transaction_retries_total", "DKG contract transaction retry attempts since process start"),
    errors => ERRORS("monad.dkg.errors_total", "DKG runner errors since process start"),
    chain_errors => CHAIN_ERRORS("monad.dkg.chain_errors_total", "DKG finalized-chain read or reconciliation errors since process start"),
    protocol_errors => PROTOCOL_ERRORS("monad.dkg.protocol_errors_total", "DKG protocol input or state-transition errors since process start"),
    transaction_errors => TRANSACTION_ERRORS("monad.dkg.transaction_errors_total", "DKG contract transaction preparation or submission errors since process start"),
    delivery_errors => DELIVERY_ERRORS("monad.dkg.delivery_errors_total", "DKG malformed-message or delivery-channel errors since process start"),
}

impl DkgRunnerMetrics {
    pub(crate) fn transaction(&self) -> DkgTransactionMetrics {
        DkgTransactionMetrics {
            pending: self.pending_transactions.clone(),
            retries: self.transaction_retries.clone(),
            errors: self.transaction_errors.clone(),
            errors_total: self.errors.clone(),
        }
    }

    pub(crate) fn set_session_state(&self, retained: usize, pending_retries: usize) {
        self.retained_sessions.set(retained as u64);
        self.pending_network_retries.set(pending_retries as u64);
    }

    pub(crate) fn session_started(&self) {
        self.sessions_started.inc();
    }

    pub(crate) fn result_finalized(&self) {
        self.results_finalized.inc();
    }

    pub(crate) fn network_retries(&self, count: usize) {
        self.network_retries.add(count as u64);
    }

    pub(crate) fn chain_error(&self) {
        self.errors.inc();
        self.chain_errors.inc();
    }

    pub(crate) fn protocol_error(&self) {
        self.errors.inc();
        self.protocol_errors.inc();
    }

    pub(crate) fn delivery_error(&self) {
        self.errors.inc();
        self.delivery_errors.inc();
    }
}

#[derive(Clone)]
pub(crate) struct DkgTransactionMetrics {
    pending: Gauge,
    retries: Gauge,
    errors: Gauge,
    errors_total: Gauge,
}

impl DkgTransactionMetrics {
    pub(crate) fn set_pending(&self, count: usize) {
        self.pending.set(count as u64);
    }

    pub(crate) fn retry(&self) {
        self.retries.inc();
    }

    pub(crate) fn error(&self) {
        self.errors.inc();
        self.errors_total.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_errors_contribute_to_total() {
        let metrics = DkgRunnerMetrics::new();
        metrics.chain_error();
        metrics.protocol_error();
        metrics.delivery_error();
        metrics.transaction().error();

        let value = |name| {
            metrics
                .executor_metrics()
                .iter_with_descriptions()
                .find_map(|(metric, value, _)| (metric == name).then_some(value))
                .unwrap()
        };
        assert_eq!(value(ERRORS.name), 4);
        assert_eq!(value(CHAIN_ERRORS.name), 1);
        assert_eq!(value(PROTOCOL_ERRORS.name), 1);
        assert_eq!(value(TRANSACTION_ERRORS.name), 1);
        assert_eq!(value(DELIVERY_ERRORS.name), 1);
    }

    #[test]
    fn retry_and_pending_metrics_keep_their_distinct_semantics() {
        let metrics = DkgRunnerMetrics::new();
        metrics.set_session_state(2, 7);
        metrics.network_retries(3);
        let transactions = metrics.transaction();
        transactions.set_pending(4);
        transactions.retry();

        let value = |name| {
            metrics
                .executor_metrics()
                .iter_with_descriptions()
                .find_map(|(metric, value, _)| (metric == name).then_some(value))
                .unwrap()
        };
        assert_eq!(value(RETAINED_SESSIONS.name), 2);
        assert_eq!(value(PENDING_NETWORK_RETRIES.name), 7);
        assert_eq!(value(NETWORK_RETRIES.name), 3);
        assert_eq!(value(PENDING_TRANSACTIONS.name), 4);
        assert_eq!(value(TRANSACTION_RETRIES.name), 1);
    }
}
