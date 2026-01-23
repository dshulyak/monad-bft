// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{
    collections::VecDeque,
    fmt::{self, Debug, Display},
    hash::Hash,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use alloy_consensus::TxEnvelope;
use bytes::Bytes;
use monad_fair_queue::{FairQueue, FairQueueBuilder, Identity};
use monad_peer_score::{Clock, ScoreReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoUnauthenticated;

impl Display for NoUnauthenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoUnauthenticated")
    }
}
use monad_chain_config::{
    execution_revision::ExecutionChainParams, revision::ChainRevision, ChainConfig,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_eth_txpool::{max_eip2718_encoded_length, EthTxPool};
use monad_eth_types::ExtractEthAddress;
use monad_state_backend::StateBackend;
use monad_validator::signature_collection::SignatureCollection;
use pin_project::pin_project;
use tracing::error;

const EGRESS_MIN_COMMITTED_SEQ_NUM_DIFF: u64 = 5;
const EGRESS_MAX_RETRIES: usize = 3;

const INGRESS_CHUNK_MAX_SIZE: usize = 128;
const INGRESS_CHUNK_INTERVAL_MS: u64 = 8;

pub fn egress_max_size_bytes(execution_params: &ExecutionChainParams) -> usize {
    max_eip2718_encoded_length(execution_params)
}

#[pin_project(project = EthTxPoolForwardingManagerProjected)]
pub struct EthTxPoolForwardingManager<N: Hash + Eq + Send + Sync, C: Clock + Send + Sync> {
    ingress: FairQueue<ScoreReader<N, C>, NoUnauthenticated, (TxEnvelope, N)>,
    #[pin]
    ingress_timer: tokio::time::Interval,
    ingress_waker: Option<Waker>,

    egress: VecDeque<Bytes>,
    egress_waker: Option<Waker>,
}

impl<N, C: Clock> EthTxPoolForwardingManager<N, C>
where
    N: Hash + Eq + Clone + Send + Sync + std::fmt::Debug + std::fmt::Display,
    C: Send + Sync,
{
    pub fn new(score_reader: ScoreReader<N, C>) -> Self {
        let mut ingress_timer =
            tokio::time::interval(Duration::from_millis(INGRESS_CHUNK_INTERVAL_MS));

        ingress_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let ingress = FairQueueBuilder::new()
            .per_id_limit(10_000)
            .max_size(100_000)
            .regular_max_size(100_000)
            .regular_bandwidth_pct(10)
            .build(score_reader);

        Self {
            ingress,
            ingress_timer,
            ingress_waker: None,

            egress: VecDeque::default(),
            egress_waker: None,
        }
    }
}

impl<N: Hash + Eq + Clone + Send + Sync + Debug + Display, C: Clock + Send + Sync>
    EthTxPoolForwardingManager<N, C>
{
    pub fn poll_ingress(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<(TxEnvelope, N)>> {
        let EthTxPoolForwardingManagerProjected {
            ingress,
            mut ingress_timer,
            ingress_waker,
            ..
        } = self.project();

        if ingress.is_empty() {
            match ingress_waker.as_mut() {
                Some(waker) => waker.clone_from(cx.waker()),
                None => *ingress_waker = Some(cx.waker().clone()),
            }
            return Poll::Pending;
        }

        let Poll::Ready(_) = ingress_timer.poll_tick(cx) else {
            return Poll::Pending;
        };

        let mut chunk = Vec::with_capacity(INGRESS_CHUNK_MAX_SIZE);
        while chunk.len() < INGRESS_CHUNK_MAX_SIZE {
            match ingress.pop() {
                Some((_, item)) => chunk.push(item),
                None => break,
            }
        }
        Poll::Ready(chunk)
    }

    pub fn poll_egress(
        self: Pin<&mut Self>,
        execution_params: &ExecutionChainParams,
        cx: &mut Context<'_>,
    ) -> Poll<Vec<Bytes>> {
        let EthTxPoolForwardingManagerProjected {
            egress,
            egress_waker,
            ..
        } = self.project();

        loop {
            if egress.is_empty() {
                match egress_waker.as_mut() {
                    Some(waker) => waker.clone_from(cx.waker()),
                    None => *egress_waker = Some(cx.waker().clone()),
                }

                return Poll::Pending;
            }

            let egress_max_size_bytes = egress_max_size_bytes(execution_params);

            let mut txs = Vec::default();
            let mut total_bytes = 0;

            while let Some(tx) = egress.front() {
                let new_total_bytes = total_bytes + tx.len();

                if new_total_bytes <= egress_max_size_bytes {
                    txs.push(egress.pop_front().unwrap());
                    total_bytes = new_total_bytes;
                    continue;
                }

                if tx.len() > egress_max_size_bytes {
                    error!("txpool forwarding manager detected tx larger than max tx byte size, skipping forwarding");
                    egress.pop_front();
                    continue;
                }

                break;
            }

            if txs.is_empty() {
                let tx = egress.pop_front();
                error!(
                    ?tx,
                    "txpool forwarding manager detected empty forward, dropping next tx"
                );
                continue;
            }

            return Poll::Ready(txs);
        }
    }

    pub fn complete_ingress(self: Pin<&mut Self>) {
        self.get_mut().ingress_timer.reset();
    }
}

impl<'a, N: Clone + Hash + Eq + Send + Sync + Debug + Display, C: Clock + Send + Sync>
    EthTxPoolForwardingManagerProjected<'a, N, C>
{
    pub fn add_ingress_txs(&mut self, sender: N, txs: Vec<TxEnvelope>) {
        let Self {
            ingress,
            ingress_waker,
            ..
        } = self;

        let mut added = 0usize;
        for tx in txs {
            let id = Identity::Authenticated(sender.clone());
            if let Err(e) = ingress.push(id, (tx, sender.clone())) {
                tracing::debug!(%sender, error = %e, "ingress queue full, dropping remaining txs");
                break;
            }
            added += 1;
        }

        if added == 0 {
            return;
        }

        if let Some(waker) = ingress_waker.take() {
            waker.wake();
        }
    }

    pub fn add_egress_txs<'b>(&mut self, txs: impl Iterator<Item = &'b TxEnvelope>) {
        let Self {
            egress,
            egress_waker,
            ..
        } = self;

        egress.extend(txs.map(alloy_rlp::encode).map(Into::into));

        if egress.is_empty() {
            return;
        }

        if let Some(waker) = egress_waker.take() {
            waker.wake();
        }
    }

    pub fn schedule_egress_txs<ST, SCT, SBT, CCT, CRT>(
        &mut self,
        pool: &mut EthTxPool<ST, SCT, SBT, CCT, CRT>,
    ) where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
        SBT: StateBackend<ST, SCT>,
        CertificateSignaturePubKey<ST>: ExtractEthAddress,
        CCT: ChainConfig<CRT>,
        CRT: ChainRevision,
    {
        let Some(forwardable_txs) =
            pool.get_forwardable_txs::<EGRESS_MIN_COMMITTED_SEQ_NUM_DIFF, EGRESS_MAX_RETRIES>()
        else {
            return;
        };

        self.add_egress_txs(forwardable_txs);
    }
}

#[cfg(test)]
mod test {
    use std::{
        pin::{pin, Pin},
        task::{Context, Poll},
        time::Duration,
    };

    use alloy_consensus::{Transaction, TxEnvelope};
    use bytes::Bytes;
    use futures::task::noop_waker_ref;
    use itertools::Itertools;
    use monad_chain_config::execution_revision::MonadExecutionRevision;
    use monad_eth_testutil::{make_eip1559_tx, make_eip7702_tx, make_legacy_tx, S1};
    use monad_peer_score::{create_scorer, ScoreConfig, StdClock};

    use crate::forward::{
        egress_max_size_bytes, EthTxPoolForwardingManager, INGRESS_CHUNK_INTERVAL_MS,
        INGRESS_CHUNK_MAX_SIZE,
    };

    const EXECUTION_REVISION: MonadExecutionRevision = MonadExecutionRevision::LATEST;

    const BASE_FEE_PER_GAS: u128 = 100_000_000_000; // 100 Gwei

    type TestNodeId = u64;

    fn setup<'a>() -> (
        EthTxPoolForwardingManager<TestNodeId, StdClock>,
        monad_peer_score::ScoreProvider<TestNodeId, StdClock>,
        Context<'a>,
    ) {
        let config = ScoreConfig {
            min_time_for_score: Duration::ZERO,
            ..ScoreConfig::default()
        };
        let (score_provider, score_reader) =
            create_scorer::<TestNodeId, StdClock>(config, StdClock);
        (
            EthTxPoolForwardingManager::new(score_reader),
            score_provider,
            Context::from_waker(noop_waker_ref()),
        )
    }

    fn generate_tx(nonce: u64) -> TxEnvelope {
        make_legacy_tx(S1, BASE_FEE_PER_GAS, 100_000, nonce, 0)
    }

    async fn assert_pending_now_and_forever(
        mut forwarding_manager: Pin<&mut EthTxPoolForwardingManager<TestNodeId, StdClock>>,
        mut cx: Context<'_>,
    ) {
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );
        assert_eq!(
            forwarding_manager
                .as_mut()
                .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx),
            Poll::Pending
        );

        tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;

        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );
        assert_eq!(
            forwarding_manager
                .as_mut()
                .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx),
            Poll::Pending
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_none() {
        let (forwarding_manager, _score_provider, cx) = setup();
        let forwarding_manager = pin!(forwarding_manager);

        assert_pending_now_and_forever(forwarding_manager, cx).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_ingress_simple() {
        for poll_ingress_before_insert in [false, true] {
            let (forwarding_manager, _score_provider, mut cx) = setup();
            let mut forwarding_manager = pin!(forwarding_manager);

            if poll_ingress_before_insert {
                assert_eq!(
                    forwarding_manager.as_mut().poll_ingress(&mut cx),
                    Poll::Pending
                );
            }

            let txs = vec![generate_tx(0)];

            forwarding_manager
                .as_mut()
                .project()
                .add_ingress_txs(0, txs.clone());

            let expected: Vec<_> = txs.into_iter().map(|tx| (tx, 0)).collect();
            assert_eq!(
                forwarding_manager.as_mut().poll_ingress(&mut cx),
                Poll::Ready(expected)
            );

            assert_pending_now_and_forever(forwarding_manager, cx).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_ingress_subsequent() {
        let (forwarding_manager, _score_provider, mut cx) = setup();
        let mut forwarding_manager = pin!(forwarding_manager);

        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        let txs = vec![generate_tx(0)];
        let expected: Vec<_> = txs.iter().cloned().map(|tx| (tx, 0)).collect();

        forwarding_manager
            .as_mut()
            .project()
            .add_ingress_txs(0, txs.clone());

        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Ready(expected.clone())
        );
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        forwarding_manager
            .as_mut()
            .project()
            .add_ingress_txs(0, txs.clone());

        // Since time is frozen and we just polled, the forwarding manager should wait its interval
        // even though it should be "empty"
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        tokio::time::advance(
            Duration::from_millis(INGRESS_CHUNK_INTERVAL_MS)
                .checked_sub(Duration::from_nanos(1))
                .unwrap(),
        )
        .await;
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Ready(expected)
        );

        assert_pending_now_and_forever(forwarding_manager, cx).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_ingress_chunks() {
        let (forwarding_manager, score_provider, mut cx) = setup();
        let mut forwarding_manager = pin!(forwarding_manager);

        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        const NUM_CHUNKS: usize = 16;

        // We insert the last tx below to test adding to an existing chunk
        const NUM_TXS: usize = INGRESS_CHUNK_MAX_SIZE * NUM_CHUNKS - 1;

        // Register sender 0 as having contributed, so they get primary tier (10K limit)
        score_provider.record_contribution(0);

        forwarding_manager
            .as_mut()
            .project()
            .add_ingress_txs(0, (0..NUM_TXS as u64).map(generate_tx).collect_vec());

        for chunk_num in 0..NUM_CHUNKS {
            tokio::time::advance(Duration::from_millis(INGRESS_CHUNK_INTERVAL_MS)).await;

            if chunk_num + 1 == NUM_CHUNKS {
                forwarding_manager
                    .as_mut()
                    .project()
                    .add_ingress_txs(0, vec![generate_tx(0)]);
            }

            let Poll::Ready(txs_with_senders) = forwarding_manager.as_mut().poll_ingress(&mut cx)
            else {
                panic!("forwarding manager should be ready after each iteration");
            };

            assert_eq!(txs_with_senders.len(), INGRESS_CHUNK_MAX_SIZE);

            // Check that txs are produced in the same order they are inserted
            txs_with_senders
                .into_iter()
                .enumerate()
                .for_each(|(idx, (tx, _sender))| {
                    // By using % NUM_TXS, we can check that the last tx is the 0 nonce added above when
                    // we're at the last chunk
                    assert_eq!(
                        tx.nonce(),
                        ((idx + chunk_num * INGRESS_CHUNK_MAX_SIZE) as u64) % (NUM_TXS as u64)
                    );
                });

            assert_eq!(
                forwarding_manager.as_mut().poll_ingress(&mut cx),
                Poll::Pending
            );
        }

        assert_pending_now_and_forever(forwarding_manager, cx).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_ingress_complete() {
        let (forwarding_manager, _score_provider, mut cx) = setup();
        let mut forwarding_manager = pin!(forwarding_manager);

        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        forwarding_manager.as_mut().project().add_ingress_txs(
            0,
            (0..2 * INGRESS_CHUNK_MAX_SIZE as u64)
                .map(generate_tx)
                .collect_vec(),
        );

        let Poll::Ready(txs_with_senders) = forwarding_manager.as_mut().poll_ingress(&mut cx)
        else {
            panic!("forwarding manager should be ready");
        };
        assert_eq!(txs_with_senders.len(), INGRESS_CHUNK_MAX_SIZE);

        tokio::time::advance(Duration::from_millis(1)).await;

        forwarding_manager.as_mut().complete_ingress();

        tokio::time::advance(
            Duration::from_millis(INGRESS_CHUNK_INTERVAL_MS)
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        )
        .await;

        // Even though we have advanced INGRESS_CHUNK_INTERVAL_MS, the forwarding manager should
        // wait an additional 1ms since complete_ingress was called 1ms after the poll.
        assert_eq!(
            forwarding_manager.as_mut().poll_ingress(&mut cx),
            Poll::Pending
        );

        tokio::time::advance(Duration::from_millis(1)).await;

        let Poll::Ready(txs_with_senders) = forwarding_manager.as_mut().poll_ingress(&mut cx)
        else {
            panic!("forwarding manager should be ready");
        };
        assert_eq!(txs_with_senders.len(), INGRESS_CHUNK_MAX_SIZE);

        assert_pending_now_and_forever(forwarding_manager, cx).await;
    }

    #[tokio::test]
    async fn test_egress_limit() {
        let (forwarding_manager, _score_provider, mut cx) = setup();
        let mut forwarding_manager = pin!(forwarding_manager);

        let mut egress_txs = Vec::new();
        let mut total_size = 0;
        let target_size = 448 * 1024;

        let mut nonce = 0u64;
        while total_size < target_size {
            let tx = generate_tx(nonce);
            total_size += tx.eip2718_encoded_length();
            egress_txs.push(tx);
            nonce += 1;
        }

        let actual_total_size = egress_txs
            .iter()
            .map(|b| b.eip2718_encoded_length())
            .sum::<usize>();
        assert!(actual_total_size >= target_size);

        forwarding_manager
            .as_mut()
            .project()
            .add_egress_txs(egress_txs.iter());

        let Poll::Ready(first_batch) = forwarding_manager
            .as_mut()
            .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx)
        else {
            panic!("first poll should be ready");
        };

        let first_batch_size: usize = first_batch.iter().map(|b| b.len()).sum();
        assert!(
            first_batch_size <= egress_max_size_bytes(EXECUTION_REVISION.execution_chain_params())
        );
        assert!(!first_batch.is_empty());

        let Poll::Ready(second_batch) = forwarding_manager
            .as_mut()
            .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx)
        else {
            panic!("second poll should be ready");
        };

        let second_batch_size: usize = second_batch.iter().map(|b| b.len()).sum();
        assert!(!second_batch.is_empty());

        assert_eq!(first_batch.len() + second_batch.len(), egress_txs.len());
        assert_eq!(first_batch_size + second_batch_size, actual_total_size);

        assert_eq!(
            forwarding_manager
                .as_mut()
                .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx),
            Poll::Pending
        )
    }

    #[tokio::test]
    async fn test_egress_limit_exceeded() {
        let (forwarding_manager, _score_provider, mut cx) = setup();
        let mut forwarding_manager = pin!(forwarding_manager);

        let legacy_tx_generator =
            |nonce, input_len| make_legacy_tx(S1, BASE_FEE_PER_GAS, 30_000_000, nonce, input_len);
        let eip1559_tx_generator = |nonce, input_len| {
            make_eip1559_tx(S1, BASE_FEE_PER_GAS, 0, 30_000_000, nonce, input_len)
        };
        let eip7702_tx_generator = |nonce, input_len| {
            make_eip7702_tx(
                S1,
                BASE_FEE_PER_GAS,
                0,
                30_000_000,
                nonce,
                vec![],
                input_len,
            )
        };

        for tx_generator in [
            legacy_tx_generator,
            eip1559_tx_generator,
            eip7702_tx_generator,
        ] {
            let tx1 = tx_generator(0, 0);
            assert!(
                tx1.eip2718_encoded_length()
                    <= egress_max_size_bytes(EXECUTION_REVISION.execution_chain_params())
            );

            let tx2 = tx_generator(
                1,
                egress_max_size_bytes(EXECUTION_REVISION.execution_chain_params()),
            );
            assert!(
                tx2.eip2718_encoded_length()
                    > egress_max_size_bytes(EXECUTION_REVISION.execution_chain_params())
            );

            let tx3 = tx_generator(2, 0);
            assert!(
                tx3.eip2718_encoded_length()
                    <= egress_max_size_bytes(EXECUTION_REVISION.execution_chain_params())
            );

            forwarding_manager
                .as_mut()
                .project()
                .add_egress_txs([&tx1, &tx2, &tx3].into_iter());

            let Poll::Ready(first_batch) = forwarding_manager
                .as_mut()
                .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx)
            else {
                panic!("first poll should be ready");
            };

            eprintln!("{first_batch:#?}\n{tx1:#?}\n{tx3:#?}");

            assert_eq!(first_batch.len(), 2);
            assert_eq!(
                first_batch.iter().map(Bytes::len).sum::<usize>(),
                alloy_rlp::encode(tx1).len() + alloy_rlp::encode(tx3).len(),
            );

            assert_eq!(
                forwarding_manager
                    .as_mut()
                    .poll_egress(EXECUTION_REVISION.execution_chain_params(), &mut cx),
                Poll::Pending
            )
        }
    }
}
