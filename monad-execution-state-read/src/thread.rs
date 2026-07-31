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

use std::sync::{mpsc, Arc};

use alloy_primitives::Address;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_eth_types::{EthAccount, EthHeader, ReceiptWithLogIndex};
use monad_ethcall::CallResult;
use monad_types::{BlockId, Epoch, SeqNum, Stake};
use monad_validator::signature_collection::{SignatureCollection, SignatureCollectionPubKeyType};
use tracing::warn;

use crate::{
    ExecutionStateRead, ExecutionStateReadError, ExecutionStateReadExt, ExecutionStateReadExtError,
    FinalizedEthCallRequest,
};

// Each synchronous caller has at most one in-flight request.
const MAX_INFLIGHT_REQUESTS: usize = 16;

enum ExecutionStateReadThreadRequest<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    GetAccountStatuses {
        block_id: BlockId,
        seq_num: SeqNum,
        is_finalized: bool,
        addresses: Vec<Address>,
        tx: mpsc::SyncSender<Result<Vec<Option<EthAccount>>, ExecutionStateReadError>>,
    },
    GetExecutionResult {
        block_id: BlockId,
        seq_num: SeqNum,
        is_finalized: bool,
        tx: mpsc::SyncSender<Result<EthHeader, ExecutionStateReadError>>,
    },
    RawReadEarliestFinalizedBlock {
        tx: mpsc::SyncSender<Option<SeqNum>>,
    },
    RawReadLatestFinalizedBlock {
        tx: mpsc::SyncSender<Option<SeqNum>>,
    },
    ReadValidatorSetAtBlock {
        block_num: SeqNum,
        requested_epoch: Epoch,
        tx: mpsc::SyncSender<
            Vec<(
                CertificateSignaturePubKey<ST>,
                SignatureCollectionPubKeyType<SCT>,
                Stake,
            )>,
        >,
    },
    TotalDbLookups {
        tx: mpsc::SyncSender<u64>,
    },
    GetLatestBlockHeader {
        tx: mpsc::SyncSender<Result<EthHeader, ExecutionStateReadExtError>>,
    },
    GetFinalizedAccount {
        block: SeqNum,
        address: Address,
        tx: mpsc::SyncSender<Result<Option<EthAccount>, ExecutionStateReadExtError>>,
    },
    GetFinalizedBlockHeader {
        block: SeqNum,
        tx: mpsc::SyncSender<Result<EthHeader, ExecutionStateReadExtError>>,
    },
    GetFinalizedReceipts {
        block: SeqNum,
        tx: mpsc::SyncSender<Result<Vec<ReceiptWithLogIndex>, ExecutionStateReadExtError>>,
    },
    EthCall {
        request: FinalizedEthCallRequest,
        tx: mpsc::SyncSender<Result<CallResult, ExecutionStateReadExtError>>,
    },
}

impl<ST, SCT> ExecutionStateReadThreadRequest<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    fn execute(self, state_read: &mut impl ExecutionStateReadExt<ST, SCT>) {
        match self {
            Self::GetAccountStatuses {
                block_id,
                seq_num,
                is_finalized,
                addresses,
                tx,
            } => tx
                .send(state_read.get_account_statuses(
                    &block_id,
                    &seq_num,
                    is_finalized,
                    addresses.iter(),
                ))
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::GetExecutionResult {
                block_id,
                seq_num,
                is_finalized,
                tx,
            } => tx
                .send(state_read.get_execution_result(&block_id, &seq_num, is_finalized))
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::RawReadEarliestFinalizedBlock { tx } => tx
                .send(state_read.raw_read_earliest_finalized_block())
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::RawReadLatestFinalizedBlock { tx } => tx
                .send(state_read.raw_read_latest_finalized_block())
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::ReadValidatorSetAtBlock {
                block_num,
                requested_epoch,
                tx,
            } => tx
                .send(state_read.read_valset_at_block(block_num, requested_epoch))
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::TotalDbLookups { tx } => tx
                .send(state_read.total_db_lookups())
                .expect("ExecutionStateReadThreadClient is alive"),
            Self::GetLatestBlockHeader { tx } => {
                let _ = tx.send(state_read.get_latest_block_header());
            }
            Self::GetFinalizedAccount { block, address, tx } => {
                let _ = tx.send(state_read.get_finalized_account(block, address));
            }
            Self::GetFinalizedBlockHeader { block, tx } => {
                let _ = tx.send(state_read.get_finalized_block_header(block));
            }
            Self::GetFinalizedReceipts { block, tx } => {
                let _ = tx.send(state_read.get_finalized_receipts(block));
            }
            Self::EthCall { request, tx } => {
                let _ = tx.send(state_read.eth_call(request));
            }
        }
    }
}

#[derive(Clone)]
pub struct ExecutionStateReadThreadClient<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    handle: Arc<std::thread::JoinHandle<()>>,
    request_tx: mpsc::SyncSender<ExecutionStateReadThreadRequest<ST, SCT>>,
}

impl<ST, SCT> ExecutionStateReadThreadClient<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    pub fn new<ESRT>(state_read: impl FnOnce() -> ESRT + Send + 'static) -> Self
    where
        ESRT: ExecutionStateReadExt<ST, SCT>,
    {
        let (request_tx, request_rx) =
            mpsc::sync_channel::<ExecutionStateReadThreadRequest<ST, SCT>>(MAX_INFLIGHT_REQUESTS);

        let handle = Arc::new(std::thread::spawn(move || {
            let mut state_read = state_read();
            for request in request_rx {
                request.execute(&mut state_read);
            }
            warn!("ExecutionStateReadThread terminating");
        }));

        Self { handle, request_tx }
    }

    fn send_and_recv_request<T>(
        &self,
        request: impl FnOnce(mpsc::SyncSender<T>) -> ExecutionStateReadThreadRequest<ST, SCT>,
    ) -> T {
        if self.handle.is_finished() {
            panic!("ExecutionStateReadThread terminated!");
        }

        let (tx, rx) = mpsc::sync_channel(0);

        self.request_tx
            .send(request(tx))
            .expect("ExecutionStateReadThread is alive");

        rx.recv().expect("ExecutionStateReadThread sends response")
    }
}

impl<ST, SCT> ExecutionStateRead<ST, SCT> for ExecutionStateReadThreadClient<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    fn get_account_statuses<'a>(
        &mut self,
        block_id: &BlockId,
        seq_num: &SeqNum,
        is_finalized: bool,
        addresses: impl Iterator<Item = &'a Address>,
    ) -> Result<Vec<Option<EthAccount>>, ExecutionStateReadError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::GetAccountStatuses {
            block_id: block_id.to_owned(),
            seq_num: seq_num.to_owned(),
            is_finalized,
            addresses: addresses.cloned().collect(),
            tx,
        })
    }

    fn get_execution_result(
        &mut self,
        block_id: &BlockId,
        seq_num: &SeqNum,
        is_finalized: bool,
    ) -> Result<EthHeader, ExecutionStateReadError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::GetExecutionResult {
            block_id: block_id.to_owned(),
            seq_num: seq_num.to_owned(),
            is_finalized,
            tx,
        })
    }

    fn raw_read_earliest_finalized_block(&self) -> Option<SeqNum> {
        self.send_and_recv_request(|tx| {
            ExecutionStateReadThreadRequest::RawReadEarliestFinalizedBlock { tx }
        })
    }

    fn raw_read_latest_finalized_block(&self) -> Option<SeqNum> {
        self.send_and_recv_request(|tx| {
            ExecutionStateReadThreadRequest::RawReadLatestFinalizedBlock { tx }
        })
    }

    fn read_valset_at_block(
        &mut self,
        block_num: SeqNum,
        requested_epoch: Epoch,
    ) -> Vec<(SCT::NodeIdPubKey, SignatureCollectionPubKeyType<SCT>, Stake)> {
        self.send_and_recv_request(
            |tx| ExecutionStateReadThreadRequest::ReadValidatorSetAtBlock {
                block_num,
                requested_epoch,
                tx,
            },
        )
    }

    fn total_db_lookups(&self) -> u64 {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::TotalDbLookups { tx })
    }
}

impl<ST, SCT> ExecutionStateReadExt<ST, SCT> for ExecutionStateReadThreadClient<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    fn get_latest_block_header(&mut self) -> Result<EthHeader, ExecutionStateReadExtError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::GetLatestBlockHeader {
            tx,
        })
    }

    fn get_finalized_account(
        &mut self,
        block: SeqNum,
        address: Address,
    ) -> Result<Option<EthAccount>, ExecutionStateReadExtError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::GetFinalizedAccount {
            block,
            address,
            tx,
        })
    }

    fn get_finalized_block_header(
        &mut self,
        block: SeqNum,
    ) -> Result<EthHeader, ExecutionStateReadExtError> {
        self.send_and_recv_request(
            |tx| ExecutionStateReadThreadRequest::GetFinalizedBlockHeader { block, tx },
        )
    }

    fn get_finalized_receipts(
        &mut self,
        block: SeqNum,
    ) -> Result<Vec<ReceiptWithLogIndex>, ExecutionStateReadExtError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::GetFinalizedReceipts {
            block,
            tx,
        })
    }

    fn eth_call(
        &mut self,
        request: FinalizedEthCallRequest,
    ) -> Result<CallResult, ExecutionStateReadExtError> {
        self.send_and_recv_request(|tx| ExecutionStateReadThreadRequest::EthCall { request, tx })
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use alloy_primitives::Address;
    use monad_crypto::NopSignature;
    use monad_eth_types::{EthAccount, EthHeader, ReceiptWithLogIndex};
    use monad_ethcall::CallResult;
    use monad_multi_sig::MultiSig;
    use monad_types::{SeqNum, GENESIS_BLOCK_ID, GENESIS_SEQ_NUM};

    use crate::{
        ExecutionStateRead, ExecutionStateReadExt, ExecutionStateReadExtError,
        ExecutionStateReadThreadClient, FinalizedEthCallRequest, InMemoryStateInner,
    };

    type TestState = InMemoryStateInner<NopSignature, MultiSig<NopSignature>>;

    fn test_state() -> TestState {
        std::sync::Arc::try_unwrap(TestState::genesis(SeqNum(4)))
            .unwrap()
            .into_inner()
            .unwrap()
    }

    impl ExecutionStateReadExt<NopSignature, MultiSig<NopSignature>> for TestState {
        fn get_latest_block_header(&mut self) -> Result<EthHeader, ExecutionStateReadExtError> {
            let mut header = alloy_consensus::Header::default();
            header.number = 11;
            Ok(EthHeader(header))
        }

        fn get_finalized_account(
            &mut self,
            _block: SeqNum,
            _address: Address,
        ) -> Result<Option<EthAccount>, ExecutionStateReadExtError> {
            Ok(None)
        }

        fn get_finalized_block_header(
            &mut self,
            block: SeqNum,
        ) -> Result<EthHeader, ExecutionStateReadExtError> {
            let mut header = alloy_consensus::Header::default();
            header.number = block.0;
            Ok(EthHeader(header))
        }

        fn get_finalized_receipts(
            &mut self,
            _block: SeqNum,
        ) -> Result<Vec<ReceiptWithLogIndex>, ExecutionStateReadExtError> {
            Ok(Vec::new())
        }

        fn eth_call(
            &mut self,
            _request: FinalizedEthCallRequest,
        ) -> Result<CallResult, ExecutionStateReadExtError> {
            Ok(CallResult::Success(Default::default()))
        }
    }

    #[test]
    fn all_requests() {
        let mut client = ExecutionStateReadThreadClient::new(test_state);

        {
            let get_account_statuses = client
                .get_account_statuses(&GENESIS_BLOCK_ID, &GENESIS_SEQ_NUM, true, [].into_iter())
                .unwrap();

            assert_eq!(get_account_statuses.len(), 0);
        }

        {
            let earliest_finalized_block = client.raw_read_earliest_finalized_block().unwrap();

            assert_eq!(earliest_finalized_block, GENESIS_SEQ_NUM);
        }

        {
            let latest_finalized_block = client.raw_read_latest_finalized_block().unwrap();

            assert_eq!(latest_finalized_block, GENESIS_SEQ_NUM);
        }

        {
            let total_db_lookups = client.total_db_lookups();

            assert_eq!(total_db_lookups, 0);
        }
    }

    #[test]
    fn shutdown() {
        let client = ExecutionStateReadThreadClient::new(test_state);

        let handle = client.handle.clone();

        drop(client);

        std::thread::sleep(Duration::from_millis(10));

        assert!(handle.is_finished());
    }

    #[test]
    fn extended_requests_use_the_same_worker() {
        let mut client = ExecutionStateReadThreadClient::new(test_state);

        let latest_header = client.get_latest_block_header().unwrap();
        assert_eq!(latest_header.0.number, 11);
        let header = client.get_finalized_block_header(SeqNum(7)).unwrap();
        assert_eq!(header.0.number, 7);
        assert!(client.get_finalized_receipts(SeqNum(7)).unwrap().is_empty());
    }
}
