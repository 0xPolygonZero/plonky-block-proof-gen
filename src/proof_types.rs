use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::once,
};

use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
    trie_subsets::create_trie_subset,
};
use ethereum_types::{H256, U256};
use plonky2_evm::{
    generation::{GenerationInputs, TrieInputs},
    proof::{BlockHashes, BlockMetadata, ExtraBlockData, TrieRoots},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{BlockHeight, PlonkyProofIntern, ProofUnderlyingTxns, TxnIdx};

pub type DummyProofIRResult<T> = Result<T, DummyProofIRError>;

#[derive(Error, Debug)]
pub enum DummyProofIRError {
    #[error("Unable to find key {1} in trie containing keys {0:?} for trie type {2}")]
    NonexistentTxnIndexForTrie(Vec<Nibbles>, TxnIdx, TrieType),
}

#[derive(Debug)]
pub enum TrieType {
    Txn,
    Receipt,
}

impl Display for TrieType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TrieType::Txn => write!(f, "transaction"),
            TrieType::Receipt => write!(f, "receipt"),
        }
    }
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    pub b_meta: BlockMetadata,
    pub b_hashes: BlockHashes,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofCommon {
    pub b_height: BlockHeight,
    pub deltas: ProofBeforeAndAfterDeltas,
    pub roots_before: TrieRoots,
    pub roots_after: TrieRoots,
}

/// An `IR` (Intermediate Representation) for a given txn in a block that we can
/// use to generate a proof for that txn.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnProofGenIR {
    /// Signed txn bytecode.
    pub signed_txn: Vec<u8>,

    /// The partial trie states at the start of the txn.
    pub tries: TrieInputs,

    /// The expected root hashes of all tries (except storage tries) after the
    /// txn is executed.
    pub trie_roots_after: TrieRoots,

    /// Additional info of state that changed before and after the txn executed.
    pub deltas: ProofBeforeAndAfterDeltas,

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked by this txn will have an
    /// entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    /// The height of the block.
    pub b_height: BlockHeight,

    /// The index of the txn in the block.
    pub txn_idx: TxnIdx,
}

impl TxnProofGenIR {
    pub fn get_txn_idx(&self) -> TxnIdx {
        self.txn_idx
    }

    pub(crate) fn into_generation_inputs(self, b_data: BlockLevelData) -> GenerationInputs {
        GenerationInputs {
            txn_number_before: self.txn_idx.into(),
            gas_used_before: self.deltas.gas_used_before,
            block_bloom_before: self.deltas.block_bloom_before,
            gas_used_after: self.deltas.gas_used_after,
            block_bloom_after: self.deltas.block_bloom_after,
            signed_txns: vec![self.signed_txn],
            tries: self.tries,
            trie_roots_after: self.trie_roots_after,
            contract_code: self.contract_code,
            block_metadata: b_data.b_meta,
            block_hashes: b_data.b_hashes,
            addresses: Vec::default(), // TODO!
        }
    }

    /// Creates a dummy transaction.
    ///
    /// These can be used to pad a block if the number of transactions in the
    /// block is below `2`.
    pub fn create_dummy(
        b_height: BlockHeight,
        txn_idx: TxnIdx,
        receipts_trie: &HashedPartialTrie,
        transactions_trie: &HashedPartialTrie,
    ) -> DummyProofIRResult<Self> {
        // TODO: Remove cast once `eth_trie_utils` get an update...
        let receipt_sub_partial_trie =
            Self::create_trie_subset_dummy_txn(receipts_trie, txn_idx, TrieType::Receipt)?;
        let txn_sub_partial_trie =
            Self::create_trie_subset_dummy_txn(transactions_trie, txn_idx, TrieType::Txn)?;

        let trie_roots_after = TrieRoots {
            transactions_root: txn_sub_partial_trie.hash(),
            receipts_root: receipt_sub_partial_trie.hash(),
            ..Default::default()
        };

        let tries = TrieInputs {
            transactions_trie: txn_sub_partial_trie,
            receipts_trie: receipt_sub_partial_trie,
            ..Default::default()
        };

        Ok(Self {
            signed_txn: Default::default(),
            tries,
            trie_roots_after,
            deltas: Default::default(),
            contract_code: Default::default(),
            b_height,
            txn_idx,
        })
    }

    fn create_trie_subset_dummy_txn(
        trie: &HashedPartialTrie,
        txn_idx: usize,
        trie_type: TrieType,
    ) -> DummyProofIRResult<HashedPartialTrie> {
        create_trie_subset(trie, once(txn_idx as u64)).map_err(|_| {
            DummyProofIRError::NonexistentTxnIndexForTrie(trie.keys().collect(), txn_idx, trie_type)
        })
    }

    /// Creates a dummy txn that appears right after a non-dummy txn.
    ///
    /// This will only occur when a block has exactly `1` txn inside it. In this
    /// special case, the dummy txn needs some information from the previous
    /// txn. Block proofs need a minimum of two transactions.
    pub fn create_dummy_following_real_txn(
        b_height: BlockHeight,
        txn_idx: TxnIdx,
        receipts_trie: &HashedPartialTrie,
        transactions_trie: &HashedPartialTrie,
        prev_real_txn: &TxnProofGenIR,
    ) -> DummyProofIRResult<Self> {
        let mut dummy = Self::create_dummy(b_height, txn_idx, receipts_trie, transactions_trie)?;

        let deltas = ProofBeforeAndAfterDeltas {
            gas_used_before: prev_real_txn.deltas.gas_used_after,
            gas_used_after: prev_real_txn.deltas.gas_used_after,
            block_bloom_before: prev_real_txn.deltas.block_bloom_after,
            block_bloom_after: prev_real_txn.deltas.block_bloom_after,
        };

        let trie_roots_after = TrieRoots {
            state_root: prev_real_txn.trie_roots_after.state_root,
            ..dummy.trie_roots_after
        };

        dummy.deltas = deltas;
        dummy.trie_roots_after = trie_roots_after;

        Ok(dummy)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProofBeforeAndAfterDeltas {
    pub gas_used_before: U256,
    pub gas_used_after: U256,
    pub block_bloom_before: [U256; 8],
    pub block_bloom_after: [U256; 8],
}

impl<T: Borrow<ExtraBlockData>> From<T> for ProofBeforeAndAfterDeltas {
    fn from(v: T) -> Self {
        let b = v.borrow();

        Self {
            gas_used_before: b.gas_used_before,
            gas_used_after: b.gas_used_after,
            block_bloom_before: b.block_bloom_before,
            block_bloom_after: b.block_bloom_after,
        }
    }
}

impl ProofBeforeAndAfterDeltas {
    pub fn into_extra_block_data(self, txn_start: TxnIdx, txn_end: TxnIdx) -> ExtraBlockData {
        ExtraBlockData {
            txn_number_before: txn_start.into(),
            txn_number_after: txn_end.into(),
            gas_used_before: self.gas_used_before,
            gas_used_after: self.gas_used_after,
            block_bloom_before: self.block_bloom_before,
            block_bloom_after: self.block_bloom_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedTxnProof {
    pub txn_idx: TxnIdx,
    pub common: ProofCommon,
    pub intern: PlonkyProofIntern,
}

impl GeneratedTxnProof {
    pub fn underlying_txns(&self) -> ProofUnderlyingTxns {
        (self.txn_idx..=self.txn_idx).into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggProof {
    pub underlying_txns: ProofUnderlyingTxns,
    pub common: ProofCommon,
    pub intern: PlonkyProofIntern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    pub b_height: BlockHeight,
    pub intern: PlonkyProofIntern,
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableProof {
    Txn(GeneratedTxnProof),
    Agg(GeneratedAggProof),
}

impl AggregatableProof {
    pub fn underlying_txns(&self) -> ProofUnderlyingTxns {
        match self {
            AggregatableProof::Txn(info) => info.underlying_txns(),
            AggregatableProof::Agg(info) => info.underlying_txns.clone(),
        }
    }

    pub fn b_height(&self) -> BlockHeight {
        match self {
            AggregatableProof::Txn(info) => info.common.b_height,
            AggregatableProof::Agg(info) => info.common.b_height,
        }
    }
}

impl From<GeneratedTxnProof> for AggregatableProof {
    fn from(v: GeneratedTxnProof) -> Self {
        Self::Txn(v)
    }
}

impl From<GeneratedAggProof> for AggregatableProof {
    fn from(v: GeneratedAggProof) -> Self {
        Self::Agg(v)
    }
}
