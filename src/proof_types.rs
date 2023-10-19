use std::{borrow::Borrow, collections::HashMap};

use ethereum_types::{H256, U256};
use plonky2_evm::{
    generation::{GenerationInputs, TrieInputs},
    proof::{ExtraBlockData, TrieRoots},
};
use proof_protocol_decoder::types::OtherBlockData;
use serde::{Deserialize, Serialize};

use crate::types::{BlockHeight, PlonkyProofIntern, ProofUnderlyingTxns, TxnIdx};

/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

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

    pub(crate) fn into_generation_inputs(self, other_data: OtherBlockData) -> GenerationInputs {
        let signed_txns = match self.signed_txn.is_empty() {
            false => vec![self.signed_txn],
            true => Vec::new(),
        };

        GenerationInputs {
            genesis_state_trie_root: other_data.genesis_state_trie_root,
            txn_number_before: self.txn_idx.into(),
            gas_used_before: self.deltas.gas_used_before,
            block_bloom_before: self.deltas.block_bloom_before,
            gas_used_after: self.deltas.gas_used_after,
            block_bloom_after: self.deltas.block_bloom_after,
            signed_txns,
            tries: self.tries,
            trie_roots_after: self.trie_roots_after,
            contract_code: self.contract_code,
            block_metadata: other_data.b_data.b_meta,
            block_hashes: other_data.b_data.b_hashes,
            addresses: Vec::default(), // TODO!
        }
    }

    /// Creates a dummy transaction.
    ///
    /// These can be used to pad a block if the number of transactions in the
    /// block is below `2`.
    pub fn create_dummy(b_height: BlockHeight, txn_idx: TxnIdx) -> Self {
        let trie_roots_after = TrieRoots {
            state_root: EMPTY_TRIE_HASH,
            transactions_root: EMPTY_TRIE_HASH,
            receipts_root: EMPTY_TRIE_HASH,
        };

        Self {
            signed_txn: Default::default(),
            tries: Default::default(),
            trie_roots_after,
            deltas: Default::default(),
            contract_code: Default::default(),
            b_height,
            txn_idx,
        }
    }

    /// Copy relevant fields of the `TxnProofGenIR` to a new `TxnProofGenIR`
    /// with a different `b_height` and `txn_idx`.
    ///
    /// This can be used to pad a block if there is only one transaction in the
    /// block. Block proofs need a minimum of two transactions.
    pub fn dummy_with_at(&self, b_height: BlockHeight, txn_idx: TxnIdx) -> Self {
        let mut dummy = Self::create_dummy(b_height, txn_idx);

        let deltas = ProofBeforeAndAfterDeltas {
            gas_used_before: self.deltas.gas_used_after,
            gas_used_after: self.deltas.gas_used_after,
            block_bloom_before: self.deltas.block_bloom_after,
            block_bloom_after: self.deltas.block_bloom_after,
        };

        dummy.deltas = deltas;
        dummy.trie_roots_after = self.trie_roots_after.clone();
        dummy
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

pub fn create_extra_block_data(
    deltas: ProofBeforeAndAfterDeltas,
    genesis_root: H256,
    txn_start: TxnIdx,
    txn_end: TxnIdx,
) -> ExtraBlockData {
    ExtraBlockData {
        genesis_state_trie_root: genesis_root,
        txn_number_before: txn_start.into(),
        txn_number_after: txn_end.into(),
        gas_used_before: deltas.gas_used_before,
        gas_used_after: deltas.gas_used_after,
        block_bloom_before: deltas.block_bloom_before,
        block_bloom_after: deltas.block_bloom_after,
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
