//! Mod of types for ethereum logs
use clarity::{Address, Uint256};
use serde::{Deserialize, Serialize};
use soliloquy_core::{
    abi::{Error, RawLog},
    // types::{Address, Log, TxHash, H256, U256, U64},
};
use web30::types::{Data, Log};

/// A trait for types (events) that can be decoded from a `RawLog`
pub trait EthLogDecode: Send + Sync {
    /// decode from a `RawLog`
    fn decode_log(log: &RawLog) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Decodes a series of logs into a vector
pub fn decode_logs<T: EthLogDecode>(logs: &[RawLog]) -> Result<Vec<T>, Error> {
    logs.iter().map(T::decode_log).collect()
}

/// Metadata inside a log
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMeta {
    /// Address from which this log originated
    pub address: Address,

    /// The block in which the log was emitted
    pub block_number: Uint256,

    /// The block hash in which the log was emitted
    pub block_hash: Data,

    /// The transaction hash in which the log was emitted
    pub transaction_hash: Data,

    /// Transactions index position log was created from
    pub transaction_index: Uint256,

    /// Log index position in the block
    pub log_index: Uint256,
}

impl From<&Log> for LogMeta {
    fn from(src: &Log) -> Self {
        LogMeta {
            address: src.address,
            block_number: src.block_number.expect("should have a block number"),
            block_hash: src.block_hash.clone().expect("should have a block hash"),
            transaction_hash: src.transaction_hash.clone().expect("should have a tx hash"),
            transaction_index: src.transaction_index.expect("should have a tx index"),
            log_index: src.log_index.expect("should have a log index"),
        }
    }
}
