#![allow(clippy::return_self_not_must_use)]

use crate::EthLogDecode;
use soliloquy_core::{
    abi::{Detokenize, Error as AbiError, RawLog},
    types::{Log, H256},
};
use std::borrow::Cow;

use crate::event::Event;
use soliloquy_core::types::Filter;
use std::marker::PhantomData;

/// Attempt to parse a log into a specific output type.
pub fn parse_log<D>(log: Log) -> std::result::Result<D, AbiError>
where
    D: EthLogDecode,
{
    D::decode_log(&RawLog {
        topics: log.topics,
        data: log.data.to_vec(),
    })
}

/// A trait for implementing event bindings
pub trait EthEvent: Detokenize + Send + Sync {
    /// The name of the event this type represents
    fn name() -> Cow<'static, str>;

    /// Retrieves the signature for the event this data corresponds to.
    /// This signature is the Keccak-256 hash of the ABI signature of
    /// this event.
    fn signature() -> H256;

    /// Retrieves the ABI signature for the event this data corresponds
    /// to.
    fn abi_signature() -> Cow<'static, str>;

    /// Decodes an Ethereum `RawLog` into an instance of the type.
    fn decode_log(log: &RawLog) -> Result<Self, soliloquy_core::abi::Error>
    where
        Self: Sized;

    /// Returns true if this is an anonymous event
    fn is_anonymous() -> bool;

    /// Returns an Event builder for the ethereum event represented by this types ABI signature.
    fn new(filter: Filter) -> Event<Self>
    where
        Self: Sized,
    {
        let filter = filter.event(&Self::abi_signature());
        Event {
            filter,
            datatype: PhantomData,
        }
    }
}

// Convenience implementation
impl<T: EthEvent> EthLogDecode for T {
    fn decode_log(log: &RawLog) -> Result<Self, soliloquy_core::abi::Error>
    where
        Self: Sized,
    {
        T::decode_log(log)
    }
}
