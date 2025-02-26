#![allow(clippy::return_self_not_must_use)]

use crate::{
    event_core::parse_log, log::LogMeta, stream::EventStream, ContractError, EthLogDecode,
};
use soliloquy_core::{
    abi::Address,
    types::{BlockNumber, Filter, Log, Topic, ValueOrArray, H256},
};
use std::{borrow::Borrow, marker::PhantomData};

/// Helper for managing the event filter before querying or streaming its logs
#[derive(Debug)]
#[must_use = "event filters do nothing unless you `query` or `stream` them"]
pub struct Event<D> {
    /// The event filter's state
    pub filter: Filter,
    /// Stores the event datatype
    pub(crate) datatype: PhantomData<D>,
}

// TODO: Improve these functions
impl<D> Event<D>
where
    D: EthLogDecode,
{
    /// Sets the filter's `from` block
    #[allow(clippy::wrong_self_convention)]
    pub fn from_block<T: Into<BlockNumber>>(mut self, block: T) -> Self {
        self.filter = self.filter.from_block(block);
        self
    }

    /// Sets the filter's `to` block
    #[allow(clippy::wrong_self_convention)]
    pub fn to_block<T: Into<BlockNumber>>(mut self, block: T) -> Self {
        self.filter = self.filter.to_block(block);
        self
    }

    /// Sets the filter's `blockHash`. Setting this will override previously
    /// set `from_block` and `to_block` fields.
    #[allow(clippy::wrong_self_convention)]
    pub fn at_block_hash<T: Into<H256>>(mut self, hash: T) -> Self {
        self.filter = self.filter.at_block_hash(hash);
        self
    }

    /// Sets the filter's 0th topic (typically the event name for non-anonymous events)
    pub fn topic0<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[0] = Some(topic.into());
        self
    }

    /// Sets the filter's 1st topic
    pub fn topic1<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[1] = Some(topic.into());
        self
    }

    /// Sets the filter's 2nd topic
    pub fn topic2<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[2] = Some(topic.into());
        self
    }

    /// Sets the filter's 3rd topic
    pub fn topic3<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[3] = Some(topic.into());
        self
    }

    /// Sets the filter's address.
    pub fn address(mut self, address: ValueOrArray<Address>) -> Self {
        self.filter = self.filter.address(address);
        self
    }
}
