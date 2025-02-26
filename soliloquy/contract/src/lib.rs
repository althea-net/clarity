#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod base;
pub use base::{decode_function_data, encode_function_data, AbiError, BaseContract};

mod call_core;
pub use call_core::EthCall;

mod error;
pub use error::{ContractRevert, EthError};

mod event_core;
pub use event_core::{parse_log, EthEvent};

mod log;
pub use log::{decode_logs, EthLogDecode, LogMeta};

pub mod stream;

pub use contract_abigen::{
    Abigen, ContractFilter, ExcludeContracts, InternalStructs, MultiAbigen, SelectContracts,
};

pub use contract_derive::{
    abigen, Eip712, EthAbiCodec, EthAbiType, EthCall, EthDisplay, EthError, EthEvent,
};

// Hide the Lazy re-export, it's just for convenience
#[doc(hidden)]
pub use once_cell::sync::Lazy;

// For macro expansions only, not public API.
// See: [#2235](https://github.com/gakonst/ethers-rs/pull/2235)

#[doc(hidden)]
#[allow(unused_extern_crates)]
extern crate self as ethers_contract;

#[doc(hidden)]
#[allow(unused_extern_crates)]
extern crate self as ethers;

#[doc(hidden)]
pub mod contract {
    pub use crate::*;
}

#[doc(hidden)]
pub use soliloquy_core as core;

mod event;
pub use event::Event;

#[path = "contract.rs"]
mod _contract;
pub use _contract::{Contract, ContractInstance};

mod call;
pub use call::{ContractCall, ContractError, FunctionCall};

/// This module exposes low lever builder structures which are only consumed by the
/// type-safe ABI bindings generators.
#[doc(hidden)]
pub mod builders {
    pub use super::{call::ContractCall, event::Event};
}
