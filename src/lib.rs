//! # Introduction
//! Clarity is a low-level Ethereum transaction library written in pure Rust.
//!
//! ## Features
//! * Any-endian, 32/64-bit support
//! * Public/private key handling
//! * Transaction signing and verification
//! * ABI enconding for common data types (see `abi::Token` variants)
//!
//! ## Getting started
//! Here's an example lifetime of an Alice-to-Bob Ethereum transaction made with Clarity:
//! ```rust,no_run
//! extern crate clarity;
//! use web30::client::Web3;
//!
//! use clarity::{Address, Signature, Transaction, PrivateKey};
//! use std::time::Duration;
//!
//!
//! // A helper for filling the keys
//! let mut key_buf: [u8; 32] = rand::random();
//!
//! let alices_key = PrivateKey::from_slice(&key_buf).unwrap();
//!
//! key_buf = rand::random();
//! let bobs_key = PrivateKey::from_slice(&key_buf).unwrap();
//!
//! // Create a new transaction
//! let tx = Transaction::Legacy {
//!     nonce: 0u32.into(),
//!     gas_price: 1_000_000_000u32.into(),
//!     gas_limit: 21_000u32.into(),
//!     to: bobs_key.to_address(),
//!     value: 100u32.into(),
//!     data: Vec::new(),
//!     signature: None, // Not signed. Yet.
//! };
//!
//! let tx_signed: Transaction = tx.sign(&alices_key, None);
//! assert!(tx_signed.is_valid());
//!
//! // You can always derive the sender from a signed transaction
//! let sender: Address = tx_signed.sender().unwrap();
//!
//! // Send the locally assembled raw transaction over web3 (no need to trust another
//! // machine with your wallet or host a node locally).
//! const TIMEOUT: Duration = Duration::from_secs(1);
//! let web3 = Web3::new("http://localhost:8545", TIMEOUT);
//! let res = web3
//!     .eth_send_raw_transaction(tx_signed.to_bytes());
//! // res.await.unwrap()
//! ```

#![warn(clippy::all)]
#![allow(clippy::pedantic)]

extern crate num_traits;
extern crate secp256k1;
extern crate serde;
extern crate sha3;
#[macro_use]
extern crate serde_derive;
extern crate num256;

pub mod abi;
pub mod address;
pub mod constants;
mod context;
pub mod error;
pub mod opcodes;
pub mod private_key;
mod raw_private_key;
pub mod rlp;
mod signature;
pub mod transaction;
pub mod types;
pub mod utils;

pub use address::Address;
pub use error::Error;
pub use num256::Uint256;
pub use private_key::PrivateKey;
pub use signature::Signature;
pub use transaction::Transaction;
pub use types::BigEndianInt;
