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
//! extern crate futures;
//! extern crate web3;
//!
//! use clarity::{Address, Signature, Transaction, PrivateKey};
//!
//! use futures::Future;
//! use web3::{transports, types::Bytes, Web3};
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
//! let tx = Transaction {
//!     nonce: 0u32.into(),
//!     gas_price: 1_000_000_000u32.into(),
//!     gas_limit: 21_000u32.into(),
//!     to: bobs_key.to_public_key().unwrap(),
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
//! let (_loop, transport) = transports::Http::new("http://localhost:8545").unwrap();
//! let web3 = Web3::new(transport);
//! let res = web3
//!     .eth()
//!     .send_raw_transaction(Bytes::from(tx_signed.to_bytes().unwrap()))
//!     .wait()
//!     .unwrap();
//! ```

#![warn(clippy::all)]
#![allow(clippy::pedantic)]

extern crate num_bigint;
extern crate num_traits;
extern crate serde;
extern crate serde_bytes;
extern crate serde_rlp;
#[macro_use]
extern crate failure;
extern crate secp256k1;
extern crate sha3;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
extern crate bytecount;
extern crate num256;

pub mod abi;
pub mod address;
pub mod constants;
mod context;
pub mod error;
pub mod opcodes;
pub mod private_key;
mod rlp;
mod signature;
pub mod transaction;
pub mod types;
pub mod utils;

pub use address::Address;
pub use error::ClarityError;
pub use private_key::PrivateKey;
pub use signature::Signature;
pub use transaction::Transaction;
pub use types::BigEndianInt;
