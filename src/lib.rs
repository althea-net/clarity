//! # Introduction
//! Clarity is a low level library designed to handle Ethereum transactions.
//!
//! You can create, sign, verify transactions, as well as work with contract calls, and encode ABI.
//! It is designed with embedded devices on mind so big/little endian architectures and 32/64 bits are supported.
//!
//! ## Features
//!
//! * Supports both little endian and big endian
//! * Works well on both 32 and 64 bit architectures
//! * Handle private keys
//! * Create public keys
//! * Sign transactions
//! * Verify transaction
//! * Handle signatures
//! * Encode ABI for contract calls
//!
//! ## Documentation
//!
//! * [GitHub repository](https://github.com/althea-mesh/clarity)
//! * [Cargo package](https://crates.io/crates/clarity)
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
extern crate num256;

pub mod abi;
pub mod address;
pub mod constants;
pub mod error;
pub mod opcodes;
pub mod private_key;
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
