#![warn(clippy::all)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::pedantic)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod amm;
pub mod client;
pub mod eth_wrapping;
pub mod gas_estimator;
pub mod jsonrpc;
pub mod types;

mod erc20_permit;
mod erc20_utils;
mod erc721_utils;
mod event_utils;
mod mem;

pub use event_utils::convert_to_event;
pub use event_utils::convert_to_event_string;
