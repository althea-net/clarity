//! Global context of Secp256k1
//!
//! Its kept as thread local for performance benefits. So it would be initialized
//! on first use.
//!
//!
use secp256k1::{All, Secp256k1};
use std::cell::RefCell;

thread_local! {
    pub(crate) static SECP256K1: RefCell<Secp256k1<All>> = RefCell::new(Secp256k1::new());
}
