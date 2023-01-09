//! A module that defines how types serialize into RLP.
//!
//! This module is left as private as this is considered a implementation detail
//! of Clarity without any intention to be available outside.
//!
//! RLP encoder requires a binary data to be encoded in a well specified method.
use crate::address::Address;
use serde::Serialize;
use serde::Serializer;
extern crate byteorder;
extern crate num;
extern crate serde;

pub mod de;
mod error;
mod rlp;
pub mod ser;

#[cfg(test)]
extern crate serde_bytes;

pub(crate) struct AddressDef<'a>(pub(crate) &'a Address);

impl<'a> Serialize for AddressDef<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *self.0 == Address::default() {
            // If the address is empty we can serialize it as empty value
            serializer.serialize_bytes(&[])
        } else {
            // Here we serialize all bytes
            serializer.serialize_bytes(self.0.as_bytes())
        }
    }
}

#[test]
fn serialize_null_address() {
    use ser::to_bytes;
    let address = Address::default();
    assert_eq!(to_bytes(&AddressDef(&address)).unwrap(), [128]);
}

#[test]
fn serialize_padded_address() {
    use ser::to_bytes;
    let address: Address = "00000000000000000000000000000000000000c0".parse().unwrap();
    assert_eq!(
        to_bytes(&AddressDef(&address)).unwrap(),
        [148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0]
    );
}

