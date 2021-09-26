//! A module that defines how types serialize into RLP.
//!
//! This module is left as private as this is considered a implementation detail
//! of Clarity without any intention to be available outside.
//!
//! RLP encoder requires a binary data to be encoded in a well specified method.
use address::Address;
use serde::Serialize;
use serde::Serializer;

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
    use serde_rlp::ser::to_bytes;
    let address = Address::default();
    assert_eq!(to_bytes(&AddressDef(&address)).unwrap(), [128]);
}

#[test]
fn serialize_padded_address() {
    use serde_rlp::ser::to_bytes;
    let address: Address = "00000000000000000000000000000000000000c0".parse().unwrap();
    assert_eq!(
        to_bytes(&AddressDef(&address)).unwrap(),
        [148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0]
    );
}
