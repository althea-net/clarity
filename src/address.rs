use serde::Serialize;
use serde::Serializer;
use std::str;
use std::str::FromStr;
use utils::{hex_str_to_bytes, ByteDecodeError};

/// This type represents ETH address
#[derive(PartialEq, Debug, Clone)]
pub struct Address {
    // TODO: address seems to be limited to 20 characters, but we keep it flexible
    data: Vec<u8>,
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *self == Address::default() {
            // If the address is empty we can serialize it as empty value
            serializer.serialize_bytes(&[])
        } else {
            // Here we serialize all bytes
            serializer.serialize_bytes(&self.data)
        }
    }
}

impl Address {
    pub fn new() -> Address {
        Address {
            data: vec![0u8; 20],
        }
    }
}

impl Default for Address {
    fn default() -> Address {
        Address {
            data: vec![0u8; 20],
        }
    }
}

impl From<[u8; 20]> for Address {
    fn from(val: [u8; 20]) -> Address {
        Address { data: val.to_vec() }
    }
}

#[derive(Fail, Debug, PartialEq)]
pub enum AddressError {
    #[fail(display = "Address should be exactly 40 bytes")]
    InvalidLengthError,
    #[fail(display = "Unable to decode bytes: {}", _0)]
    DecodeError(ByteDecodeError),
}

impl From<ByteDecodeError> for AddressError {
    fn from(e: ByteDecodeError) -> AddressError {
        AddressError::DecodeError(e)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.starts_with("0x") { &s[2..] } else { &s };
        // Simple sanitizer
        if s.len() > 40 || s.len() % 2 != 0 {
            return Err(AddressError::InvalidLengthError.into());
        }
        Ok(Address {
            data: hex_str_to_bytes(&s)?,
        })
    }
}

#[test]
#[should_panic]
fn decode_invalid_length() {
    "123".parse::<Address>().unwrap();
}

#[test]
#[should_panic]
fn decode_invalid_character() {
    "\u{012345}123456789012345678901234567890123456"
        .parse::<Address>()
        .unwrap();
}

#[test]
fn decode() {
    let address: Address = "1234567890123456789012345678901234567890"
        .parse::<Address>()
        .unwrap();

    assert_eq!(
        address,
        Address::from([
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
            0x90, 0x12, 0x34, 0x56, 0x78, 0x90
        ])
    );
}

#[test]
fn serialize_null_address() {
    use serde_rlp::ser::to_bytes;
    let address = Address::new();
    assert_eq!(to_bytes(&address).unwrap(), [128]);
}

#[test]
fn serialize_padded_address() {
    use serde_rlp::ser::to_bytes;
    let address: Address = "00000000000000000000000000000000000000c0".parse().unwrap();
    assert_eq!(
        to_bytes(&address).unwrap(),
        [148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0]
    );
}

#[test]
fn address_less_than_20_filler() {
    // Data found in AddressLessThan20Filler.json
    use serde_rlp::ser::to_bytes;
    let address: Address = "0b9331677e6ebf".parse().unwrap();
    assert_eq!(
        to_bytes(&address).unwrap(),
        [128 + 7, 0x0b, 0x93, 0x31, 0x67, 0x7e, 0x6e, 0xbf]
    );
}

#[test]
fn handle_prefixed() {
    let address: Address = "0x000000000000000000000000000b9331677e6ebf"
        .parse()
        .unwrap();
    assert_eq!(
        address,
        Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0x93, 0x31, 0x67, 0x7e, 0x6e, 0xbf
        ])
    );
}
