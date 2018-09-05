use serde::Serialize;
use serde::Serializer;
use std::str;
use std::str::FromStr;
use utils::{hex_str_to_bytes, ByteDecodeError};

/// This type represents ETH address
#[derive(PartialEq, Debug)]
pub struct Address([u8; 20]);

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl Address {
    pub fn new() -> Address {
        Address([0u8; 20])
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
        if s.len() != 40 {
            return Err(AddressError::InvalidLengthError.into());
        }
        let bytes = hex_str_to_bytes(&s)?;
        debug_assert_eq!(bytes.len(), 20);
        let mut res = [0x0u8; 20];
        res.copy_from_slice(&bytes[..]);
        Ok(Address(res))
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
        Address([
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
            0x90, 0x12, 0x34, 0x56, 0x78, 0x90
        ])
    );
}
