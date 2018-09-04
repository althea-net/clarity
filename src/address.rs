use serde::Serialize;
use serde::Serializer;
use std::str;
use std::str::FromStr;
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

#[derive(Fail, Debug, PartialEq)]
pub enum AddressError {
    #[fail(display = "Address should be exactly 40 bytes")]
    InvalidLengthError,
    #[fail(display = "Address contains invalid characters")]
    InvalidCharacterError,
    #[fail(display = "Address contains invalid format")]
    InvalidFormatError,
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40 {
            return Err(AddressError::InvalidLengthError.into());
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in s
            .as_bytes()
            .chunks(2)
            .map(|ch| str::from_utf8(&ch).map_err(|_| AddressError::InvalidCharacterError.into()))
            .enumerate()
        {
            bytes[i] = u8::from_str_radix(&chunk?, 16)
                .map_err(|_| AddressError::InvalidFormatError.into())?;
        }
        Ok(Address(bytes))
    }
}

#[test]
fn decode_invalid_length() {
    assert_eq!(
        "123".parse::<Address>().unwrap_err(),
        AddressError::InvalidLengthError
    );
}

#[test]
fn decode_invalid_character() {
    assert_eq!(
        "\u{012345}123456789012345678901234567890123456"
            .parse::<Address>()
            .unwrap_err(),
        AddressError::InvalidCharacterError
    );
}

#[test]
fn decode() {
    let address: Address = "1234567890123456789012345678901234567890".parse().unwrap();

    assert_eq!(
        address,
        Address([
            0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
            0x90, 0x12, 0x34, 0x56, 0x78, 0x90
        ])
    );
}
