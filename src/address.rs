use failure::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;
use std::str;
use std::str::FromStr;
use utils::bytes_to_hex_str;
use utils::{hex_str_to_bytes, ByteDecodeError};

/// Representation of an Ethereum address.
///
/// Address is usually derived from a `PrivateKey`, or converted from its
/// textual representation.
#[derive(PartialEq, Debug, Clone, Copy, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address([u8; 20]);

impl Address {
    /// Get raw bytes of the address.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates an Address from a slice.
    ///
    /// This requires a slice to be exactly 20 bytes in length,
    pub fn from_slice(data: &[u8]) -> Result<Address, Error> {
        ensure!(
            data.len() == 20,
            "Address requires exactly 20 bytes but {} were found",
            data.len()
        );
        let mut result: [u8; 20] = Default::default();
        result.copy_from_slice(&data);
        Ok(Address(result))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = if s.starts_with("0x") { &s[2..] } else { &s };

        hex_str_to_bytes(&s)
            .and_then(move |bytes| Address::from_slice(&bytes))
            .map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 20]> for Address {
    fn from(val: [u8; 20]) -> Address {
        Address(val)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let res = write!(f, "0x");
            if res.is_err() {
                return res;
            }
        }

        for hex_char in self.0.iter() {
            let res = write!(f, "{:x}", hex_char);
            if res.is_err() {
                return res;
            }
        }
        Ok(())
    }
}

impl fmt::UpperHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let res = write!(f, "0x");
            if res.is_err() {
                return res;
            }
        }

        for hex_char in self.0.iter() {
            let res = write!(f, "{:X}", hex_char);
            if res.is_err() {
                return res;
            }
        }
        Ok(())
    }
}

#[derive(Fail, Debug, PartialEq)]
pub enum AddressError {
    #[fail(display = "Address should be exactly 40 bytes")]
    InvalidLengthError,
    #[fail(display = "Unable to decode bytes: {}", _0)]
    DecodeError(ByteDecodeError),
    #[fail(display = "Checksum error")]
    ChecksumError,
    #[fail(display = "Invalid checksum")]
    InvalidChecksum,
}

impl From<ByteDecodeError> for AddressError {
    fn from(e: ByteDecodeError) -> AddressError {
        AddressError::DecodeError(e)
    }
}

impl FromStr for Address {
    type Err = Error;

    /// Parses a string into a valid Ethereum address.
    ///
    /// # Supported formats
    ///
    /// * `0x` prefixed address
    /// * Raw bytes of an address represented by a bytes as an hexadecimal.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// use clarity::Address;
    /// // Method 1
    /// Address::from_str("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    /// // Method 1 (without 0x prefix)
    /// Address::from_str("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    /// // Method 2
    /// let _address : Address = "14131211100f0e0d0c0b0a090807060504030201".parse().unwrap();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Address::default());
        }
        let s = if s.starts_with("0x") { &s[2..] } else { &s };
        if s.len() == 40 {
            Ok(Address::from_slice(&hex_str_to_bytes(&s)?)?)
        } else {
            Err(AddressError::InvalidLengthError.into())
        }
    }
}

impl ToString for Address {
    /// Creates a textual representation of the `Address`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use clarity::Address;
    /// let address = Address::default();
    /// address.to_string(); // 0x0000000000000000000000000000000000000000
    /// ```
    fn to_string(&self) -> String {
        format!("0x{}", bytes_to_hex_str(&self.0))
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
    let address = Address::default();
    let s = serde_json::to_string(&address).unwrap();
    assert_eq!(s, r#""0x0000000000000000000000000000000000000000""#);
    let recovered_addr: Address = serde_json::from_str(&s).unwrap();
    assert_eq!(address, recovered_addr);
}

#[test]
fn serialize_padded_address() {
    let raw_address = "00000000000000000000000000000000000000c0";
    let address: Address = raw_address.parse().unwrap();
    assert_eq!(
        serde_json::to_string(&address).unwrap(),
        format!(r#""0x{}""#, raw_address)
    );
}

#[test]
#[should_panic]
fn address_less_than_20_filler() {
    // Data found in AddressLessThan20Filler.json
    let _address: Address = "0b9331677e6ebf".parse().unwrap();
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

#[test]
fn hashed() {
    // One of the use cases for Address could be a key in a HashMap to store some
    // additional values per address.
    use std::collections::HashMap;
    let a = Address::from_str("0x000000000000000000000000000b9331677e6ebf").unwrap();
    let b = Address::from_str("0x00000000000000000000000000000000deadbeef").unwrap();
    let mut map = HashMap::new();
    map.insert(a, "Foo");
    map.insert(b, "Bar");

    assert_eq!(&map[&a], &"Foo");
    assert_eq!(&map[&b], &"Bar");
}

#[test]
fn ordered() {
    let a = Address::from_str("0x000000000000000000000000000000000000000a").unwrap();
    let b = Address::from_str("0x000000000000000000000000000000000000000b").unwrap();
    let c = Address::from_str("0x000000000000000000000000000000000000000c").unwrap();
    assert!(c > b);
    assert!(b > a);
    assert!(b < c);
    assert!(a < c);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn to_hex() {
    let address: Address = "1234567890123456789ABCDEF678901234567890"
        .parse::<Address>()
        .unwrap();

    assert_eq!(
        format!("{:x}", address),
        "1234567890123456789abcdef678901234567890",
    );
    assert_eq!(
        format!("{:#x}", address),
        "0x1234567890123456789abcdef678901234567890",
    );
    assert_eq!(
        format!("{:#X}", address),
        "0x1234567890123456789ABCDEF678901234567890",
    );
}
