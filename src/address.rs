use crate::rlp::RlpToken;
use crate::utils::bytes_to_hex_str;
use crate::utils::display_uint256_as_address;
use crate::utils::hex_str_to_bytes;
use crate::Error;
use num256::Uint256;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sha3::{Digest, Keccak256};
use std::str;
use std::str::FromStr;
use std::{
    convert::TryFrom,
    fmt::{self, Display},
};

/// Representation of an Ethereum address.
///
/// Address is usually derived from a `PrivateKey`, or converted from its
/// textual representation.
#[derive(PartialEq, Clone, Copy, Eq, PartialOrd, Ord, Hash, Default)]
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
        if data.len() != 20 {
            return Err(Error::InvalidAddressLength {
                got: data.len(),
                expected: 20,
            });
        }

        let mut result: [u8; 20] = Default::default();
        result.copy_from_slice(data);
        Ok(Address(result))
    }

    /// Attempts to decode an address from RLP data, with special case
    /// handling for the zero address case
    pub fn from_rlp_data(data: RlpToken) -> Result<Address, Error> {
        let address_data = &data.get_byte_content()?;
        match Address::from_slice(address_data) {
            Ok(v) => Ok(v),
            Err(e) => {
                // an empty address field means the zero address
                // anything in between 0 bytes and 20 bytes is an error
                if address_data.is_empty() {
                    Ok(Address::default())
                } else {
                    Err(e)
                }
            }
        }
    }

    // Parses and validates the address according to the EIP-55 standard
    pub fn parse_and_validate(input: &str) -> Result<Address, Error> {
        let address: Address = input.parse()?;
        let eip_55_encoded = address.to_string();
        if eip_55_encoded == input {
            Ok(address)
        } else {
            Err(Error::InvalidEip55)
        }
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
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => &s,
        };

        hex_str_to_bytes(s)
            .and_then(move |bytes| Address::from_slice(&bytes))
            .map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 20]> for Address {
    fn from(val: [u8; 20]) -> Address {
        Address(val)
    }
}

impl From<[u8; 32]> for Address {
    fn from(val: [u8; 32]) -> Address {
        let mut data: [u8; 20] = Default::default();
        data.copy_from_slice(&val[12..]);
        Address(data)
    }
}

#[allow(clippy::from_over_into)]
impl Into<[u8; 20]> for Address {
    fn into(self) -> [u8; 20] {
        self.0
    }
}

#[allow(clippy::from_over_into)]
impl Into<[u8; 32]> for Address {
    fn into(self) -> [u8; 32] {
        let mut data: [u8; 32] = Default::default();
        data[12..].copy_from_slice(self.as_bytes());
        data
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let res = write!(f, "0x");
            res?;
        }

        for hex_char in self.0.iter() {
            let res = write!(f, "{hex_char:x}");
            res?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            let res = write!(f, "0x");
            res?;
        }

        for hex_char in self.0.iter() {
            let res = write!(f, "{hex_char:X}");
            res?;
        }
        Ok(())
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
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => s,
        };

        if s.len() == 40 {
            let r = hex_str_to_bytes(s)?;
            Ok(Address::from_slice(&r)?)
        } else {
            Err(Error::InvalidAddressLength {
                got: s.len(),
                expected: 40,
            })
        }
    }
}

/// Gets the EIP-55 encoded version of an address passed in as bytes
fn eip_55_string(address_bytes: [u8; 20]) -> String {
    let hex_str = bytes_to_hex_str(&address_bytes);
    let hash = Keccak256::digest(hex_str.as_bytes());
    let mut capitalized_hex_str: Vec<char> = Vec::new();
    for (counter, character) in hex_str.chars().enumerate() {
        match character {
            'a'..='f' => {
                // this is the real doozy here we're indexing
                // into the array to mask against the correct byte
                let index = (4 * counter) / 8;
                let bit = if counter > 0 {
                    // the 4 * i th bit indexed from the right which is why
                    // we need the -1 yes this is a bit backwards to think about
                    ((4 * counter) - 1) % 8
                } else {
                    // represent the zeroth bit of the hash string which
                    // is seven indexed from the other direction
                    7
                };
                if hash[index] & 1 << bit != 0 {
                    capitalized_hex_str.push(character.to_ascii_uppercase());
                } else {
                    capitalized_hex_str.push(character);
                }
            }
            '0'..='9' => capitalized_hex_str.push(character),
            // impossible output from bytes to hex str
            _ => panic!(),
        }
    }
    capitalized_hex_str.iter().collect()
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", eip_55_string(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", eip_55_string(self.0))
    }
}

impl TryFrom<Uint256> for Address {
    type Error = Error;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        let string = display_uint256_as_address(value);
        string.parse()
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
    let raw_address = "00000000000000000000000000000000000000C0";
    let address: Address = raw_address.parse().unwrap();
    assert_eq!(
        serde_json::to_string(&address).unwrap(),
        format!(r#""0x{raw_address}""#)
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
        format!("{address:x}"),
        "1234567890123456789abcdef678901234567890",
    );
    assert_eq!(
        format!("{address:#x}"),
        "0x1234567890123456789abcdef678901234567890",
    );
    assert_eq!(
        format!("{address:#X}"),
        "0x1234567890123456789ABCDEF678901234567890",
    );
}

#[test]
fn eip_55_validate() {
    // testcases taken from here https://eips.ethereum.org/EIPS/eip-55
    let eip_55_testcases = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    let eip_55_invalid = [
        "0x52908400098527886E0F7030069857D2E4169eE7",
        "0x8617E340b3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fB77",
        "0x27b1fDb04752bbc536007a920d24acb045561c26",
        "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xFB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01e7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDB",
    ];
    for starting_address in eip_55_testcases.iter() {
        let unvalidated: Address = starting_address.parse().unwrap();
        let failure_message =
            format!("Failed to validate address theirs: {starting_address} ours: {unvalidated} !");
        let _address: Address =
            Address::parse_and_validate(starting_address).expect(&failure_message);
    }
    for starting_address in eip_55_invalid.iter() {
        assert!(Address::parse_and_validate(starting_address).is_err())
    }
}

#[test]
fn eip_55_display() {
    // testcases taken from here https://eips.ethereum.org/EIPS/eip-55
    let eip_55_testcases = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    for starting_address in eip_55_testcases.iter() {
        // this also checks that parse still functions properly with
        // eip invalid but otherwise correct addresses
        let unvalidated: Address = starting_address.parse().unwrap();
        assert_eq!(format!("{unvalidated}"), **starting_address)
    }
}
