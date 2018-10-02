use address::Address;
use byteorder::{BigEndian, WriteBytesExt};
/// A module to simplify ABI encoding
///
/// For simplicity, it is based on tokens. You have to specify a list of
/// tokens and they will be automatically encoded.
///
/// Additionally there are helpers to help deal with deriving a function
/// signatures.
///
/// This is not a full fledged implemementation of ABI encoder, it is more
/// like a bunch of helpers that would help to successfuly encode a contract
/// call.
///
use num_bigint::{BigInt, BigUint};
use sha3::{Digest, Keccak256};

/// A token represents a value of parameter of the contract call.
///
/// For numbers it uses `num_bigint` crate directly.
pub enum Token {
    /// Unsigned type with value already encoded.
    Uint {
        size: usize,
        value: BigUint,
    },
    Address(Address),
    Bool(bool),
    /// Represents a string
    String(String),
    /// Dynamic array of bytes
    DynamicBytes(Vec<u8>),
    /// Fixed size array of bytes
    Bytes {
        size: usize,
        value: Vec<u8>,
    },
}

/// Representation of a serialized token.
pub enum SerializedToken {
    /// This data can be safely appended to the output stream
    Static([u8; 32]),
    /// This data should be saved up in a buffer, and an offset should be
    /// appended to the output stream.
    Dynamic([u8; 32]),
}

impl Token {
    fn fixed_bytes(size: usize, value: Vec<u8>) -> Token {
        Token::Bytes {
            size: size,
            value: value,
        }
    }

    fn serialize(&self) -> SerializedToken {
        match *self {
            Token::Uint { size, ref value } => {
                assert!(size % 8 == 0);
                let bytes = value.to_bytes_be();
                let mut res: [u8; 32] = Default::default();
                res[32 - bytes.len()..].copy_from_slice(&bytes);
                SerializedToken::Static(res)
            }
            Token::Bool(value) => {
                let mut res: [u8; 32] = Default::default();
                res[31] = value as u8;
                SerializedToken::Static(res)
            }
            _ => unimplemented!("I dont know yet"),
        }
    }
}

impl From<u8> for Token {
    fn from(v: u8) -> Token {
        Token::Uint {
            size: 8,
            value: BigUint::from(v),
        }
    }
}

impl From<u16> for Token {
    fn from(v: u16) -> Token {
        Token::Uint {
            size: 16,
            value: BigUint::from(v),
        }
    }
}

impl From<u32> for Token {
    fn from(v: u32) -> Token {
        Token::Uint {
            size: 32,
            value: BigUint::from(v),
        }
    }
}

impl From<u64> for Token {
    fn from(v: u64) -> Token {
        Token::Uint {
            size: 64,
            value: BigUint::from(v),
        }
    }
}

impl From<BigUint> for Token {
    fn from(v: BigUint) -> Token {
        // BigUint are assumed to have 256 bits
        assert!(v.bits() <= 256);
        Token::Uint {
            size: 256,
            value: v,
        }
    }
}

impl From<bool> for Token {
    fn from(v: bool) -> Token {
        Token::Bool(v)
    }
}

impl From<Vec<u8>> for Token {
    fn from(v: Vec<u8>) -> Token {
        Token::DynamicBytes(v)
    }
}

/// Given a signature it derives a Method ID
fn derive_method_id(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    debug_assert!(digest.len() >= 4);
    let mut result: [u8; 4] = Default::default();
    result.copy_from_slice(&digest[0..4]);
    result
}

#[test]
fn derive_baz() {
    use utils::bytes_to_hex_str;
    assert_eq!(
        bytes_to_hex_str(&derive_method_id("baz(uint32,bool)")),
        "cdcd77c0"
    );
}

#[test]
fn derive_bar() {
    use utils::bytes_to_hex_str;
    assert_eq!(
        bytes_to_hex_str(&derive_method_id("bar(bytes3[2])")),
        "fce353f6"
    );
}

#[test]
fn derive_sam() {
    use utils::bytes_to_hex_str;
    assert_eq!(
        bytes_to_hex_str(&derive_method_id("sam(bytes,bool,uint256[])")),
        "a5643bf2"
    );
}

#[test]
fn derive_f() {
    use utils::bytes_to_hex_str;
    assert_eq!(
        bytes_to_hex_str(&derive_method_id("f(uint256,uint32[],bytes10,bytes)")),
        "8be65246"
    );
}

/// This one is a very simplified ABI encoder that takes a bunch of tokens,
/// and serializes them.
///
/// This version is greatly simplified and doesn't support nested arrays etc.
///
/// Use with caution!
fn encode_tokens(tokens: &[Token]) -> Vec<u8> {
    let mut res = Vec::new();
    for ref token in tokens.iter() {
        match token.serialize() {
            SerializedToken::Static(data) => res.extend(&data),
            SerializedToken::Dynamic(data) => unimplemented!("Dynamic unsupported yet"),
        }
    }
    res
}

#[test]
fn encode_simple() {
    use utils::bytes_to_hex_str;
    let result = encode_tokens(&[69u32.into(), true.into()]);
    assert_eq!(
        bytes_to_hex_str(&result),
        concat!(
            "0000000000000000000000000000000000000000000000000000000000000045",
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    );
}
