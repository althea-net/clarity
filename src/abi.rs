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
#[derive(Debug)]
pub enum Token {
    /// Unsigned type with value already encoded.
    Uint(BigUint),
    Address(Address),
    Bool(bool),
    /// Represents a string
    String(String),
    /// Fixed size array of bytes
    Bytes(Vec<u8>),
    /// Dynamic array
    Dynamic(Vec<Token>),
}

/// Representation of a serialized token.
pub enum SerializedToken {
    /// This data can be safely appended to the output stream
    Static([u8; 32]),
    /// This data should be saved up in a buffer, and an offset should be
    /// appended to the output stream.
    Dynamic(Vec<u8>),
}

impl SerializedToken {
    /// Gets a reference to value held by Static
    fn as_static_ref(&self) -> Option<&[u8; 32]> {
        match *self {
            SerializedToken::Static(ref data) => Some(&data),
            _ => None,
        }
    }
    /// Gets a reference to value held by Dynamic
    fn as_dynamic_ref(&self) -> Option<&Vec<u8>> {
        match *self {
            SerializedToken::Dynamic(ref data) => Some(&data),
            _ => None,
        }
    }
}

impl Token {
    pub fn serialize(&self) -> SerializedToken {
        match *self {
            Token::Uint(ref value) => {
                assert!(value.bits() <= 256);
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
            Token::Dynamic(ref tokens) => {
                // This one supports only 1 dimension, and in theory
                // adding support for multiple dimmension mixed with static
                // or dynamic bounds (i.e. string[10][9]) could be trivial
                // and we could call serialize recursively, and return multiple
                // SerializedTokens. For our needs it implements just simple case
                // with one dimension max.
                let mut wtr = vec![];
                let prefix: Token = (tokens.len() as u64).into();
                wtr.extend(prefix.serialize().as_static_ref().unwrap());
                for token in tokens.iter() {
                    wtr.extend(
                        token
                            .serialize()
                            .as_static_ref()
                            .expect("Only nested tokens of static size are supported"),
                    );
                }
                SerializedToken::Dynamic(wtr)
            }
            Token::String(ref s) => {
                let mut wtr = vec![];
                // Encode prefix
                let prefix: Token = (s.len() as u64).into();
                wtr.extend(prefix.serialize().as_static_ref().unwrap());
                // Pad on the right
                wtr.extend(s.as_bytes());

                let pad_right = (((s.len() - 1) / 32) + 1) * 32;
                wtr.extend(vec![0x00u8; pad_right - s.len()]);
                SerializedToken::Dynamic(wtr)
            }
            Token::Bytes(ref value) => {
                // This value is padded at the end. It is limited to 32 bytes.
                assert!(value.len() <= 32);
                let mut wtr: [u8; 32] = Default::default();
                wtr[0..value.len()].copy_from_slice(&value[..]);
                SerializedToken::Static(wtr)
            }
            Token::Address(ref address) => {
                // Address is the same as above, but for extra syntax sugar
                // we treat it as separate case.
                let mut wtr: [u8; 32] = Default::default();
                let bytes = address.as_bytes();
                wtr[32 - bytes.len()..].copy_from_slice(&bytes);
                SerializedToken::Static(wtr)
            }
        }
    }
}

impl From<u8> for Token {
    fn from(v: u8) -> Token {
        Token::Uint(BigUint::from(v))
    }
}

impl From<u16> for Token {
    fn from(v: u16) -> Token {
        Token::Uint(BigUint::from(v))
    }
}

impl From<u32> for Token {
    fn from(v: u32) -> Token {
        Token::Uint(BigUint::from(v))
    }
}

impl From<u64> for Token {
    fn from(v: u64) -> Token {
        Token::Uint(BigUint::from(v))
    }
}

impl From<BigUint> for Token {
    fn from(v: BigUint) -> Token {
        // BigUint are assumed to have maximum of 256 bits
        assert!(v.bits() <= 256);
        Token::Uint(v)
    }
}

impl From<bool> for Token {
    fn from(v: bool) -> Token {
        Token::Bool(v)
    }
}

impl From<Vec<u32>> for Token {
    fn from(v: Vec<u32>) -> Token {
        Token::Dynamic(v.into_iter().map(|v| v.into()).collect())
    }
}

impl From<Address> for Token {
    fn from(v: Address) -> Token {
        Token::Address(v)
    }
}

impl<'a> From<&'a str> for Token {
    fn from(v: &'a str) -> Token {
        Token::String(v.into())
    }
}

/// Given a signature it derives a Method ID
pub fn derive_method_id(signature: &str) -> [u8; 4] {
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
pub fn encode_tokens(tokens: &[Token]) -> Vec<u8> {
    // This is the result data buffer
    let mut res = Vec::new();

    // A cache of dynamic data buffers that are stored here.
    let mut dynamic_data: Vec<Vec<u8>> = Vec::new();

    for ref token in tokens.iter() {
        match token.serialize() {
            SerializedToken::Static(data) => res.extend(&data),
            SerializedToken::Dynamic(data) => {
                // This is the offset for dynamic data that is calculated
                // based on the lengtho f all dynamic data buffers stored,
                // and added to the "base" offset which is all tokens length.
                // The base offset is assumed to be 32 * len(tokens) which is true
                // since dynamic data is actually an static variable of size of
                // 32 bytes.
                let dynamic_offset = dynamic_data
                    .iter()
                    .map(|data| data.len() as u64)
                    .fold(tokens.len() as u64 * 32, |r, v| r + v);

                // Store next dynamic buffer *after* dynamic offset is calculated.
                dynamic_data.push(data);
                // Convert into token for easy serialization
                let offset: Token = dynamic_offset.into();
                // Write the offset of the dynamic data as a value of static size.
                match offset.serialize() {
                    SerializedToken::Static(bytes) => res.extend(&bytes),
                    _ => panic!("Offset token is expected to be static"),
                }
            }
        }
    }
    // Concat all the dynamic data buffers at the end of the process
    // All the offsets are calculated while iterating and properly stored
    // in a single pass.
    for ref data in dynamic_data.iter() {
        res.extend(&data[..]);
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

#[test]
fn encode_sam() {
    use utils::bytes_to_hex_str;
    let result = encode_tokens(&["dave".into(), true.into(), vec![1u32, 2u32, 3u32].into()]);
    assert!(result.len() % 8 == 0);
    assert_eq!(
        bytes_to_hex_str(&result),
        concat![
            // the location of the data part of the first parameter
            // (dynamic type), measured in bytes from the start of the
            // arguments block. In this case, 0x60.
            "0000000000000000000000000000000000000000000000000000000000000060",
            // the second parameter: boolean true.
            "0000000000000000000000000000000000000000000000000000000000000001",
            // the location of the data part of the third parameter
            // (dynamic type), measured in bytes. In this case, 0xa0.
            "00000000000000000000000000000000000000000000000000000000000000a0",
            // the data part of the first argument, it starts with the length
            // of the byte array in elements, in this case, 4.
            "0000000000000000000000000000000000000000000000000000000000000004",
            // the contents of the first argument: the UTF-8 (equal to ASCII
            // in this case) encoding of "dave", padded on the right to 32
            // bytes.
            "6461766500000000000000000000000000000000000000000000000000000000",
            // the data part of the third argument, it starts with the length
            // of the array in elements, in this case, 3.
            "0000000000000000000000000000000000000000000000000000000000000003",
            // the first entry of the third parameter.
            "0000000000000000000000000000000000000000000000000000000000000001",
            // the second entry of the third parameter.
            "0000000000000000000000000000000000000000000000000000000000000002",
            // the third entry of the third parameter.
            "0000000000000000000000000000000000000000000000000000000000000003",
        ]
    );
}

#[test]
fn encode_f() {
    use utils::bytes_to_hex_str;
    let result = encode_tokens(&[
        0x123u32.into(),
        vec![0x456u32, 0x789u32].into(),
        Token::Bytes("1234567890".as_bytes().to_vec()),
        "Hello, world!".into(),
    ]);
    assert!(result.len() % 8 == 0);
    assert_eq!(
        result[..]
            .chunks(32)
            .map(|c| bytes_to_hex_str(&c))
            .collect::<Vec<String>>(),
        vec![
            "0000000000000000000000000000000000000000000000000000000000000123".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000080".to_owned(),
            "3132333435363738393000000000000000000000000000000000000000000000".to_owned(),
            "00000000000000000000000000000000000000000000000000000000000000e0".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000002".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000456".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000789".to_owned(),
            "000000000000000000000000000000000000000000000000000000000000000d".to_owned(),
            "48656c6c6f2c20776f726c642100000000000000000000000000000000000000".to_owned(),
        ]
    );
}

#[test]
fn encode_address() {
    use utils::bytes_to_hex_str;
    let result = encode_tokens(&["0x00000000000000000000000000000000deadbeef"
        .parse::<Address>()
        .expect("Unable to parse address")
        .into()]);
    assert!(result.len() % 8 == 0);
    assert_eq!(
        result[..]
            .chunks(32)
            .map(|c| bytes_to_hex_str(&c))
            .collect::<Vec<String>>(),
        vec!["00000000000000000000000000000000000000000000000000000000deadbeef".to_owned(),]
    );
}

#[test]
fn encode_dynamic_only() {
    use utils::bytes_to_hex_str;
    let result = encode_tokens(&["foo".into(), "bar".into()]);
    assert!(result.len() % 8 == 0);
    assert_eq!(
        result[..]
            .chunks(32)
            .map(|c| bytes_to_hex_str(&c))
            .collect::<Vec<String>>(),
        vec![
            "0000000000000000000000000000000000000000000000000000000000000040".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000080".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000003".to_owned(),
            "666f6f0000000000000000000000000000000000000000000000000000000000".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000003".to_owned(),
            "6261720000000000000000000000000000000000000000000000000000000000".to_owned(),
        ]
    );
}

/// A helper function that encodes both signature and a list of tokens.
pub fn encode_call(sig: &str, tokens: &[Token]) -> Vec<u8> {
    let mut wtr = vec![];
    wtr.extend(&derive_method_id(sig));
    wtr.extend(encode_tokens(tokens));
    wtr
}
