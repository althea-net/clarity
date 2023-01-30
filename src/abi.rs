//! A module to simplify ABI encoding
//!
//! For simplicity, it is based on tokens (as in items, not as in coin tokens). You have to specify a list of
//! tokens and they will be automatically encoded.
//!
//! Additionally there are helpers to help deal with deriving a function
//! signatures.
//!
//! This is not a full fledged implementation of ABI encoder, it is more
//! like a bunch of helpers that would help to successfully encode a contract
//! call.
//!
//! ## Limitation
//!
//! Currently this module can only serialize types that can be represented by a [Token](#struct.Token).
//!
//! Unfortunately if you need to support custom type that is not currently supported you are welcome to open an issue [on issues page](https://github.com/althea-net/clarity/issues/new),
//! or do the serialization yourself by converting your custom type into a `[u8; 32]` array and creating a proper Token instance.

use crate::address::Address;
use crate::error::Error;
use num256::Uint256;
use sha3::{Digest, Keccak256};

/// A token represents a value of parameter of the contract call.
///
/// For each supported type there is separate entry that later is helpful to determine
/// actual byte representation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Token {
    /// Unsigned type with value already encoded.
    Uint(Uint256),
    /// Ethereum Address
    Address(Address),
    /// A boolean logic
    Bool(bool),
    /// Represents a string
    String(String),
    /// Represents a string encoded into a fixed size bytes32
    FixedString(String),
    /// Fixed size array of bytes
    Bytes(Vec<u8>),
    /// This is a dynamic array of bytes that reflects dynamic "bytes" type in Solidity
    UnboundedBytes(Vec<u8>),
    /// Dynamic array with supported values of supported types already converted
    Dynamic(Vec<Token>),
    /// A struct to be encoded as a contract call argument
    Struct(Vec<Token>),
}

/// Representation of a serialized token.
///
/// Serialization occurs once a list of tokens is passed. After that
/// the library will determine the actual ABI encoding of a each type wrapped in
/// a token, and then it will return a
/// [SerializedToken::Static](#variant.Static), or
/// [SerializedToken::Dynamic](#variant.Dynamic) depending on encoding rules
/// used for a given type.
///
/// With a list of values of type `SerializedToken` a caller can construct a final
/// binary data that will represent a valid ABI encoding of function parameters.
pub enum SerializedToken {
    /// This data can be safely appended to the output stream
    Static([u8; 32]),
    /// This data should be saved up in a buffer, and an offset should be
    /// appended to the output stream instead.
    Dynamic(Vec<u8>),
}

impl SerializedToken {
    /// Gets a reference to value held by Static
    fn as_static_ref(&self) -> Option<&[u8; 32]> {
        match *self {
            SerializedToken::Static(ref data) => Some(data),
            _ => None,
        }
    }
}

impl Token {
    /// Serializes a token into a [SerializedToken]()
    pub fn serialize(&self) -> SerializedToken {
        match *self {
            Token::Uint(ref value) => {
                assert!(value.bits() <= 256);
                let bytes = value.to_be_bytes();
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
                let mut wtr = vec![];
                let prefix: Token = (tokens.len() as u64).into();
                wtr.extend(prefix.serialize().as_static_ref().unwrap());
                wtr.extend(encode_tokens(tokens));
                SerializedToken::Dynamic(wtr)
            }
            Token::Struct(ref tokens) => SerializedToken::Dynamic(encode_tokens(tokens)),
            Token::UnboundedBytes(ref v) => {
                let mut wtr = vec![];
                // Encode prefix
                let prefix: Token = (v.len() as u64).into();
                wtr.extend(prefix.serialize().as_static_ref().unwrap());
                // Pad on the right
                wtr.extend(v);

                let pad_right = (((v.len() - 1) / 32) + 1) * 32;
                wtr.extend(vec![0x00u8; pad_right - v.len()]);
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
            Token::FixedString(ref s) => {
                // gets the utf8 encoded bytes of the string value
                let value = s.to_string().as_bytes().to_vec();
                // This value is padded at the end. It is limited to 32 bytes.
                // if the fixed string is too long here we panic
                assert!(value.len() <= 32);
                let mut wtr: [u8; 32] = Default::default();
                wtr[0..value.len()].copy_from_slice(&value[..]);
                SerializedToken::Static(wtr)
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
                wtr[32 - bytes.len()..].copy_from_slice(bytes);
                SerializedToken::Static(wtr)
            }
        }
    }
}

impl From<u8> for Token {
    fn from(v: u8) -> Token {
        Token::Uint(Uint256::from(v))
    }
}

impl From<u16> for Token {
    fn from(v: u16) -> Token {
        Token::Uint(Uint256::from(v))
    }
}

impl From<u32> for Token {
    fn from(v: u32) -> Token {
        Token::Uint(Uint256::from(v))
    }
}

impl From<u64> for Token {
    fn from(v: u64) -> Token {
        Token::Uint(Uint256::from(v))
    }
}

impl From<u128> for Token {
    fn from(v: u128) -> Token {
        Token::Uint(Uint256::from(v))
    }
}

impl From<bool> for Token {
    fn from(v: bool) -> Token {
        Token::Bool(v)
    }
}

impl From<Vec<u8>> for Token {
    fn from(v: Vec<u8>) -> Token {
        Token::UnboundedBytes(v)
    }
}

impl From<Vec<u16>> for Token {
    fn from(v: Vec<u16>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<u32>> for Token {
    fn from(v: Vec<u32>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<u64>> for Token {
    fn from(v: Vec<u64>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<u128>> for Token {
    fn from(v: Vec<u128>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<Address> for Token {
    fn from(v: Address) -> Token {
        Token::Address(v)
    }
}

impl From<&Address> for Token {
    fn from(v: &Address) -> Token {
        Token::Address(*v)
    }
}

impl<'a> From<&'a str> for Token {
    fn from(v: &'a str) -> Token {
        Token::String(v.into())
    }
}

impl From<Vec<Address>> for Token {
    fn from(v: Vec<Address>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<Token>> for Token {
    fn from(v: Vec<Token>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<&[Address]> for Token {
    fn from(v: &[Address]) -> Token {
        Token::Dynamic(v.iter().map(Into::into).collect())
    }
}

impl From<Uint256> for Token {
    fn from(v: Uint256) -> Token {
        Token::Uint(v)
    }
}

impl From<&Uint256> for Token {
    fn from(v: &Uint256) -> Token {
        Token::Uint(*v)
    }
}

impl From<Vec<Uint256>> for Token {
    fn from(v: Vec<Uint256>) -> Token {
        Token::Dynamic(v.into_iter().map(Into::into).collect())
    }
}

impl From<&[Uint256]> for Token {
    fn from(v: &[Uint256]) -> Token {
        Token::Dynamic(v.iter().map(Into::into).collect())
    }
}

/// Raw derive for a Keccak256 digest from a string
///
/// This function should be used when trying to filter out interesting
/// events from a contract. This is different than contract function
/// calls because it uses whole 32 bytes of the hash digest.
pub fn derive_signature(data: &str) -> Result<[u8; 32], Error> {
    if data.contains(' ') {
        return Err(Error::InvalidCallError(
            "No spaces are allowed in call names".to_string(),
        ));
    } else if !(data.contains('(') && data.contains(')')) {
        return Err(Error::InvalidCallError(
            "Mismatched call braces".to_string(),
        ));
    }

    let digest = Keccak256::digest(data.as_bytes());
    let mut result: [u8; 32] = Default::default();
    result.copy_from_slice(&digest);
    Ok(result)
}

/// Given a signature it derives a Method ID
pub fn derive_method_id(signature: &str) -> Result<[u8; 4], Error> {
    let digest = derive_signature(signature)?;
    let mut result: [u8; 4] = Default::default();
    result.copy_from_slice(&digest[0..4]);
    Ok(result)
}

/// This one is a very simplified ABI encoder that takes a bunch of tokens,
/// and serializes them.
///
/// Use with caution!
pub fn encode_tokens(tokens: &[Token]) -> Vec<u8> {
    // This is the result data buffer
    let mut res = Vec::new();

    // A cache of dynamic data buffers that are stored here.
    let mut dynamic_data: Vec<Vec<u8>> = Vec::new();

    for token in tokens.iter() {
        match token.serialize() {
            SerializedToken::Static(data) => res.extend(data),
            SerializedToken::Dynamic(data) => {
                // This is the offset for dynamic data that is calculated
                // based on the length of all dynamic data buffers stored,
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

                // static structs do not require offsets as they aren't actually
                // of dynamic length
                if !is_static_struct_array(tokens) {
                    // Convert into token for easy serialization
                    let offset: Token = dynamic_offset.into();
                    // Write the offset of the dynamic data as a value of static size.
                    match offset.serialize() {
                        SerializedToken::Static(bytes) => res.extend(bytes),
                        _ => panic!("Offset token is expected to be static"),
                    }
                }
            }
        }
    }
    // Concat all the dynamic data buffers at the end of the process
    // All the offsets are calculated while iterating and properly stored
    // in a single pass.
    // let values = &dynamic_data.iter();
    for data in dynamic_data.iter() {
        res.extend(&data[..]);
    }
    res
}

/// Gets the Keccak256 hash of some input bytes. Signatures in Ethereum are nearly without
/// exception performed after encoding using the ABI, then hashing using this function.
pub fn get_hash(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// A helper function that encodes both signature and a list of tokens.
pub fn encode_call(sig: &str, tokens: &[Token]) -> Result<Vec<u8>, Error> {
    let mut wtr = vec![];
    wtr.extend(derive_method_id(sig)?);

    let args_count = get_args_count(sig)?;
    let token_count = get_tokens_count(tokens);
    if args_count != token_count {
        return Err(Error::InvalidCallError(format!(
            "Function call contains {args_count} arguments, but {token_count} provided"
        )));
    }

    wtr.extend(encode_tokens(tokens));
    Ok(wtr)
}

/// Counts the number of tokens in a token array, including nested tokens
/// this will give you the number of tokens you need in a function call
/// argument string
fn get_tokens_count(tokens: &[Token]) -> usize {
    let mut count = 0;
    for token in tokens {
        match token {
            Token::Struct(v) => count += get_tokens_count(v),
            // for the case of an array of structs we count that structs members
            // that is what we'll see in the function header
            Token::Dynamic(d) => {
                if is_struct_array(d) && !d.is_empty() {
                    count += get_tokens_count(&[d[0].clone()])
                } else {
                    count += 1
                }
            }
            _ => count += 1,
        }
    }
    count
}

/// Simple utility function to detect arrays of structs
fn is_struct_array(input: &[Token]) -> bool {
    // arguable null case, could go either way
    if input.is_empty() {
        return false;
    }
    for t in input {
        match t {
            Token::Struct(_) => {}
            _ => return false,
        }
    }
    true
}

/// Simple utility function to detect arrays of structs that are all static in size
fn is_static_struct_array(input: &[Token]) -> bool {
    // arguable null case, could go either way
    if input.is_empty() {
        return false;
    }
    for t in input {
        match t {
            Token::Struct(v) => {
                for t in v {
                    if let SerializedToken::Dynamic(_) = t.serialize() {
                        return false;
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

/// Gets the number of arguments by parsing a function signature
/// string.
fn get_args_count(sig: &str) -> Result<usize, Error> {
    // number of opening brackets must match number of closing brackets
    if sig.matches('(').count() != sig.matches(')').count() {
        return Err(Error::InvalidCallError(
            "Mismatched call braces".to_string(),
        ));
    }
    // split on either an opening or closing bracket, substrings are now all batches of arguments
    let args = sig.split(|ch| ch == '(' || ch == ')');
    let mut num_args = 0;
    for substring in args {
        // leading or trailing ,'s or []
        let substring = substring.trim_matches(|c| c == ']' || c == '[');
        let substring = substring.trim_matches(',');
        let substring = substring.trim();
        if !substring.is_empty() {
            num_args += substring.split(',').count();
        }
    }
    // subtract one because the function signature will be in
    // one substring always
    Ok(num_args - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex_str_to_bytes;

    #[test]
    fn derive_event_signature() {
        use crate::utils::bytes_to_hex_str;
        let derived = derive_signature("HelloWorld(string)").unwrap();
        assert_eq!(
            bytes_to_hex_str(&derived),
            "86066750c0fd4457fd16f79750914fbd72db952f2ff0a7b5c6a2a531bc15ce2c"
        );
        let derived = derive_signature("Transfer(address,address,uint256)").unwrap();
        assert_eq!(
            bytes_to_hex_str(&derived),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
        let derived = derive_signature("Approval(address,address,uint256)").unwrap();
        assert_eq!(
            bytes_to_hex_str(&derived),
            "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
        );
    }

    #[test]
    fn derive_baz() {
        use crate::utils::bytes_to_hex_str;
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("baz(uint32,bool)").unwrap()),
            "cdcd77c0"
        );
    }

    #[test]
    fn derive_bar() {
        use crate::utils::bytes_to_hex_str;
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("bar(bytes3[2])").unwrap()),
            "fce353f6"
        );
    }

    #[test]
    fn derive_sam() {
        use crate::utils::bytes_to_hex_str;
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("sam(bytes,bool,uint256[])").unwrap()),
            "a5643bf2"
        );
    }

    #[test]
    fn derive_complex_signatures() {
        use crate::utils::bytes_to_hex_str;
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("dummyUpdateValset(address[])").unwrap()),
            "fd9b9103"
        );
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("dummyUpdateValset(address[],uint256[])").unwrap()),
            "711ca6ac"
        );
        assert_eq!(bytes_to_hex_str(&derive_method_id("updateValset((address[],uint256[],uint256,uint256,address),(address[],uint256[],uint256,uint256,address),(uint8,bytes32,bytes32)[])").unwrap()), "aca6b1c1");
        assert_eq!(bytes_to_hex_str(&derive_method_id("submitLogicCall((address[],uint256[],uint256,uint256,address),(uint8,bytes32,bytes32)[],(uint256[],address[],uint256[],address[],address,bytes,uint256,bytes32,uint256))").unwrap()), "6941db93");
    }

    #[test]
    fn derive_f() {
        use crate::utils::bytes_to_hex_str;
        assert_eq!(
            bytes_to_hex_str(&derive_method_id("f(uint256,uint32[],bytes10,bytes)").unwrap()),
            "8be65246"
        );
    }

    #[test]
    fn derive_function_with_args() {
        encode_call("f()", &[]).unwrap();
        encode_call("f(uint256)", &["66u64".into()]).unwrap();
        encode_call("f(uint256,uint256)", &["66u64".into(), "66u64".into()]).unwrap();
        encode_call(
            "f(uint256,uint256,uint256)",
            &["66u64".into(), "66u64".into(), "66u64".into()],
        )
        .unwrap();
    }

    #[test]
    fn attempt_to_derive_invalid_function_signatures() {
        assert!(derive_method_id("dummyUpdateValset( address[])").is_err());
        assert!(derive_method_id("dummyUpdateValsetaddress[],uint256[])").is_err());
        assert!(encode_call("dummyUpdateValset(address[],uint256[])", &["66u64".into()]).is_err());
    }

    #[test]
    fn encode_simple() {
        use crate::utils::bytes_to_hex_str;
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
        use crate::utils::bytes_to_hex_str;
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
        use crate::utils::bytes_to_hex_str;
        let result = encode_tokens(&[
            0x123u32.into(),
            vec![0x456u32, 0x789u32].into(),
            Token::Bytes(b"1234567890".to_vec()),
            "Hello, world!".into(),
        ]);
        assert!(result.len() % 8 == 0);
        assert_eq!(
            result[..]
                .chunks(32)
                .map(bytes_to_hex_str)
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
    fn encode_f_with_real_unbounded_bytes() {
        use crate::utils::bytes_to_hex_str;
        let result = encode_tokens(&[
            0x123u32.into(),
            vec![0x456u32, 0x789u32].into(),
            Token::Bytes(b"1234567890".to_vec()),
            b"Hello, world!".to_vec().into(),
        ]);
        assert!(result.len() % 8 == 0);
        assert_eq!(
            result[..]
                .chunks(32)
                .map(bytes_to_hex_str)
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
        use crate::utils::bytes_to_hex_str;
        let result = encode_tokens(&["0x00000000000000000000000000000000deadbeef"
            .parse::<Address>()
            .expect("Unable to parse address")
            .into()]);
        assert!(result.len() % 8 == 0);
        assert_eq!(
            result[..]
                .chunks(32)
                .map(bytes_to_hex_str)
                .collect::<Vec<String>>(),
            vec!["00000000000000000000000000000000000000000000000000000000deadbeef".to_owned(),]
        );
    }

    #[test]
    fn encode_dynamic_only() {
        use crate::utils::bytes_to_hex_str;
        let result = encode_tokens(&["foo".into(), "bar".into()]);
        assert!(result.len() % 8 == 0);
        assert_eq!(
            result[..]
                .chunks(32)
                .map(bytes_to_hex_str)
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

    #[test]
    fn encode_peggy_checkpoint_hash() {
        use crate::utils::bytes_to_hex_str;
        // the valset nonce
        let nonce: Uint256 = 0u32.into();
        // the list of validator ethereum addresses represented by this
        let validators: Token = vec![
            "0xc783df8a850f42e7F7e57013759C285caa701eB6"
                .parse::<Address>()
                .unwrap(),
            "0xeAD9C93b79Ae7C1591b1FB5323BD777E86e150d4"
                .parse()
                .unwrap(),
            "0xE5904695748fe4A84b40b3fc79De2277660BD1D3"
                .parse()
                .unwrap(),
        ]
        .into();
        // list of powers represented
        let powers: Token = vec![3333u32, 3333, 3333].into();
        let encoded = "666f6f0000000000000000000000000000000000000000000000000000000000636865636b706f696e7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000003000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb6000000000000000000000000ead9c93b79ae7c1591b1fb5323bd777e86e150d4000000000000000000000000e5904695748fe4a84b40b3fc79de2277660bd1d300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d05";
        // the hash resulting from the encode call
        let encoded_hash = "88165860d955aee7dc3e83d9d1156a5864b708841965585d206dbef6e9e1a499";
        let result = encode_tokens(&[
            Token::FixedString("foo".to_string()),
            Token::FixedString("checkpoint".to_string()),
            nonce.into(),
            validators,
            powers,
        ]);

        assert_eq!(encoded, bytes_to_hex_str(&result));
        assert_eq!(encoded_hash, bytes_to_hex_str(&get_hash(&result)))
    }

    #[test]
    fn encode_function_with_only_struct_arg() {
        let correct = hex_str_to_bytes(
            "0x414bf389000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb6000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb600000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb600000000000000000000000000000000000000000000000000000000000186a000000000000000000000000000000000000000000000000000000000000186a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let address: Address = "0xc783df8a850f42e7F7e57013759C285caa701eB6"
            .parse()
            .unwrap();

        let tokens: Vec<Token> = vec![
            address.into(),
            address.into(),
            500u16.into(),
            address.into(),
            100_000u32.into(),
            100_000u32.into(),
            0u8.into(),
            0u8.into(),
        ];
        let tokens = [Token::Struct(tokens)];
        let sig =
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))";
        let payload = encode_call(sig, &tokens).unwrap();
        assert_eq!(correct, payload);
    }

    #[test]
    /// This test encodes an abiV2 function call, specifically one
    /// with a nontrivial struct in the header
    fn encode_abiv2_function_header() {
        use crate::utils::bytes_to_hex_str;
        let signature = "submitLogicCall(address[],uint256[],uint256,uint8[],bytes32[],bytes32[],(uint256[],address[],uint256[],address[],address,bytes,uint256,bytes32,uint256))";
        let encoded_method_id = "0x0c246c82";
        let res = derive_method_id(signature).unwrap();
        assert_eq!(encoded_method_id, format!("0x{}", bytes_to_hex_str(&res)));
    }

    #[test]
    /// This test encodes an abiV2 function call, specifically one
    /// with a nontrivial struct in the header
    fn encode_uniswap_header() {
        use crate::utils::bytes_to_hex_str;
        let signature =
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))";
        let encoded_method_id = "0x414bf389";
        let res = derive_method_id(signature).unwrap();
        assert_eq!(encoded_method_id, format!("0x{}", bytes_to_hex_str(&res)));
    }

    #[test]
    fn test_args_count() {
        let test_signatures = [
            ("testCall()", 0),
            ("testCall(uint256,uint256,uint256)", 3),
            ("updateValset((address[],uint256[],uint256,uint256,address),(address[],uint256[],uint256,uint256,address),uint8[],bytes32[],bytes32[])", 13),
        ("submitLogicCall(address[],uint256[],uint256,uint8[],bytes32[],bytes32[],(uint256[],address[],uint256[],address[],address,bytes,uint256,bytes32,uint256))", 15),
        ("updateValset((address[],uint256[],uint256,uint256,address),(address[],uint256[],uint256,uint256,address),(uint8[],bytes32[],bytes32[]))", 13),
        ("updateValset((address[],uint256[],uint256,uint256,address),(address[],uint256[],uint256,uint256,address),(uint8,bytes32,bytes32)[])", 13),
        ("submitBatch((address[],uint256[],uint256,uint256,address),(uint8,bytes32,bytes32)[],uint256[],address[],uint256[],uint256,address,uint256)", 14)
        ];
        for (sig, count) in test_signatures.iter() {
            assert_eq!(get_args_count(sig).unwrap(), *count);
        }
    }
}
