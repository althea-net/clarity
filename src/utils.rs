use crate::private_key::ETHEREUM_SALT;
use crate::Error;
use num256::Uint256;
use serde::{
    de::{Deserialize, Deserializer},
    ser::Serializer,
};
use sha3::{Digest, Keccak256};
use std::str;

/// Takes a signature payload of arbitrary size and creates a proper payload
/// for an ethereum_msg signature.
///
/// Internally this means `Keccak256` hashing the data, appending the Ethereum signed
/// msg constant, then hashing it again.
///
/// This is how you would verify the data from [sign_ethereum_msg](#method.sign_ethereum_msg)
///
/// # Example
///
/// ```rust
/// use clarity::PrivateKey;
/// use clarity::utils::get_ethereum_msg_hash;
/// let private_key : PrivateKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e".parse().unwrap();
/// let signature = private_key.sign_ethereum_msg("Hello, world!".as_bytes());
/// // on the other side verifying the signature
/// let hash = get_ethereum_msg_hash("Hello, world!".as_bytes());
/// assert_eq!(signature.recover(&hash).unwrap(), private_key.to_address());
/// ```

pub fn get_ethereum_msg_hash(data: &[u8]) -> Vec<u8> {
    let digest = Keccak256::digest(data);
    let salt_string = ETHEREUM_SALT.to_string();
    let salt_bytes = salt_string.as_bytes();
    let digest = Keccak256::digest([salt_bytes, &digest].concat());
    digest.to_vec()
}

/// A function that takes a hexadecimal representation of bytes
/// back into a stream of bytes.
pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, Error> {
    let s = match s.strip_prefix("0x") {
        Some(s) => s,
        None => s,
    };
    let bytes = s
        .as_bytes()
        .chunks(2)
        .map::<Result<u8, Error>, _>(|ch| {
            let str = str::from_utf8(ch)?;
            let byte = u8::from_str_radix(str, 16)?;

            Ok(byte)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(bytes)
}

/// Function used for debug printing hex dumps
/// of ethereum events with each uint256 on a new
/// line
pub fn debug_print_data(input: &[u8]) -> String {
    let mut out = String::new();
    let count = input.len() / 32;
    out += "data hex dump\n";
    for i in 0..count {
        out += &format!(
            "0x{}\n",
            bytes_to_hex_str(&input[(i * 32)..((i * 32) + 32)])
        )
    }
    out += "end hex dump\n";
    out
}

/// This function displays a uint256 as an Ethereum address
/// which requires specific formatting, mostly useful for logging
/// and to avoid trying convert the Uint256 into an address
pub fn display_uint256_as_address(input: Uint256) -> String {
    format!("{input:#066x}")
}

pub fn big_endian_uint256_serialize<S>(x: &Uint256, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if x == &0u32.into() {
        s.serialize_bytes(&[])
    } else {
        let mut bytes = x.to_be_bytes().to_vec();
        // remove unneeded leading zeros
        while let Some(0) = bytes.first() {
            bytes.drain(0..1);
        }
        s.serialize_bytes(&bytes)
    }
}

pub fn big_endian_uint256_deserialize<'de, D>(d: D) -> Result<Uint256, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Uint256::from_be_bytes(&Vec::<u8>::deserialize(d)?))
}

#[test]
fn decode_bytes() {
    assert_eq!(
        hex_str_to_bytes("deadbeef").expect("Unable to decode"),
        [222, 173, 190, 239]
    );
}

#[test]
fn decode_odd_amount_of_bytes() {
    assert_eq!(hex_str_to_bytes("f").unwrap(), vec![15]);
}

#[test]
fn bytes_raises_decode_error() {
    let e = hex_str_to_bytes("\u{012345}deadbeef").unwrap_err();

    match e {
        Error::InvalidUtf8(_) => {}
        _ => panic!(),
    };
}

#[test]
fn bytes_raises_parse_error() {
    let e = hex_str_to_bytes("Lorem ipsum").unwrap_err();
    match e {
        Error::InvalidHex(_) => {}
        _ => panic!(),
    }
}

#[test]
fn parse_prefixed_empty() {
    assert_eq!(hex_str_to_bytes("0x").unwrap(), Vec::<u8>::new());
}

#[test]
fn parse_prefixed_non_empty() {
    assert_eq!(
        hex_str_to_bytes("0xdeadbeef").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
}

pub fn bytes_to_hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:0>2x?}"))
        .fold(String::new(), |acc, x| acc + &x)
}

#[test]
fn encode_bytes() {
    assert_eq!(bytes_to_hex_str(&[0xf]), "0f".to_owned());
    assert_eq!(bytes_to_hex_str(&[0xff]), "ff".to_owned());
    assert_eq!(
        bytes_to_hex_str(&[0xde, 0xad, 0xbe, 0xef]),
        "deadbeef".to_owned()
    );
}

/// Pad bytes with zeros at the start.
pub fn zpad(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes.to_vec();
    }
    let mut pad = vec![0u8; len - bytes.len()];
    pad.extend(bytes);
    pad
}

#[test]
fn verify_zpad() {
    assert_eq!(zpad(&[1, 2, 3, 4], 8), [0, 0, 0, 0, 1, 2, 3, 4]);
}

#[test]
fn verify_zpad_exact() {
    assert_eq!(zpad(&[1, 2, 3, 4], 4), [1, 2, 3, 4]);
}

#[test]
fn verify_zpad_less_than_size() {
    assert_eq!(zpad(&[1, 2, 3, 4], 2), [1, 2, 3, 4]);
}
