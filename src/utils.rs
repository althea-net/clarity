use num256::Uint256;
use serde::{
    de::{Deserialize, Deserializer},
    ser::Serializer,
};
use std::str;
use Error;

/// A function that takes a hexadecimal representation of bytes
/// back into a stream of bytes.
pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, Error> {
    let s = match s.strip_prefix("0x") {
        Some(s) => s,
        None => &s,
    };
    let bytes = s
        .as_bytes()
        .chunks(2)
        .map::<Result<u8, Error>, _>(|ch| {
            let str = str::from_utf8(&ch)?;
            let byte = u8::from_str_radix(&str, 16)?;

            Ok(byte)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(bytes)
}

pub fn display_uint256_as_address(input: Uint256) -> String {
    format!("{:#066x}", input)
}

pub fn big_endian_uint256_serialize<S>(x: &Uint256, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if x == &0u32.into() {
        s.serialize_bytes(&[])
    } else {
        let bytes = x.to_bytes_be();
        s.serialize_bytes(&bytes)
    }
}

pub fn big_endian_uint256_deserialize<'de, D>(d: D) -> Result<Uint256, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Uint256::from_bytes_be(&Vec::<u8>::deserialize(d)?))
}

#[test]
fn decode_bytes() {
    assert_eq!(
        hex_str_to_bytes(&"deadbeef".to_owned()).expect("Unable to decode"),
        [222, 173, 190, 239]
    );
}

#[test]
fn decode_odd_amount_of_bytes() {
    assert_eq!(hex_str_to_bytes(&"f".to_owned()).unwrap(), vec![15]);
}

#[test]
fn bytes_raises_decode_error() {
    let e = hex_str_to_bytes(&"\u{012345}deadbeef".to_owned()).unwrap_err();

    match e {
        Error::InvalidUtf8(_) => {}
        _ => panic!(),
    };
}

#[test]
fn bytes_raises_parse_error() {
    let e = hex_str_to_bytes(&"Lorem ipsum".to_owned()).unwrap_err();
    match e {
        Error::InvalidHex(_) => {}
        _ => panic!(),
    }
}

#[test]
fn parse_prefixed_empty() {
    assert_eq!(
        hex_str_to_bytes(&"0x".to_owned()).unwrap(),
        Vec::<u8>::new()
    );
}

#[test]
fn parse_prefixed_non_empty() {
    assert_eq!(
        hex_str_to_bytes(&"0xdeadbeef".to_owned()).unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
}

pub fn bytes_to_hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:0>2x?}", b))
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
