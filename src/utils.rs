use std::num::ParseIntError;
use std::str;

#[derive(Debug, Fail, PartialEq)]
pub enum ByteDecodeError {
    #[fail(display = "{}", _0)]
    DecodeError(str::Utf8Error),
    #[fail(display = "{}", _0)]
    ParseError(ParseIntError),
}

/// A function that takes a hexadecimal representation of bytes
/// back into a stream of bytes.
pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, ByteDecodeError> {
    let s = if s.starts_with("0x") { &s[2..] } else { s };
    s.as_bytes()
        .chunks(2)
        .map(|ch| {
            str::from_utf8(&ch)
                .map_err(|e| ByteDecodeError::DecodeError(e))
                .and_then(|res| {
                    u8::from_str_radix(&res, 16).map_err(|e| ByteDecodeError::ParseError(e))
                })
        }).collect()
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
    match hex_str_to_bytes(&"\u{012345}deadbeef".to_owned()).unwrap_err() {
        ByteDecodeError::DecodeError(_) => assert!(true),
        _ => assert!(false),
    }
}

#[test]
fn bytes_raises_parse_error() {
    match hex_str_to_bytes(&"Lorem ipsum".to_owned()).unwrap_err() {
        ByteDecodeError::ParseError(_) => assert!(true),
        _ => assert!(false),
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
    assert_eq!(bytes_to_hex_str(&vec![0xf]), "0f".to_owned());
    assert_eq!(bytes_to_hex_str(&vec![0xff]), "ff".to_owned());
    assert_eq!(
        bytes_to_hex_str(&vec![0xde, 0xad, 0xbe, 0xef]),
        "deadbeef".to_owned()
    );
}

/// Pad bytes with zeros at the beggining.
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
