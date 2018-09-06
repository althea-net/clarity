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
    s.as_bytes()
        .chunks(2)
        .map(|ch| {
            str::from_utf8(&ch)
                .map_err(|e| ByteDecodeError::DecodeError(e))
                .and_then(|res| {
                    u8::from_str_radix(&res, 16).map_err(|e| ByteDecodeError::ParseError(e))
                })
        })
        .collect()
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

pub fn bytes_to_hex_str(bytes: &Vec<u8>) -> String {
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
