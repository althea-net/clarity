// Copyright 2018 Althea Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::serde_rlp::error::Error;
use byteorder::{BigEndian, WriteBytesExt};
use num::Num;
use num::Unsigned;
use std::mem::size_of;

fn to_binary(x: u64) -> Vec<u8> {
    if x == 0 {
        Vec::new()
    } else {
        let mut result = to_binary(x / 256);
        result.push((x % 256) as u8);
        result
    }
}

#[test]
fn test_to_binary_null() {
    assert_eq!(to_binary(0u64), [0; 0]);
}

#[test]
fn test_to_binary_non_null() {
    assert_eq!(to_binary(1024u64), [0x04, 0x00]);
    assert_eq!(
        to_binary(18446744073709551615u64),
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

pub fn encode_length(l: u64, offset: u8) -> Vec<u8> {
    if l < 56 {
        vec![l as u8 + offset]
    } else if l < u64::max_value() {
        let mut bl = to_binary(l);
        let magic = bl.len() as u8 + offset + 55;
        bl.insert(0, magic);
        bl
    } else {
        panic!("input too long");
    }
}

#[test]
fn test_encode_length_small() {
    assert_eq!(encode_length(55u64, 0xc0), [55 + 0xc0]);
}

#[test]
fn test_encode_length_big() {
    assert_eq!(
        encode_length(18446744073709551614u64, 0x80),
        [191, 255, 255, 255, 255, 255, 255, 255, 254]
    );
}

#[test]
#[should_panic]
fn test_encode_length_of_wrong_size() {
    encode_length(18446744073709551615u64, 0x80);
}

pub fn encode_number<T: Num + Unsigned>(v: T) -> Vec<u8>
where
    T: Into<u64>,
{
    let mut wtr = vec![];
    wtr.write_uint::<BigEndian>(v.into(), size_of::<T>())
        .unwrap();
    let index = wtr.iter().position(|&r| r > 0u8).unwrap_or(0);
    wtr.split_off(index)
}

#[test]
fn test_encode_number() {
    assert_eq!(encode_number(255u8), [0xff]);
    assert_eq!(encode_number(1024u16), [0x04, 0x00]);
    assert_eq!(encode_number(1024u32), [0x04, 0x00]);
    assert_eq!(encode_number(1024u64), [0x04, 0x00]);
}

fn to_integer(b: &[u8]) -> Option<u64> {
    if b.len() == 0 {
        None
    } else if b.len() == 1 {
        Some(b[0] as u64)
    } else {
        return Some(b[b.len() - 1] as u64 + to_integer(&b[0..b.len() - 1]).unwrap() * 256);
    }
}

#[test]
fn to_integer_with_empty_buffer() {
    assert!(to_integer(&[]).is_none());
}

#[test]
fn to_integer_with_single_byte() {
    assert_eq!(to_integer(&[0xffu8]).unwrap(), 255u64);
}

#[test]
fn to_integer_with_multiple_bytes() {
    assert_eq!(to_integer(&[0x04u8, 0x00u8]).unwrap(), 1024u64);
}

#[test]
fn decode_u32_max() {
    assert_eq!(to_integer(&[0xffu8; 4]).unwrap(), 4294967295u64);
}

#[test]
fn decode_u64_max() {
    assert_eq!(to_integer(&[0xffu8; 8]).unwrap(), 18446744073709551615u64);
}

#[derive(Debug, PartialEq)]
pub enum ExpectedType {
    /// Expecting a string
    StringType,
    /// Expecting a list
    ListType,
}

#[derive(Debug)]
pub struct DecodeLengthResult {
    pub offset: usize,
    pub length: usize,
    pub expected_type: ExpectedType,
}

/// Decodes chunk of data and outputs offset, length of nested data and its expected type
pub fn decode_length(input: &[u8]) -> Result<DecodeLengthResult, Error> {
    if input.len() == 0 {
        return Err(Error::EmptyBuffer);
    }
    let prefix = input[0];
    if prefix <= 0x7f {
        Ok(DecodeLengthResult {
            offset: 0,
            length: 1usize,
            expected_type: ExpectedType::StringType,
        })
    } else if prefix <= 0xb7 && input.len() > (prefix - 0x80) as usize {
        let str_len = prefix - 0x80;
        Ok(DecodeLengthResult {
            offset: 1,
            length: str_len as usize,
            expected_type: ExpectedType::StringType,
        })
    } else if prefix <= 0xbf
        && input.len() > prefix.checked_sub(0xb7).ok_or(Error::WrongPrefix)? as usize
        && input.len() as u64
            > prefix as u64 - 0xb7u64
                + to_integer(&input[1..prefix as usize - 0xb7 + 1])
                    .ok_or(Error::StringPrefixTooSmall)?
    {
        let len_of_str_len = prefix as usize - 0xb7;
        let str_len = to_integer(&input[1..len_of_str_len + 1]).unwrap();
        Ok(DecodeLengthResult {
            offset: 1 + len_of_str_len,
            length: str_len as usize,
            expected_type: ExpectedType::StringType,
        })
    } else if prefix <= 0xf7 && input.len() > prefix as usize - 0xc0 {
        let list_len = prefix as usize - 0xc0;
        Ok(DecodeLengthResult {
            offset: 1,
            length: list_len,
            expected_type: ExpectedType::ListType,
        })
    } else if
    /* prefix <= 0xff && */
    input.len() as u64 > prefix as u64 - 0xf7
        && input.len() as u64
            > prefix as u64 - 0xf7u64
                + to_integer(&input[1..prefix as usize - 0xf7 + 1])
                    .ok_or(Error::ListPrefixTooSmall)?
    {
        let len_of_list_len = prefix as usize - 0xf7;
        let list_len = to_integer(&input[1..len_of_list_len + 1]).unwrap();
        Ok(DecodeLengthResult {
            offset: 1 + len_of_list_len,
            length: list_len as usize,
            expected_type: ExpectedType::ListType,
        })
    } else {
        unreachable!();
    }
}

#[test]
fn decode_empty_byte_slice() {
    assert!(decode_length(&[]).is_err());
}

#[test]
fn decode_single_byte() {
    // "a"
    let res = decode_length(&[0x61u8]).unwrap();
    assert_eq!(res.offset, 0);
    assert_eq!(res.length, 1);
    assert_eq!(res.expected_type, ExpectedType::StringType);
}

#[test]
fn decode_short_string() {
    // "abc"
    let input = vec![0x83, 0x61, 0x62, 0x63, 0xff];
    let res = decode_length(&input[..]).unwrap();
    assert_eq!(res.offset, 1);
    assert_eq!(res.length, 3);
    assert_eq!(res.expected_type, ExpectedType::StringType);
}

#[test]
fn decode_short_array() {
    // 1024
    let res = decode_length(&[0xc4, 0x83, 0x61, 0x62, 0x63]).unwrap();
    assert_eq!(res.offset, 1);
    assert_eq!(res.length, 4);
    assert_eq!(res.expected_type, ExpectedType::ListType);
}
