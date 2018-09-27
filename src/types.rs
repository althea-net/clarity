use failure::Error;
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive, Zero};
use serde::Serialize;
use serde::Serializer;
use std::fmt;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Sub;
use std::ops::{Add, AddAssign};
use std::str::FromStr;

/// A wrapper for BigUint which provides serialization to BigEndian in radix 16
#[derive(PartialEq, Eq, PartialOrd, Clone)]
pub struct BigEndianInt(BigUint);

impl Zero for BigEndianInt {
    fn zero() -> BigEndianInt {
        BigEndianInt(BigUint::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Add for BigEndianInt {
    type Output = BigEndianInt;

    fn add(self, other: BigEndianInt) -> BigEndianInt {
        BigEndianInt(self.0 + other.0)
    }
}

impl AddAssign for BigEndianInt {
    fn add_assign(&mut self, other: BigEndianInt) {
        self.0 += other.0;
    }
}

impl Sub for BigEndianInt {
    type Output = BigEndianInt;

    fn sub(self, other: BigEndianInt) -> BigEndianInt {
        BigEndianInt(self.0 - other.0)
    }
}

impl Mul for BigEndianInt {
    type Output = BigEndianInt;

    fn mul(self, other: BigEndianInt) -> BigEndianInt {
        BigEndianInt(self.0 * other.0)
    }
}

impl Div for BigEndianInt {
    type Output = BigEndianInt;

    fn div(self, other: BigEndianInt) -> BigEndianInt {
        BigEndianInt(self.0 / other.0)
    }
}

/// Implement serialization that would serialize as bytes
impl Serialize for BigEndianInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0 == BigUint::zero() {
            serializer.serialize_bytes(&[])
        } else {
            let bytes = self.to_bytes_be();
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl ToPrimitive for BigEndianInt {
    fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }
    fn to_u64(&self) -> Option<u64> {
        self.0.to_u64()
    }

    fn to_isize(&self) -> Option<isize> {
        self.0.to_isize()
    }
    fn to_i8(&self) -> Option<i8> {
        self.0.to_i8()
    }
    fn to_i16(&self) -> Option<i16> {
        self.0.to_i16()
    }
    fn to_i32(&self) -> Option<i32> {
        self.0.to_i32()
    }
    fn to_usize(&self) -> Option<usize> {
        self.0.to_usize()
    }
    fn to_u8(&self) -> Option<u8> {
        self.0.to_u8()
    }
    fn to_u16(&self) -> Option<u16> {
        self.0.to_u16()
    }
    fn to_u32(&self) -> Option<u32> {
        self.0.to_u32()
    }
    fn to_f32(&self) -> Option<f32> {
        self.0.to_f32()
    }
    fn to_f64(&self) -> Option<f64> {
        self.0.to_f64()
    }
}

impl BigEndianInt {
    // TODO: Leverage Num trait once all required traits are implemented
    pub fn from_str_radix(src: &str, radix: u32) -> Result<BigEndianInt, Error> {
        let raw = BigUint::from_str_radix(&src, radix)?;
        Ok(BigEndianInt(raw))
    }

    pub fn from_bytes_be(bytes: &[u8]) -> BigEndianInt {
        BigEndianInt(BigUint::from_bytes_be(bytes))
    }
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }
}

#[derive(Fail, Debug)]
pub enum BigEndianIntError {
    #[fail(display = "Invalid radix 16 value")]
    InvalidHexValue,
    #[fail(display = "Invalid radix 10 value")]
    InvalidDecValue,
}

impl FromStr for BigEndianInt {
    type Err = BigEndianIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = if s.starts_with("0x") {
            // Parse as hexadecimal big endian value
            BigUint::parse_bytes(&s.as_bytes()[2..], 16)
                .ok_or(BigEndianIntError::InvalidHexValue)?
        } else {
            BigUint::parse_bytes(s.as_bytes(), 10).ok_or(BigEndianIntError::InvalidDecValue)?
        };
        Ok(BigEndianInt(value))
    }
}

impl From<u32> for BigEndianInt {
    fn from(v: u32) -> Self {
        BigEndianInt(BigUint::from(v))
    }
}

impl From<u64> for BigEndianInt {
    fn from(v: u64) -> Self {
        BigEndianInt(BigUint::from(v))
    }
}

impl<'a> From<&'a [u8]> for BigEndianInt {
    fn from(v: &'a [u8]) -> Self {
        BigEndianInt(BigUint::from_bytes_be(v))
    }
}

impl Into<[u8; 32]> for BigEndianInt {
    fn into(self) -> [u8; 32] {
        let bytes = self.0.to_bytes_be();
        let mut res = [0u8; 32];
        res[32 - bytes.len()..].copy_from_slice(&bytes);
        res
    }
}

impl fmt::Debug for BigEndianInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_str_radix(10))
    }
}

#[test]
fn serialize() {
    use serde_rlp::ser::to_bytes;
    let value: BigEndianInt =
        "115792089237316195423570985008687907853269984665640564039457584007913129639934"
            .parse()
            .unwrap();
    assert_eq!(
        to_bytes(&value).expect("Unable to serialize BigEndianInt"),
        vec![
            160, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
        ]
    );
}

#[test]
fn serialize_zeros() {
    use serde_rlp::ser::to_bytes;
    let value: BigEndianInt = "0".parse().unwrap();
    assert_eq!(
        to_bytes(&value).expect("Unable to serialize zero"),
        vec![128]
    );
}

#[test]
fn compares() {
    let a = BigEndianInt::from(42u64);
    let b = BigEndianInt::from(42u64);
    assert_eq!(a, b);
}

#[test]
fn zero() {
    let a = BigEndianInt::zero();
    assert_eq!(a, "0".parse().unwrap());
}

#[test]
fn clone() {
    let a = BigEndianInt::zero();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn into_array_of_32_bytes() {
    let bytes: [u8; 32] = BigEndianInt::from(1024u64).into();
    assert_eq!(
        bytes,
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 4, 0
        ]
    );
}
