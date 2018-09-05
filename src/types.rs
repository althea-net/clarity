use failure::Error;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Serialize;
use serde::Serializer;
use std::str::FromStr;
/// A wrapper for BigUint which provides serialization to BigEndian in radix 16
pub struct BigEndianInt(BigUint);

/// Implement serialization that would serialize as bytes
impl Serialize for BigEndianInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_radix_be(16))
    }
}

impl BigEndianInt {
    // TODO: Leverage Num trait once all required traits are implemented
    pub fn from_str_radix(src: &str, radix: u32) -> Result<BigEndianInt, Error> {
        let raw = BigUint::from_str_radix(&src, radix)?;
        Ok(BigEndianInt(raw))
    }
}

#[derive(Fail, Debug)]
pub enum BigEndianIntError {
    #[fail(display = "Overflow occurred while parsing number")]
    OverflowError,
}

impl FromStr for BigEndianInt {
    type Err = BigEndianIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(BigEndianInt(
            BigUint::parse_bytes(s.as_bytes(), 10).ok_or(BigEndianIntError::OverflowError)?,
        ))
    }
}

impl From<u64> for BigEndianInt {
    fn from(v: u64) -> Self {
        BigEndianInt(BigUint::from(v))
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
            184, 64, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            14,
        ]
    );
}
