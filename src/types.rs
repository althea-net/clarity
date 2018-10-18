use num256::Uint256;
use num_traits::Zero;
use serde::Serialize;
use serde::Serializer;
use utils::big_endian_int_serialize;

/// A wrapper for BigUint which provides serialization to BigEndian in radix 16
#[derive(Serialize)]
pub struct BigEndianInt(#[serde(serialize_with = "big_endian_int_serialize")] pub Uint256);

#[test]
fn serialize() {
    use serde_rlp::ser::to_bytes;
    let value: Uint256 =
        "115792089237316195423570985008687907853269984665640564039457584007913129639934"
            .parse()
            .unwrap();
    assert_eq!(
        to_bytes(&BigEndianInt(value.clone())).expect("Unable to serialize BigEndianInt"),
        vec![
            160, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
        ]
    );
}
