use crate::utils::{big_endian_uint256_deserialize, big_endian_uint256_serialize};
use num256::Uint256;

/// A thin wrapper type to change the way Uint256 is serialized.
///
/// This is done this way to overcome the "orphan rule" where you can't
/// implement traits for a type that comes from different crate.
#[derive(Serialize, Deserialize)]
pub struct BigEndianInt(
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub Uint256,
);

#[test]
fn serialize() {
    use crate::rlp::pack_rlp;

    let value: Uint256 =
        "115792089237316195423570985008687907853269984665640564039457584007913129639934"
            .parse()
            .unwrap();
    assert_eq!(
        pack_rlp(vec![value.into()]),
        vec![
            160, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
        ]
    );
}
