use crate::Address;
use num256::Uint256;
use num_traits::Bounded;
use std::str::FromStr;

pub fn tt256() -> Uint256 {
    Uint256::max_value()
}

pub fn tt256m1() -> Uint256 {
    Uint256::max_value() - 1u8.into()
}

pub fn tt255() -> Uint256 {
    Uint256::from_str(
        "57896044618658097711785492504343953926634992332820282019728792003956564819968",
    )
    .unwrap() //2 ** 255
}

pub fn tt160m1() -> Uint256 {
    Uint256::from_str("1461501637330902918203684832716283019655932542975").unwrap()
    // 2 ** 160 - 1
}

pub fn tt24m1() -> Uint256 {
    Uint256::from_str("16777215").unwrap() // 2 ** 24 - 1
}

pub fn secp256k1p() -> Uint256 {
    Uint256::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap() // 2**256 - 4294968273
}

pub fn secpk1n() -> Uint256 {
    Uint256::from_str(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    )
    .unwrap()
}

pub fn zero_address() -> Address {
    "0x0000000000000000000000000000000000000000"
        .parse()
        .unwrap()
}

pub fn null_address() -> Address {
    Address::from([0xffu8; 20])
}
