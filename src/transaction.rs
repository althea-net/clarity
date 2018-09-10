use address::Address;
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use serde_bytes::ByteBuf;
use signature::Signature;
use types::BigEndianInt;
use utils::{bytes_to_hex_str, hex_str_to_bytes};

/// Transaction as explained in the Ethereum Yellow paper section 4.2
struct Transaction {
    nonce: BigEndianInt,
    gas_price: BigEndianInt,
    gas_limit: BigEndianInt,
    to: Address,
    value: BigEndianInt,
    data: Vec<u8>,
    signature: Option<Signature>,
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let sig = self.signature.clone().unwrap_or(Signature::default());
        let data = (
            &self.nonce,
            &self.gas_price,
            &self.gas_limit,
            &self.to,
            &self.value,
            &ByteBuf::from(self.data.clone()),
            &sig.v,
            &sig.r,
            &sig.s,
        );
        data.serialize(serializer)
    }
}

#[test]
fn test_vitaliks_eip_158_vitalik_12_json() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let tx = Transaction {
        nonce: BigEndianInt::from_str_radix("0e", 16).unwrap(),
        gas_price: BigEndianInt::from_str_radix("00", 16).unwrap(),
        gas_limit: BigEndianInt::from_str_radix("0493e0", 16).unwrap(),
        to: Address::new(), // "" - zeros only
        value: BigEndianInt::from_str_radix("00", 16).unwrap(),
        data: hex_str_to_bytes("60f2ff61000080610011600039610011565b6000f3").unwrap(),
        signature: Some(Signature::new(
            BigEndianInt::from_str_radix("1c", 16).unwrap(),
            BigEndianInt::from_str_radix(
                "a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4",
                16,
            ).unwrap(),
            BigEndianInt::from_str_radix(
                "6dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6",
                16,
            ).unwrap(),
        )),
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f8610e80830493e080809560f2ff61000080610011600039610011565b6000f31ca0a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4a06dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6".to_owned();
    assert_eq!(lhs, rhs);
}

#[test]
fn test_vitaliks_eip_158_vitalik_1_json() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let tx = Transaction {
        nonce: BigEndianInt::from_str_radix("00", 16).unwrap(),
        gas_price: BigEndianInt::from_str_radix("04a817c800", 16).unwrap(),
        gas_limit: BigEndianInt::from_str_radix("5208", 16).unwrap(),
        to: "3535353535353535353535353535353535353535".parse().unwrap(),
        value: BigEndianInt::from_str_radix("00", 16).unwrap(),
        data: Vec::new(),
        signature: Some(Signature::new(
            BigEndianInt::from_str_radix("25", 16).unwrap(),
            BigEndianInt::from_str_radix(
                "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                16,
            ).unwrap(),
            BigEndianInt::from_str_radix(
                "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                16,
            ).unwrap(),
        )),
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d".to_owned();
    assert_eq!(lhs, rhs);
}

#[test]
fn test_basictests_txtest_1() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let tx = Transaction {
        nonce: BigEndianInt::from_str_radix("00", 16).unwrap(),
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "10000".parse().unwrap(),
        to: "13978aee95f38490e9769c39b2773ed763d9cd5f".parse().unwrap(),
        value: "10000000000000000".parse().unwrap(),
        data: Vec::new(),
        signature: None,
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs =
        "eb8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc1000080808080"
            .to_owned();
    assert_eq!(lhs, rhs);
}

#[test]
fn test_basictests_txtest_2() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let tx = Transaction {
        nonce: "0".parse().unwrap(),
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "10000".parse().unwrap(),
        to: Address::new(),
        value: "0".parse().unwrap(),
        data: hex_str_to_bytes("6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2").unwrap(),
        signature: None
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f83f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2808080".to_owned();
    assert_eq!(lhs, rhs);
}
