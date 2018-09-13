use address::Address;
use constants::SECPK1N;
use constants::TT256;
use opcodes::GTXCOST;
use opcodes::GTXDATANONZERO;
use opcodes::GTXDATAZERO;
use private_key::PrivateKey;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use serde_bytes::ByteBuf;
use serde_rlp::ser::to_bytes;
use sha3::{Digest, Keccak256};
use signature::Signature;
use types::BigEndianInt;
use utils::{bytes_to_hex_str, hex_str_to_bytes};

/// Transaction as explained in the Ethereum Yellow paper section 4.2
#[derive(Clone, Debug)]
pub struct Transaction {
    pub nonce: BigEndianInt,
    pub gas_price: BigEndianInt,
    pub gas_limit: BigEndianInt,
    pub to: Address,
    pub value: BigEndianInt,
    pub data: Vec<u8>,
    pub signature: Option<Signature>,
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialization of a transaction without signature serializes
        // the data assuming the "vrs" params are set to 0.
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

impl Transaction {
    pub fn is_valid(&self) -> bool {
        if self.gas_price >= *TT256
            || self.gas_limit >= *TT256
            || self.value >= *TT256
            || self.nonce >= *TT256
        {
            // Way too high values
            return false;
        }

        if self.gas_limit < self.intrinsic_gas_used() {
            return false;
        }
        true
    }

    pub fn intrinsic_gas_used(&self) -> BigEndianInt {
        let num_zero_bytes = self.data.iter().filter(|&&b| b == 0u8).count();
        let num_non_zero_bytes = self.data.len() - num_zero_bytes;
        BigEndianInt::from(GTXCOST)
            + BigEndianInt::from(GTXDATAZERO) * BigEndianInt::from(num_zero_bytes as u32)
            + BigEndianInt::from(GTXDATANONZERO) * BigEndianInt::from(num_non_zero_bytes as u32)
    }

    /// Creates a raw data without signature params
    fn to_unsigned_tx_params(&self) -> Vec<u8> {
        assert!(self.signature.is_none());
        // TODO: Could be refactored in a better way somehow
        let data = (
            &self.nonce,
            &self.gas_price,
            &self.gas_limit,
            &self.to,
            &self.value,
            &ByteBuf::from(self.data.clone()),
        );
        to_bytes(&data).unwrap()
    }
    /// Creates a Transaction with new
    fn sign(&self, key: &PrivateKey, network_id: Option<u64>) -> Transaction {
        // This is a special matcher to prepare raw RLP data with correct network_id.
        let rlpdata = match network_id {
            Some(network_id) => {
                assert!(1 <= network_id && network_id < 9223372036854775790u64); // 1 <= id < 2**63 - 18
                unimplemented!("Network IDs not implemented yet");
            }
            None => self.to_unsigned_tx_params(),
        };
        // Prepare a raw hash of RLP encoded TX params
        let rawhash = Keccak256::digest(&rlpdata);
        debug_assert_eq!(rawhash.len(), 32);
        // Sign RLP encoded data
        let full = Secp256k1::new(); // TODO: in original libsecp256k1 source code there is a suggestion that the context should be kept for the duration of the program.
                                     // TODO: secp256k1 types could be hidden somehow
        let msg = Message::from_slice(&rawhash).unwrap();
        let sk = SecretKey::from_slice(&full, &key.to_bytes()).unwrap();
        // Sign the raw hash of RLP encoded transaction data with a private key.
        let sig = full.sign_recoverable(&msg, &sk);
        // Serialize the signature into the "compact" form which means
        // it will be exactly 64 bytes, and the "excess" information of
        // recovery id will be given to us.
        let (recovery_id, compact) = sig.serialize_compact(&full);
        debug_assert_eq!(compact.len(), 64);
        // I assume recovery ID is always greater than 0 to simplify
        // the conversion from i32 to BigEndianInt. On a side note,
        // I believe "v" could be an u64 value (TODO).
        let recovery_id = recovery_id.to_i32();
        assert!(recovery_id >= 0);
        let recovery_id = recovery_id as u32;
        let v: BigEndianInt = (recovery_id + 27).into();
        let r = BigEndianInt::from_bytes_be(&compact[0..32]);
        let s = BigEndianInt::from_bytes_be(&compact[32..64]);
        // This will swap the signature of a transaction, and returns a new signed TX.
        let mut tx = self.clone();
        tx.signature = Some(Signature::new(v, r, s));
        tx
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
    // Unsigned
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs =
        "eb8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc1000080808080"
            .to_owned();
    assert_eq!(lhs, rhs);

    // Signed
    let key: PrivateKey = "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"
        .parse()
        .unwrap();
    let signed_tx = tx.sign(&key, None);

    let lhs = to_bytes(&signed_tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f86b8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc10000801ba0eab47c1a49bf2fe5d40e01d313900e19ca485867d462fe06e139e3a536c6d4f4a014a569d327dcda4b29f74f93c0e9729d2f49ad726e703f9cd90dbb0fbf6649f1".to_owned();

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
    // Unsigned
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f83f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2808080".to_owned();
    assert_eq!(lhs, rhs);

    // Signed
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    let signed_tx = tx.sign(&key, None);

    let lhs = to_bytes(&signed_tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);

    // This value is wrong
    let rhs = "f87f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f21ca05afed0244d0da90b67cf8979b0f246432a5112c0d31e8d5eedd2bc17b171c694a044efca37cb9883d1ee7a47236f3592df152931a930566933de2dc6e341c11426".to_owned();

    assert_eq!(lhs, rhs);
}
