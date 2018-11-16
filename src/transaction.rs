use address::Address;
use constants::SECPK1N;
use constants::TT256;
use error::ClarityError;
use failure::Error;
use num256::Uint256;
use num_traits::ToPrimitive;
use num_traits::Zero;
use opcodes::GTXCOST;
use opcodes::GTXDATANONZERO;
use opcodes::GTXDATAZERO;
use private_key::PrivateKey;
use secp256k1::{Message, RecoverableSignature, RecoveryId, Secp256k1, SecretKey};
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use serde_bytes::ByteBuf;
use serde_rlp::ser::to_bytes;
use sha3::{Digest, Keccak256};
use signature::Signature;
use types::BigEndianInt;
use utils::{bytes_to_hex_str, hex_str_to_bytes, zpad};

/// Transaction as explained in the Ethereum Yellow paper section 4.2
#[derive(Clone, Debug, PartialEq)]
pub struct Transaction {
    pub nonce: Uint256,
    pub gas_price: Uint256,
    pub gas_limit: Uint256,
    pub to: Address,
    pub value: Uint256,
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
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &self.to,
            &BigEndianInt(self.value.clone()),
            &ByteBuf::from(self.data.clone()),
            &BigEndianInt(sig.v.clone()),
            &BigEndianInt(sig.r.clone()),
            &BigEndianInt(sig.s.clone()),
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

    pub fn intrinsic_gas_used(&self) -> Uint256 {
        let num_zero_bytes = self.data.iter().filter(|&&b| b == 0u8).count();
        let num_non_zero_bytes = self.data.len() - num_zero_bytes;
        Uint256::from(GTXCOST)
            + Uint256::from(GTXDATAZERO) * Uint256::from(num_zero_bytes as u32)
            + Uint256::from(GTXDATANONZERO) * Uint256::from(num_non_zero_bytes as u32)
    }

    /// Creates a raw data without signature params
    fn to_unsigned_tx_params(&self) -> Vec<u8> {
        // TODO: Could be refactored in a better way somehow
        let data = (
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &self.to,
            &BigEndianInt(self.value.clone()),
            &ByteBuf::from(self.data.clone()),
        );
        to_bytes(&data).unwrap()
    }
    fn to_unsigned_tx_params_for_network(&self, network_id: Uint256) -> Vec<u8> {
        // assert!(self.signature.is_none());
        // TODO: Could be refactored in a better way somehow
        let data = (
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &self.to,
            &BigEndianInt(self.value.clone()),
            &ByteBuf::from(self.data.clone()),
            &BigEndianInt(network_id.clone()),
            &ByteBuf::new(),
            &ByteBuf::new(),
        );
        to_bytes(&data).unwrap()
    }
    /// Creates a Transaction with new
    pub fn sign(&self, key: &PrivateKey, network_id: Option<u64>) -> Transaction {
        // This is a special matcher to prepare raw RLP data with correct network_id.
        let rlpdata = match network_id {
            Some(network_id) => {
                assert!(1 <= network_id && network_id < 9223372036854775790u64); // 1 <= id < 2**63 - 18
                self.to_unsigned_tx_params_for_network(network_id.into())
            }
            None => self.to_unsigned_tx_params(),
        };
        // Prepare a raw hash of RLP encoded TX params
        let rawhash = Keccak256::digest(&rlpdata);
        let mut sig = key.sign_hash(&rawhash);
        if network_id.is_some() {
            // Account v for the network_id value
            sig.v += 8u64 + network_id.unwrap() * 2u64;
        }
        let mut tx = self.clone();
        tx.signature = Some(sig);
        tx
    }

    /// Get the sender's `Address`; derived from the `signature` field, null ETH address if the
    /// field is `None`.
    pub fn sender(&self) -> Result<Address, Error> {
        if self.signature.is_none() {
            // Returns a "null" address
            return Ok(Address::from([0xffu8; 20]));
        }
        let sig = self.signature.as_ref().unwrap();
        // Zero RS also mean the resulting address is "null"
        if sig.r == Uint256::zero() && sig.s == Uint256::zero() {
            return Ok(Address::from([0xffu8; 20]));
        } else {
            let (vee, sighash) = if sig.v == 27u32.into() || sig.v == 28u32.into() {
                // Valid V values are in {27, 28} according to Ethereum Yellow paper Appendix F (282).
                let vee = sig.v.clone();
                let sighash = Keccak256::digest(&self.to_unsigned_tx_params());
                (vee, sighash)
            } else if sig.v >= 37u32.into() {
                let network_id = sig.network_id().ok_or(ClarityError::InvalidNetworkId)?;
                // Otherwise we have to extract "v"...
                let vee = sig.v.clone() - network_id.clone() * 2u32 - 8u32;
                // ... so after all v will still match 27<=v<=28
                assert!(vee == 27u32.into() || vee == 28u32.into());
                // In this case hash of the transaction is usual RLP paremeters but "VRS" params
                // are swapped for [network_id, '', '']. See Appendix F (285)
                let rlp_data = self.to_unsigned_tx_params_for_network(network_id.clone());
                let sighash = Keccak256::digest(&rlp_data);
                (vee, sighash)
            } else {
                // All other V values would be errorneous for our calculations
                return Err(ClarityError::InvalidV.into());
            };

            // Validate signates
            if sig.r >= *SECPK1N
                || sig.s >= *SECPK1N
                || sig.r == Uint256::zero()
                || sig.s == Uint256::zero()
            {
                return Err(ClarityError::InvalidSignatureValues.into());
            }

            // prepare secp256k1 context
            let secp256k1 = Secp256k1::new();

            // Prepare compact signature that consists of (r, s) padded to 32 bytes to make 64 bytes data
            let r = zpad(&sig.r.to_bytes_be(), 32);
            debug_assert_eq!(r.len(), 32);
            let s = zpad(&sig.s.to_bytes_be(), 32);
            debug_assert_eq!(s.len(), 32);

            // Join together rs into a compact signature
            let mut compact_bytes: Vec<u8> = Vec::new();
            compact_bytes.extend(r);
            compact_bytes.extend(s);
            debug_assert_eq!(compact_bytes.len(), 64);

            // Create recovery ID which is "v" minus 27. Without this it wouldn't be possible to extract recoverable signature.
            let v = RecoveryId::from_i32(vee.to_i32().expect("Unable to convert vee to i32") - 27)?;
            // Get recoverable signature given rs, and v.
            let compact = RecoverableSignature::from_compact(&secp256k1, &compact_bytes, v)?;
            // A message to recover which is a hash of the transaction
            let msg = Message::from_slice(&sighash)?;
            let pkey = secp256k1.recover(&msg, &compact)?;
            // Serialize the recovered public key in uncompressed format
            let pkey = pkey.serialize_uncompressed();
            assert_eq!(pkey.len(), 65);
            if pkey[1..].to_vec() == [0x00u8; 64].to_vec() {
                return Err(ClarityError::ZeroPrivKey.into());
            }
            // Finally an address is last 20 bytes of a hash of the public key.
            let sender = Keccak256::digest(&pkey[1..]);
            debug_assert_eq!(sender.len(), 32);
            return Ok(Address::from(&sender[12..]));
        }
    }
    /// Creates a hash of a transaction given all TX attributes
    /// including signature (VRS) whether it is present, or not.
    pub fn hash(&self) -> Vec<u8> {
        Keccak256::digest(&to_bytes(&self).unwrap()).to_vec()
    }
    /// Creates a byte representation of this transaction
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(to_bytes(&self)?)
    }
}

#[test]
fn test_vitaliks_eip_158_vitalik_12_json() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let tx = Transaction {
        nonce: Uint256::from_str_radix("0e", 16).unwrap(),
        gas_price: Uint256::from_str_radix("00", 16).unwrap(),
        gas_limit: Uint256::from_str_radix("0493e0", 16).unwrap(),
        to: Address::new(), // "" - zeros only
        value: Uint256::from_str_radix("00", 16).unwrap(),
        data: hex_str_to_bytes("60f2ff61000080610011600039610011565b6000f3").unwrap(),
        signature: Some(Signature::new(
            Uint256::from_str_radix("1c", 16).unwrap(),
            Uint256::from_str_radix(
                "a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4",
                16,
            ).unwrap(),
            Uint256::from_str_radix(
                "6dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6",
                16,
            ).unwrap(),
        )),
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f8610e80830493e080809560f2ff61000080610011600039610011565b6000f31ca0a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4a06dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6".to_owned();
    assert_eq!(lhs, rhs);

    assert_eq!(
        bytes_to_hex_str(&tx.sender().unwrap().as_bytes()),
        "874b54a8bd152966d63f706bae1ffeb0411921e5"
    );
}

#[test]
fn test_vitaliks_eip_158_vitalik_1_json() {
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let tx = Transaction {
        nonce: Uint256::from_str_radix("00", 16).unwrap(),
        gas_price: Uint256::from_str_radix("04a817c800", 16).unwrap(),
        gas_limit: Uint256::from_str_radix("5208", 16).unwrap(),
        to: "3535353535353535353535353535353535353535".parse().unwrap(),
        value: Uint256::from_str_radix("00", 16).unwrap(),
        data: Vec::new(),
        signature: Some(Signature::new(
            Uint256::from_str_radix("25", 16).unwrap(),
            Uint256::from_str_radix(
                "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                16,
            ).unwrap(),
            Uint256::from_str_radix(
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
        nonce: Uint256::from_str_radix("00", 16).unwrap(),
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
