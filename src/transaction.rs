use crate::address::Address;
use crate::constants::TT256;
use crate::error::Error;
use crate::opcodes::GTXCOST;
use crate::opcodes::GTXDATANONZERO;
use crate::opcodes::GTXDATAZERO;
use crate::private_key::PrivateKey;
use crate::rlp::AddressDef;
use crate::signature::Signature;
use crate::types::BigEndianInt;
use crate::utils::bytes_to_hex_str;
use num256::Uint256;
use serde::Serialize;
use serde::Serializer;
use serde_bytes::{ByteBuf, Bytes};
use serde_rlp::de::from_bytes;
use serde_rlp::ser::to_bytes;
use sha3::{Digest, Keccak256};
use std::fmt;
use std::fmt::Display;

/// Transaction as explained in the Ethereum Yellow paper section 4.2
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub nonce: Uint256,
    pub gas_price: Uint256,
    pub gas_limit: Uint256,
    pub to: Address,
    pub value: Uint256,
    pub data: Vec<u8>,
    pub signature: Option<Signature>,
}

impl Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}",
            bytes_to_hex_str(&self.to_bytes().unwrap_or_default())
        )
    }
}

impl fmt::LowerHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.to_bytes().unwrap_or_default()).to_lowercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.to_bytes().unwrap_or_default()).to_lowercase()
            )
        }
    }
}

impl fmt::UpperHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.to_bytes().unwrap_or_default()).to_uppercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.to_bytes().unwrap_or_default()).to_uppercase()
            )
        }
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialization of a transaction without signature serializes
        // the data assuming the "vrs" params are set to 0.
        let sig = self.signature.clone().unwrap_or_default();
        let data = (
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &AddressDef(&self.to),
            &BigEndianInt(self.value.clone()),
            &ByteBuf::from(self.data.clone()),
            &BigEndianInt(sig.v.clone()),
            &BigEndianInt(sig.r.clone()),
            &BigEndianInt(sig.s),
        );
        data.serialize(serializer)
    }
}

/// Naive bytecount function, is slower than the bytecount crate but we only count bytes
/// for this single intrinsic gas function. Also has a limit of u32 bytes which is a 4gb
/// transaction so I think that's reasonable to assume.
fn naive_count_32(haystack: &[u8], needle: u8) -> u32 {
    haystack.iter().fold(0, |n, c| n + (*c == needle) as u32)
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

        // invalid signature check
        if let Some(sig) = self.signature.clone() {
            if !sig.is_valid() {
                return false;
            }
        }
        // check that the signature is actually correct, not just valid

        // rudimentary gas limit check, needs opcode awareness
        if self.gas_limit < self.intrinsic_gas_used() {
            return false;
        }

        true
    }

    pub fn intrinsic_gas_used(&self) -> Uint256 {
        let num_zero_bytes = naive_count_32(&self.data, 0u8);
        let num_non_zero_bytes = self.data.len() as u32 - num_zero_bytes;
        Uint256::from(GTXCOST)
            + Uint256::from(GTXDATAZERO) * Uint256::from(num_zero_bytes)
            + Uint256::from(GTXDATANONZERO) * Uint256::from(num_non_zero_bytes)
    }

    /// Creates a raw data without signature params
    fn to_unsigned_tx_params(&self) -> Vec<u8> {
        // TODO: Could be refactored in a better way somehow
        let data = (
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &AddressDef(&self.to),
            &BigEndianInt(self.value.clone()),
            &ByteBuf::from(self.data.clone()),
        );
        to_bytes(&data).unwrap()
    }
    fn to_unsigned_tx_params_for_network(&self, network_id: &Uint256) -> Vec<u8> {
        // assert!(self.signature.is_none());
        // TODO: Could be refactored in a better way somehow
        let data = (
            &BigEndianInt(self.nonce.clone()),
            &BigEndianInt(self.gas_price.clone()),
            &BigEndianInt(self.gas_limit.clone()),
            &AddressDef(&self.to),
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
                assert!((1..9_223_372_036_854_775_790u64).contains(&network_id)); // 1 <= id < 2**63 - 18
                self.to_unsigned_tx_params_for_network(&network_id.into())
            }
            None => self.to_unsigned_tx_params(),
        };
        // Prepare a raw hash of RLP encoded TX params
        let rawhash = Keccak256::digest(&rlpdata);
        let mut sig = key.sign_hash(&rawhash);
        if let Some(network_id) = network_id {
            // Account v for the network_id value
            sig.v += Uint256::from(8u64) + Uint256::from(network_id) * 2u64.into();
        }
        let mut tx = self.clone();
        tx.signature = Some(sig);
        tx
    }

    /// Get the sender's `Address`; derived from the `signature` field, does not keep with convention
    /// returns error if the signature is invalid. Traditional return would be `constants::NULL_ADDRESS`
    /// you may need to insert that yourself after matching on errors
    pub fn sender(&self) -> Result<Address, Error> {
        if self.signature.is_none() {
            return Err(Error::NoSignature);
        }
        let sig = self.signature.as_ref().unwrap();
        if !sig.is_valid() {
            Err(Error::InvalidSignatureValues)
        } else {
            let sighash = if sig.v == 27u32.into() || sig.v == 28u32.into() {
                Keccak256::digest(&self.to_unsigned_tx_params())
            } else if sig.v >= 37u32.into() {
                let network_id = sig.network_id().ok_or(Error::InvalidNetworkId)?;
                // In this case hash of the transaction is usual RLP paremeters but "VRS" params
                // are swapped for [network_id, '', '']. See Appendix F (285)
                let rlp_data = self.to_unsigned_tx_params_for_network(&network_id);
                Keccak256::digest(&rlp_data)
            } else {
                // All other V values would be errorneous for our calculations
                return Err(Error::InvalidV);
            };

            // Validate signatures
            if !sig.is_valid() {
                return Err(Error::InvalidSignatureValues);
            }

            sig.recover(&sighash)
        }
    }

    /// Creates a hash of a transaction given all TX attributes
    /// including signature (VRS) whether it is present, or not.
    pub fn hash(&self) -> Vec<u8> {
        Keccak256::digest(&to_bytes(&self).unwrap()).to_vec()
    }

    /// Creates a byte representation of this transaction
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_bytes(&self).map_err(|_| Error::SerializeRlp)
    }

    /// Creates a transaction from raw RLP bytes, can not decode unsigned transactions
    pub fn decode_from_rlp(raw_rlp_bytes: &[u8]) -> Result<Self, Error> {
        // Try to decode the bytes into a Vec of Bytes which will enforce structure of a n-element vector with bytearrays.
        let data: Vec<&Bytes> = match from_bytes(raw_rlp_bytes) {
            Ok(data) => data,
            Err(_) => {
                return Err(Error::DeserializeRlp);
            }
        };
        // A valid decoded transaction has exactly 9 elements.
        if data.len() != 9 {
            return Err(Error::DeserializeRlp);
        }

        Ok(Transaction {
            nonce: (**data[0]).into(),
            gas_price: (**data[1]).into(),
            gas_limit: (**data[2]).into(),
            to: Address::from_slice(&*data[3]).unwrap_or_default(),
            value: (**data[4]).into(),
            data: (**data[5]).into(),
            signature: Some(Signature::new(
                (**data[6]).into(),
                (**data[7]).into(),
                (**data[8]).into(),
            )),
        })
    }
}

#[test]
fn test_vitaliks_eip_158_vitalik_12_json() {
    use crate::utils::{bytes_to_hex_str, hex_str_to_bytes};
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let tx = Transaction {
        nonce: Uint256::from_str_radix("0e", 16).unwrap(),
        gas_price: Uint256::from_str_radix("00", 16).unwrap(),
        gas_limit: Uint256::from_str_radix("0493e0", 16).unwrap(),
        to: Address::default(), // "" - zeros only
        value: Uint256::from_str_radix("00", 16).unwrap(),
        data: hex_str_to_bytes("60f2ff61000080610011600039610011565b6000f3").unwrap(),
        signature: Some(Signature::new(
            Uint256::from_str_radix("1c", 16).unwrap(),
            Uint256::from_str_radix(
                "a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4",
                16,
            )
            .unwrap(),
            Uint256::from_str_radix(
                "6dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6",
                16,
            )
            .unwrap(),
        )),
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f8610e80830493e080809560f2ff61000080610011600039610011565b6000f31ca0a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4a06dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6".to_owned();
    assert_eq!(lhs, rhs);

    assert_eq!(
        bytes_to_hex_str(tx.sender().unwrap().as_bytes()),
        "874b54a8bd152966d63f706bae1ffeb0411921e5"
    );
}

#[test]
fn test_vitaliks_eip_158_vitalik_1_json() {
    use crate::utils::bytes_to_hex_str;
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
            )
            .unwrap(),
            Uint256::from_str_radix(
                "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                16,
            )
            .unwrap(),
        )),
    };
    let lhs = to_bytes(&tx).unwrap();
    let lhs = bytes_to_hex_str(&lhs);
    let rhs = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d".to_owned();
    assert_eq!(lhs, rhs);
}

#[test]
fn test_basictests_txtest_1() {
    use crate::utils::bytes_to_hex_str;
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
    use crate::utils::{bytes_to_hex_str, hex_str_to_bytes};
    use serde_rlp::ser::to_bytes;
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let tx = Transaction {
        nonce: "0".parse().unwrap(),
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "10000".parse().unwrap(),
        to: Address::default(),
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
