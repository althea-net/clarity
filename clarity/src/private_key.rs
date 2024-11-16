use crate::address::Address;
use crate::context::SECP256K1;
use crate::error::Error;
use crate::raw_private_key::RawPrivateKey;
use crate::signature::Signature;
use crate::utils::{bytes_to_hex_str, hex_str_to_bytes};
use num256::Uint256;
use secp256k1::{Message, SecretKey};
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Debug, Display};
use std::str::FromStr;

// the standard Ethereum message signing salt, used to prevent any signed message
// from ever being a valid transaction. This prevents situations where an application
// contrives a collision between the message you need to sign and a valid transaction that
// can be submitted to spend your funds.
pub const ETHEREUM_SALT: &str = "\x19Ethereum Signed Message:\n32";

/// Representation of an Ethereum private key.
///
/// Private key can be created using a textual representation,
/// a raw binary form using array of bytes.
///
/// With PrivateKey you are able to sign messages, derive
/// public keys. Cryptography-related methods use
/// SECP256K1 elliptic curves.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub struct PrivateKey {
    key: [u8; 32],
    address: Address,
}

impl FromStr for PrivateKey {
    type Err = Error;

    /// Parse a textual representation of a private key back into PrivateKey type.
    ///
    /// It has to be a string that represents 64 characters that are hexadecimal
    /// representation of 32 bytes. Optionally this string can be prefixed with `0x`
    /// at the start.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // uses from_str for RawPrivateKey
        let raw: RawPrivateKey = s.parse()?;
        let public_key = raw.to_address()?;

        Ok(PrivateKey {
            key: raw.to_bytes(),
            address: public_key,
        })
    }
}

impl TryFrom<[u8; 32]> for PrivateKey {
    type Error = Error;
    fn try_from(val: [u8; 32]) -> Result<PrivateKey, Error> {
        // uses from for RawPrivateKey
        let raw: RawPrivateKey = val.into();
        let public_key = raw.to_address()?;

        Ok(PrivateKey {
            key: raw.to_bytes(),
            address: public_key,
        })
    }
}

impl PrivateKey {
    /// Convert a given slice of bytes into a valid private key.
    ///
    /// Input bytes are validated and an Error is returned if they are invalid
    ///
    /// * `bytes` - A static array of length 32
    pub fn from_bytes(bytes: [u8; 32]) -> Result<PrivateKey, Error> {
        // uses from for RawPrivateKey
        let raw: RawPrivateKey = bytes.into();
        let public_key = raw.to_address()?;

        Ok(PrivateKey {
            key: raw.to_bytes(),
            address: public_key,
        })
    }

    /// Get bytes back from a PrivateKey
    pub fn to_bytes(self) -> [u8; 32] {
        self.key
    }

    /// Get the address key for a given private key.
    ///
    /// This is well explained in the Ethereum Yellow Paper Appendix F.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use clarity::PrivateKey;
    /// let private_key : PrivateKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e".parse().unwrap();
    /// let public_key = private_key.to_address();
    /// ```
    pub fn to_address(self) -> Address {
        self.address
    }

    /// Signs a message that is represented by a hash contained in a binary form.
    ///
    /// Requires the data buffer to be exactly 32 bytes in length. You can prepare
    /// an input using a hashing function such as `Keccak256` which will return
    /// a buffer of exact size.
    ///
    /// You are advised, though, to use [sign_msg](#method.sign_msg)
    /// which is more user friendly version that uses Keccak256 internally.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sha3;
    /// # extern crate clarity;
    /// # use clarity::PrivateKey;
    /// # use sha3::{Keccak256, Digest};
    /// let private_key : PrivateKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e".parse().unwrap();
    /// let hash = Keccak256::digest("Hello, world!".as_bytes());
    /// let signature = private_key.sign_hash(&hash);
    /// ```
    pub fn sign_hash(&self, data: &[u8]) -> Signature {
        debug_assert_eq!(data.len(), 32);
        // Create a secret key for Secp256k1 operations
        let sk = SecretKey::from_slice(&self.to_bytes()).unwrap();
        // Acquire SECP256K1 context from thread local storage and
        // do some operations on it.
        let (recovery_id, compact) = SECP256K1.with(move |object| {
            // Borrow from a cell and reuse that borrow for subsequent
            // operations.
            let context = object.borrow();
            // Create a Secp256k1 message inside the scope without polluting
            // outside scope.
            let msg = Message::from_digest_slice(data).unwrap();
            // Sign the raw hash of RLP encoded transaction data with a private key.
            let sig = context.sign_ecdsa_recoverable(&msg, &sk);
            // Serialize the signature into the "compact" form which means
            // it will be exactly 64 bytes, and the "excess" information of
            // recovery id will be given to us.
            sig.serialize_compact()
        });
        debug_assert_eq!(compact.len(), 64);
        // I assume recovery ID is always greater than 0 to simplify
        // the conversion from i32 to Uint256. On a side note,
        // I believe "v" could be an u64 value (TODO).
        let recovery_id = match recovery_id {
            secp256k1::ecdsa::RecoveryId::Zero => 0,
            secp256k1::ecdsa::RecoveryId::One => 1,
            secp256k1::ecdsa::RecoveryId::Two => 2,
            secp256k1::ecdsa::RecoveryId::Three => 3,
        };
        assert!(recovery_id >= 0);
        let recovery_id = recovery_id as u32;
        let v: Uint256 = (recovery_id + 27).into();
        let v = v == 28u8.into();
        let r = Uint256::from_be_bytes(&compact[0..32]);
        let s = Uint256::from_be_bytes(&compact[32..64]);
        Signature::new(v, r, s)
    }

    /// Signs any message represented by a slice of data.
    ///
    /// Internally it makes `Keccak256` hash out of your data, and then creates a
    /// signature.
    ///
    /// This is more user friendly version of [sign_hash](#method.sign_hash) which means
    /// it will use `Keccak256` function to hash your input data.
    ///
    /// This method is provided on the assumption you know what you are doing, it does not prevent signed messages
    /// from being possibly valid transactions. No Ethereum signed message salt is appended. Use with Caution!
    ///
    /// # Example
    ///
    /// ```rust
    /// # use clarity::PrivateKey;
    /// let private_key : PrivateKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e".parse().unwrap();
    /// let signature = private_key.sign_insecure_msg("Hello, world!".as_bytes());
    /// ```
    pub fn sign_insecure_msg(&self, data: &[u8]) -> Signature {
        let digest = Keccak256::digest(data);
        self.sign_hash(&digest)
    }

    /// Signs any message represented by a slice of data.
    ///
    /// Internally it makes `Keccak256` hash out of your data, and then creates a
    /// signature.
    ///
    /// This is more user friendly version of [sign_hash](#method.sign_hash) which means
    /// it will use `Keccak256` function to hash your input data.
    ///
    /// Remember this function appends \x19Ethereum Signed Message:\n32 to your hash! so
    /// you may need to take that into account when you go to verify
    ///
    /// # Example
    ///
    /// ```rust
    /// # use clarity::PrivateKey;
    /// let private_key : PrivateKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1e".parse().unwrap();
    /// let signature = private_key.sign_ethereum_msg("Hello, world!".as_bytes());
    /// ```
    pub fn sign_ethereum_msg(&self, data: &[u8]) -> Signature {
        let digest = Keccak256::digest(data);
        let salt_string = ETHEREUM_SALT.to_string();
        let salt_bytes = salt_string.as_bytes();
        let digest = Keccak256::digest([salt_bytes, &digest].concat());
        self.sign_hash(&digest)
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()))
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()))
    }
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => &s,
        };

        let bytes = hex_str_to_bytes(s);

        match bytes {
            Ok(bytes) => {
                let mut res = [0u8; 32];
                res.copy_from_slice(&bytes);
                let key = PrivateKey::from_bytes(res);
                match key {
                    Ok(key) => Ok(key),
                    Err(e) => Err(serde::de::Error::custom(e)),
                }
            }
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}

impl fmt::LowerHex for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_lowercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_lowercase())
        }
    }
}

impl fmt::UpperHex for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        }
    }
}

#[test]
#[should_panic]
fn too_short() {
    PrivateKey::from_str("abcdef").unwrap();
}

#[test]
#[should_panic]
fn invalid_data() {
    let key = "\u{012345}c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438";
    assert_eq!(key.len(), 64);
    PrivateKey::from_str(key).unwrap();
}

#[test]
fn parse_address_1() {
    use crate::utils::bytes_to_hex_str;
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let key: PrivateKey = "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"
        .parse()
        .unwrap();
    assert_eq!(
        key.to_bytes(),
        [
            0xc8, 0x5e, 0xf7, 0xd7, 0x96, 0x91, 0xfe, 0x79, 0x57, 0x3b, 0x1a, 0x70, 0x64, 0xc1,
            0x9c, 0x1a, 0x98, 0x19, 0xeb, 0xdb, 0xd1, 0xfa, 0xaa, 0xb1, 0xa8, 0xec, 0x92, 0x34,
            0x44, 0x38, 0xaa, 0xf4
        ]
    );

    // geth account import <(echo c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4)
    assert_eq!(
        bytes_to_hex_str(key.to_address().as_bytes()),
        "cd2a3d9f938e13cd947ec05abc7fe734df8dd826"
    );
}

#[test]
fn parse_address_2() {
    use crate::utils::bytes_to_hex_str;
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    assert_eq!(
        key.to_bytes(),
        [
            0xc8, 0x7f, 0x65, 0xff, 0x3f, 0x27, 0x1b, 0xf5, 0xdc, 0x86, 0x43, 0x48, 0x4f, 0x66,
            0xb2, 0x00, 0x10, 0x9c, 0xaf, 0xfe, 0x4b, 0xf9, 0x8c, 0x4c, 0xb3, 0x93, 0xdc, 0x35,
            0x74, 0x0b, 0x28, 0xc0
        ]
    );

    // geth account import <(echo c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0)
    assert_eq!(
        bytes_to_hex_str(key.to_address().as_bytes()),
        "13978aee95f38490e9769c39b2773ed763d9cd5f"
    );
}

#[test]
fn to_upper_hex() {
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    let key_string = format!("{key:X}");
    assert_eq!(
        key_string,
        "C87F65FF3F271BF5DC8643484F66B200109CAFFE4BF98C4CB393DC35740B28C0"
    );
    let key_string = format!("{key:#X}");
    assert_eq!(
        key_string,
        "0xC87F65FF3F271BF5DC8643484F66B200109CAFFE4BF98C4CB393DC35740B28C0"
    );
}
#[test]
fn to_lower_hex() {
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    let key_string = format!("{key:x}");
    assert_eq!(
        key_string,
        "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
    );
    let key_string = format!("{key:#x}");
    assert_eq!(
        key_string,
        "0xc87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
    );
}

#[test]
fn sign_message() {
    // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
    let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
        .parse()
        .unwrap();
    assert_eq!(
        key.to_bytes(),
        [
            0xc8, 0x7f, 0x65, 0xff, 0x3f, 0x27, 0x1b, 0xf5, 0xdc, 0x86, 0x43, 0x48, 0x4f, 0x66,
            0xb2, 0x00, 0x10, 0x9c, 0xaf, 0xfe, 0x4b, 0xf9, 0x8c, 0x4c, 0xb3, 0x93, 0xdc, 0x35,
            0x74, 0x0b, 0x28, 0xc0
        ]
    );

    let hash = Keccak256::digest(b"Hello, world!");

    // geth account import <(echo c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0)
    let sig = key.sign_hash(&hash);
    assert_eq!(sig.get_signature_v().unwrap(), 27);
    assert_eq!(
        sig.get_r(),
        "60846573560682549108588594828362990367411621835316234394067988873897934296519"
            .parse()
            .unwrap()
    );
    assert_eq!(
        sig.get_s(),
        "38796436849307511461301231459196686786518980571289303247679628937607287361713"
            .parse()
            .unwrap()
    );

    let sig_2 = key.sign_insecure_msg(b"Hello, world!");
    assert_eq!(sig, sig_2);

    // Recover address using just a signature
    let recovered = sig
        .recover(&hash)
        .expect("Unable to recover address from a signature");
    assert_eq!(recovered, key.to_address());
}

#[test]
fn serialize_to_json() {
    let unsafe_key: PrivateKey = "0101010101010101010101010101010101010101010101010101010101010101"
        .parse()
        .unwrap();
    let j = serde_json::to_string(&unsafe_key).unwrap();
    assert_eq!(
        j,
        r#""0x0101010101010101010101010101010101010101010101010101010101010101""#
    );
    let recovered_key: PrivateKey = serde_json::from_str(&j).unwrap();
    assert_eq!(unsafe_key, recovered_key);
}

#[test]
fn from_string_with_prefix_issue_58() {
    let unsafe_key: PrivateKey =
        "0x0101010101010101010101010101010101010101010101010101010101010101"
            .parse()
            .unwrap();
    assert_eq!(
        unsafe_key.to_bytes(),
        [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1
        ]
    );
}

#[test]
fn test_salt() {
    let salt_string = ETHEREUM_SALT.to_string();
    let salt_bytes = salt_string.as_bytes();
    assert_eq!(
        hex_str_to_bytes("0x19457468657265756d205369676e6564204d6573736167653a0a3332").unwrap(),
        salt_bytes
    );
}
