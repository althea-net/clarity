//! A raw private key type, used to bootstrap to a validated private key exposed to the outside world.

use crate::address::Address;
use crate::context::SECP256K1;
use crate::error::Error;
use crate::utils::hex_str_to_bytes;
use secp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

/// Representation of an Ethereum private key, this is unvalidated
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub struct RawPrivateKey([u8; 32]);

impl FromStr for RawPrivateKey {
    type Err = Error;

    /// Parse a textual representation of a private key back into PrivateKey type.
    ///
    /// It has to be a string that represents 64 characters that are hexadecimal
    /// representation of 32 bytes. Optionally this string can be prefixed with `0x`
    /// at the start.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strip optional prefix if its there
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => s,
        };
        if s.len() != 64 {
            return Err(Error::InvalidPrivKeyLength {
                got: s.len(),
                expected: 64,
            });
        }
        let bytes = hex_str_to_bytes(s)?;
        debug_assert_eq!(bytes.len(), 32);
        let mut res = [0x0u8; 32];
        res.copy_from_slice(&bytes[..]);
        Ok(RawPrivateKey(res))
    }
}

impl From<[u8; 32]> for RawPrivateKey {
    fn from(val: [u8; 32]) -> RawPrivateKey {
        RawPrivateKey(val)
    }
}

impl RawPrivateKey {
    /// Get bytes back from a PrivateKey
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Creates an Address key for a given private key.
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
    pub fn to_address(self) -> Result<Address, Error> {
        // Create a secret key instance first
        let sk = SecretKey::from_slice(&self.0).map_err(Error::DecodePrivKey)?;
        // Closure below has Result type with inferred T as we don't
        // need to really assume type of the returned array from
        // `serialize_uncompressed`.
        let pkey = SECP256K1.with(move |object| -> Result<_, Error> {
            let secp256k1 = object.borrow();
            let pkey = PublicKey::from_secret_key(&secp256k1, &sk);
            // Serialize the recovered public key in uncompressed format
            Ok(pkey.serialize_uncompressed())
        })?;
        // TODO: This part is duplicated with sender code.
        assert_eq!(pkey.len(), 65);
        if pkey[1..] == [0x00u8; 64][..] {
            return Err(Error::ZeroPrivKey);
        }
        // Finally an address is last 20 bytes of a hash of the public key.
        let sender = Keccak256::digest(&pkey[1..]);
        debug_assert_eq!(sender.len(), 32);
        Address::from_slice(&sender[12..])
    }
}

#[test]
#[should_panic]
fn zero_private_key() {
    // A key full of zeros is an invalid private key.
    let raw: [u8; 32] = [0; 32];
    let key: RawPrivateKey = raw.into();
    key.to_address().unwrap();
}
