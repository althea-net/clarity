use crate::address::Address;
use crate::constants::secpk1n;
use crate::context::SECP256K1;
use crate::error::Error;
use crate::transaction::v_to_num;
use crate::utils::{
    big_endian_uint256_deserialize, big_endian_uint256_serialize, bytes_to_hex_str,
    hex_str_to_bytes,
};
use num256::Uint256;
use num_traits::{ToPrimitive, Zero};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Message;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Display};
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum Signature {
    LegacySignature {
        #[serde(
            serialize_with = "big_endian_uint256_serialize",
            deserialize_with = "big_endian_uint256_deserialize"
        )]
        v: Uint256,
        #[serde(
            serialize_with = "big_endian_uint256_serialize",
            deserialize_with = "big_endian_uint256_deserialize"
        )]
        r: Uint256,
        #[serde(
            serialize_with = "big_endian_uint256_serialize",
            deserialize_with = "big_endian_uint256_deserialize"
        )]
        s: Uint256,
    },
    ModernSignature {
        /// todo fix serialization here
        v: bool,
        #[serde(
            serialize_with = "big_endian_uint256_serialize",
            deserialize_with = "big_endian_uint256_deserialize"
        )]
        r: Uint256,
        #[serde(
            serialize_with = "big_endian_uint256_serialize",
            deserialize_with = "big_endian_uint256_deserialize"
        )]
        s: Uint256,
    },
}

impl Signature {
    pub fn new(v: bool, r: Uint256, s: Uint256) -> Signature {
        Signature::ModernSignature { r, s, v }
    }

    pub fn new_legacy(v: Uint256, r: Uint256, s: Uint256) -> Signature {
        Signature::LegacySignature { v, r, s }
    }

    pub fn get_r(&self) -> Uint256 {
        match self {
            Signature::LegacySignature { r, .. } | Signature::ModernSignature { r, .. } => *r,
        }
    }

    pub fn get_s(&self) -> Uint256 {
        match self {
            Signature::LegacySignature { s, .. } | Signature::ModernSignature { s, .. } => *s,
        }
    }

    /// Gets the v value, potentially encoded with a chain id
    pub fn get_v(&self) -> Uint256 {
        match self {
            Signature::LegacySignature { v, .. } => *v,
            Signature::ModernSignature { v, .. } => v_to_num(*v),
        }
    }

    /// Like is_valid() but returns a reason
    pub fn error_check(&self) -> Result<(), Error> {
        if self.get_r() >= secpk1n() || self.get_r() == Uint256::zero() {
            return Err(Error::InvalidR);
        } else if self.get_s() > secpk1n() / 2u8.into() || self.get_s() == Uint256::zero() {
            return Err(Error::InvalidS);
        }
        // this is suppposedly invalid in the VRS value tests, there's no clear spec that gives
        // this value though so it may be an implicit standard
        if self.get_v() >= 61480u32.into() {
            return Err(Error::InvalidV);
        }
        match self.get_signature_v() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.error_check().is_ok()
    }

    /// Extracts the chain id from the legacy signature v value
    /// will return none if the signature is either a legacy signature not protected from replay
    /// or if the signature is a modern signature at which point the chain_id value is contained in the tx
    pub fn legacy_network_id(&self) -> Option<Uint256> {
        match self {
            Signature::LegacySignature { v, .. } => {
                // signature with no replay protection
                if *v == 27u8.into() || *v == 28u8.into() {
                    None
                } else {
                    // bit hacked network id value, decode here
                    let network_id = ((*v - 1u8.into()) / 2u8.into()) - 17u8.into();
                    // these cover depricated testnets and are now considered invalid
                    if network_id == 3u8.into() || network_id == 2u8.into() {
                        None
                    } else {
                        Some(network_id)
                    }
                }
            }
            Signature::ModernSignature { .. } => None,
        }
    }

    /// Get the actual signature component V value, only two possibilities 27 or 28
    /// this is different from V encoded with a chain id for which you should use get_v()
    pub fn get_signature_v(&self) -> Result<u8, Error> {
        match self {
            Signature::LegacySignature { v, .. } => {
                // Valid V values are in {27, 28} according to Ethereum Yellow paper Appendix F (282).
                if *v == 27u8.into() {
                    Ok(27)
                } else if *v == 28u8.into() {
                    Ok(28)
                } else if *v >= 37u8.into() {
                    let network_id = self.legacy_network_id().ok_or(Error::InvalidNetworkId)?;
                    // // Otherwise we have to extract "v"...
                    let vee = *v - (network_id * 2u8.into()) - 8u8.into();
                    let vee = vee.to_be_bytes()[31];
                    // // ... so after all v will still match 27<=v<=28
                    assert!(vee == 27 || vee == 28);
                    Ok(vee)
                } else {
                    // All other V values would be errorneous for our calculations
                    Err(Error::InvalidV)
                }
            }
            Signature::ModernSignature { v, .. } => {
                if *v {
                    Ok(28)
                } else {
                    Ok(27)
                }
            }
        }
    }

    /// Converts a signature into a bytes string.
    ///
    /// A signature in binary form consists of 65 bytes where
    /// first 32 bytes are "r" in big endian form, next 32 bytes are "s"
    /// in big endian form, and at the end there is one byte made of "v".
    ///
    /// This also consumes the signature.
    pub fn into_bytes(self) -> [u8; 65] {
        // Since 0.1.20 it calls `as_bytes` and consumes self
        self.to_bytes()
    }
    /// Extracts signature as bytes.
    ///
    /// This supersedes `into_bytes` as it does not consume the object itself.
    pub fn to_bytes(&self) -> [u8; 65] {
        // Usually `to_bytes` function in standard library returns a borrowed
        // value, but its impossible in our case since VRS are separate objects,
        // and its impossible to just cast a struct into a slice of bytes.
        let r: [u8; 32] = self.get_r().into();
        let s: [u8; 32] = self.get_s().into();
        let mut result = [0x00u8; 65];
        // Put r at the beginning
        result[0..32].copy_from_slice(&r);
        // Add s in the middle
        result[32..64].copy_from_slice(&s);
        // End up with v at the end
        result[64] = self
            .get_signature_v()
            .expect("Into bytes on invalid signature");
        result
    }
    /// Constructs a signature from a bytes string
    ///
    /// This is opposite to `into_bytes()` where a signature is created based
    /// on a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 {
            return Err(Error::InvalidSignatureLength);
        }

        let r: Uint256 = {
            let mut data: [u8; 32] = Default::default();
            data.copy_from_slice(&bytes[0..32]);
            data.into()
        };
        let s: Uint256 = {
            let mut data: [u8; 32] = Default::default();
            data.copy_from_slice(&bytes[32..64]);
            data.into()
        };
        let v = bytes[64];
        if v == 27 || v == 28 {
            // we actually can't tell in this case if we have a modern signature of an unprotected legacy
            // sig, so we just return modern
            Ok(Signature::ModernSignature { v: v == 28, r, s })
        } else {
            Ok(Signature::LegacySignature { v: v.into(), r, s })
        }
    }

    /// Recover an address from a signature
    ///
    /// This can be called with any arbitrary signature, and a hashed message.
    pub fn recover(&self, hash: &[u8]) -> Result<Address, Error> {
        // Create recovery ID which is "v" minus 27. Without this it wouldn't be possible to extract recoverable signature.
        let v_num = self.get_signature_v()?.to_i32().ok_or(Error::InvalidV)? - 27;
        let v = match v_num {
            0 => RecoveryId::Zero,
            1 => RecoveryId::One,
            2 => RecoveryId::Two,
            3 => RecoveryId::Three,
            _ => return Err(Error::InvalidV),
        };
        // A message to recover which is a hash of the transaction
        let mut msg_buf = [0u8; 32];
        msg_buf.copy_from_slice(hash);
        let msg = Message::from_digest(msg_buf);

        // Get the compact form using bytes, and "v" parameter
        let compact = RecoverableSignature::from_compact(&self.to_bytes()[..64], v)
            .map_err(Error::ParseRecoverableSignature)?;
        // Acquire secp256k1 context from thread local storage
        let pkey = SECP256K1.with(move |object| -> Result<_, Error> {
            // Borrow once and reuse
            let secp256k1 = object.borrow();
            // Recover public key
            let pkey = secp256k1
                .recover_ecdsa(msg, &compact)
                .map_err(Error::RecoverSignature)?;
            // Serialize the recovered public key in uncompressed format
            Ok(pkey.serialize_uncompressed())
        })?;
        assert_eq!(pkey.len(), 65);
        if pkey[1..].to_vec() == [0x00u8; 64].to_vec() {
            return Err(Error::ZeroPrivKey);
        }
        // Finally an address is last 20 bytes of a hash of the public key.
        let sender = Keccak256::digest(&pkey[1..]);
        debug_assert_eq!(sender.len(), 32);
        Address::from_slice(&sender[12..])
    }
}

impl Display for Signature {
    // Constructs a string from a given signature
    // The resulting string's length is 130
    // first 32 bytes is "r" value
    // second 32 bytes i s "s" value
    // last byte is "v"
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()))
    }
}

impl FromStr for Signature {
    type Err = Error;
    /// Constructs a signature back from a string representation
    ///
    /// The input string's length should be exactly 130 not including
    /// optional "0x" prefix at the beggining.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strip optional prefix
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => s,
        };

        // Parse hexadecimal form back to bytes
        let bytes = hex_str_to_bytes(s)?;
        Signature::from_bytes(&bytes)
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.clone().to_bytes()).to_lowercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.clone().to_bytes()).to_lowercase()
            )
        }
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        }
    }
}

#[test]
fn new_signature() {
    let sig = Signature::new(false, 2u32.into(), 3u32.into());
    assert_eq!(sig.get_signature_v().unwrap(), 27);
    assert_eq!(sig.get_r(), 2u32.into());
    assert_eq!(sig.get_s(), 3u32.into());
}

#[test]
fn to_string() {
    let sig = Signature::new(true, 2u32.into(), 3u32.into());
    let sig_string = sig.to_string();
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "1c"
        )
    );
    let new_sig = Signature::from_str(&sig_string).expect("Unable to parse signature");
    assert_eq!(sig, new_sig);

    // Without 0x
    assert!(sig_string.starts_with("0x"));
    let new_sig = Signature::from_str(&sig_string[2..]).expect("Unable to parse signature");
    assert_eq!(sig, new_sig);
}

#[test]
fn to_upper_hex() {
    let sig = Signature::new(true, 65450u32.into(), 32456u32.into());
    let sig_string = format!("{sig:#X}");
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "1C"
        )
    );
    let sig_string = format!("{sig:X}");
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "1C"
        )
    );
}
#[test]
fn to_lower_hex() {
    let sig = Signature::new(true, 65450u32.into(), 32456u32.into());
    let sig_string = format!("{sig:#x}");
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "1c"
        )
    );
    let sig_string = format!("{sig:x}");
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "1c"
        )
    );
}

#[test]
fn into_bytes() {
    let sig = Signature::new(true, 2u32.into(), 3u32.into());

    let sig_bytes = sig.to_bytes();
    assert_eq!(
        sig_bytes.to_vec(),
        vec![
            /* r */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, /* s */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, /* v */ 28
        ],
    );

    let new_sig = Signature::from_bytes(&sig_bytes).expect("Unable to reconstruct signature");
    assert_eq!(sig, new_sig);
}

#[test]
#[should_panic]
fn parse_invalid_signature() {
    let _sig: Signature = "deadbeef".parse().unwrap();
    let _sig: Signature = "0x".parse().unwrap();
}

#[test]
fn generate_ethereum_signature() {
    use crate::PrivateKey;
    let private_key: PrivateKey =
        "0xc5e8f61d1ab959b397eecc0a37a6517b8e67a0e7cf1f4bce5591f3ed80199122"
            .parse()
            .unwrap();
    let address: Address = "0xc783df8a850f42e7F7e57013759C285caa701eB6"
        .parse()
        .unwrap();
    let checkpoint =
        hex_str_to_bytes("0x666f6f0000000000000000000000000000000000000000000000000000000000636865636b706f696e7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000003000000000000000000000000c783df8a850f42e7f7e57013759c285caa701eb6000000000000000000000000ead9c93b79ae7c1591b1fb5323bd777e86e150d4000000000000000000000000e5904695748fe4a84b40b3fc79de2277660bd1d300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d050000000000000000000000000000000000000000000000000000000000000d05")
            .unwrap();
    let sig: Signature = "0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae7706b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d01c".parse().unwrap();

    assert_eq!(private_key.to_address(), address);

    let generated_sig = private_key.sign_ethereum_msg(&checkpoint);
    assert_eq!(sig, generated_sig)
}

#[test]
fn parse_hex_signature() {
    let sig: Signature = "0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae7706b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d01c".parse().unwrap();
    let correct_r =
        hex_str_to_bytes("0xe108a7776de6b87183b0690484a74daef44aa6daf907e91abaf7bbfa426ae770")
            .unwrap();
    let correct_s =
        hex_str_to_bytes("0x6b12e0bd44ef7b0634710d99c2d81087a2f39e075158212343a3b2948ecf33d0")
            .unwrap();

    assert_eq!(sig.get_r(), Uint256::from_be_bytes(&correct_r));
    assert_eq!(sig.get_s(), Uint256::from_be_bytes(&correct_s));
    assert_eq!(sig.get_signature_v().unwrap(), 28);
}
