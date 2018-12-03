use constants::SECPK1N;
use error::ClarityError;
use failure::Error;
use num256::Uint256;
use num_traits::Zero;
use std::fmt;
use std::str::FromStr;
use utils::{
    big_endian_uint256_deserialize, big_endian_uint256_serialize, bytes_to_hex_str,
    hex_str_to_bytes,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Signature {
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub v: Uint256,
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub r: Uint256,
    #[serde(
        serialize_with = "big_endian_uint256_serialize",
        deserialize_with = "big_endian_uint256_deserialize"
    )]
    pub s: Uint256,
}

impl Signature {
    pub fn new(v: Uint256, r: Uint256, s: Uint256) -> Signature {
        Signature { v, r, s }
    }

    pub fn is_valid(&self) -> bool {
        if self.s >= *SECPK1N {
            return false;
        }

        if self.r >= *SECPK1N
            || self.s >= *SECPK1N
            || self.r == Uint256::zero()
            || self.s == Uint256::zero()
        {
            return false;
        }

        true
    }

    pub fn network_id(&self) -> Option<Uint256> {
        if self.r == Uint256::zero() && self.s == Uint256::zero() {
            Some(self.v.clone())
        } else if self.v == 27u32.into() || self.v == 28u32.into() {
            None
        } else {
            Some(((self.v.clone() - 1u32) / 2u32) - 17u32)
        }
    }

    pub fn check_low_s_metropolis(&self) -> Result<(), Error> {
        if self.s > (SECPK1N.clone() / Uint256::from(2u32)) {
            return Err(ClarityError::InvalidS.into());
        }
        Ok(())
    }

    pub fn check_low_s_homestead(&self) -> Result<(), Error> {
        if self.s > (SECPK1N.clone() / Uint256::from(2u32)) || self.s == Uint256::zero() {
            return Err(ClarityError::InvalidS.into());
        }
        Ok(())
    }

    /// Converts a signature into a bytes string.
    ///
    /// A signature in binary form consists of 65 bytes where
    /// first 32 bytes are "r" in big endian form, next 32 bytes are "s"
    /// in big endian form, and at the end there is one byte made of "v".
    ///
    /// This also consumes the signature.
    pub fn into_bytes(self) -> [u8; 65] {
        let r: [u8; 32] = self.r.into();
        let s: [u8; 32] = self.s.into();
        let mut result = [0x00u8; 65];
        // Put r at the beggining
        result[0..32].copy_from_slice(&r);
        // Add s in the middle
        result[32..64].copy_from_slice(&s);
        // End up with v at the end
        let v = self.v.to_bytes_be();
        result[64] = v[v.len() - 1];
        result
    }

    /// Constructs a signature from a bytes string
    ///
    /// This is opposite to `into_bytes()` where a signature is created based
    /// on a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(
            bytes.len() == 65,
            "Signature in binary form is exactly 65 bytes long"
        );
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
        Ok(Signature::new(v.into(), r, s))
    }
}

impl Default for Signature {
    fn default() -> Signature {
        Signature {
            r: Uint256::zero(),
            v: Uint256::zero(),
            s: Uint256::zero(),
        }
    }
}

impl ToString for Signature {
    // Constructs a string from a given signature
    // The resulting string's length is 130
    // first 32 bytes is "r" value
    // second 32 bytes i s "s" value
    // last byte is "v"
    fn to_string(&self) -> String {
        // Convert and make a signature made of bytes
        let sig_bytes = self.clone().into_bytes();

        // Convert those bytes in a string
        let mut result = "0x".to_owned();
        result += &bytes_to_hex_str(&sig_bytes);
        result
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
        let s = if s.starts_with("0x") { &s[2..] } else { &s };

        // Signature has exactly 130 characters (65 as bytes)
        ensure!(
            s.len() == 130,
            "Signature as a string should contain exactly 130 characters"
        );
        // Parse hexadecimal form back to bytes
        let bytes = hex_str_to_bytes(&s)?;
        Signature::from_bytes(&bytes)
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.clone().into_bytes()).to_lowercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.clone().into_bytes()).to_lowercase()
            )
        }
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "0x{}",
                bytes_to_hex_str(&self.clone().into_bytes()).to_uppercase()
            )
        } else {
            write!(
                f,
                "{}",
                bytes_to_hex_str(&self.clone().into_bytes()).to_uppercase()
            )
        }
    }
}

#[test]
fn new_signature() {
    let sig = Signature::new(1u32.into(), 2u32.into(), 3u32.into());
    assert_eq!(sig.v, 1u32.into());
    assert_eq!(sig.r, 2u32.into());
    assert_eq!(sig.s, 3u32.into());
}

#[test]
fn to_string() {
    let sig = Signature::new(1u32.into(), 2u32.into(), 3u32.into());
    let sig_string = sig.to_string();
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "01"
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
    let sig = Signature::new(1u32.into(), 65450u32.into(), 32456u32.into());
    let sig_string = format!("{:#X}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "01"
        )
    );
    let sig_string = format!("{:X}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000FFAA",
            "0000000000000000000000000000000000000000000000000000000000007EC8",
            "01"
        )
    );
}
#[test]
fn to_lower_hex() {
    let sig = Signature::new(1u32.into(), 65450u32.into(), 32456u32.into());
    let sig_string = format!("{:#x}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "0x",
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "01"
        )
    );
    let sig_string = format!("{:x}", sig);
    assert_eq!(
        sig_string,
        concat!(
            "000000000000000000000000000000000000000000000000000000000000ffaa",
            "0000000000000000000000000000000000000000000000000000000000007ec8",
            "01"
        )
    );
}

#[test]
fn into_bytes() {
    let sig = Signature::new(1u32.into(), 2u32.into(), 3u32.into());

    let sig_bytes = sig.clone().into_bytes();
    assert_eq!(
        sig_bytes.to_vec(),
        vec![
            /* r */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2, /* s */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, /* v */ 1
        ],
    );

    let new_sig = Signature::from_bytes(&sig_bytes).expect("Unable to reconstruct signature");
    assert_eq!(sig, new_sig);
}

#[test]
fn to_string_with_zero_v() {
    let sig = Signature::new(0u32.into(), 2u32.into(), 3u32.into());
    let sig_str = sig.to_string();
    assert_eq!(
        sig_str,
        concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "00"
        )
    );

    let new_sig = Signature::from_str(&sig_str).expect("Unable to reconstruct signature");
    assert_eq!(sig, new_sig);
}

#[test]
#[should_panic]
fn parse_invalid_signature() {
    let _sig: Signature = "deadbeef".parse().unwrap();
    let _sig: Signature = "0x".parse().unwrap();
}
