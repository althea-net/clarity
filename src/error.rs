use std::fmt;
use std::num::ParseIntError;
use std::str::Utf8Error;

/// Custom error implementation that describes possible
/// error states.
///
/// This is shared by a whole crate.
#[derive(Debug)]
pub enum Error {
    InvalidNetworkId,
    InvalidV,
    InvalidR,
    InvalidS,
    InvalidSignatureValues,
    ZeroPrivKey,
    InvalidPrivKeyLength { got: usize, expected: usize },
    DecodePrivKey(secp256k1::Error),
    DecodeRecoveryId(secp256k1::Error),
    ParseMessage(secp256k1::Error),
    ParseRecoverableSignature(secp256k1::Error),
    RecoverSignature(secp256k1::Error),
    InvalidAddressLength { got: usize, expected: usize },
    InvalidUtf8(Utf8Error),
    InvalidHex(ParseIntError),
    InvalidEip55,
    InvalidCallError(String),
    InvalidSignatureLength,
    SerializeRlp,
    DeserializeRlp,
    NoSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidNetworkId => write!(f, "Invalid network id"),
            Error::InvalidV => write!(f, "Invalid V value"),
            Error::InvalidR => write!(f, "Invalid R value"),
            Error::InvalidS => write!(f, "Invalid S value"),
            Error::InvalidSignatureValues => write!(f, "Invalid signature values"),
            Error::ZeroPrivKey => write!(f, "Zero priv key cannot sign"),
            Error::InvalidPrivKeyLength { got, expected } => write!(
                f,
                "Invalid private key length, got {got} expected {expected}"
            ),
            Error::DecodePrivKey(_) => write!(f, "Failed to decode private key"),
            Error::DecodeRecoveryId(_) => write!(f, "Failed to decode recovery id"),
            Error::ParseMessage(_) => write!(f, "Failed to parse message"),
            Error::ParseRecoverableSignature(_) => {
                write!(f, "Failed to parse recoverable signature")
            }
            Error::RecoverSignature(_) => write!(f, "Failed to recover signature"),
            Error::InvalidAddressLength { got, expected } => {
                write!(f, "Invalid address length, got {got}, expected {expected}")
            }
            Error::InvalidUtf8(_) => write!(f, "Failed to parse bytes as utf8"),
            Error::InvalidHex(_) => write!(f, "Invalid hex character"),
            Error::InvalidEip55 => write!(f, "Invalid EIP-55 Address encoding"),
            Error::InvalidCallError(val) => write!(f, "Invalid function call {val}"),
            Error::InvalidSignatureLength => write!(f, "Signature should be exactly 65 bytes long"),
            Error::SerializeRlp => write!(f, "failed to serialize using RLP-encoding"),
            Error::DeserializeRlp => write!(f, "failed to deserialize using RLP-encoding"),
            Error::NoSignature => write!(f, "This transaction does not have a signature attached"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::DecodePrivKey(inner) => Some(inner),
            Error::DecodeRecoveryId(inner) => Some(inner),
            Error::ParseMessage(inner) => Some(inner),
            Error::ParseRecoverableSignature(inner) => Some(inner),
            Error::RecoverSignature(inner) => Some(inner),
            Error::InvalidHex(inner) => Some(inner),
            Error::InvalidUtf8(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Error::InvalidUtf8(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::InvalidHex(e)
    }
}
