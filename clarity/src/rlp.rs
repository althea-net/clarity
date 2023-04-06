use crate::{Address, Error};
/// RLP encoder and decoder, transactions are encoded via rlp whereas contract calls are encoded with the Ethereum ABI
/// transactions include contract calls so this is the outer wrapper for any ABI encoded value
use num256::Uint256;

/// Intermediate representation for RLP serialization and deserialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpToken {
    List(Vec<RlpToken>),
    /// conceptually a string is just an arbitrary set of data, many trings
    /// are 64 bytes long and represent a 256bit integer or 8 bytes long for a 64 bit integer
    String(Vec<u8>),
    /// A single byte value, often just a length or offset, sometimes small numbers like a nonce may
    /// get folded into this
    SingleByte(u8),
}

impl RlpToken {
    /// Returns the byte content of String and SingleByte types
    /// returns an Error if the enum is the list variant
    pub fn get_byte_content(&self) -> Result<Vec<u8>, Error> {
        match self {
            RlpToken::List(_) => Err(Error::DeserializeRlp),
            RlpToken::String(b) => Ok(b.clone()),
            RlpToken::SingleByte(b) => Ok(vec![*b]),
        }
    }

    /// Returns the list content of a List type RLP token, returns an Error
    /// for the String and SingleByte variants
    pub fn get_list_content(&self) -> Result<Vec<RlpToken>, Error> {
        match self {
            RlpToken::List(v) => Ok(v.clone()),
            RlpToken::String(_) | RlpToken::SingleByte(_) => Err(Error::DeserializeRlp),
        }
    }
}

impl From<u8> for RlpToken {
    fn from(value: u8) -> Self {
        RlpToken::SingleByte(value)
    }
}

// trim leading zero bytes of a provided array
fn trim_leading_zero_bytes(bytes: Vec<u8>) -> Vec<u8> {
    for (i, v) in bytes.iter().enumerate() {
        if *v != 0 {
            return bytes[i..].to_vec();
        }
    }
    Vec::new()
}

impl From<Uint256> for RlpToken {
    fn from(value: Uint256) -> Self {
        if value < 127u8.into() {
            RlpToken::SingleByte(value.to_le_bytes()[0])
        } else {
            let value = value.to_be_bytes().to_vec();
            RlpToken::String(trim_leading_zero_bytes(value))
        }
    }
}

impl From<&Uint256> for RlpToken {
    fn from(value: &Uint256) -> Self {
        (*value).into()
    }
}

impl From<Address> for RlpToken {
    fn from(value: Address) -> Self {
        RlpToken::String(value.as_bytes().to_vec())
    }
}

impl From<&Address> for RlpToken {
    fn from(value: &Address) -> Self {
        RlpToken::String(value.as_bytes().to_vec())
    }
}

/// Unpacks RLP encoded bytes into a series of arrays
/// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
/// From there further decoding can occur
pub fn unpack_rlp(input: &[u8]) -> Result<Vec<RlpToken>, Error> {
    // too small or too large
    if input.is_empty() || input.len() as u64 > u64::MAX {
        return Err(Error::DeserializeRlp);
    }

    match input[0] {
        d if d <= 0x7f => {
            // unit value
            let mut out = vec![RlpToken::SingleByte(d)];
            // base case, no other elements
            if input.len() == 1 {
                Ok(out)
            } else {
                // recurse for other elements
                out.extend(unpack_rlp(&input[1..])?);
                Ok(out)
            }
        }
        d if d <= 0xb7 => {
            // case for a small string
            let len_of_string = (d - 0x80) as usize;
            let end_index = 1 + len_of_string;

            if end_index > input.len() {
                return Err(Error::DeserializeRlp);
            }

            let mut out = if len_of_string == 0 {
                // special case for encoding an empty string
                // this can also be interpreted as the single byte zero
                // but it seems encoders expect 0x80 rather than 0x00
                vec![RlpToken::String(vec![])]
            } else if len_of_string == 1 {
                // speical case for a single byte value
                vec![RlpToken::SingleByte(input[1])]
            } else {
                vec![RlpToken::String(input[1..end_index].to_vec())]
            };
            // base case, no other elements
            if input.len() == end_index {
                Ok(out)
            } else {
                // recurse for other elements
                out.extend(unpack_rlp(&input[end_index..])?);
                Ok(out)
            }
        }
        d if d < 0xc0 => {
            // case for long string, decode both the length of the length and then the actual data
            let len_of_len_of_string = (d - 0xb7) as usize;
            if len_of_len_of_string >= input.len() - 1 {
                // impossibly long
                return Err(Error::DeserializeRlp);
            }
            let len_of_string =
                downcast(Uint256::from_be_bytes(&input[1..1 + len_of_len_of_string]))?;
            let start_index = 1 + len_of_len_of_string;
            let end_index = start_index + len_of_string;
            if start_index + len_of_string >= input.len() {
                // impossibly long
                return Err(Error::DeserializeRlp);
            }
            let mut out = vec![RlpToken::String(
                input[start_index..start_index + len_of_string].to_vec(),
            )];
            // base case, no other elements
            if input.len() == end_index {
                Ok(out)
            } else {
                // recurse for other elements
                out.extend(unpack_rlp(&input[end_index..])?);
                Ok(out)
            }
        }
        d if d <= 0xf7 => {
            // case for a short list, recurse
            let len_of_list = (d - 0xc0) as usize;
            let start_index = 1;
            let end_index = start_index + len_of_list;

            if end_index > input.len() {
                return Err(Error::DeserializeRlp);
            }

            let mut out = if len_of_list == 0 {
                // special case for encoding an empty list
                vec![RlpToken::List(vec![])]
            } else {
                vec![RlpToken::List(unpack_rlp(&input[start_index..end_index])?)]
            };
            // base case, no other elements
            if input.len() == end_index {
                Ok(out)
            } else {
                // recurse for other elements
                out.extend(unpack_rlp(&input[end_index..])?);
                Ok(out)
            }
        }
        d => {
            // case for long list, decode both the length of the length and then recurse
            let len_of_len_of_list = (d - 0xf7) as usize;
            if len_of_len_of_list >= input.len() - 1 {
                // impossibly long
                return Err(Error::DeserializeRlp);
            }
            let len_of_list = downcast(Uint256::from_be_bytes(&input[1..1 + len_of_len_of_list]))?;
            let start_index = 1 + len_of_len_of_list;
            let end_index = start_index + len_of_list;

            if end_index > input.len() {
                return Err(Error::DeserializeRlp);
            }

            let mut out = vec![RlpToken::List(unpack_rlp(&input[start_index..end_index])?)];
            // base case, no other elements
            if input.len() == end_index {
                Ok(out)
            } else {
                // recurse for other elements
                out.extend(unpack_rlp(&input[end_index..])?);
                Ok(out)
            }
        }
    }
}

/// Takes RLP token structs and packs the values into a single rlp
/// encoded byte array
pub fn pack_rlp(input: Vec<RlpToken>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for token in input {
        match token {
            RlpToken::List(list) => {
                let encoded_list_data = pack_rlp(list);
                if encoded_list_data.len() <= 55 {
                    // small list case, encode length in single byte
                    out.extend(vec![0xc0 + encoded_list_data.len() as u8]);
                    // special case for zero length
                    if !encoded_list_data.is_empty() {
                        out.extend(encoded_list_data);
                    }
                } else {
                    // large list case, encoded the length of the length, then the data
                    let encoded_len_of_data =
                        trim_leading_zero_bytes(encoded_list_data.len().to_be_bytes().to_vec());
                    let len_of_len = encoded_len_of_data.len();
                    // this will overflow if trying to encode a value that's too large for rlp
                    out.extend(vec![0xf7 + len_of_len as u8]);
                    out.extend(encoded_len_of_data);
                    out.extend(encoded_list_data);
                }
            }
            RlpToken::String(string) => {
                // this is a series of observed hacky conditions, I believe because we compress addresses that are
                // less than 20 bytes to zeros
                let encoded_string_data = if all_bytes_are_zero(&string) && string.len() <= 20 {
                    vec![]
                } else {
                    string
                };
                if encoded_string_data.len() <= 55 {
                    // special case for zero length
                    let len = if encoded_string_data == vec![0] {
                        0
                    } else {
                        encoded_string_data.len()
                    };
                    // small string case, encode length in single byte
                    out.extend(vec![0x80 + len as u8]);
                    if len != 0 {
                        out.extend(encoded_string_data);
                    }
                } else {
                    // large list case, encoded the length of the length, then the string
                    let encoded_len_of_string =
                        trim_leading_zero_bytes(encoded_string_data.len().to_be_bytes().to_vec());
                    let len_of_len = encoded_len_of_string.len();
                    // this will overflow if trying to encode a value that's too large for rlp
                    out.extend(vec![0xb7 + len_of_len as u8]);
                    out.extend(encoded_len_of_string);
                    out.extend(encoded_string_data);
                }
            }
            RlpToken::SingleByte(b) => {
                // a single byte can be encoded as itself or as a single byte string
                if b > 0x7f {
                    // larger value encoded as a single byte string
                    out.extend(vec![0x81]);
                    // the actaul value
                    out.extend(vec![b])
                } else if b == 0 {
                    // the value 0 is encoded as a zero length string
                    // rather than 0x00 for some reason
                    out.extend(vec![0x80]);
                } else {
                    // all other numbers less than 0x7f
                    out.extend(vec![b])
                }
            }
        }
    }
    out
}

fn all_bytes_are_zero(input: &[u8]) -> bool {
    for b in input {
        if *b != 0 {
            return false;
        }
    }
    true
}

/// Safely downcasts a Uint256 to system integer size, note that on systems with 32 bit integer size
/// this may return invalid for some otherwise valid RLP, but only in the case that the system doesn't have
/// enough memory to decode the value anyways. I guess swap might allow this error case to actually be encountered
pub fn downcast(input: Uint256) -> Result<usize, Error> {
    if input > usize::MAX.into() {
        Err(Error::DeserializeRlp)
    } else {
        const USIZE_BYTES: usize = (usize::BITS / 8) as usize;
        let bytes = input.to_le_bytes();
        let mut slice = [0; USIZE_BYTES];
        slice.copy_from_slice(&bytes[0..USIZE_BYTES]);
        Ok(usize::from_le_bytes(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_fuzz_bytes;
    use rand::thread_rng;
    use std::time::{Duration, Instant};

    const FUZZ_TIME: Duration = Duration::from_secs(30);

    #[test]
    fn test_downcast() {
        assert_eq!(downcast(50u8.into()).unwrap(), 50);
        let max = Uint256::from(u32::MAX);
        // note this will not work on systems with a 16 bit integer size
        #[cfg(all(unix, target_pointer_width = "32"))]
        assert!(downcast(max + 1u8.into()).is_err());
        #[cfg(all(unix, target_pointer_width = "64"))]
        assert_eq!(downcast(max + 1u8.into()).unwrap(), (u32::MAX as usize + 1));
    }

    #[test]
    fn fuzz_rlp_decode() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let transaction_bytes = get_fuzz_bytes(&mut rng);

            let res = unpack_rlp(&transaction_bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }
}
