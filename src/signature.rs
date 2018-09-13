use constants::SECPK1N;
use num_traits::Zero;
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use types::BigEndianInt;

#[derive(Clone, Debug)]
pub struct Signature {
    pub v: BigEndianInt,
    pub r: BigEndianInt,
    pub s: BigEndianInt,
}

impl Signature {
    pub fn new(v: BigEndianInt, r: BigEndianInt, s: BigEndianInt) -> Signature {
        Signature { v, r, s }
    }

    pub fn is_valid(&self) -> bool {
        if self.s >= *SECPK1N {
            return false;
        }

        if self.r >= *SECPK1N
            || self.s >= *SECPK1N
            || self.r == BigEndianInt::zero()
            || self.s == BigEndianInt::zero()
        {
            return false;
        }

        true
    }
}

impl Default for Signature {
    fn default() -> Signature {
        Signature {
            r: BigEndianInt::zero(),
            v: BigEndianInt::zero(),
            s: BigEndianInt::zero(),
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
