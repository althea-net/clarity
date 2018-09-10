use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use types::BigEndianInt;
use num_traits::Zero;

#[derive(Clone)]
pub struct Signature {
    pub v: BigEndianInt,
    pub r: BigEndianInt,
    pub s: BigEndianInt,
}

impl Signature {
    pub fn new(v: BigEndianInt, r: BigEndianInt, s: BigEndianInt) -> Signature {
        Signature { v, r, s }
    }
}

impl Default for Signature {
    fn default() -> Signature {
        Signature { r: BigEndianInt::zero(), v: BigEndianInt::zero(), s: BigEndianInt::zero() }
    }
}

#[test]
fn new_signature() {
    let sig = Signature::new(1.into(), 2.into(), 3.into());
    assert_eq!(sig.v, 1.into());
    assert_eq!(sig.r, 2.into());
    assert_eq!(sig.s, 3.into());
}
