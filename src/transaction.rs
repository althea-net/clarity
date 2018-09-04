use address::Address;
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use types::BigEndianInt;

/// Transaction as explained in the Ethereum Yellow paper section 4.2
struct Transaction {
    nonce: BigEndianInt,
    gas_price: BigEndianInt,
    gas_limit: BigEndianInt,
    to: Address,
    value: BigEndianInt,
    data: Vec<u8>,
    v: BigEndianInt,
    r: BigEndianInt,
    s: BigEndianInt,
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(9)?;
        tup.serialize_element(&self.nonce)?;
        tup.serialize_element(&self.gas_price)?;
        tup.serialize_element(&self.gas_limit)?;
        tup.serialize_element(&self.to)?;
        tup.serialize_element(&self.value)?;
        tup.serialize_element(&self.data)?;
        tup.serialize_element(&self.v)?;
        tup.serialize_element(&self.r)?;
        tup.serialize_element(&self.s)?;
        tup.end()
    }
}

#[test]
fn dummy_transaction() {
    // Just to verify iff we can construct TX with data that looks like valid data.
    let _tx = Transaction {
        nonce: 1u64.into(),
        gas_price: 1_000_000_000u64.into(),
        gas_limit: 123u64.into(),
        to: "1234567890123456789012345678901234567890".parse().unwrap(),
        value: 0u64.into(),
        data: Vec::new(),
        v: 1u64.into(),
        r: 2u64.into(),
        s: 3u64.into(),
    };
}
