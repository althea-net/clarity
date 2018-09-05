use address::Address;
use serde::ser::SerializeTuple;
use serde::Serialize;
use serde::Serializer;
use types::BigEndianInt;
use utils::hex_str_to_bytes;

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
fn test_vitaliks_eip_158_vitalik_12_json() {
    // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
    let _tx = Transaction {
        nonce: BigEndianInt::from_str_radix("0e", 16).unwrap(),
        gas_price: BigEndianInt::from_str_radix("00", 16).unwrap(),
        gas_limit: BigEndianInt::from_str_radix("0493e0", 16).unwrap(),
        to: Address::new(), // "" - zeros only
        value: "00".parse().unwrap(),
        data: Vec::new(),
        v: BigEndianInt::from_str_radix("1c", 16).unwrap(),
        r: BigEndianInt::from_str_radix(
            "a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4",
            16,
        ).unwrap(),
        s: BigEndianInt::from_str_radix(
            "6dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6",
            16,
        ).unwrap(),
    };
}
