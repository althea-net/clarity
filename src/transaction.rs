use crate::address::Address;
use crate::constants::zero_address;
use crate::error::Error;
use crate::opcodes::GTXACCESSLISTADDRESS;
use crate::opcodes::GTXACCESSLISTSTORAGE;
use crate::opcodes::GTXCONTRACTCREATION;
use crate::opcodes::GTXCOST;
use crate::opcodes::GTXDATANONZERO;
use crate::opcodes::GTXDATAZERO;
use crate::private_key::PrivateKey;
use crate::rlp::pack_rlp;
use crate::rlp::unpack_rlp;
use crate::rlp::RlpToken;
use crate::signature::Signature;
use crate::utils::bytes_to_hex_str;
use num256::Uint256;
use serde::Serialize;
use serde::Serializer;
use sha3::{Digest, Keccak256};
use std::fmt;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Transaction {
    /// The original Ethereum transaction format, will always start with a byte >=0xc0
    Legacy {
        /// Replay prevention counter, this must be the last nonce successfully on the
        /// chain plus one, multiple tx with incrementing nonces can wait in the mempool
        /// but they must execute in order. If you have multiple tx in the pool, one with
        /// a lower nonce fails, and is then replaced the following tx will execute immediately
        nonce: Uint256,
        /// The price of gas for this transaction, total spend will be price * limit with no
        /// refund for actual utilization
        gas_price: Uint256,
        /// The maximum amount of gas that can be used by this transaction, total spend will be
        /// price * limit with no refund for if the actual utilization is below this value
        gas_limit: Uint256,
        /// The destination address, this can be a contract or another account, in the contract
        /// case the data field will be populated with an encoded contract call
        to: Address,
        /// The amount of Ether to send with this transaction, while this can be used with
        /// contract calls see ERC-1363, it's mostly used for Ether transfers. Remember ERC20
        /// ERC721 and other non Ether 'tokens' are contact calls! So an ERC20 send will have
        /// zero here
        value: Uint256,
        /// Encoded contract call or contract creation
        data: Vec<u8>,
        // Contains the chain id bit-hacked into the V field of the signature
        signature: Option<Signature>,
    },
    // A transaction type designed for optimized access to specific storage
    /// using an access list
    Eip2930 {
        /// A list of addresses mapped to storage keys
        /// access within this range is cheaper in terms of gas
        /// for this tx type as an incentive to assist with node
        /// optimization
        access_list: Vec<(Address, Vec<Uint256>)>,
        /// Chain-id value, used to prevent replay attacks accross chains
        chain_id: Uint256,
        /// The signature, encoded such that the V value is a boolean
        /// and does not include an encoded chain id
        signature: Option<Signature>,
        /// Replay prevention counter, this must be the last nonce successfully on the
        /// chain plus one, multiple tx with incrementing nonces can wait in the mempool
        /// but they must execute in order. If you have multiple tx in the pool, one with
        /// a lower nonce fails, and is then replaced the following tx will execute immediately
        nonce: Uint256,
        /// The price of gas for this transaction, total spend will be price * limit with no
        /// refund for actual utilization
        gas_price: Uint256,
        /// The maximum amount of gas that can be used by this transaction, total spend will be
        /// price * limit with no refund for if the actual utilization is below this value
        gas_limit: Uint256,
        /// The destination address, this can be a contract or another account, in the contract
        /// case the data field will be populated with an encoded contract call
        to: Address,
        /// The amount of Ether to send with this transaction, while this can be used with
        /// contract calls see ERC-1363, it's mostly used for Ether transfers. Remember ERC20
        /// ERC721 and other non Ether 'tokens' are contact calls! So an ERC20 send will have
        /// zero here
        value: Uint256,
        /// Encoded contract call or contract creation
        data: Vec<u8>,
    },
    Eip1559 {
        /// Chain-id value, used to prevent replay attacks accross chains
        chain_id: Uint256,
        /// Replay prevention counter, this must be the last nonce successfully on the
        /// chain plus one, multiple tx with incrementing nonces can wait in the mempool
        /// but they must execute in order. If you have multiple tx in the pool, one with
        /// a lower nonce fails, and is then replaced the following tx will execute immediately
        nonce: Uint256,
        max_priority_fee_per_gas: Uint256,
        max_fee_per_gas: Uint256,
        gas_limit: Uint256,
        /// The destination address, this can be a contract or another account, in the contract
        /// case the data field will be populated with an encoded contract call
        to: Address,
        /// The amount of Ether to send with this transaction, while this can be used with
        /// contract calls see ERC-1363, it's mostly used for Ether transfers. Remember ERC20
        /// ERC721 and other non Ether 'tokens' are contact calls! So an ERC20 send will have
        /// zero here
        value: Uint256,
        /// Encoded contract call or contract creation
        data: Vec<u8>,
        signature: Option<Signature>,
        /// A list of addresses mapped to storage keys
        /// access within this range is cheaper in terms of gas
        /// for this tx type as an incentive to assist with node
        /// optimization
        access_list: Vec<(Address, Vec<Uint256>)>,
    },
}

impl Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()))
    }
}

impl fmt::LowerHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_lowercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_lowercase())
        }
    }
}

impl fmt::UpperHex for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        } else {
            write!(f, "{}", bytes_to_hex_str(&self.to_bytes()).to_uppercase())
        }
    }
}

/// utility fucntion for converting the boolean representation of
/// v into the two allowed values
pub fn v_to_num(v: bool) -> Uint256 {
    if v {
        28u8.into()
    } else {
        27u8.into()
    }
}

/// Encodes access list data, note that access lists are encoded as a list
/// of strings with each address/storagekey pair being encoded recursively
/// as a string that decodes to a list
fn access_list_to_rlp(list: Vec<(Address, Vec<Uint256>)>) -> RlpToken {
    let mut tokens = Vec::new();
    for (address, storage_locations) in list {
        let mut locations: Vec<RlpToken> = Vec::new();
        for location in storage_locations {
            locations.push(location.into())
        }
        tokens.push(RlpToken::List(vec![
            address.into(),
            RlpToken::List(locations),
        ]))
    }
    RlpToken::List(tokens)
}

/// Decodes an access list from a list RLP token containing the data, returns a DeserializeRLP
/// error in any invalid case
fn access_list_from_rlp(list: RlpToken) -> Result<Vec<(Address, Vec<Uint256>)>, Error> {
    // access list is encoded as a List containing a string which is itself rlp encoded
    let data = list.get_list_content()?;
    let mut ret = Vec::new();
    for pair in data {
        let pair = pair.get_list_content()?;
        if pair.len() != 2 {
            return Err(Error::DeserializeRlp);
        }
        let address = Address::from_rlp_data(pair[0].clone())?;
        let storage_keys = pair[1].get_list_content()?;
        let mut inner_vec = Vec::new();
        for key in storage_keys {
            let key = key.get_byte_content()?;
            let storage_address = Uint256::from_be_bytes(&key);
            inner_vec.push(storage_address);
        }
        ret.push((address, inner_vec));
    }
    Ok(ret)
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_rlp_bytes().serialize(serializer)
    }
}

/// Count the number of nonzero bytes in this array
fn count_nonzero_bytes(haystack: &[u8]) -> usize {
    let mut ret = 0;
    for i in haystack {
        if *i != 0 {
            ret += 1;
        }
    }
    ret
}

impl Transaction {
    pub fn is_valid(&self) -> bool {
        // invalid signature check
        if let Some(sig) = self.get_signature() {
            if !sig.is_valid() {
                return false;
            }

            if self.sender().is_err() {
                return false;
            }
        }

        // EIP-2681 proposes to limit nonces to 2^64-1 this is already the case in Geth
        // but since this is not yet an actually accepted standard we put the check informally here
        if self.get_nonce() >= u64::MAX.into() {
            return false;
        }

        // the gas price times the gas limit can not overflow or the tx is invalid
        match self {
            Transaction::Legacy {
                gas_limit,
                gas_price,
                ..
            }
            | Transaction::Eip2930 {
                gas_price,
                gas_limit,
                ..
            } => {
                if gas_limit.checked_mul(**gas_price).is_none() {
                    return false;
                }
            }
            Transaction::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_limit,
                ..
            } => {
                if gas_limit.checked_mul(**max_fee_per_gas).is_none()
                    || max_priority_fee_per_gas > max_fee_per_gas
                {
                    return false;
                }
            }
        }

        // rudimentary gas limit check, needs opcode awareness
        if self.get_gas_limit() < self.intrinsic_gas_used()
            || self.get_gas_limit() > u64::MAX.into()
        {
            return false;
        }

        true
    }

    pub fn get_signature(&self) -> Option<Signature> {
        match self {
            Transaction::Legacy { signature, .. } => signature.clone(),
            Transaction::Eip2930 { signature, .. } => signature.clone(),
            Transaction::Eip1559 { signature, .. } => signature.clone(),
        }
    }
    pub fn get_nonce(&self) -> Uint256 {
        match self {
            Transaction::Legacy { nonce, .. } => *nonce,
            Transaction::Eip2930 { nonce, .. } => *nonce,
            Transaction::Eip1559 { nonce, .. } => *nonce,
        }
    }
    pub fn get_data(&self) -> Vec<u8> {
        match self {
            Transaction::Legacy { data, .. } => data.clone(),
            Transaction::Eip2930 { data, .. } => data.clone(),
            Transaction::Eip1559 { data, .. } => data.clone(),
        }
    }
    pub fn as_data(self) -> Vec<u8> {
        match self {
            Transaction::Legacy { data, .. } => data,
            Transaction::Eip2930 { data, .. } => data,
            Transaction::Eip1559 { data, .. } => data,
        }
    }
    pub fn data_ref(&self) -> &[u8] {
        match self {
            Transaction::Legacy { data, .. } => data,
            Transaction::Eip2930 { data, .. } => data,
            Transaction::Eip1559 { data, .. } => data,
        }
    }
    pub fn get_to(&self) -> Address {
        match self {
            Transaction::Legacy { to, .. } => *to,
            Transaction::Eip2930 { to, .. } => *to,
            Transaction::Eip1559 { to, .. } => *to,
        }
    }
    pub fn get_value(&self) -> Uint256 {
        match self {
            Transaction::Legacy { value, .. } => *value,
            Transaction::Eip2930 { value, .. } => *value,
            Transaction::Eip1559 { value, .. } => *value,
        }
    }
    pub fn get_gas_limit(&self) -> Uint256 {
        match self {
            Transaction::Legacy { gas_limit, .. } => *gas_limit,
            Transaction::Eip2930 { gas_limit, .. } => *gas_limit,
            Transaction::Eip1559 { gas_limit, .. } => *gas_limit,
        }
    }

    // approximate intrinsic gas function, does not detect things like create calls
    pub fn intrinsic_gas_used(&self) -> Uint256 {
        let num_zero_bytes = count_nonzero_bytes(&self.get_data());
        let num_non_zero_bytes = self.get_data().len() - num_zero_bytes;

        let contract_creation_gas: Uint256 = if self.get_to() == zero_address() {
            Uint256::from(GTXCONTRACTCREATION)
        } else {
            0u8.into()
        };

        let access_list_gas: Uint256 = match self {
            Transaction::Eip2930 { access_list, .. } | Transaction::Eip1559 { access_list, .. } => {
                let mut sum = 0u8.into();
                sum += Uint256::from(access_list.len()) * Uint256::from(GTXACCESSLISTADDRESS);
                for (_, i) in access_list {
                    sum += Uint256::from(i.len()) * Uint256::from(GTXACCESSLISTSTORAGE);
                }
                sum
            }
            Transaction::Legacy { .. } => 0u8.into(),
        };

        Uint256::from(GTXCOST)
            + Uint256::from(GTXDATAZERO) * Uint256::from(num_zero_bytes)
            + Uint256::from(GTXDATANONZERO) * Uint256::from(num_non_zero_bytes)
            + access_list_gas
            + contract_creation_gas
    }

    /// Used to encode transaction components for signature, provides rlp encoded transaction bytes
    /// formatted exactly as they would be for serialization except missing the signature
    fn to_unsigned_tx_params(&self, network_id: Option<Uint256>) -> Vec<u8> {
        match (self, network_id) {
            (
                Transaction::Legacy {
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    value,
                    data,
                    signature: _,
                },
                None,
            ) => {
                let data: Vec<RlpToken> = vec![
                    nonce.into(),
                    gas_price.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                ];
                pack_rlp(vec![RlpToken::List(data)])
            }
            (
                Transaction::Legacy {
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    value,
                    data,
                    signature: _,
                },
                Some(network_id),
            ) => {
                let data: Vec<RlpToken> = vec![
                    nonce.into(),
                    gas_price.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    network_id.into(),
                    // this should maybe be two empty arrays?
                    0u8.into(),
                    0u8.into(),
                ];
                pack_rlp(vec![RlpToken::List(data)])
            }
            (
                Transaction::Eip2930 {
                    access_list,
                    chain_id,
                    signature: _,
                    nonce,
                    gas_price,
                    gas_limit,
                    to,
                    value,
                    data,
                },
                _,
            ) => {
                let data: Vec<RlpToken> = vec![
                    chain_id.into(),
                    nonce.into(),
                    gas_price.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    access_list_to_rlp(access_list.clone()),
                ];
                pack_rlp(vec![1u8.into(), RlpToken::List(data)])
            }
            (
                Transaction::Eip1559 {
                    chain_id,
                    nonce,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas_limit,
                    to,
                    value,
                    data,
                    signature: _,
                    access_list,
                },
                _,
            ) => {
                let data: Vec<RlpToken> = vec![
                    chain_id.into(),
                    nonce.into(),
                    max_priority_fee_per_gas.into(),
                    max_fee_per_gas.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    access_list_to_rlp(access_list.clone()),
                ];
                pack_rlp(vec![2u8.into(), RlpToken::List(data)])
            }
        }
    }

    /// Signs the provided transaction, with a legacy format signature if a network_id is provided
    pub fn sign(&self, key: &PrivateKey, network_id: Option<u64>) -> Transaction {
        // This is a special matcher to prepare raw RLP data with correct network_id.
        let rlpdata = match network_id {
            Some(network_id) => {
                assert!((1..9_223_372_036_854_775_790u64).contains(&network_id)); // 1 <= id < 2**63 - 18
                self.to_unsigned_tx_params(Some(network_id.into()))
            }
            None => self.to_unsigned_tx_params(None),
        };
        // Prepare a raw hash of RLP encoded TX params
        let rawhash = Keccak256::digest(rlpdata);
        let sig = key.sign_hash(&rawhash);
        let mut tx = self.clone();
        if let Some(network_id) = network_id {
            // Account v for the network_id value, converting to legacy signature if a network_id is provided
            let v = sig.get_signature_v().unwrap() as u64;
            let v = v + 8 + network_id * 2;
            tx.set_signature(Signature::LegacySignature {
                v: v.into(),
                r: sig.get_r(),
                s: sig.get_s(),
            })
        } else {
            tx.set_signature(sig)
        }
        tx
    }

    fn set_signature(&mut self, sig: Signature) {
        match self {
            Transaction::Legacy { signature, .. }
            | Transaction::Eip2930 { signature, .. }
            | Transaction::Eip1559 { signature, .. } => *signature = Some(sig),
        }
    }

    /// Get the sender's `Address`; derived from the `signature` field, does not keep with convention
    /// returns error if the signature is invalid. Traditional return would be `constants::NULL_ADDRESS`
    /// you may need to insert that yourself after matching on errors
    pub fn sender(&self) -> Result<Address, Error> {
        match self.get_signature() {
            None => Err(Error::NoSignature),
            Some(sig) => {
                if !sig.is_valid() {
                    Err(Error::InvalidSignatureValues)
                } else {
                    let sighash = match sig {
                        Signature::LegacySignature { v, .. } => {
                            if v == 27u8.into() || v == 28u8.into() {
                                Keccak256::digest(self.to_unsigned_tx_params(None))
                            } else if v >= 37u32.into() {
                                let network_id =
                                    sig.legacy_network_id().ok_or(Error::InvalidNetworkId)?;
                                // In this case hash of the transaction is usual RLP paremeters but "VRS" params
                                // are swapped for [network_id, '', '']. See Appendix F (285)
                                let rlp_data = self.to_unsigned_tx_params(Some(network_id));
                                Keccak256::digest(rlp_data)
                            } else {
                                // All other V values would be errorneous for our calculations
                                return Err(Error::InvalidV);
                            }
                        }
                        Signature::ModernSignature { .. } => {
                            // for new format transactions the chain_id is already in the tx params and does not need to be added
                            Keccak256::digest(self.to_unsigned_tx_params(None))
                        }
                    };
                    sig.recover(&sighash)
                }
            }
        }
    }

    /// Creates a hash of a transaction given all TX attributes
    /// including signature (VRS) whether it is present, or not.
    pub fn hash(&self) -> Vec<u8> {
        Keccak256::digest(self.to_rlp_bytes()).to_vec()
    }

    /// Creates a byte representation of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_rlp_bytes()
    }

    /// Generates rlp ethereum encoded byte format of this transaction
    pub fn to_rlp_bytes(&self) -> Vec<u8> {
        // Serialization of a transaction without signature serializes
        // the data assuming the "vrs" params are set to 0.
        let (v, r, s) = match self.get_signature() {
            Some(sig) => match sig {
                Signature::LegacySignature { v, r, s } => (v, r, s),
                Signature::ModernSignature { v, r, s } => (v_to_num(v), r, s),
            },
            None => (0u8.into(), 0u8.into(), 0u8.into()),
        };

        // special handling for the v value which is encoded as a string
        // even though it's a single 0 or 1 (should be a single byte right?)
        let new_sig_v = if v == 28u8.into() {
            RlpToken::String(vec![1u8])
        } else {
            RlpToken::String(vec![0u8])
        };

        match self {
            Transaction::Legacy {
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                signature: _,
            } => {
                let data: Vec<RlpToken> = vec![
                    nonce.into(),
                    gas_price.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    v.into(),
                    r.into(),
                    s.into(),
                ];
                pack_rlp(vec![RlpToken::List(data)])
            }
            Transaction::Eip2930 {
                access_list,
                chain_id,
                signature: _,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
            } => {
                let data: Vec<RlpToken> = vec![
                    chain_id.into(),
                    nonce.into(),
                    gas_price.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    access_list_to_rlp(access_list.clone()),
                    new_sig_v,
                    r.into(),
                    s.into(),
                ];
                pack_rlp(vec![1u8.into(), RlpToken::List(data)])
            }
            Transaction::Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                signature: _,
                access_list,
            } => {
                let data: Vec<RlpToken> = vec![
                    chain_id.into(),
                    nonce.into(),
                    max_priority_fee_per_gas.into(),
                    max_fee_per_gas.into(),
                    gas_limit.into(),
                    to.into(),
                    value.into(),
                    RlpToken::String(data.clone()),
                    access_list_to_rlp(access_list.clone()),
                    new_sig_v,
                    r.into(),
                    s.into(),
                ];
                pack_rlp(vec![2u8.into(), RlpToken::List(data)])
            }
        }
    }

    /// Creates a transaction from raw RLP bytes, can not decode unsigned transactions
    pub fn decode_from_rlp(raw_rlp_bytes: &[u8]) -> Result<Self, Error> {
        if raw_rlp_bytes.is_empty() {
            return Err(Error::DeserializeRlp);
        }
        // transaction type is also actually the first rlp encoding byte
        let transaction_type = raw_rlp_bytes[0];

        let decoded_rlp = if transaction_type >= 0xc {
            // in the legacy tx case decode the entire input
            unpack_rlp(raw_rlp_bytes)?
        } else {
            // in the modern tx case drop the first byte as it's just the
            // transaction type number
            unpack_rlp(&raw_rlp_bytes[1..])?
        };

        if decoded_rlp.is_empty() {
            return Err(Error::DeserializeRlp);
        }

        // legacy transaction case, see https://eips.ethereum.org/EIPS/eip-2718 for the reasoning
        if transaction_type >= 0xc0 {
            if let RlpToken::List(data) = decoded_rlp[0].clone() {
                // legacy transactions have exactly 9 elements
                if data.len() != 9 {
                    return Err(Error::DeserializeRlp);
                }

                Ok(Transaction::Legacy {
                    nonce: (*data[0].get_byte_content()?).into(),
                    gas_price: (*data[1].get_byte_content()?).into(),
                    gas_limit: (*data[2].get_byte_content()?).into(),
                    to: Address::from_rlp_data(data[3].clone())?,
                    value: (*data[4].get_byte_content()?).into(),
                    data: (*data[5].get_byte_content()?).into(),
                    signature: Some(Signature::new_legacy(
                        (*data[6].get_byte_content()?).into(),
                        (*data[7].get_byte_content()?).into(),
                        (*data[8].get_byte_content()?).into(),
                    )),
                })
            } else {
                Err(Error::DeserializeRlp)
            }
        } else {
            // typed transactions
            // EIP-2930
            if transaction_type == 1 {
                if let RlpToken::List(data) = decoded_rlp[0].clone() {
                    // EIP-2930 transactions have exactly 11 elements
                    if data.len() != 11 {
                        return Err(Error::DeserializeRlp);
                    }
                    Ok(Transaction::Eip2930 {
                        chain_id: (*data[0].get_byte_content()?).into(),
                        nonce: (*data[1].get_byte_content()?).into(),
                        gas_price: (*data[2].get_byte_content()?).into(),
                        gas_limit: (*data[3].get_byte_content()?).into(),
                        to: Address::from_rlp_data(data[4].clone())?,
                        value: (*data[5].get_byte_content()?).into(),
                        data: (*data[6].get_byte_content()?).into(),
                        access_list: access_list_from_rlp(data[7].clone())?,
                        signature: Some(Signature::new(
                            decode_v(&data[8])?,
                            (*data[9].get_byte_content()?).into(),
                            (*data[10].get_byte_content()?).into(),
                        )),
                    })
                } else {
                    Err(Error::DeserializeRlp)
                }
            // EIP-1559 (the standard)
            } else if transaction_type == 2 {
                if let RlpToken::List(data) = decoded_rlp[0].clone() {
                    // EIP 1559 transactions have exactly 12 elements
                    if data.len() != 12 {
                        return Err(Error::DeserializeRlp);
                    }
                    Ok(Transaction::Eip1559 {
                        chain_id: (*data[0].get_byte_content()?).into(),
                        nonce: (*data[1].get_byte_content()?).into(),
                        max_priority_fee_per_gas: (*data[2].get_byte_content()?).into(),
                        max_fee_per_gas: (*data[3].get_byte_content()?).into(),
                        gas_limit: (*data[4].get_byte_content()?).into(),
                        to: Address::from_rlp_data(data[5].clone())?,
                        value: (*data[6].get_byte_content()?).into(),
                        data: (*data[7].get_byte_content()?).into(),
                        access_list: access_list_from_rlp(data[8].clone())?,
                        signature: Some(Signature::new(
                            // valid values are 27/28 represented by true and false
                            decode_v(&data[9])?,
                            (*data[10].get_byte_content()?).into(),
                            (*data[11].get_byte_content()?).into(),
                        )),
                    })
                } else {
                    Err(Error::DeserializeRlp)
                }
            } else {
                Err(Error::UnknownTxType(transaction_type.into()))
            }
        }
    }
}

// helper for decoding v for new sig format tx
fn decode_v(input: &RlpToken) -> Result<bool, Error> {
    match input {
        // intutitively I would expect v to be single byte 0 or 1 but that's not the case
        // in practice
        RlpToken::List(_) | RlpToken::SingleByte(_) => Err(Error::DeserializeRlp),
        RlpToken::String(bytes) => {
            if bytes.is_empty() {
                Ok(false)
            } else if bytes[0] == 1 {
                Ok(true)
            } else {
                Err(Error::DeserializeRlp)
            }
        }
    }
}

/// Function used for debug printing hex dumps
/// of ethereum events with each uint256 on a new
/// line
// fn debug_print_data(input: &[u8]) {
//     let count = input.len() / 32;
//     println!("data hex dump");
//     for i in 0..count {
//         println!("0x{}", bytes_to_hex_str(&input[(i * 32)..((i * 32) + 32)]))
//     }
//     println!("end dump");
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::get_fuzz_bytes;
    use crate::utils::hex_str_to_bytes;
    use rand::thread_rng;
    use std::time::Duration;
    use std::time::Instant;

    const FUZZ_TIME: Duration = Duration::from_secs(30);

    #[test]
    fn decode_simple_tx() {
        let bytes = "0xd1808609184e72a00082f3888080801b2c04";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        let _tx = Transaction::decode_from_rlp(&bytes).unwrap();
    }

    // unlike the below two tests, this is a random tx off of Etherscan since nonde of the eip1559 in the test fixutres are suppposed
    // to be successfully decoded, hash is 0x605b05a65c4fff114ee1e0d64f4895c11966a0a89e37abfab50836e4a18d9410
    #[test]
    fn test_deocde_eip_1559() {
        let bytes = "0x02f877018304d0f384018432db850df0b722d183015f9094ab02ac6987384f556181d06adf866ebe810a64888801cf2ca4aca83ff080c080a0da85545426c43062c319391db96fea52d773fba2c943d4c256d02be0e6cd2386a068256eabd9875ca38bbb4525b968060e82b7f73bb49a9962f911c41ec71afb85";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        let tx = Transaction::decode_from_rlp(&bytes).unwrap();
        let sender = tx.sender();
        assert_eq!(bytes, tx.to_rlp_bytes());
        if let Transaction::Eip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            signature: _,
            access_list,
        } = tx
        {
            assert_eq!(chain_id, 1u8.into());
            assert_eq!(nonce, 315635u32.into());
            assert_eq!(max_priority_fee_per_gas, 25440987u32.into());
            assert_eq!(max_fee_per_gas, 59873108689u64.into());
            assert_eq!(gas_limit, 90_000u64.into());
            assert_eq!(
                to,
                "0xab02ac6987384f556181d06adf866ebe810a6488"
                    .parse()
                    .unwrap()
            );
            assert_eq!(value, 130371999999999984u128.into());
            assert!(data.is_empty());
            assert!(access_list.is_empty());
            assert_eq!(
                sender.unwrap(),
                "0xcbd6832ebc203e49e2b771897067fce3c58575ac"
                    .parse()
                    .unwrap()
            )
        } else {
            panic!("Wrong tx type")
        }
    }

    #[test]
    fn test_deocde_eip_2930() {
        let bytes = "0x01f89a018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f838f794a95e7baea6a6c7c4c2dfeb977efac326af552d87e1a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        let tx = Transaction::decode_from_rlp(&bytes).unwrap();
        let sender = tx.sender();
        if let Transaction::Eip2930 {
            access_list,
            chain_id,
            signature: _,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        } = tx
        {
            assert_eq!(chain_id, 1u8.into());
            assert_eq!(nonce, 0u8.into());
            assert_eq!(gas_limit, 27_200u64.into());
            assert_eq!(gas_price, 1u8.into());
            assert_eq!(
                to,
                "0x095e7baea6a6c7c4c2dfeb977efac326af552d87"
                    .parse()
                    .unwrap()
            );
            assert_eq!(value, 0u8.into());
            assert!(data.is_empty());
            let access_list_exp: Vec<(Address, Vec<Uint256>)> = vec!(("0xa95e7bAEa6A6C7C4C2dfEb977efac326AF552D87".parse().unwrap(), vec!["115792089237316195423570985008687907853269984665640564039457584007913129639935".parse().unwrap()]));
            assert_eq!(access_list, access_list_exp);

            assert_eq!(
                sender.unwrap(),
                "0xebe76799923fd62804659fb00b4f0f1a94c0eb1e"
                    .parse()
                    .unwrap()
            );
        } else {
            panic!("Wrong tx type")
        }
    }

    #[test]
    fn test_decode_zero_byte_data_legacy_tx() {
        let bytes = "0xf87c80018261a894095e7baea6a6c7c4c2dfeb977efac326af552d870a9d00000000000000000000000000000000000000000000000000000000001ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a01fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804";
        let bytes = hex_str_to_bytes(bytes).unwrap();
        Transaction::decode_from_rlp(&bytes).unwrap();
    }

    #[test]
    fn test_vitaliks_eip_158_vitalik_12_json() {
        use crate::utils::{bytes_to_hex_str, hex_str_to_bytes};
        use num_traits::Num;
        // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
        let tx = Transaction::Legacy {
            nonce: Uint256::from_str_radix("0e", 16).unwrap(),
            gas_price: Uint256::from_str_radix("00", 16).unwrap(),
            gas_limit: Uint256::from_str_radix("0493e0", 16).unwrap(),
            to: Address::default(), // "" - zeros only
            value: Uint256::from_str_radix("00", 16).unwrap(),
            data: hex_str_to_bytes("60f2ff61000080610011600039610011565b6000f3").unwrap(),
            signature: Some(Signature::new(
                true,
                Uint256::from_str_radix(
                    "a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4",
                    16,
                )
                .unwrap(),
                Uint256::from_str_radix(
                    "6dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6",
                    16,
                )
                .unwrap(),
            )),
        };

        let lhs = tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);
        let rhs = "f8610e80830493e080809560f2ff61000080610011600039610011565b6000f31ca0a310f4d0b26207db76ba4e1e6e7cf1857ee3aa8559bcbc399a6b09bfea2d30b4a06dff38c645a1486651a717ddf3daccb4fd9a630871ecea0758ddfcf2774f9bc6".to_owned();
        assert_eq!(lhs, rhs);

        assert_eq!(
            bytes_to_hex_str(tx.sender().unwrap().as_bytes()),
            "874b54a8bd152966d63f706bae1ffeb0411921e5"
        );
    }

    #[test]
    fn test_vitaliks_eip_158_vitalik_1_json() {
        use crate::utils::bytes_to_hex_str;
        use num_traits::Num;
        // https://github.com/ethereum/tests/blob/69f55e8608126e6470c2888a5b344c93c1550f40/TransactionTests/ttEip155VitaliksEip158/Vitalik_12.json
        let tx = Transaction::Legacy {
            nonce: Uint256::from_str_radix("00", 16).unwrap(),
            gas_price: Uint256::from_str_radix("04a817c800", 16).unwrap(),
            gas_limit: Uint256::from_str_radix("5208", 16).unwrap(),
            to: "3535353535353535353535353535353535353535".parse().unwrap(),
            value: Uint256::from_str_radix("00", 16).unwrap(),
            data: Vec::new(),
            signature: Some(Signature::new_legacy(
                Uint256::from_str_radix("25", 16).unwrap(),
                Uint256::from_str_radix(
                    "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                    16,
                )
                .unwrap(),
                Uint256::from_str_radix(
                    "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d",
                    16,
                )
                .unwrap(),
            )),
        };
        let lhs = tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);
        let rhs = "f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d".to_owned();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_basictests_txtest_1() {
        use crate::utils::bytes_to_hex_str;
        use num_traits::Num;
        // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
        let tx = Transaction::Legacy {
            nonce: Uint256::from_str_radix("00", 16).unwrap(),
            gas_price: "1000000000000".parse().unwrap(),
            gas_limit: "10000".parse().unwrap(),
            to: "13978aee95f38490e9769c39b2773ed763d9cd5f".parse().unwrap(),
            value: "10000000000000000".parse().unwrap(),
            data: Vec::new(),
            signature: None,
        };
        // Unsigned
        let lhs = tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);
        let rhs =
        "eb8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc1000080808080"
            .to_owned();
        assert_eq!(lhs, rhs);

        // Signed
        let key: PrivateKey = "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"
            .parse()
            .unwrap();
        let signed_tx = tx.sign(&key, None);

        let lhs = signed_tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);
        let rhs = "f86b8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc10000801ba0eab47c1a49bf2fe5d40e01d313900e19ca485867d462fe06e139e3a536c6d4f4a014a569d327dcda4b29f74f93c0e9729d2f49ad726e703f9cd90dbb0fbf6649f1".to_owned();

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_basictests_txtest_2() {
        use crate::utils::{bytes_to_hex_str, hex_str_to_bytes};
        // https://github.com/ethereum/tests/blob/b44cea1cccf1e4b63a05d1ca9f70f2063f28da6d/BasicTests/txtest.json
        let tx = Transaction::Legacy {
        nonce: "0".parse().unwrap(),
        gas_price: "1000000000000".parse().unwrap(),
        gas_limit: "10000".parse().unwrap(),
        to: Address::default(),
        value: "0".parse().unwrap(),
        data: hex_str_to_bytes("6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2").unwrap(),
        signature: None
    };
        // Unsigned
        let lhs = tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);
        let rhs = "f83f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2808080".to_owned();
        assert_eq!(lhs, rhs);

        // Signed
        let key: PrivateKey = "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0"
            .parse()
            .unwrap();
        let signed_tx = tx.sign(&key, None);

        let lhs = signed_tx.to_bytes();
        let lhs = bytes_to_hex_str(&lhs);

        // This value is wrong
        let rhs = "f87f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f21ca05afed0244d0da90b67cf8979b0f246432a5112c0d31e8d5eedd2bc17b171c694a044efca37cb9883d1ee7a47236f3592df152931a930566933de2dc6e341c11426".to_owned();

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn fuzz_transaction_decode() {
        let start = Instant::now();
        let mut rng = thread_rng();
        while Instant::now() - start < FUZZ_TIME {
            let transaction_bytes = get_fuzz_bytes(&mut rng);

            let res = Transaction::decode_from_rlp(&transaction_bytes);
            match res {
                Ok(_) => println!("Got valid output, this should happen very rarely!"),
                Err(_e) => {}
            }
        }
    }
}
