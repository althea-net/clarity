use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::Address;
use num256::Uint256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use std::{cmp::Ordering, ops::Deref};

/// Serializes slice of data as "UNFORMATTED DATA" format required
/// by Ethereum JSONRPC API.
///
/// See more https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
pub fn data_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("0x{}", bytes_to_hex_str(x)))
}

/// Deserializes slice of data as "UNFORMATTED DATA" format required
/// by Ethereum JSONRPC API.
///
/// See more https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
pub fn data_deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    hex_str_to_bytes(&s).map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Eq, PartialEq)]
pub struct Log {
    /// true when the log was removed, due to a chain reorganization. false if its a valid log.
    pub removed: Option<bool>,
    /// integer of the log index position in the block. null when its pending log.
    #[serde(rename = "logIndex")]
    pub log_index: Option<Uint256>,
    /// integer of the transactions index position log was created from. null when its pending log.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Uint256>,
    /// hash of the transactions this log was created from. null when its pending log.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<Data>,
    /// hash of the block where this log was in. null when its pending. null when its pending log.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Data>,
    /// the block number where this log was in. null when its pending. null when its pending log.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<Uint256>,
    /// 20 Bytes - address from which this log originated.
    pub address: Address,
    /// contains the non-indexed arguments of the log.
    pub data: Data,
    /// Array of 0 to 4 32 Bytes DATA of indexed log arguments. (In solidity:
    /// The first topic is the hash of the signature of the
    /// event (e.g. Deposit(address,bytes32,uint256)), except you declared
    /// the event with the anonymous specifier.)
    pub topics: Vec<Data>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, PartialEq, Eq, Hash)]
pub struct Data(
    #[serde(
        serialize_with = "data_serialize",
        deserialize_with = "data_deserialize"
    )]
    pub Vec<u8>,
);

impl Deref for Data {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data(v)
    }
}

/// As received by getTransactionByHash
///
/// See more: https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactionbyhash
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct TransactionResponse {
    /// hash of the block where this transaction was in. null when its pending.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Data>,
    /// block number where this transaction was in. null when its pending.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<Uint256>,
    /// address of the sender.
    pub from: Address,
    /// gas provided by the sender.
    pub gas: Uint256,
    /// gas price provided by the sender in Wei.
    #[serde(rename = "gasPrice")]
    pub gas_price: Uint256,
    /// hash of the transaction
    pub hash: Data,
    /// the data send along with the transaction.
    pub input: Data,
    /// the number of transactions made by the sender prior to this one.
    pub nonce: Uint256,
    /// address of the receiver. null when its a contract creation transaction.
    pub to: Option<Address>,
    /// integer of the transaction's index position in the block. null when its pending.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Uint256>,
    /// value transferred in Wei.
    pub value: Uint256,
    /// ECDSA recovery id
    pub v: Uint256,
    /// ECDSA signature r
    pub r: Uint256,
    /// ECDSA signature s
    pub s: Uint256,
}

impl Ord for TransactionResponse {
    /// the goal of this ordering is to sort transactions by their block number,
    /// in the case of transactions in the same block or transactions without a block
    /// number transactions without a block are greater than transactions with one and
    /// are sorted by nonce when in the same block or without a block.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.block_number, other.block_number) {
            (Some(self_block), Some(other_block)) => {
                if self_block != other_block {
                    self_block.cmp(&other_block)
                } else {
                    self.nonce.cmp(&other.nonce)
                }
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => self.nonce.cmp(&other.nonce),
        }
    }
}

impl PartialOrd for TransactionResponse {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Serialize, Default, Debug, Clone)]
pub struct NewFilter {
    #[serde(rename = "fromBlock", skip_serializing_if = "Option::is_none")]
    pub from_block: Option<String>,
    #[serde(rename = "toBlock", skip_serializing_if = "Option::is_none")]
    pub to_block: Option<String>,
    pub address: Vec<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<Vec<Option<String>>>>>,
}

#[derive(Serialize, Clone, Eq, PartialEq, Debug)]
pub struct TransactionRequest {
    //The address the transaction is send from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    // The address the transaction is directed to.
    pub to: Address,
    // Integer of the gas provided for the transaction execution. It will return unused gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<UnpaddedHex>,
    // Integer of the gasPrice used for each paid gas
    #[serde(rename = "gasPrice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<UnpaddedHex>,
    // Integer of the value sent with this transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<UnpaddedHex>,
    // The compiled code of a contract OR the hash of the invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    //  This allows to overwrite your own pending transactions that use the same nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<UnpaddedHex>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct UnpaddedHex(pub Uint256);

impl Serialize for UnpaddedHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:#x}", *self.0))
    }
}

impl From<Uint256> for UnpaddedHex {
    fn from(v: Uint256) -> Self {
        UnpaddedHex(v)
    }
}

impl From<u64> for UnpaddedHex {
    fn from(v: u64) -> Self {
        UnpaddedHex(v.into())
    }
}

/// Ethereum block
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct Block {
    // geth does not include the author in it's RPC response.
    pub author: Option<Address>,
    pub difficulty: Uint256,
    #[serde(
        rename = "extraData",
        deserialize_with = "parse_possibly_empty_hex_val"
    )]
    pub extra_data: Uint256,
    #[serde(rename = "gasLimit")]
    pub gas_limit: Uint256,
    #[serde(rename = "gasUsed")]
    pub gas_used: Uint256,
    /// this field will not exist until after
    /// the london hardfork
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<Uint256>,
    pub hash: Uint256,
    #[serde(rename = "logsBloom")]
    pub logs_bloom: Data,
    pub miner: Address,
    pub number: Uint256,
    #[serde(rename = "parentHash")]
    pub parent_hash: Uint256,
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: Uint256,
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: Uint256,
    pub size: Uint256,
    #[serde(rename = "stateRoot")]
    pub state_root: Uint256,
    pub timestamp: Uint256,
    #[serde(rename = "totalDifficulty")]
    pub total_difficulty: Uint256,
    pub transactions: Vec<TransactionResponse>,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: Uint256,
    pub uncles: Vec<Uint256>,
}

/// block with more concise tx hashes instead of full transactions
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ConciseBlock {
    // geth does not include the author in it's RPC response.
    pub author: Option<Address>,
    pub difficulty: Uint256,
    #[serde(
        rename = "extraData",
        deserialize_with = "parse_possibly_empty_hex_val"
    )]
    pub extra_data: Uint256,
    #[serde(rename = "gasLimit")]
    pub gas_limit: Uint256,
    #[serde(rename = "gasUsed")]
    pub gas_used: Uint256,
    /// this field will not exist until after
    /// the london hardfork
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<Uint256>,
    pub hash: Uint256,
    #[serde(rename = "logsBloom")]
    pub logs_bloom: Data,
    pub miner: Address,
    pub number: Uint256,
    #[serde(rename = "parentHash")]
    pub parent_hash: Uint256,
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: Uint256,
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: Uint256,
    pub size: Uint256,
    #[serde(rename = "stateRoot")]
    pub state_root: Uint256,
    pub timestamp: Uint256,
    #[serde(rename = "totalDifficulty")]
    pub total_difficulty: Uint256,
    pub transactions: Vec<Uint256>,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: Uint256,
    pub uncles: Vec<Uint256>,
}

/// Used to configure send_transaction
#[derive(Debug, Clone, PartialEq)]
pub enum SendTxOption {
    GasMaxFee(Uint256),
    GasPriorityFee(Uint256),
    GasLimitMultiplier(f32),
    GasLimit(Uint256),
    Nonce(Uint256),
    AccessList(Vec<(Address, Vec<Uint256>)>),
}

fn parse_possibly_empty_hex_val<'de, D>(deserializer: D) -> Result<Uint256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    match Uint256::from_str(&s) {
        Ok(val) => Ok(val),
        Err(_e) => Ok(0u32.into()),
    }
}

/// This enum encapsulates the syncing status returned by a call to eth_syncing
/// This will either return a bool 'false' if not syncing, or an object with details
/// about which blocks are syncing
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SyncingStatus {
    NotSyncing(bool),
    #[serde(rename_all = "camelCase")]
    Syncing {
        starting_block: Uint256,
        current_block: Uint256,
        highest_block: Uint256,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Web3;
    use std::fs::read_to_string;
    use std::time::Duration;

    /// This test is used to get new blocks for testing easily
    #[test]
    #[ignore]
    fn test_arbitrary_block() {
        use actix::System;
        env_logger::init();
        let runner = System::new();
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
        runner.block_on(async move {
            let res = web3.eth_get_block_by_number(10750715u32.into()).await;
            if res.is_err() {
                println!("{res:?}");
                System::current().stop_with_code(1);
            }
        });
    }

    #[test]
    fn decode_log() {
        let res: Vec<Log> = serde_json::from_str(
            r#"[{
      "address": "0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359",
      "blockHash": "0xd8fb35a10b60e5fd1848a83d052424954e4a400fc7826bf85a743ff55acf73d3",
      "blockNumber": "0x74de5d",
      "data": "0x00000000000000000000000000000000000000000000000dae06677922ff8290",
      "logIndex": "0x14",
      "removed": false,
      "topics": [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "0x000000000000000000000000802275979b020f0ec871c5ec1db6e412b72ff20b",
        "0x000000000000000000000000af38668f4719ecf9452dc0300be3f6c83cbf3721"
      ],
      "transactionHash": "0xceb484eb92fd7ad626bc5aced6d669a693baf3d776b515a08d65fafca633a6a6",
      "transactionIndex": "0xc"
    }]"#,
        )
        .unwrap();

        println!("{res:#?}");
    }

    #[test]
    fn decode_block_concise() {
        let original = r#"
{
    "author": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
    "difficulty": "0x857744c52180e",
    "extraData": "0x6574682d70726f2d687a682d74303032",
    "gasLimit": "0x98700f",
    "gasUsed": "0x983ace",
    "hash": "0xab18cc7cc1ed62252fc5f12b73a2d336c4b90f45855b1ac1de375898aa77695c",
    "logsBloom": "0x9a224020268280ae20cc8401e6a98480625710800c53260c84112180303b9c40440422003a08746c024579423410434082061d14cc0184a19bc6d465d97c642e420890f5a008c4918a0831d801aa0df30028294402c3600118c697d88045b021bc361305d21222001d7438481044d9c427427f46b84514242b40c9120b12229c884e308b11808d1080d2004dc81902289163118d4dec8278f04b414a01541294a383001ac1c0201258650e921406882e1197104aacf80b70202444299a00018104096a0221b0040810169145058835081b0412452428f21404264893ec61a0120c1a2081d8241044d01302f4a13084a4112228c064fa0448440228450d000289",
    "miner": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
    "mixHash": "0x7875d003e13d6d519700e9c859b3bac2a3269bff54730db80b0eb115cc7ff66b",
    "nonce": "0xa5b9444000e3b9b6",
    "number": "0x9c0a2a",
    "parentHash": "0x9b4b4e0035143fdf83020e7cb5a7e92ad17d0f33d28dc4f2b33a8c8c20f8ffa9",
    "receiptsRoot": "0xedee082e0a3f9f746091946a669afe00fd715be350e4b65f6017371c275d7d6c",
    "sealFields": [
      "0xa07875d003e13d6d519700e9c859b3bac2a3269bff54730db80b0eb115cc7ff66b",
      "0x88a5b9444000e3b9b6"
    ],
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x9162",
    "stateRoot": "0x1b63e35e6660ca519923caa659124f75018a43c52c988dbb0259917e06ace28c",
    "timestamp": "0x5ede683f",
    "totalDifficulty": "0x35816e51ca117f27581",
    "transactions": [
      "0x326502312ba1279d08e7d86366436dd776700ff2eb75ec19e4800c5ad0c39459",
      "0x8bf3b8ec5d56b7161dc267582b1630ee934eb2cc44ec9e0dc88944bd7b3f18de",
      "0x679c58277d25b7bf8bcce236e1283dc4df5f5169d8c1325912e33ff8cb48c528",
      "0xe8b43247336722353eb32d5817f8bf1f01eadd71b74ff9fb23fd1320af8a16c2",
      "0xec7aa694f24f8a066c2ceb3a3bde17fd25171d4e4a345b177d702efe8c073963"
    ],
    "transactionsRoot": "0x575a82c7b35408d0894203d6af648f27575bab4d9dcca6772c017b9e06dfb75f",
    "uncles": []
}
"#;
        let _decoded: ConciseBlock = serde_json::from_str(original).unwrap();
    }

    #[test]
    fn decode_xdai_block_concise() {
        let original = r#"
{
    "author": "0xb76756f95a9fb6ff9ad3e6cb41b734c1bd805103",
    "difficulty": "0xfffffffffffffffffffffffffffffffe",
    "extraData": "0xde830207028f5061726974792d457468657265756d86312e34312e30826c69",
    "gasLimit": "0x989680",
    "gasUsed": "0x0",
    "hash": "0xee0bcfc930d4481c945c1ad63d8ea2b09b9214544736a21c1e6682c2a41103e9",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0xb76756f95a9fb6ff9ad3e6cb41b734c1bd805103",
    "number": "0x9c0a2a",
    "parentHash": "0xac3a6c20e924a36553af671e47ee7d5fa807fe9fe82f3c8781eac4f67fc312b2",
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "sealFields": [
      "0x8412f799f1",
      "0xb84164f1672483581db09090b4e8462085cc16d23d21572886e86db314adfe1044e519103df48f3b7d521fc98220ba4401b610d1420b9fdee434adeaacc7a642f20000"
    ],
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "signature": "64f1672483581db09090b4e8462085cc16d23d21572886e86db314adfe1044e519103df48f3b7d521fc98220ba4401b610d1420b9fdee434adeaacc7a642f20000",
    "size": "0x24c",
    "stateRoot": "0xaf196ea8d73362ee5cba1f30c1705e50f2bb45bc3b9e81dbf86fe5449df5b00d",
    "step": "318216689",
    "timestamp": "0x5ed601b5",
    "totalDifficulty": "0x9c0a29ffffffffffffffffffffffffec6e5be5",
    "transactions": [],
    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "uncles": []
}
"#;
        let _decoded: ConciseBlock = serde_json::from_str(original).unwrap();

        let original_2 = r#"
        {
    "author": "0xd653a665ff07d48fe0f239d184f28a54b00ec1ce",
    "difficulty": "0xfffffffffffffffffffffffffffffffe",
    "extraData": "0x4e65746865726d696e64",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x19b6c",
    "hash": "0xfbe725380efc0208ffdd45c0e06de5a1a478eb6b0ac5361d85ab1f4b59102691",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000008000000000000000000000000000000000000000000010008000000000000000000000000000000000000020000000000000000000000000000020000000000000000000000000010000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200004000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000",
    "miner": "0xd653a665ff07d48fe0f239d184f28a54b00ec1ce",
    "number": "0x1810890",
    "parentHash": "0xd85c7fd8c39406d4c7d6e87d8ca718314ed8eed989fb27c73ff8f37f6e46a553",
    "receiptsRoot": "0x223ea9ebab548b147c459aa98c25cdabf81b06cd91572238ee23b269afb5dff5",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "signature": "0x327ee1880ab9ad31ae83669bcf0f8d74fdc0c2ece681065f9e5bd9e46804f6d41c7548ce6d47d7d02144a00ffe299e25fd914fca3e5c4bbd585f478e1353445501",
    "size": "0x3fb",
    "stateRoot": "0x55a720816a33f93343fa1a9cba04f157240e49ed46616d460120fe9d37d35dad",
    "step": 333965182,
    "totalDifficulty": "0x181088fffffffffffffffffffffffffea990ff2",
    "timestamp": "0x63878576",
    "baseFeePerGas": "0x7",
    "transactions": [
      "0x6a15f46514b459c01df01572b1325f296e51af830c1497a3b77c69673e4167d3",
      "0xab56a411cbebbe3c7e2725ec4cd0aa192160d9e88b7da449a31060fdd7f3793b",
      "0xb0e64f9f8d0ff81c0967e343608c402af46d222fb0b3b3549668d52872ed1bba"
    ],
    "transactionsRoot": "0xd8825c8523866becd01351ee34821cd832ba608e170a2a09426cc1ca509cda2f",
    "uncles": []
        }
        "#;

        let _decoded: ConciseBlock = serde_json::from_str(original_2).unwrap();

        let original_3 = r#"
        {
            "author": "0x0000000000000000000000000000000000000000",
            "difficulty": "0x0",
            "extraData": "0x4e65746865726d696e64",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x300617",
            "hash": "0x16a2e52277bab1733a915ccf32f9ef570c750920fac880860846022bb6f3a7a9",
            "logsBloom": "0x142400400000000800c000008881202000000080400000011000000800000040208000080001408000000001000002000004400000900000000001014002000000000020000080000000000800210022000000000201040004001000000020000000000002800000010000001000080000000000200040000000001000000a80080000000000000008080084080200011000000000000448000000400000a120020000000000000000810000200006000000010004000010001000014000000046002022000000000004000000000004000200000010001472000010010020002000000042000000000044040083204000000020400204000000000080502800",
            "miner": "0x0000000000000000000000000000000000000000",
            "mixHash": "0x1a039b0e86666ecae056f68aee88d1dcf55a42906dbc3a933c6c70c7d194573d",
            "nonce": "0x0000000000000000",
            "number": "0x182cda1",
            "parentHash": "0xf5cff68065ac6014bb7c9aa731d4d4084de0994f807ac1df3856308b3c9b2b48",
            "receiptsRoot": "0xa74f6b2415ce575737eb9506d962cfc73cc49eedca64768472871c6dedb6748a",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0x2689",
            "stateRoot": "0x3748aef0bfc4093620b3172d70386b3ee5fc879c5037723d288bd1622f5d5e9c",
            "totalDifficulty": "0x182cd9fffffffffffffffffffffffffea9528a2",
            "timestamp": "0x639230c5",
            "baseFeePerGas": "0x7",
            "transactions": [
              "0x60cef2489561b636f5793c98120cfe6bfc3b15a898daf11c84ce80878b1b3431",
              "0xee3d828f293133254edb18d21fc392871acdf6aa2ecf739422fbe9cecf8c6498",
              "0xd22c2ea2a16b46fdd34c383f0153945c628d128288c6cae0a9373ec2d220bde7",
              "0x7f8a2bedc26c824b7fcf769e825652fe25e9e5bb8b2ecafc3ab555a131fa69f3",
              "0x19765aca533e3862f687371bc02b38e391928b13ab046550a8dee6d0d260aa29",
              "0x6813a65e2b8e328a983304596ac23c0e86c14a3c1e20ea2f9b2479c490723b8a",
              "0x068f12560208612f087b117d28ccd9dbda4b48a4a02c2445b3634447597a0d97",
              "0xda7ee89de3f89d5a86c568addf1b11e49164dec3de29707eaa7e860aadb43625",
              "0x9f46345740e266958970ea02f88630d8b09cc1b69fffe0c3d21fa6de2e814f8e",
              "0xea9ca613fa4a74e3fbad3706e987c99dd94bcb11210a4c8fe2493f6bec25957c",
              "0x7c814f10f78d37f3dd24c402814b5e1af90b48f285d6d03523c5609398ee4657",
              "0xf15eb52dc060e181c5f13ad0fd8f480748cc8019caa0b27ab158d29f016c144f",
              "0x2edf6111cbd6d81c50e1c6a2b6b8f06f9b543ed1b2a0315b57fb3c0671648472",
              "0xa1e440de0edf3bcff46a7843b27f5fa2e6a37ac1d0e47c05cf960c1022a97f60",
              "0xb33827a02e123a1e56b52bcd70962ede42f5d4c65fb322cd0c25fa76c9541de9",
              "0xae375b9963318d42b6c19a66a3ce7664fcfaccee40a4799ece6af644ea53c705",
              "0x22d2f1baadd1984a088c2efc9e9fd80f2b0a140ba2b253ebfd8eb6c371eba057",
              "0x9c77b2e9df09ed82c1f34787ca0239444c8a056ff4b4d55307befaf2c4e59f39",
              "0xfee4eca8820b8b40a5f0753b1b64148b805bbe968b18a346f4adf57a25fa6b9c",
              "0x577fe6aedb2e1ce7de98558552926697b5d840c6db4b900d32080cd3bc772ffb",
              "0xebb83e56edc9ad99352f31e5ab8e39bc3a93adae55eea1f8079da10f0ebd2343",
              "0x713652fd3fd612391c6a837f303b6243e4034c83bdc6506f01da22daa6e20d9b"
            ],
            "transactionsRoot": "0x8b2b9dcc882c5dd1db598b53e3dfb73a1b03004fe09ff2a55e8e499640e738eb",
            "uncles": []
          }
        "#;

        let _decoded: ConciseBlock = serde_json::from_str(original_3).unwrap();
    }

    #[test]
    fn decode_block() {
        let file = read_to_string("test_files/complete_parity_eth_block.json")
            .expect("Failed to read test files!");

        let _decoded: Block = serde_json::from_str(&file).unwrap();

        let file =
            read_to_string("test_files/eth_A40AFB_block.json").expect("Failed to read test files!");

        let _decoded: Block = serde_json::from_str(&file).unwrap();

        let file = read_to_string("test_files/complete_geth_eth_block.json")
            .expect("Failed to read test files!");

        let _decoded: Block = serde_json::from_str(&file).unwrap();
    }

    #[test]
    fn decode_concise_block() {
        let file = read_to_string("test_files/concise_parity_eth_block.json")
            .expect("Failed to read test files!");

        let _decoded: ConciseBlock = serde_json::from_str(&file).unwrap();

        let file = read_to_string("test_files/concise_geth_eth_block.json")
            .expect("Failed to read test files!");

        let _decoded: ConciseBlock = serde_json::from_str(&file).unwrap();
    }

    #[test]
    fn decode_xdai_block() {
        let file = read_to_string("test_files/complete_xdai_block.json")
            .expect("Failed to read test files!");

        let _decoded: Block = serde_json::from_str(&file).unwrap();
    }
}
