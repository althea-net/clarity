extern crate clarity;
extern crate num256;
extern crate num_traits;
extern crate rustc_test as test;
extern crate serde_bytes;
extern crate serde_json;
use std::{cmp::Ordering, collections::HashMap, fmt::Display, str::FromStr};

use clarity::{utils::hex_str_to_bytes, Signature, Transaction, Uint256};
use num_traits::Zero;

pub fn default_gas_limit() -> String {
    "0".to_owned()
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestFillerTransaction {
    pub data: String,
    #[serde(rename = "gasLimit", default = "default_gas_limit")]
    pub gas_limit: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    pub nonce: String,
    pub to: String,
    #[serde(default = "String::new")]
    pub value: String,
    pub v: String,
    pub r: String,
    pub s: String,
}

impl TryInto<Transaction> for TestFillerTransaction {
    type Error = clarity::Error;

    fn try_into(self) -> Result<Transaction, Self::Error> {
        // data comes in the format "raw: 0xABCD"
        let data = match self.data.strip_prefix(":raw ") {
            Some(v) => v,
            None => &self.data,
        };
        let value = match self.value.strip_prefix("0x:bigint ") {
            Some(v) => v,
            None => &self.value,
        };
        let value = match (value.parse(), hex_str_to_bytes(value)) {
            (Ok(v), _) => v,
            (_, Ok(bytes)) => Uint256::from_be_bytes(&bytes),
            (Err(_), Err(_)) => panic!("Invalid value for filler tx"),
        };
        Ok(Transaction {
            nonce: self.nonce.parse().unwrap_or_else(|_| Uint256::zero()),
            gas_price: self
                .gas_price
                .clone()
                .unwrap_or("0".to_string())
                .parse()
                .unwrap_or_else(|_| Uint256::zero()),
            gas_limit: self.gas_limit.parse().expect("Unable to parse gas_limit"),
            to: self.to.parse()?,
            value,
            data: hex_str_to_bytes(data).expect("Unable to parse data"),
            signature: Some(Signature::new(
                self.v.parse().unwrap(),
                self.r.parse().unwrap(),
                self.s.parse().unwrap(),
            )),
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum TestFiller {
    ExpectExceptionFormat {
        /// This is a list of expection exceptions based on versions, empty means success is expected
        ///  ie >=Frontier : AddressTooShort
        ///     <London : InvalidVRS
        #[serde(rename = "expectException")]
        expect_exception: HashMap<String, String>,
        /// Test transaction, we may not deserialize all elements, just the ones
        /// in our struct
        transaction: Option<TestFillerTransaction>,
    },
    ResultFormat {
        result: TestFixtureResult,
        txbytes: String,
    },
}

impl TestFiller {
    /// Returns true if a failure is expected for the given test and version of Ethereum consensus rules
    pub fn should_fail(&self, version: EthereumNetworkVersion) -> bool {
        self.get_exception(version).is_some()
    }

    /// Returns the expected exception string given a version, none is returned if the test is expected to succeed
    pub fn get_exception(&self, version: EthereumNetworkVersion) -> Option<String> {
        match self {
            TestFiller::ExpectExceptionFormat {
                expect_exception,
                transaction: _,
            } => {
                if expect_exception.is_empty() {
                    None
                } else {
                    for (ineqality, error) in expect_exception {
                        if ineqality.starts_with(">=") {
                            let compare_to: EthereumNetworkVersion =
                                ineqality.strip_prefix(">=").unwrap().parse().unwrap();
                            if version >= compare_to {
                                return Some(error.clone());
                            }
                        } else if ineqality.starts_with("<=") {
                            let compare_to: EthereumNetworkVersion =
                                ineqality.strip_prefix("<=").unwrap().parse().unwrap();
                            if compare_to <= version {
                                return Some(error.clone());
                            }
                        } else if ineqality.starts_with('<') {
                            let compare_to: EthereumNetworkVersion =
                                ineqality.strip_prefix('<').unwrap().parse().unwrap();
                            if compare_to < version {
                                return Some(error.clone());
                            }
                        } else if ineqality.starts_with('>') {
                            let compare_to: EthereumNetworkVersion =
                                ineqality.strip_prefix('>').unwrap().parse().unwrap();
                            if compare_to > version {
                                return Some(error.clone());
                            }
                        } else if let Ok(compare_to) = ineqality.parse() {
                            let compare_to: EthereumNetworkVersion = compare_to;
                            if version == compare_to {
                                return Some(error.clone());
                            }
                        } else {
                            panic!("Invalid inequality {ineqality}")
                        }
                    }
                    None
                }
            }
            TestFiller::ResultFormat { result, txbytes: _ } => match version {
                EthereumNetworkVersion::Berlin => result.berlin.get_exception(),
                EthereumNetworkVersion::Byzantium => result.byzantium.get_exception(),
                EthereumNetworkVersion::Constantinople => result.constantinople.get_exception(),
                EthereumNetworkVersion::ConstantinopleFix => {
                    result.constantinople_fix.get_exception()
                }
                EthereumNetworkVersion::EIP150 => result.eip150.get_exception(),
                EthereumNetworkVersion::EIP158 => result.eip158.get_exception(),
                EthereumNetworkVersion::Frontier => result.frontier.get_exception(),
                EthereumNetworkVersion::Homestead => result.homestead.get_exception(),
                EthereumNetworkVersion::Instanbul => result.istanbul.get_exception(),
                EthereumNetworkVersion::London => result.london.get_exception(),
                // This test format has not been updated
                EthereumNetworkVersion::Shanghi => unimplemented!(),
                // This test format has not been updated
                EthereumNetworkVersion::Merge => unimplemented!(),
            },
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestFixtureInfo {
    pub comment: String,
    #[serde(rename = "filling-rpc-server")]
    pub filling_rpc_server: String,
    #[serde(rename = "filling-tool-version")]
    pub filling_tool_version: String,
    #[serde(rename = "generatedTestHash")]
    pub generated_test_hash: String,
    pub lllcversion: String,
    pub source: String,
    #[serde(rename = "sourceHash")]
    pub source_hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum TestFixtureNetwork {
    Success {
        hash: String,
        #[serde(rename = "intrinsicGas")]
        intrinsic_gas: Option<String>,
        sender: String,
    },
    Failure {
        intrinsic_gas: Option<String>,
        exception: String,
    },
}

impl TestFixtureNetwork {
    pub fn get_exception(&self) -> Option<String> {
        match self {
            TestFixtureNetwork::Success { .. } => None,
            TestFixtureNetwork::Failure {
                intrinsic_gas: _,
                exception,
            } => Some(exception.clone()),
        }
    }
}

/// These can show up in the fixture or in the filler (fixture being TransactionTests/ and Filler being src/TransactionTestsFiller)
/// It can have an exception if the output is failure, or hash and sender if successful
#[derive(Deserialize, Debug, Clone)]
pub struct TestFixtureResult {
    #[serde(rename = "Byzantium")]
    pub byzantium: TestFixtureNetwork,
    #[serde(rename = "Constantinople")]
    pub constantinople: TestFixtureNetwork,
    #[serde(rename = "EIP150")]
    pub eip150: TestFixtureNetwork,
    #[serde(rename = "EIP158")]
    pub eip158: TestFixtureNetwork,
    #[serde(rename = "Frontier")]
    pub frontier: TestFixtureNetwork,
    #[serde(rename = "Homestead")]
    pub homestead: TestFixtureNetwork,
    #[serde(rename = "London")]
    pub london: TestFixtureNetwork,
    #[serde(rename = "Berlin")]
    pub berlin: TestFixtureNetwork,
    #[serde(rename = "ConstantinopleFix")]
    pub constantinople_fix: TestFixtureNetwork,
    #[serde(rename = "Istanbul")]
    pub istanbul: TestFixtureNetwork,
}

impl TestFixtureResult {
    pub fn _get_exception(self, network: EthereumNetworkVersion) -> Option<String> {
        self.get_fixture(network).get_exception()
    }

    pub fn get_fixture(self, network: EthereumNetworkVersion) -> TestFixtureNetwork {
        match network {
            EthereumNetworkVersion::Berlin => self.berlin,
            EthereumNetworkVersion::Byzantium => self.byzantium,
            EthereumNetworkVersion::Constantinople => self.constantinople,
            EthereumNetworkVersion::ConstantinopleFix => self.constantinople_fix,
            EthereumNetworkVersion::EIP150 => self.eip150,
            EthereumNetworkVersion::EIP158 => self.eip158,
            EthereumNetworkVersion::Frontier => self.frontier,
            EthereumNetworkVersion::Homestead => self.homestead,
            EthereumNetworkVersion::Instanbul => self.istanbul,
            EthereumNetworkVersion::London => self.london,
            // This test format has not been updated
            EthereumNetworkVersion::Shanghi => unimplemented!(),
            // This test format has not been updated
            EthereumNetworkVersion::Merge => unimplemented!(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthereumNetworkVersion {
    Berlin,
    Byzantium,
    Constantinople,
    ConstantinopleFix,
    EIP150,
    EIP158,
    Frontier,
    Homestead,
    Instanbul,
    London,
    Shanghi,
    Merge,
}

impl Ord for EthereumNetworkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_num().cmp(&other.as_num())
    }
}

impl PartialOrd for EthereumNetworkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.as_num().cmp(&other.as_num()))
    }
}

impl FromStr for EthereumNetworkVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Berlin" => Ok(EthereumNetworkVersion::Berlin),
            "Byzantium" => Ok(EthereumNetworkVersion::Byzantium),
            "Constantinople" => Ok(EthereumNetworkVersion::Constantinople),
            "ConstantinopleFix" => Ok(EthereumNetworkVersion::ConstantinopleFix),
            "EIP150" => Ok(EthereumNetworkVersion::EIP150),
            "EIP158" => Ok(EthereumNetworkVersion::EIP158),
            "Frontier" => Ok(EthereumNetworkVersion::Frontier),
            "Homestead" => Ok(EthereumNetworkVersion::Homestead),
            "Istanbul" => Ok(EthereumNetworkVersion::Instanbul),
            "London" => Ok(EthereumNetworkVersion::London),
            "Shanghai" => Ok(EthereumNetworkVersion::Shanghi),
            "Merge" => Ok(EthereumNetworkVersion::Merge),
            v => Err(format!("Invalid version {v}")),
        }
    }
}

impl Display for EthereumNetworkVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthereumNetworkVersion::Berlin => write!(f, "Berlin"),
            EthereumNetworkVersion::Byzantium => write!(f, "Byzantium"),
            EthereumNetworkVersion::Constantinople => write!(f, "Constantinople"),
            EthereumNetworkVersion::ConstantinopleFix => write!(f, "ConstantinopleFix"),
            EthereumNetworkVersion::EIP150 => write!(f, "EIP150"),
            EthereumNetworkVersion::EIP158 => write!(f, "EIP158"),
            EthereumNetworkVersion::Frontier => write!(f, "Frontier"),
            EthereumNetworkVersion::Homestead => write!(f, "Homestead"),
            EthereumNetworkVersion::Instanbul => write!(f, "Istantbul"),
            EthereumNetworkVersion::London => write!(f, "London"),
            EthereumNetworkVersion::Shanghi => write!(f, "Shanghi"),
            EthereumNetworkVersion::Merge => write!(f, "Merge"),
        }
    }
}

impl EthereumNetworkVersion {
    // converts to an internal number representation, used for ordering
    pub fn as_num(&self) -> usize {
        match self {
            EthereumNetworkVersion::Frontier => 1,
            EthereumNetworkVersion::Homestead => 2,
            EthereumNetworkVersion::EIP150 => 3,
            // not totally sure aSbout this one
            EthereumNetworkVersion::EIP158 => 4,
            EthereumNetworkVersion::Byzantium => 5,
            EthereumNetworkVersion::Constantinople => 6,
            EthereumNetworkVersion::ConstantinopleFix => 7,
            EthereumNetworkVersion::Instanbul => 8,
            EthereumNetworkVersion::Berlin => 9,
            EthereumNetworkVersion::London => 10,
            EthereumNetworkVersion::Merge => 11,
            EthereumNetworkVersion::Shanghi => 12,
        }
    }
    pub fn get_all() -> [EthereumNetworkVersion; 10] {
        [
            EthereumNetworkVersion::Berlin,
            EthereumNetworkVersion::Byzantium,
            EthereumNetworkVersion::Constantinople,
            EthereumNetworkVersion::ConstantinopleFix,
            EthereumNetworkVersion::EIP150,
            EthereumNetworkVersion::EIP158,
            EthereumNetworkVersion::Frontier,
            EthereumNetworkVersion::Homestead,
            EthereumNetworkVersion::Instanbul,
            EthereumNetworkVersion::London,
        ]
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestFixture {
    #[serde(rename = "_info")]
    pub info: TestFixtureInfo,
    pub result: TestFixtureResult,
    pub txbytes: String,
}
