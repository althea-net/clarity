extern crate num256;
extern crate num_traits;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::Transaction;

use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs::{self, DirEntry, File};
use std::io;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use structs::*;
use test::{DynTest, DynTestName, ShouldPanic, TestDesc, TestDescAndFn};

mod stats;
mod structs;
mod test;

/// These are tests we exlude ourselves from becuase they are either invalid or don't apply to us
/// since we are not a consensus client
/// Reasoning:
/// tr201506052141PYTHON
/// Geth accepts this tx as valid, I can't determine what critera by which 137 is an invalid chain id
///
/// DataTestNotEnoughGasInitCode
/// DataTestEnoughGasInitCode
/// this spec EIP3860 is not yet final
///
/// DataTestSufficientGas2028
/// DataTestInsufficientGas2028
/// this spec EIP2028 is not yet
const BLACKLISTED_TESTS: [&str; 5] = [
    "tr201506052141PYTHON",
    "DataTestNotEnoughGasInitCode",
    "DataTestEnoughGasInitCode",
    "DataTestInsufficientGas2028",
    "DataTestSufficientGas2028",
];

fn test_on_blacklist(test_name: &str) -> bool {
    for t in BLACKLISTED_TESTS {
        if t == test_name {
            return true;
        }
    }
    false
}

fn visit_dirs(dir: &Path, cb: &mut dyn FnMut(&DirEntry)) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry);
            }
        }
    }
    Ok(())
}

fn get_fixtures_path() -> PathBuf {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push("tests");
    path.push("fixtures");
    path
}

/// Loads a single test fixture along with it's name
fn load_fixture(path: &Path) -> HashMap<String, TestFixture> {
    // Read JSON in advance before running this particular test.
    // This way we can construct human readable test name based on the JSON contents
    let file = File::open(path).unwrap_or_else(|_| panic!("Could not open file {path:?}"));
    let buffered_reader = BufReader::new(file);
    let json_data: Value =
        serde_json::from_reader(buffered_reader).expect("Unable to read JSON file");
    // Deserialize fixture object
    serde_json::from_value(json_data).unwrap()
}

/// Loads the transaction and test data for a single fixture along with it's name
fn load_filler(fixture: &TestFixture) -> HashMap<String, TestFiller> {
    // Load filler
    let mut filler_path = get_fixtures_path();
    filler_path.push(&fixture.info.source);
    let file = File::open(&filler_path)
        .unwrap_or_else(|_| panic!("Unable to open filler {filler_path:?}"));
    let reader = BufReader::new(file);
    if filler_path.extension().unwrap() == "json" {
        let json_data: Value = serde_json::from_reader(reader).unwrap();
        serde_json::from_value(json_data)
            .unwrap_or_else(|e| panic!("Unable to deserialize filler at {filler_path:?}: {e}"))
    } else if filler_path.extension().unwrap() == "yml" {
        let yaml_data: serde_yaml::Value = serde_yaml::from_reader(reader).unwrap();
        serde_yaml::from_value(yaml_data)
            .unwrap_or_else(|e| panic!("Unable to deserialize filler at {filler_path:?}: {e}"))
    } else {
        panic!("Invalid extension for path {filler_path:?}")
    }
}

fn test_fn(fixtures: &TestFixture, filler: &TestFiller, network: EthereumNetworkVersion) {
    let raw_rlp_bytes =
        hex_str_to_bytes(&fixtures.txbytes).unwrap_or_else(|e| panic!("Unable to decode {}", e));
    let decoded_tx = Transaction::decode_from_rlp(&raw_rlp_bytes).expect("Decoding failed with");

    // this filters out some of the validity checks that we don't support disabling as generating older
    // transactions is not in our purview
    if !filler.should_fail(network) && network == EthereumNetworkVersion::Frontier {
        return;
    }

    match filler {
        TestFiller::ExpectExceptionFormat {
            expect_exception: _,
            transaction,
        } => {
            let raw_params = transaction.clone().unwrap();

            // unsupported tx like eip1559 on Frontier for example
            if !raw_params.is_supported(network) {
                panic!("Not supported tx type!")
            }

            // Create a tx based on filler params
            let tx: Transaction = match raw_params.clone().try_into() {
                Ok(tx) => tx,
                Err(e) => {
                    if filler.should_fail(network) {
                        panic!("Tx decoding failed correctly with {:?}", e);
                    } else {
                        panic!("Tx decoding failed with {:?}", e);
                    }
                }
            };

            // Compare decoded transaction based on RLP and a transaction based on TX.
            // No need to go through validation for `decoded_tx` since we can rely on the equality here,
            // and assume if tx is valid, then decoded_tx is valid as well.
            assert_eq!(decoded_tx, tx);

            // Encoding of our transaction
            let our_rlp = tx.to_bytes();
            // All rlp's Fixtures
            assert!(fixtures.txbytes.starts_with("0x"));

            assert!(tx.is_valid());
            assert!(
                tx.get_signature().unwrap().is_valid(),
                "{:?} {:?} {:?}",
                tx.get_signature().unwrap(),
                raw_params,
                filler
            );
            // Comparing our encoding with the "ground truth" in the fixture
            assert_eq!(
                bytes_to_hex_str(&our_rlp),
                &fixtures.txbytes[2..],
                "{:?} != {:?} (filler {:?})",
                &tx,
                &raw_params,
                &filler
            );

            // Verify network id
            let network_id = tx.get_signature().unwrap().legacy_network_id();

            // fail in valid v on early networks
            if network == EthereumNetworkVersion::Frontier
                || network == EthereumNetworkVersion::Homestead
                || network == EthereumNetworkVersion::EIP150
            {
                let v = tx.get_signature().unwrap().get_v();
                if v > 28u8.into() || v < 27u8.into() {
                    panic!("Invalid VRS")
                }
                assert!(network_id.is_none() || network_id.unwrap() == 1u8.into());
            }

            if filler.should_fail(network) {
                println!("Tx should not be valid");
            }
        }
        TestFiller::ResultFormat { result, txbytes } => {
            let decoded_tx: Transaction =
                Transaction::decode_from_rlp(&hex_str_to_bytes(txbytes).unwrap()).unwrap();
            match result.clone().get_fixture(network) {
                TestFixtureNetwork::Success {
                    hash,
                    _intrinsic_gas: _,
                    sender,
                } => {
                    assert_eq!(decoded_tx.hash(), hex_str_to_bytes(&hash).unwrap());
                    assert_eq!(decoded_tx.sender().unwrap(), sender.parse().unwrap());
                }
                TestFixtureNetwork::Failure {
                    _intrinsic_gas: _,
                    exception: _,
                } => {
                    if decoded_tx.is_valid() {
                        println!("Tx should not be valid!")
                    } else {
                        panic!("Tx successfully detected as invalid")
                    }
                }
            }
        }
    }
}

/// Takes a path to JSON file and returns a test
fn make_test(path: &Path) -> Vec<TestDescAndFn> {
    // For now all the test and filler data is parsed upfront,
    // to only create tests that contains data that we're able to parse.
    // This means only tests that have filler "transaction" values can be verified.
    // Once serde-rlp's decoder is merged upstream we can do two way verification.

    // Test case is always an object with a single key
    // Grab name of the actual test together with its value

    let fixture = load_fixture(path);
    assert_eq!(fixture.len(), 1);
    let (_, fixture) = fixture.into_iter().next().unwrap();
    // Load filler data
    let filler = load_filler(&fixture);
    assert_eq!(filler.len(), 1);
    let (name, filler) = filler.into_iter().next().unwrap();

    // skip blacklisted tests
    if test_on_blacklist(&name) {
        return Vec::new();
    }

    // used to narrow things down for debugging
    // if name != "DataTestInsufficientGas2028" {
    //     return Vec::new();
    // }

    // This stores all tests per all networks
    let mut tests = Vec::new();

    for network in EthereumNetworkVersion::get_all() {
        let test = create_test_with_network(path, network, &filler, &fixture);
        tests.push(test);
    }

    tests
}

fn create_test_with_network(
    path: &Path,
    network: EthereumNetworkVersion,
    filler: &TestFiller,
    fixture: &TestFixture,
) -> TestDescAndFn {
    let state = match &filler.get_exception(network) {
        Some(v) => v.clone(),
        None => "valid".to_string(),
    };
    let mut desc = TestDesc::new(DynTestName(format!(
        "{}@{}@{}",
        path.strip_prefix(get_fixtures_path())
            .unwrap()
            .to_string_lossy(),
        network,
        state,
    )));

    desc.should_panic = if filler.should_fail(network) {
        ShouldPanic::Yes
    } else {
        ShouldPanic::No
    };

    // TODO: I couldn't figure a better way to pass those values to the closure without cloning.
    let a = fixture.clone();
    let b = filler.clone();

    TestDescAndFn {
        desc,
        testfn: DynTest(Box::new(move || {
            test_fn(&a, &b, network);
        })),
    }
}

fn tests() -> Vec<TestDescAndFn> {
    let mut res = Vec::new();

    let mut testdir = get_fixtures_path();
    testdir.push("TransactionTests");
    if !testdir.is_dir() {
        // this sometimes is a false positive
        println!("Directory does not exist {testdir:?}. Did you remember to execute \"git submodule update --init\"?");
    }
    visit_dirs(&testdir, &mut |entry| {
        let tests = make_test(&entry.path());
        res.extend(tests)
    })
    .unwrap();
    res
}

/// This checks if the git submodule for the transaction tests has been initialized
/// otherwise this test will silently pass
fn check_submodule_init() {
    match get_fixtures_path().read_dir() {
        Ok(mut info) => {
            if info.next().is_none() {
                panic!("Please run 'git submodule update --init --recursive'")
            }
        }
        Err(_) => panic!(
            "Can't find {:?} did you delete it from the repo?",
            get_fixtures_path().to_str()
        ),
    }
}

//#[test]
fn main() {
    check_submodule_init();
    let args: Vec<_> = env::args().collect();
    test::test_main(&args, tests());
}
