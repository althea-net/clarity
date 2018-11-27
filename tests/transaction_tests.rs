extern crate clarity;
extern crate num256;
extern crate num_traits;
extern crate rustc_test as test;
extern crate serde_bytes;
extern crate serde_json;
extern crate serde_rlp;
#[macro_use]
extern crate serde_derive;
use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::{Address, Signature, Transaction};
use num256::Uint256;
use num_traits::Zero;
use serde_bytes::Bytes;
use serde_json::{Error, Value};
use serde_rlp::de::from_bytes;
use serde_rlp::ser::to_bytes;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs::{self, DirEntry, File};
use std::io;
use std::io::BufReader;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use test::{DynTestFn, DynTestName, ShouldPanic, TestDesc, TestDescAndFn};

fn visit_dirs(dir: &Path, cb: &mut FnMut(&DirEntry)) -> io::Result<()> {
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

#[derive(Deserialize, Debug, Clone)]
struct TestFillerExpect {
    /// I.e. ["ALL"]
    network: HashSet<String>,
    /// I.e. "invalid"
    result: String,
    /// I.e. 40 bytes characters
    sender: Option<String>,
}

fn default_gas_limit() -> String {
    "0".to_owned()
}

#[derive(Deserialize, Debug, Clone)]
struct TestFillerTransaction {
    data: String,
    #[serde(rename = "gasLimit", default = "default_gas_limit")]
    gas_limit: String,
    #[serde(rename = "gasPrice")]
    gas_price: String,
    nonce: String,
    to: String,
    #[serde(default = "String::new")]
    value: String,
    v: String,
    r: String,
    s: String,
}

#[derive(Deserialize, Debug, Clone)]
struct TestFiller {
    // I.e. [{"network": ["ALL"], "result": "invalid"}]
    #[serde(default = "Vec::new")]
    expect: Vec<TestFillerExpect>,
    // This is kind of unnatural in our environment, but there is at least
    // one test case where they have more transaction params than expected.
    // It doesn't really matter in our case because we operate on structs,
    // without any dynamic fields, but just to be sure, we can
    // verify that this map has exactly 9 elements (or all expected
    // elements exists).
    transaction: Option<TestFillerTransaction>,
}

#[derive(Deserialize, Debug, Clone)]
struct TestFixtureInfo {
    comment: String,
    filledwith: String,
    lllcversion: String,
    source: String,
    #[serde(rename = "sourceHash")]
    source_hash: String,
}

#[derive(Deserialize, Debug, Clone)]
struct TestFixtureNetwork {
    hash: Option<String>,
    sender: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct TestFixture {
    #[serde(rename = "Byzantium")]
    byzantium: TestFixtureNetwork,
    #[serde(rename = "Constantinople")]
    constantinople: TestFixtureNetwork,
    #[serde(rename = "EIP150")]
    eip150: TestFixtureNetwork,
    #[serde(rename = "EIP158")]
    eip158: TestFixtureNetwork,
    #[serde(rename = "Frontier")]
    frontier: TestFixtureNetwork,
    #[serde(rename = "Homestead")]
    homestead: TestFixtureNetwork,
    #[serde(rename = "_info")]
    info: TestFixtureInfo,
    rlp: String,
}

fn get_fixtures_path() -> PathBuf {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push("tests");
    path.push("fixtures");
    path
}

fn load_fixtures(path: &Path) -> HashMap<String, TestFixture> {
    // Read JSON in advance before running this particular test.
    // This way we can construct human readable test name based on the JSON contents, and
    let file = File::open(&path).unwrap_or_else(|_| panic!("Could not open file {:?}", path));
    let buffered_reader = BufReader::new(file);
    let json_data: Value =
        serde_json::from_reader(buffered_reader).expect("Unable to read JSON file");
    // Deserialize fixture object
    serde_json::from_value(json_data).unwrap()
}

fn load_filler(fixture: &TestFixture) -> HashMap<String, TestFiller> {
    // Load filler
    let mut filler_path = get_fixtures_path();
    filler_path.push(&fixture.info.source);
    let file = File::open(&filler_path)
        .unwrap_or_else(|_| panic!("Unable to open filler {:?}", filler_path));
    let reader = BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader).unwrap();
    serde_json::from_value(json_data)
        .unwrap_or_else(|e| panic!("Unable to deserialize filler at {:?}: {}", filler_path, e))
}

fn test_fn(fixtures: &TestFixture, filler: &TestFiller, expect: Option<&TestFillerExpect>) {
    let raw_rlp_bytes = hex_str_to_bytes(&fixtures.rlp)
        .unwrap_or_else(|e| panic!("Unable to decode {}: {}", fixtures.rlp, e));
    // Try to decode the bytes into a Vec of Bytes which will enforce structure of a n-element vector with bytearrays.
    let data: Vec<Bytes> = match from_bytes(&raw_rlp_bytes) {
        Ok(data) => {
            if filler.transaction.is_none() {
                assert_eq!(filler.expect.len(), 0);
                panic!("Decoding of this RLP data should fail");
            }

            data
        }
        Err(e) => {
            panic!("Decoding failed correctly with {:?}", e);
            return;
        }
    };
    // A valid decoded transaction has exactly 9 elements.
    assert_eq!(data.len(), 9);

    let decoded_tx = Transaction {
        nonce: (&*data[0]).into(),
        gas_price: (&*data[1]).into(),
        gas_limit: (&*data[2]).into(),
        to: Address::from_slice(&*data[3]).unwrap_or(Address::default()),
        value: (&*data[4]).into(),
        data: (&*data[5]).into(),
        signature: Some(Signature::new(
            (&*data[6]).into(),
            (&*data[7]).into(),
            (&*data[8]).into(),
        )),
    };

    // We skipped all fillers without transaction data, so now this unwrap is safe.
    let raw_params = filler.transaction.as_ref().unwrap();
    // Create a tx based on filler params
    let tx = Transaction {
        nonce: raw_params.nonce.parse().unwrap_or(Uint256::zero()),
        gas_price: raw_params.gas_price.parse().unwrap_or(Uint256::zero()),
        gas_limit: raw_params
            .gas_limit
            .parse()
            .expect("Unable to parse gas_limit"),
        to: raw_params.to.parse().expect("Unable to parse address"),
        value: raw_params.value.parse().unwrap_or(Uint256::zero()),
        data: hex_str_to_bytes(&raw_params.data).expect("Unable to parse data"),
        signature: Some(Signature::new(
            raw_params.v.parse().expect("Unable to parse v"),
            raw_params.r.parse().expect("Unable to parse r"),
            raw_params.s.parse().expect("Unable to parse s"),
        )),
    };

    // Compare decoded transaction based on RLP and a transaction based on TX.
    // No need to go through validation for `decoded_tx` since we can rely on the equality here,
    // and assume if tx is valid, then decoded_tx is valid as well.
    assert_eq!(decoded_tx, tx);

    // Encoding of our transaction
    let our_rlp = to_bytes(&tx).unwrap();
    // All rlp's Fixtures
    assert!(fixtures.rlp.starts_with("0x"));

    assert!(tx.is_valid(), "{:?} {:?} {:?}", tx, raw_params, filler);
    assert!(
        tx.signature.as_ref().unwrap().is_valid(),
        "{:?} {:?} {:?}",
        tx.signature.as_ref().unwrap(),
        raw_params,
        filler
    );
    // Comparing our encoding with the "ground truth" in the fixture
    assert_eq!(
        bytes_to_hex_str(&our_rlp),
        &fixtures.rlp[2..],
        "{:?} != {:?} (filler {:?})",
        &tx,
        &raw_params,
        &filler
    );

    // We have verified that case already so unwrapping an expect data is safe.
    let expect = expect.expect("Expect should be available at this point");

    // TODO: Change v to u64 so it would validate overflow when decoding/creating (v <= 2**64-1 so it can't overflow)
    assert!(tx.signature.as_ref().unwrap().v <= "18446744073709551615".parse().unwrap());

    // Since Homestead we have to verify if 0<s<secpk1n/2
    if HashSet::from_iter(
        vec!["Homestead", "EIP150"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>(),
    ).is_subset(&expect.network)
    {
        let res = tx.signature.as_ref().unwrap().check_low_s_homestead();
        if expect.result == "invalid" {
            res.unwrap_err();
        } else if expect.result == "valid" {
            res.unwrap();
        } else {
            unreachable!("This case is validated before");
        }
    }

    // Since Constantinople verify if 0<s<secpk1n/2 and s != 0
    if expect.network.contains(&"Constantinople".to_owned()) {
        let res = tx.signature.as_ref().unwrap().check_low_s_metropolis();
        if expect.result == "invalid" {
            res.unwrap_err();
        } else if expect.result == "valid" {
            res.unwrap();
        } else {
            unreachable!("This case is validated before");
        }
    }

    // Retrieving sender key is also validating parameters
    let sender = tx.sender().unwrap();
    if !expect.sender.is_none() {
        // Compare only if we know we have sender provided
        assert_eq!(
            &bytes_to_hex_str(&sender.as_bytes()),
            expect.sender.as_ref().unwrap()
        );
    }

    // Verify network id
    let network_id = tx.signature.as_ref().unwrap().network_id();

    if HashSet::from_iter(
        vec!["Byzantium", "Constantinople", "EIP158"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>(),
    ).is_subset(&expect.network)
    {
        // Since Spurious Dragon
        assert!(network_id.is_some() || network_id.unwrap() == 1u32.into());
    } else {
        // Before Spurious Dragon
        assert!(network_id.is_none());
    }
}

/// Takes a path to JSON file and returns a test
fn make_test(path: PathBuf) -> Option<Vec<TestDescAndFn>> {
    // For now all the test and filler data is parsed upfront,
    // to only create tests that contains data that we're able to parse.
    // This means only tests that have filler "transaction" values can be verified.
    // Once serde-rlp's decoder is merged upstream we can do two way verification.

    // Test case is always an object with a single key
    // Grab name of the actual test together with its value

    let fixtures = load_fixtures(path.as_path());
    assert_eq!(fixtures.len(), 1);
    let (_, fixtures) = fixtures.into_iter().nth(0).unwrap();
    // Load filler data
    let filler = load_filler(&fixtures);
    assert_eq!(filler.len(), 1);
    let (_name, filler) = filler.into_iter().nth(0).unwrap();

    // Obvious expected failure as there are no expect values
    if filler.expect.len() == 0 {
        let mut desc = TestDesc::new(DynTestName(format!(
            "{}",
            path.strip_prefix(get_fixtures_path())
                .unwrap()
                .to_string_lossy()
                .to_string()
        )));
        assert!(filler.transaction.is_none());
        desc.should_panic = ShouldPanic::Yes;

        let test = TestDescAndFn {
            desc: desc,
            testfn: DynTestFn(Box::new(move || {
                test_fn(&fixtures, &filler, None);
            })),
        };

        return Some(vec![test]);
    }

    // This stores all tests per all networks
    let mut tests = Vec::new();

    for expect in &filler.expect {
        // let networks = vec!["a", "b"].fjoin(",");
        let networks = expect
            .network
            .iter()
            .map(|s| &s[..])
            .collect::<Vec<&str>>()
            .join(",");
        // for network in expect.network.iter() {
        let mut desc = TestDesc::new(DynTestName(format!(
            "{}@{}@{}",
            path.strip_prefix(get_fixtures_path())
                .unwrap()
                .to_string_lossy()
                .to_string(),
            networks,
            expect.result
        )));

        desc.should_panic = if &expect.result == "invalid" {
            ShouldPanic::Yes
        } else if &expect.result == "valid" {
            ShouldPanic::No
        } else {
            panic!("Unknown expect result {}", &expect.result);
        };

        // TODO: I couldn't figure a better way to pass those values to the closure without cloning.
        let a = fixtures.clone();
        let b = filler.clone();
        let c = expect.clone();

        let test = TestDescAndFn {
            desc: desc,
            testfn: DynTestFn(Box::new(move || {
                test_fn(&a, &b, Some(&c));
            })),
        };
        tests.push(test);
    }
    Some(tests)
}

fn tests() -> Vec<TestDescAndFn> {
    let mut res = Vec::new();

    let mut testdir = get_fixtures_path();
    testdir.push("TransactionTests");
    if !testdir.is_dir() {
        panic!("Directory does not exists. Did you remember to execute \"git submodule update --init\"?");
    }
    visit_dirs(&testdir, &mut |entry| match make_test(entry.path()) {
        Some(tests) => res.extend(tests),
        None => (),
    }).unwrap();
    res
}

fn main() {
    let args: Vec<_> = env::args().collect();
    test::test_main(&args, tests());
}
