extern crate clarity;
extern crate num_traits;
extern crate rustc_test as test;
extern crate serde_bytes;
extern crate serde_json;
extern crate serde_rlp;
#[macro_use]
extern crate serde_derive;
use clarity::utils::{bytes_to_hex_str, hex_str_to_bytes};
use clarity::{Address, BigEndianInt, Signature, Transaction};
use num_traits::Zero;
use serde_bytes::Bytes;
use serde_json::{Error, Value};
use serde_rlp::de::from_bytes;
use serde_rlp::ser::to_bytes;
use std::collections::HashMap;
use std::env;
use std::fs::{self, DirEntry, File};
use std::io;
use std::io::BufReader;
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

#[derive(Deserialize, Debug)]
struct TestFillerExpect {
    /// I.e. ["ALL"]
    network: Vec<String>,
    /// I.e. "invalid"
    result: String,
    /// I.e. 40 bytes characters
    sender: Option<String>,
}

fn default_gas_limit() -> String {
    "0".to_owned()
}

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
struct TestFixtureInfo {
    comment: String,
    filledwith: String,
    lllcversion: String,
    source: String,
    #[serde(rename = "sourceHash")]
    source_hash: String,
}

#[derive(Deserialize, Debug)]
struct TestFixture {
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

/// Takes a path to JSON file and returns a test
fn make_test(path: PathBuf) -> Option<TestDescAndFn> {
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

    let mut desc = TestDesc::new(DynTestName(path.to_string_lossy().to_string()));

    desc.should_panic = match filler.expect.get(0) {
        // Our tests should fail with a panic
        Some(ref expect) if expect.result == "invalid" => ShouldPanic::Yes,
        // All assertions shall pass
        Some(ref expect) if expect.result == "valid" => ShouldPanic::No,
        Some(_) => panic!("Invalid filler data {:?}", filler),
        None => {
            // No "expect" key means no "transaction" key
            assert!(filler.transaction.is_none());
            // If we know there is no transaction, so we panic when we're unable to decode RLP data.
            ShouldPanic::Yes
        }
    };

    Some(TestDescAndFn {
        desc: desc,
        testfn: DynTestFn(Box::new(move || {
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
                to: (&*data[3]).into(),
                value: (&*data[4]).into(),
                data: (&*data[5]).into(),
                signature: Some(Signature::new(
                    (&*data[6]).into(),
                    (&*data[7]).into(),
                    (&*data[8]).into(),
                )),
            };

            // We skipped all fillers without transaction data
            let raw_params = filler.transaction.as_ref().unwrap();
            let tx = Transaction {
                nonce: raw_params.nonce.parse().unwrap_or(BigEndianInt::zero()),
                gas_price: raw_params.gas_price.parse().unwrap_or(BigEndianInt::zero()),
                gas_limit: raw_params
                    .gas_limit
                    .parse()
                    .expect("Unable to parse gas_limit"),
                to: raw_params.to.parse().expect("Unable to parse address"),
                value: raw_params.value.parse().unwrap_or(BigEndianInt::zero()),
                data: hex_str_to_bytes(&raw_params.data).expect("Unable to parse data"),
                signature: Some(Signature::new(
                    raw_params.v.parse().expect("Unable to parse v"),
                    raw_params.r.parse().expect("Unable to parse r"),
                    raw_params.s.parse().expect("Unable to parse s"),
                )),
            };

            assert_eq!(decoded_tx, tx);

            let our_rlp = to_bytes(&tx).unwrap();

            assert!(fixtures.rlp.starts_with("0x"));

            assert!(tx.is_valid(), "{:?} {:?} {:?}", tx, raw_params, filler);
            assert!(
                tx.signature.as_ref().unwrap().is_valid(),
                "{:?} {:?} {:?}",
                tx.signature.as_ref().unwrap(),
                raw_params,
                filler
            );
            assert_eq!(
                bytes_to_hex_str(&our_rlp),
                &fixtures.rlp[2..],
                "{:?} != {:?} (filler {:?})",
                &tx,
                &raw_params,
                &filler
            );

            match filler.expect.get(0) {
                Some(ref expect) if !expect.sender.is_none() => {
                    assert_eq!(
                        &bytes_to_hex_str(&tx.sender().unwrap().as_bytes()),
                        expect.sender.as_ref().unwrap()
                    );
                }
                _ => (),
            }

            // match filler.expect {
            //     // Our tests should fail with a panic
            //     Some(ref expect) => {
            //         let expect = expect.get(0).as_ref().unwrap();
            //         if !expect.sender.is_none() {
            //         }
            //     },
            //     //     assert_ne!(
            //     //         &bytes_to_hex_str(&tx.sender().as_bytes()),
            //     //         expect.get(0).as_ref().unwrap().sender.as_ref().unwrap()
            //     //     );
            //     // },
            //     // Some(ref expect) if expect.get(0).as_ref().unwrap().result == "valid" => {
            //     //     assert_ne!(
            //     //         &bytes_to_hex_str(&tx.sender().as_bytes()),
            //     //         expect.get(0).as_ref().unwrap().sender.as_ref().unwrap()
            //     //     );
            //     // }
            //     _ => (),
            // }
        })),
    })
}

fn tests() -> Vec<TestDescAndFn> {
    let mut res = Vec::new();

    let mut testdir = get_fixtures_path();
    testdir.push("TransactionTests");
    if !testdir.is_dir() {
        panic!("Directory does not exists. Did you remember to execute \"git submodule update --init\"?");
    }
    visit_dirs(&testdir, &mut |entry| match make_test(entry.path()) {
        Some(test) => res.push(test),
        None => (),
    }).unwrap();
    res
}

fn main() {
    let args: Vec<_> = env::args().collect();
    test::test_main(&args, tests());
}
