extern crate clarity;
extern crate rand;
extern crate web3;
use clarity::utils::bytes_to_hex_str;
use clarity::{PrivateKey, Transaction};
use rand::{OsRng, Rng};
use std::env;
use std::{thread, time};
use web3::api::Web3;
use web3::futures::Future;
use web3::types::{Bytes, TransactionRequest, U256};

/// Creates a random key by reading random data from the available OS facility
fn make_random_key() -> PrivateKey {
    let mut rng = OsRng::new().unwrap();
    let mut data = [0u8; 32];
    rng.fill_bytes(&mut data);

    let res = PrivateKey::from(data);
    debug_assert_ne!(res, PrivateKey::default());
    res
}

/// This function verifies if a web3 transport can be safely created.
fn make_web3() -> Option<(
    web3::transports::EventLoopHandle,
    Web3<web3::transports::Http>,
)> {
    let address = env::var("GANACHE_HOST").unwrap_or_else(|_| "http://localhost:8545".to_string());
    eprintln!("Trying to create a Web3 connection to {:?}", address);
    for counter in 0..30 {
        match web3::transports::Http::new(&address) {
            Ok((evloop, transport)) => {
                let web3 = Web3::new(transport);
                match web3.eth().accounts().wait() {
                    Ok(accounts) => {
                        println!("Got accounts {:?}", accounts);
                        return Some((evloop, web3));
                    }
                    Err(e) => {
                        eprintln!("Unable to retrieve accounts ({}): {}", counter, e);
                        thread::sleep(time::Duration::from_millis(500));
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Unable to create transport ({}): {}", counter, e);
                thread::sleep(time::Duration::from_millis(500));
                continue;
            }
        }
    }
    None
}

/// Test that makes bunch of transactions between Alice and Bob
///
/// Two private keys are created (Alice, Bob), and then a list of accounts is
/// retrieved from the Ganache server, and then 10 ETH is sent to Alice.
/// After that, Alice sends 5 transactions with 0.1ETH to Bob.
///
/// At the end there is verification how big the balance is on Alice, and how much
/// Bob received.
///
/// This test tries assumes that localhost:8545 is the Ganache server. Easiest way
/// to do it is to use Docker and execute:
///
/// docker run \
///   -p 8545:8545 \
///   trufflesuite/ganache-cli:latest \
///   -a 10 \
///   -i 42 \
///   -e 1000 \
///   --debug
///
/// Other parameters could be changed, but most important parameter is "-i 42" which sets
/// the network ID to "42". This is very important as this test signs transactions for this
/// network. Other values will make the test failing.
///
/// Additionally Ganache by default makes 10 accounts with 100 ETH each, so
/// this test could be probably run few times on a single instance.
#[test]
#[ignore]
fn testnet_alice_and_bob() {
    let (_evloop, web3) =
        make_web3().expect("Unable to create a valid transport for Web3 protocol");

    let alice_priv_key = make_random_key();
    println!("Alice private key: 0x{}", alice_priv_key.to_string());
    let bob_priv_key = make_random_key();
    assert_ne!(alice_priv_key, bob_priv_key);

    println!("Bob private key: 0x{}", bob_priv_key.to_string());

    let accounts = web3
        .eth()
        .accounts()
        .wait()
        .expect("Unable to retrieve accounts");

    let one_eth: U256 = "de0b6b3a7640000".parse().unwrap();

    let seed = &accounts[0];
    println!("Sending 10 ETH to Alice from {:?}", seed);
    // Send 1 ETH to Alice from a first account from Ganache
    let tx_req = TransactionRequest {
        from: *seed,
        to: Some(alice_priv_key.to_public_key().unwrap().as_bytes().into()),
        gas: None,
        gas_price: Some(0x1.into()),
        value: Some(one_eth * 10u64),
        data: None,
        nonce: None,
        condition: None,
    };
    let res = web3.eth().send_transaction(tx_req).wait().unwrap();
    println!("Res {:?}", res);
    let res = web3
        .eth()
        .balance(
            alice_priv_key.to_public_key().unwrap().as_bytes().into(),
            None,
        )
        .wait()
        .unwrap();

    // assert_eq!("")
    println!("Alice balance {:?}", res);
    assert_eq!(res, one_eth * 10u64);

    // Send 5 transactions using Clarity from Alice to Bob
    for nonce in 0u64..5u64 {
        let tx = Transaction {
            nonce: nonce.into(),
            gas_price: 1_000_000_000u64.into(),
            gas_limit: 21000u64.into(),
            to: bob_priv_key.to_public_key().unwrap(),
            value: 1_000_000_000_000_000_000u64.into(), // 0.1ETH
            data: Vec::new(),
            signature: None,
        };
        let signed_tx = tx.sign(&alice_priv_key, Some(42));
        assert!(signed_tx.is_valid());
        assert_eq!(
            signed_tx.sender().unwrap(),
            alice_priv_key.to_public_key().unwrap()
        );
        let res = web3
            .eth()
            .send_raw_transaction(Bytes::from(signed_tx.to_bytes().unwrap()))
            .wait()
            .unwrap();
        println!(
            "Tx {} Hash {:?} Our hash {:?}",
            nonce,
            res,
            bytes_to_hex_str(&signed_tx.hash())
        );
    }
    let res = web3
        .eth()
        .balance(
            alice_priv_key.to_public_key().unwrap().as_bytes().into(),
            None,
        )
        .wait()
        .unwrap();
    println!("Alice balance {:?}", res);
    assert_eq!(res, (one_eth * 5u64) - 2100u64 * 5u64 * 10_000_000_000u64);
    let res = web3
        .eth()
        .balance(
            bob_priv_key.to_public_key().unwrap().as_bytes().into(),
            None,
        )
        .wait()
        .unwrap();
    println!("Bob balance {:?}", res);
    assert_eq!(res, one_eth * 5u64);
}
