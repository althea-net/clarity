//! Byte-order safe and lightweight Web3 client.
//!
//! Rust-web3 has its problems because it uses ethereum-types which does not
//! work on big endian. We can do better than that just crafting our own
//! JSONRPC requests.
//!
const ETHEREUM_INTRINSIC_GAS: u32 = 21000;

pub mod core;
pub mod gas;
pub mod misc;
pub mod net;
pub mod query;
pub mod transactions;

// The actual Web3 client is defined in core.rs, export here
pub use core::Web3;

#[cfg(test)]
mod test {
    use std::{str::FromStr, time::Duration};

    use clarity::Address;
    use num256::Uint256;

    use super::*;

    #[actix_rt::test]
    async fn test_chain_id() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let web3_xdai = Web3::new("https://dai.althea.net", Duration::from_secs(30));
        assert_eq!(Some(Uint256::from(1u8)), web3.eth_chainid().await.unwrap());
        assert_eq!(
            Some(Uint256::from(100u8)),
            web3_xdai.eth_chainid().await.unwrap()
        );
    }

    #[actix_rt::test]
    async fn test_net_version() {
        let web3_xdai = Web3::new("https://dai.althea.net", Duration::from_secs(30));
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        assert_eq!(1u64, web3.net_version().await.unwrap());
        assert_eq!(100u64, web3_xdai.net_version().await.unwrap());
    }
    #[ignore]
    #[actix_rt::test]
    async fn test_complex_response() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let txid1 = "0x9e936b617c45261deafc4af557ce0969d0cbaba00e79357729208f6e56027f81"
            .parse()
            .unwrap();
        let val = web3.eth_get_transaction_by_hash(txid1).await;
        let val = val.expect("Actix failure");
        let response = val.expect("Failed to parse transaction response");
        assert!(response.get_block_number().unwrap() > 10u32.into());
    }

    #[actix_rt::test]
    async fn test_transaction_count_response() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let address: Address = "0x04668ec2f57cc15c381b461b9fedab5d451c8f7f"
            .parse()
            .unwrap();
        let val = web3.eth_get_transaction_count(address).await;
        let val = val.unwrap();
        assert!(val > 0u32.into());
    }

    #[actix_rt::test]
    async fn test_block_response() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let val = web3.eth_get_latest_block().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());

        let val = web3.eth_get_latest_block_full().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
        trace!("latest {}", val.number);
        let latest = val.number;

        let val = web3.eth_get_finalized_block_full().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
        trace!(
            "finalized {}, diff {}",
            val.number.clone(),
            latest - val.number
        );
    }

    #[actix_rt::test]
    async fn test_dai_block_response() {
        let web3 = Web3::new("https://dai.althea.net", Duration::from_secs(30));
        let val = web3.eth_get_latest_block().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
        let val = web3.eth_get_finalized_block().await;
        let val = val.expect("Actix failure");
        assert!(val.number > 10u32.into());
    }

    /// Testing all function that involve a syncing node check
    #[ignore]
    #[actix_rt::test]
    async fn test_syncing_check_functions() {
        ////// TEST ON NON SYNCING BLOCK
        let web3 = Web3::new("https://dai.althea.net", Duration::from_secs(30));
        ////// TEST ON SYNCING BLOCK
        //let web3 = Web3::new("http://127.0.0.1:8545", Duration::from_secs(30));
        let random_address = "0xE04b765c6Ffcc5981DDDcf7e6E2c9E7DB634Df72";
        let val = web3
            .eth_get_balance(Address::parse_and_validate(random_address).unwrap())
            .await;
        println!("{val:?}");

        let val = web3
            .eth_get_transaction_count(Address::parse_and_validate(random_address).unwrap())
            .await;
        println!("{val:?}");

        let val = web3.eth_block_number().await;
        println!("{val:?}");

        let val = web3.eth_synced_block_number().await;
        println!("{val:?}");

        let val = web3.eth_gas_price().await;
        println!("{val:?}");

        //// CHECK THAT when using syncing block, we retrieve a synced block without error
        // let val = web3.eth_get_block_by_number(4792816_u128.into()).await;
        // assert!(!val.is_err());

        // let val = web3.eth_get_block_by_number(4792815_u128.into()).await;
        // assert!(!val.is_err());

        // let val = web3.eth_get_block_by_number(8792900_u128.into()).await;
        // assert!(val.is_err());
        // /////////

        let val = web3
            .eth_get_block_by_number(web3.eth_block_number().await.unwrap())
            .await;
        println!("{val:?}");

        #[allow(unused_variables)]
        let val = web3.eth_get_block_by_number(20000000_u128.into()).await;
        //println!("{:?}", val);

        #[allow(unused_variables)]
        let val = web3
            .eth_get_concise_block_by_number(web3.eth_block_number().await.unwrap())
            .await;
        //println!("{:?}", val);

        let val = web3
            .eth_get_concise_block_by_number(web3.eth_block_number().await.unwrap() + 1_u128.into())
            .await;
        println!("{val:?}");

        #[allow(unused_variables)]
        let val = web3.eth_get_latest_block().await;
        //println!("{:?}", val);
    }

    #[actix_rt::test]
    #[ignore]
    async fn test_transaction_receipt() {
        let web3 = Web3::new("http://testnet.althea.net:8545", Duration::from_secs(30));
        let val = web3
            .eth_get_transaction_receipt(
                Uint256::from_str(
                    "0x3c096fe3fdee374fd47b7d493e22be515c39b77501751f94b28b1e0d47483289",
                )
                .unwrap(),
            )
            .await
            .unwrap();
        println!("{:?}", val);
    }
}
