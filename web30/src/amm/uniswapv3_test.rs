//! Uniswap V3 tests
//!
//! Tests for Uniswap V3 price checking and swapping functionality.

use super::uniswapv3::*;
use crate::client::Web3;
use clarity::{Address, PrivateKey, Uint256};
use num_traits::Inv;

/// This test acquires the sqrt price from the Uniswap v3 DAI / WETH 0.05% pool, then simulates 4 swaps with varying
/// sqrt price limits, amounts being swapped, and asserts that our sqrt price limit methods work as expected
///
/// This test is ignored because it suffers from EIP 1559 failures intermittently, where we try to specify a good
/// gas price but due to latency the transaction is rejected with GasPriceLowerThanBaseFee
#[test]
#[ignore]
fn uniswap_sqrt_price_test() {
    use actix::System;
    use futures::join;
    use std::time::Duration;
    // use env_logger::{Builder, Env};
    // Builder::from_env(Env::default().default_filter_or("error")).init();
    let runner = System::new();
    let web3 = Web3::new("https://cloudflare-eth.com/", Duration::from_secs(15));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();
    let one_eth = Uint256::from(1_000_000_000_000_000_000u64); // 10^18 1 eth
    let fee_0dot05_pct = Uint256::from(500u16); // 0.05%, determines the uniswap pool to use
    let no_price_limit: Uint256 = 0u8.into();

    runner.block_on(async move {
        let token_a = *WETH_CONTRACT_ADDRESS;
        let token_b = *DAI_CONTRACT_ADDRESS;

        let pool_addr = web3
            .get_uniswap_v3_pool_address(
                caller_address,
                token_a,
                token_b,
                Some(fee_0dot05_pct),
                None,
            )
            .await
            .unwrap();
        let tokens = web3
            .get_uniswap_v3_pool_tokens(caller_address, pool_addr)
            .await;
        info!("tokens result: {:?}", tokens);
        let tokens = tokens.unwrap();

        let price = web3
            .get_uniswap_v3_price(
                caller_address,
                token_a,
                token_b,
                Some(fee_0dot05_pct),
                one_eth,
                Some(no_price_limit),
                None,
            )
            .await;
        let weth2dai = price.unwrap();
        info!("weth->dai current price is {}", weth2dai);

        let pool = web3
            .get_uniswap_v3_pool_address(
                caller_address,
                token_a,
                token_b,
                Some(fee_0dot05_pct),
                None,
            )
            .await
            .unwrap();

        let sqrt_price = web3.get_uniswap_v3_sqrt_price(caller_address, pool).await;
        let sqrt_price = sqrt_price.unwrap();

        let spot_price_token0 = decode_uniswap_v3_sqrt_price(sqrt_price);
        let spot_price_token1 = spot_price_token0.inv();
        info!(
            "Calculated token0 ({}) worth in token1 ({}): {}",
            tokens.0, tokens.1, spot_price_token0,
        );
        info!(
            "Calculated token1 ({}) worth in token0 ({}): {}",
            tokens.1, tokens.0, spot_price_token1,
        );

        let little_pad_factor = 0.001f64;
        let little_padded_sqrt_price_0_to_1 =
            scale_v3_uniswap_sqrt_price(sqrt_price, little_pad_factor, true);
        let little_padded_sqrt_price_1_to_0 =
            scale_v3_uniswap_sqrt_price(sqrt_price, little_pad_factor, false);

        let pad_factor = 0.05f64; // 5% tolerance
        let padded_sqrt_price_0_to_1 = scale_v3_uniswap_sqrt_price(sqrt_price, pad_factor, true);
        info!(
            "Calculated padded 0->1 sqrt price limit: {}, original {}",
            decode_uniswap_v3_sqrt_price(padded_sqrt_price_0_to_1),
            spot_price_token0.clone(),
        );
        let padded_sqrt_price_1_to_0 = scale_v3_uniswap_sqrt_price(sqrt_price, pad_factor, false);
        info!(
            "Calculated padded 1->0 sqrt price limit: {}, original {}",
            decode_uniswap_v3_sqrt_price(padded_sqrt_price_1_to_0),
            spot_price_token0.clone(),
        );
        let little_eth = one_eth; // One Ether
        let little_dai = one_eth * 2_000u32.into(); // $2k
        let lots_of_eth = one_eth * 100u32.into(); // 100 Ether
        let lots_of_dai = one_eth * 200_000u32.into(); // $200k

        // Test two swaps with low slippage tolerance and a small amount
        let a = attempt_swap_with_limit(
            &web3,
            11,
            caller_address,
            tokens.0, // DAI
            tokens.1, // ETH
            sqrt_price,
            little_padded_sqrt_price_0_to_1, // No slippage
            little_dai,
            fee_0dot05_pct,
            false,
        );

        let b = attempt_swap_with_limit(
            &web3,
            21,
            caller_address,
            tokens.1, // ETH
            tokens.0, // DAI
            sqrt_price,
            little_padded_sqrt_price_1_to_0, // No slippage
            little_eth,
            fee_0dot05_pct,
            false,
        );

        // Test two swaps with `pad_factor` slippage tolerance and an amount which should push the price past tolerance
        // These swaps should be either reverted or result in too little token output
        let c = attempt_swap_with_limit(
            &web3,
            31,
            caller_address,
            tokens.0, // DAI
            tokens.1, // ETH
            sqrt_price,
            padded_sqrt_price_0_to_1, // With slippage
            lots_of_dai,
            fee_0dot05_pct,
            true,
        );

        let d = attempt_swap_with_limit(
            &web3,
            41,
            caller_address,
            tokens.1, // ETH
            tokens.0, // DAI
            sqrt_price,
            padded_sqrt_price_1_to_0, // With slippage
            lots_of_eth,
            fee_0dot05_pct,
            true,
        );
        join!(a, b, c, d);
    });
}

/// A test utility function which will get a swap price from the quoter and assert that the amount out is reasonable
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn attempt_swap_with_limit(
    web3: &Web3,
    i: i32,                            // an identifier for logs
    caller_address: Address,           // an arbitrary ethereum address with some amount of ether
    token_in: Address,                 // the held token
    token_out: Address,                // the desired token
    sqrt_price_no_slippage: Uint256,   // the current sqrt price stored in the uniswap pool
    sqrt_price_with_slippage: Uint256, // a sqrt price with a bit of slippage tolerance factored in
    amount: Uint256,                   // the amount to swap
    pool_fee: Uint256, // the fee level of the pool, given in hundredths of basis points (e.g. 0.05% -> 500)
    expect_failure: bool, // whether or not the amount swapped should violate sqrt_price_with_slippage, causing a panic
) {
    let base_spot_price = decode_uniswap_v3_sqrt_price(sqrt_price_no_slippage);
    let slippage_spot_price = decode_uniswap_v3_sqrt_price(sqrt_price_with_slippage);
    let slippage_tolerance = slippage_spot_price - base_spot_price;
    let pretty_amount = amount.to_string().parse::<f64>().unwrap() / 10f64.powi(18);
    info!(
        "{}: Attempting swap with {} slippage - sqrt_price {}, amount {}, token_in {}, token_out {}",
        i,
        slippage_tolerance,
        decode_uniswap_v3_sqrt_price(sqrt_price_with_slippage),
        pretty_amount,
        token_in,
        token_out,
    );
    let swap_out = web3
        .get_uniswap_v3_price(
            caller_address,
            token_in,
            token_out,
            Some(pool_fee),
            amount,
            Some(sqrt_price_with_slippage),
            None,
        )
        .await;
    info!(
        "{}: get_uniswap_price with limit {:.8}: result {:?}",
        i, slippage_spot_price, swap_out
    );
    if swap_out.is_err() {
        if !expect_failure {
            panic!("Swap failed! {}", swap_out.unwrap_err());
        }
        return;
    }
    let swap_out = swap_out.unwrap();

    // We expect at least the worst slippage amount out of the swap
    let expected_out_0_1 = (pretty_amount * slippage_spot_price) * 10f64.powi(18);
    let expected_out_1_0 = pretty_amount * slippage_spot_price.inv() * 10f64.powi(18);
    let f_swap = swap_out.to_string().parse::<f64>().unwrap();
    if f_swap < expected_out_0_1 && f_swap < expected_out_1_0 {
        if !expect_failure {
            panic!(concat!(
                "{} Found that the tokens we got out {} are less than we would expect for a 0>1 {} ",
                    "and for a 1>0 swap {}, this should have been covered earlier!"),
                i, f_swap, expected_out_0_1, expected_out_1_0
            );
        }
        info!(
            "Received {} {} for {} {}, expected amounts were [{} or {}]",
            f_swap,
            token_out,
            amount.clone(),
            token_in,
            expected_out_0_1,
            expected_out_1_0
        );
    }
}

#[ignore]
#[test]
fn get_uniswap_price_test() {
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to debug for logs
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(5));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();
    let amount = Uint256::from(1_000_000_000_000_000_000u64);
    let fee = Uint256::from(500u16);
    let sqrt_price_limit_x96_uint160 = Uint256::from(0u16);

    runner.block_on(async move {
        let price = web3
            .get_uniswap_v3_price(
                caller_address,
                *WETH_CONTRACT_ADDRESS,
                *DAI_CONTRACT_ADDRESS,
                Some(fee),
                amount,
                Some(sqrt_price_limit_x96_uint160),
                None,
            )
            .await;
        let weth2dai = price.unwrap();
        debug!("weth->dai price is {}", weth2dai);
        assert!(weth2dai > 0u32.into());
        let price = web3
            .get_uniswap_v3_price(
                caller_address,
                *DAI_CONTRACT_ADDRESS,
                *WETH_CONTRACT_ADDRESS,
                Some(fee),
                weth2dai,
                Some(sqrt_price_limit_x96_uint160),
                None,
            )
            .await;
        let dai2weth = price.unwrap();
        debug!("dai->weth price is {}", &dai2weth);
        let amount_float: f64 = (amount.to_string()).parse().unwrap();
        let dai2weth_float: f64 = (dai2weth.to_string()).parse().unwrap();
        // If we were to swap, we should get within 5% back what we originally put in to account for slippage and fees
        assert!((0.95 * amount_float) < dai2weth_float && dai2weth_float < (1.05 * amount_float));
    });
}

#[test]
// Avoid accidentally spending funds or failing when not running hardhat
#[ignore]
// Note: If you specify a live eth node in Web3::new() and a real private key below, real funds will be used.
// Run this test with the local hardhat environment running
// Swaps WETH for DAI then back again
fn swap_hardhat_test() {
    // this key is the private key for the public key defined in tests/assets/ETHGenesis.json
    // where the full node / miner sends its rewards. Therefore it's always going
    // to have a lot of ETH to pay for things like contract deployments
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_address();

    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to debug for logs
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1000000000000000000u64); // 1 weth
    let amount_out_min: Uint256 = 0u8.into();
    let fee = Uint256::from(500u16);

    let sqrt_price_limit_x96_uint160: Uint256 = 0u8.into();
    runner.block_on(async move {
        let block = web3.eth_get_latest_block().await.unwrap();
        let deadline = block.timestamp + (10u32 * 60u32 * 100000u32).into();

        let success = web3.wrap_eth(amount, miner_private_key, None, None).await;
        if let Ok(b) = success {
            info!("Wrapped eth: {}", b);
        } else {
            panic!("Failed to wrap eth before testing uniswap");
        }
        let initial_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        let initial_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();

        info!(
            "Initial WETH: {}, Initial DAI: {}",
            initial_weth, initial_dai
        );

        let result = web3
            .swap_uniswap_v3(
                miner_private_key,
                *WETH_CONTRACT_ADDRESS,
                *DAI_CONTRACT_ADDRESS,
                Some(fee),
                amount,
                Some(deadline),
                Some(amount_out_min),
                Some(sqrt_price_limit_x96_uint160),
                None,
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing first swap: {:?}", result.err());
        }
        let executing_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        let executing_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        info!(
            "Executing WETH: {}, Executing DAI: {}",
            executing_weth, executing_dai
        );

        let dai_gained = executing_dai - initial_dai;
        assert!(dai_gained > 0u8.into());
        let result = web3
            .swap_uniswap_v3(
                miner_private_key,
                *DAI_CONTRACT_ADDRESS,
                *WETH_CONTRACT_ADDRESS,
                Some(fee),
                dai_gained,
                Some(deadline),
                Some(amount_out_min),
                Some(sqrt_price_limit_x96_uint160),
                None,
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing second swap: {:?}", result.err());
        }
        let final_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        let final_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        info!("Final WETH: {}, Final DAI: {}", final_weth, final_dai);
        let final_dai_delta = final_dai - initial_dai;
        assert!(final_dai_delta == 0u8.into()); // We should have gained little to no dai

        let weth_gained: f64 = (final_weth - executing_weth).to_string().parse().unwrap();
        let original_amount: f64 = (amount).to_string().parse().unwrap();
        // we should not have lost or gained much
        assert!(0.95 * original_amount < weth_gained && weth_gained < 1.05 * original_amount);
    });
}

#[test]
// Avoid accidentally spending funds or failing when not running hardhat
#[ignore]
// Note: If you specify a live eth node in Web3::new() and a real private key below, real funds will be used.
// Run this test with the local hardhat environment running
// Swaps WETH for DAI then back again
fn swap_hardhat_eth_in_test() {
    // this key is the private key for the public key defined in tests/assets/ETHGenesis.json
    // where the full node / miner sends its rewards. Therefore it's always going
    // to have a lot of ETH to pay for things like contract deployments
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_address();

    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("warn")).init(); // Change to warn for logs
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1000000000000000000u64); // 1 weth
    let amount_out_min: Uint256 = 0u8.into();
    let fee = Uint256::from(500u16);

    let sqrt_price_limit_x96_uint160: Uint256 = 0u8.into();
    runner.block_on(async move {
        let block = web3.eth_get_latest_block().await.unwrap();
        let deadline = block.timestamp + (10u32 * 60u32 * 100000u32).into();

        let initial_eth = web3.eth_get_balance(miner_address).await.unwrap();
        let initial_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        let initial_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();

        info!(
            "Initial ETH: {}, Initial WETH: {}, Initial DAI: {}",
            initial_eth, initial_weth, initial_dai
        );
        let result = web3
            .swap_uniswap_v3_eth_in(
                miner_private_key,
                *DAI_CONTRACT_ADDRESS,
                Some(fee),
                amount,
                Some(deadline),
                Some(amount_out_min),
                Some(sqrt_price_limit_x96_uint160),
                None,
                None,
                None,
            )
            .await;
        if result.is_err() {
            panic!("Error performing first swap: {:?}", result.err());
        }
        let final_eth = web3.eth_get_balance(miner_address).await.unwrap();
        let final_weth = web3
            .get_erc20_balance(*WETH_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        let final_dai = web3
            .get_erc20_balance(*DAI_CONTRACT_ADDRESS, miner_address, vec![])
            .await
            .unwrap();
        info!(
            "Final ETH: {}, Final WETH: {}, Final DAI: {}",
            final_eth, final_weth, final_dai
        );

        let dai_gained = final_dai - initial_dai;
        // At the point the chain is frozen for the relay market test,
        // we expect to receive expect to receive about 2,300 dai
        let two_k_dai = 2000 * 1_000_000_000_000_000_000u128;
        let one_eth = 1_000_000_000_000_000_000u128;
        assert!(
            dai_gained > two_k_dai.into(),
            "dai_gained = {dai_gained} <= 2000 * 10^18"
        );
        let eth_lost = initial_eth - final_eth;
        assert!(
            eth_lost > one_eth.into(),
            "eth_lost = {eth_lost} <= 1 * 10^18"
        );

        assert_eq!(
            final_weth, initial_weth,
            "Did not expect to modify wETH balance. Started with {initial_weth} ended with {final_weth}"
        );

        info!(
            "Effectively swapped {} eth for {} dai",
            eth_lost, dai_gained
        );
    });
}

#[test]
#[ignore]
fn example_weth_price_fetching() {
    use actix::System;
    use clarity::Address;
    use std::time::Duration;
    // use env_logger::{Builder, Env};
    // Builder::from_env(Env::default().default_filter_or("debug")).init(); // Change to debug for logs

    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();
    let ten_e18: Uint256 = 1_000_000_000_000_000_000u64.into();
    let ten_e6: Uint256 = 1_000_000u64.into();

    let weth = *WETH_CONTRACT_ADDRESS;
    let dai = *DAI_CONTRACT_ADDRESS;
    let pstake = Address::parse_and_validate("0xfB5c6815cA3AC72Ce9F5006869AE67f18bF77006").unwrap();
    let nym = Address::parse_and_validate("0x525A8F6F3Ba4752868cde25164382BfbaE3990e1").unwrap();
    let slippage = Some(0.05);

    runner.block_on(async move {
        let pstake_price = web3
            .get_uniswap_v3_price_with_retries(
                caller_address,
                pstake,
                weth,
                ten_e18,
                slippage,
                None,
            )
            .await;
        info!("PSTAKE: {:?}", pstake_price);
        let nym_price = web3
            .get_uniswap_v3_price_with_retries(caller_address, nym, weth, ten_e6, slippage, None)
            .await;
        info!("NYM: {:?}", nym_price);
        let dai_price = web3
            .get_uniswap_v3_price_with_retries(caller_address, dai, weth, ten_e18, slippage, None)
            .await;
        info!("DAI: {:?}", dai_price);
    });
}

#[test]
#[ignore]
fn example_weth_price_v2() {
    use actix::System;
    use clarity::Address;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("debug")).init(); // Change to debug for logs

    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let caller_address =
        Address::parse_and_validate("0x810C91f0ca7248744393Ef5C6445146F795AB438").unwrap();
    let ten_e18: Uint256 = 1_000_000_000_000_000_000u64.into();
    let ten_e6: Uint256 = 1_000_000u64.into();
    let ten_e9: Uint256 = 1_000_000_000u64.into();

    let weth = *WETH_CONTRACT_ADDRESS;
    let ustd = *USDT_CONTRACT_ADDRESS;
    let pstake = Address::parse_and_validate("0xfB5c6815cA3AC72Ce9F5006869AE67f18bF77006").unwrap();
    let nym = Address::parse_and_validate("0x525A8F6F3Ba4752868cde25164382BfbaE3990e1").unwrap();
    let cheq = Address::parse_and_validate("0x70EDF1c215D0ce69E7F16FD4E6276ba0d99d4de7").unwrap();
    runner.block_on(async move {
        let pstake_price = web3
            .get_uniswap_v2_price(caller_address, pstake, weth, ten_e18, None)
            .await;
        info!("PSTAKE->WETH: {:?}", pstake_price);
        let pstake_price = web3
            .get_uniswap_v2_price(caller_address, weth, pstake, ten_e18, None)
            .await;
        info!("WETH->PSTAKE: {:?}", pstake_price);
        let nym_price = web3
            .get_uniswap_v2_price(caller_address, nym, weth, ten_e6, None)
            .await;
        info!("NYM->WETH: {:?}", nym_price);
        let pstake_price = web3
            .get_uniswap_v2_price(caller_address, weth, nym, ten_e18, None)
            .await;
        info!("WETH->NYM: {:?}", pstake_price);
        let cheq_price = web3
            .get_uniswap_v2_price(caller_address, ustd, cheq, ten_e9, None)
            .await;
        info!("USDT->CHEQ: {:?}", cheq_price);
    });
}

#[test]
#[ignore]
fn example_weth_price_v3() {
    use actix::System;
    use clarity::Address;
    use env_logger::{Builder, Env};
    use std::time::Duration;
    Builder::from_env(Env::default().default_filter_or("debug")).init(); // Change to debug for logs

    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let caller_address =
        Address::parse_and_validate("0x810C91f0ca7248744393Ef5C6445146F795AB438").unwrap();
    let ten_e10: Uint256 = 10_000_000_000u64.into();

    let weth = *WETH_CONTRACT_ADDRESS;
    let cheq = Address::parse_and_validate("0x70EDF1c215D0ce69E7F16FD4E6276ba0d99d4de7").unwrap();

    runner.block_on(async move {
        let cheq_price = web3
            .get_uniswap_v3_price(caller_address, cheq, weth, None, ten_e10, None, None)
            .await;
        info!("CHEQ->WETH: {:?}", cheq_price.unwrap());
        let cheq_price = web3
            .get_uniswap_v3_price(caller_address, weth, cheq, None, ten_e10, None, None)
            .await;
        info!("WETH->CHEQ: {:?}", cheq_price.unwrap());
    });
}
