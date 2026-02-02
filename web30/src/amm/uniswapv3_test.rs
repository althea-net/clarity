//! Uniswap V3 tests
//!
//! Tests for Uniswap V3 price checking and swapping functionality.

use super::router::SwapHop;
use super::uniswapv3::*;
use crate::client::Web3;
use clarity::{Address, PrivateKey, Uint256};
use num_traits::Inv;

/// Test encode_v3_path using the example from the Uniswap V3 documentation:
/// Swap DAI -> USDC -> WETH9 with 0.3% pool fees
/// The path encoding is: (DAI, 0.3%, USDC, 0.3%, WETH9)
/// https://docs.uniswap.org/contracts/v3/guides/swaps/multihop-swaps
#[test]
fn test_encode_v3_path_multihop_exact_input_from_docs() {
    let dai = *DAI_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let weth = *WETH_CONTRACT_ADDRESS;
    let pool_fee: u32 = 3000; // 0.3%

    // Path: DAI -> USDC (0.3% fee) -> WETH (0.3% fee)
    let path = vec![SwapHop::new(usdc, pool_fee), SwapHop::new(weth, pool_fee)];

    let encoded = encode_v3_path(dai, &path).unwrap();

    // Expected format: DAI (20 bytes) + fee (3 bytes) + USDC (20 bytes) + fee (3 bytes) + WETH (20 bytes)
    // Total: 20 + 3 + 20 + 3 + 20 = 66 bytes
    assert_eq!(encoded.len(), 66);

    // Verify the structure:
    // First 20 bytes: DAI address
    assert_eq!(&encoded[0..20], dai.as_bytes());

    // Next 3 bytes: fee (3000 = 0x000BB8, we take last 3 bytes: 0x00 0x0B 0xB8)
    assert_eq!(&encoded[20..23], &[0x00, 0x0B, 0xB8]);

    // Next 20 bytes: USDC address
    assert_eq!(&encoded[23..43], usdc.as_bytes());

    // Next 3 bytes: fee (3000)
    assert_eq!(&encoded[43..46], &[0x00, 0x0B, 0xB8]);

    // Last 20 bytes: WETH address
    assert_eq!(&encoded[46..66], weth.as_bytes());
}

/// Test encode_v3_path_exact_output using the example from the Uniswap V3 documentation:
/// For exactOutput, the path must be reversed: (tokenOut, fee, tokenIn/tokenOut, fee, tokenIn)
/// For DAI -> USDC -> WETH swap, exactOutput path is: (WETH, 0.3%, USDC, 0.3%, DAI)
/// https://docs.uniswap.org/contracts/v3/guides/swaps/multihop-swaps
#[test]
fn test_encode_v3_path_exact_output_from_docs() {
    let dai = *DAI_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let weth = *WETH_CONTRACT_ADDRESS;
    let pool_fee: u32 = 3000; // 0.3%

    // Path (logical order): DAI -> USDC (0.3% fee) -> WETH (0.3% fee)
    let path = vec![SwapHop::new(usdc, pool_fee), SwapHop::new(weth, pool_fee)];

    let encoded = encode_v3_path_exact_output(dai, &path).unwrap();

    // Expected format (reversed): WETH (20 bytes) + fee (3 bytes) + USDC (20 bytes) + fee (3 bytes) + DAI (20 bytes)
    // Total: 20 + 3 + 20 + 3 + 20 = 66 bytes
    assert_eq!(encoded.len(), 66);

    // Verify the structure (reversed order):
    // First 20 bytes: WETH address (output token)
    assert_eq!(&encoded[0..20], weth.as_bytes());

    // Next 3 bytes: fee for USDC->WETH hop (3000)
    assert_eq!(&encoded[20..23], &[0x00, 0x0B, 0xB8]);

    // Next 20 bytes: USDC address
    assert_eq!(&encoded[23..43], usdc.as_bytes());

    // Next 3 bytes: fee for DAI->USDC hop (3000)
    assert_eq!(&encoded[43..46], &[0x00, 0x0B, 0xB8]);

    // Last 20 bytes: DAI address (input token)
    assert_eq!(&encoded[46..66], dai.as_bytes());
}

/// Test a single hop swap path (direct swap with no intermediaries)
#[test]
fn test_encode_v3_path_single_hop() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let pool_fee: u32 = 500; // 0.05% fee tier (common for stablecoin pairs)

    // Direct swap: WETH -> USDC
    let path = vec![SwapHop::new(usdc, pool_fee)];

    let encoded = encode_v3_path(weth, &path).unwrap();

    // Expected format: WETH (20 bytes) + fee (3 bytes) + USDC (20 bytes)
    // Total: 20 + 3 + 20 = 43 bytes
    assert_eq!(encoded.len(), 43);

    // Verify structure
    assert_eq!(&encoded[0..20], weth.as_bytes());
    assert_eq!(&encoded[20..23], &[0x00, 0x01, 0xF4]); // 500 = 0x0001F4
    assert_eq!(&encoded[23..43], usdc.as_bytes());
}

/// Test single hop exact output path (should be reversed)
#[test]
fn test_encode_v3_path_exact_output_single_hop() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let pool_fee: u32 = 500; // 0.05%

    // Logical path: WETH -> USDC
    let path = vec![SwapHop::new(usdc, pool_fee)];

    let encoded = encode_v3_path_exact_output(weth, &path).unwrap();

    // Expected format (reversed): USDC (20 bytes) + fee (3 bytes) + WETH (20 bytes)
    assert_eq!(encoded.len(), 43);

    // Verify structure (reversed)
    assert_eq!(&encoded[0..20], usdc.as_bytes()); // output token first
    assert_eq!(&encoded[20..23], &[0x00, 0x01, 0xF4]); // 500
    assert_eq!(&encoded[23..43], weth.as_bytes()); // input token last
}

/// Test three-hop path (four tokens)
#[test]
fn test_encode_v3_path_three_hops() {
    let dai = *DAI_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let usdt = *USDT_CONTRACT_ADDRESS;
    let weth = *WETH_CONTRACT_ADDRESS;

    // Path: DAI -> USDC (0.01%) -> USDT (0.01%) -> WETH (0.3%)
    let path = vec![
        SwapHop::new(usdc, 100),  // 0.01% fee
        SwapHop::new(usdt, 100),  // 0.01% fee
        SwapHop::new(weth, 3000), // 0.3% fee
    ];

    let encoded = encode_v3_path(dai, &path).unwrap();

    // Format: DAI + fee + USDC + fee + USDT + fee + WETH
    // Size: 20 + 3 + 20 + 3 + 20 + 3 + 20 = 89 bytes
    assert_eq!(encoded.len(), 89);

    // Verify first token
    assert_eq!(&encoded[0..20], dai.as_bytes());

    // Verify first fee (100 = 0x000064)
    assert_eq!(&encoded[20..23], &[0x00, 0x00, 0x64]);

    // Verify second token (USDC)
    assert_eq!(&encoded[23..43], usdc.as_bytes());

    // Verify second fee (100)
    assert_eq!(&encoded[43..46], &[0x00, 0x00, 0x64]);

    // Verify third token (USDT)
    assert_eq!(&encoded[46..66], usdt.as_bytes());

    // Verify third fee (3000)
    assert_eq!(&encoded[66..69], &[0x00, 0x0B, 0xB8]);

    // Verify output token (WETH)
    assert_eq!(&encoded[69..89], weth.as_bytes());
}

/// Test three-hop exact output path (reversed)
#[test]
fn test_encode_v3_path_exact_output_three_hops() {
    let dai = *DAI_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let usdt = *USDT_CONTRACT_ADDRESS;
    let weth = *WETH_CONTRACT_ADDRESS;

    // Logical path: DAI -> USDC (0.01%) -> USDT (0.01%) -> WETH (0.3%)
    let path = vec![
        SwapHop::new(usdc, 100),  // 0.01% fee
        SwapHop::new(usdt, 100),  // 0.01% fee
        SwapHop::new(weth, 3000), // 0.3% fee
    ];

    let encoded = encode_v3_path_exact_output(dai, &path).unwrap();

    // Reversed format: WETH + fee + USDT + fee + USDC + fee + DAI
    // Size: 20 + 3 + 20 + 3 + 20 + 3 + 20 = 89 bytes
    assert_eq!(encoded.len(), 89);

    // Verify output token first (WETH)
    assert_eq!(&encoded[0..20], weth.as_bytes());

    // Verify last hop's fee (3000 for USDT->WETH)
    assert_eq!(&encoded[20..23], &[0x00, 0x0B, 0xB8]);

    // Verify USDT
    assert_eq!(&encoded[23..43], usdt.as_bytes());

    // Verify middle hop's fee (100 for USDC->USDT)
    assert_eq!(&encoded[43..46], &[0x00, 0x00, 0x64]);

    // Verify USDC
    assert_eq!(&encoded[46..66], usdc.as_bytes());

    // Verify first hop's fee (100 for DAI->USDC)
    assert_eq!(&encoded[66..69], &[0x00, 0x00, 0x64]);

    // Verify input token last (DAI)
    assert_eq!(&encoded[69..89], dai.as_bytes());
}

/// Test that empty path returns error
#[test]
fn test_encode_v3_path_empty_path_error() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let path: Vec<SwapHop> = vec![];

    let result = encode_v3_path(weth, &path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("at least one swap"));
}

/// Test that empty path returns error for exact output
#[test]
fn test_encode_v3_path_exact_output_empty_path_error() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let path: Vec<SwapHop> = vec![];

    let result = encode_v3_path_exact_output(weth, &path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("at least one swap"));
}

/// Test fee validation (fee must fit in uint24)
#[test]
fn test_encode_v3_path_invalid_fee_error() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;

    // Fee exceeds uint24 max (0xFFFFFF = 16777215)
    let path = vec![SwapHop::new(usdc, 0x1000000)];

    let result = encode_v3_path(weth, &path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds uint24"));
}

/// Test all standard Uniswap V3 fee tiers
#[test]
fn test_encode_v3_path_all_fee_tiers() {
    let weth = *WETH_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let usdt = *USDT_CONTRACT_ADDRESS;
    let dai = *DAI_CONTRACT_ADDRESS;

    // Test all four standard fee tiers: 0.01%, 0.05%, 0.3%, 1%
    let path = vec![
        SwapHop::new(usdc, 100),   // 0.01%
        SwapHop::new(usdt, 500),   // 0.05%
        SwapHop::new(dai, 3000),   // 0.3%
        SwapHop::new(weth, 10000), // 1%
    ];

    let encoded = encode_v3_path(dai, &path).unwrap();

    // Verify each fee encoding:
    // 100 = 0x000064
    assert_eq!(&encoded[20..23], &[0x00, 0x00, 0x64]);
    // 500 = 0x0001F4
    assert_eq!(&encoded[43..46], &[0x00, 0x01, 0xF4]);
    // 3000 = 0x000BB8
    assert_eq!(&encoded[66..69], &[0x00, 0x0B, 0xB8]);
    // 10000 = 0x002710
    assert_eq!(&encoded[89..92], &[0x00, 0x27, 0x10]);
}

/// Test that exact input and exact output paths are correctly related
/// (exact output should be the reverse of exact input)
#[test]
fn test_exact_input_and_output_paths_are_reversed() {
    let dai = *DAI_CONTRACT_ADDRESS;
    let usdc = *USDC_CONTRACT_ADDRESS;
    let weth = *WETH_CONTRACT_ADDRESS;

    let path = vec![SwapHop::new(usdc, 3000), SwapHop::new(weth, 3000)];

    let exact_input = encode_v3_path(dai, &path).unwrap();
    let exact_output = encode_v3_path_exact_output(dai, &path).unwrap();

    // Both should be 66 bytes
    assert_eq!(exact_input.len(), exact_output.len());
    assert_eq!(exact_input.len(), 66);

    // Exact input starts with DAI, ends with WETH
    assert_eq!(&exact_input[0..20], dai.as_bytes());
    assert_eq!(&exact_input[46..66], weth.as_bytes());

    // Exact output starts with WETH, ends with DAI
    assert_eq!(&exact_output[0..20], weth.as_bytes());
    assert_eq!(&exact_output[46..66], dai.as_bytes());
}

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
    if let Err(e) = swap_out {
        if !expect_failure {
            panic!("Swap failed! {}", e);
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
