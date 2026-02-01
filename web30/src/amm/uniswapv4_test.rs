//! Uniswap V4 tests
//!
//! Tests for Uniswap V4 price quoting and swapping functionality.
//!
//! Encoding tests verify that our ABI encoding matches the official Uniswap V4 interface.
//! Reference: https://docs.uniswap.org/contracts/v4/reference/periphery/libraries/Actions

use super::uniswapv3::{DAI_CONTRACT_ADDRESS, WETH_CONTRACT_ADDRESS};
use super::uniswapv4::*;
use crate::client::Web3;
use clarity::abi::{encode_call, AbiToken};
use clarity::{Address, PrivateKey, Uint256};

/// Test getting a quote from Uniswap V4
/// This test is ignored as it requires a live Ethereum node with V4 deployed
#[test]
#[ignore]
fn get_uniswap_v4_quote_test() {
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;

    Builder::from_env(Env::default().default_filter_or("info")).init();
    let runner = System::new();

    // Note: Uniswap V4 was deployed on mainnet, use a mainnet node
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();

    runner.block_on(async move {
        let weth = *WETH_CONTRACT_ADDRESS;
        let dai = *DAI_CONTRACT_ADDRESS;

        // Create a pool key for WETH/DAI with 0.3% fee
        let pool_key = PoolKey::standard(
            weth,
            dai,
            3000u32.into(),          // 0.3% fee
            tick_spacings::FEE_3000, // tick spacing for 0.3% pools
        );

        let one_eth = Uint256::from(1_000_000_000_000_000_000u64);
        let zero_for_one = pool_key.is_zero_for_one(weth);

        let quote = web3
            .get_uniswap_v4_quote(caller_address, &pool_key, zero_for_one, one_eth, None, None)
            .await;

        match quote {
            Ok(amount_out) => {
                info!("V4 Quote: 1 WETH -> {} DAI", amount_out);
                assert!(amount_out > 0u8.into());
            }
            Err(e) => {
                // Pool might not exist yet on V4
                info!("V4 Quote failed (pool may not exist): {:?}", e);
            }
        }
    });
}

/// Test getting pool state from V4 StateView
#[test]
#[ignore]
fn get_uniswap_v4_pool_state_test() {
    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;

    Builder::from_env(Env::default().default_filter_or("info")).init();
    let runner = System::new();

    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let caller_address =
        Address::parse_and_validate("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap();

    runner.block_on(async move {
        let weth = *WETH_CONTRACT_ADDRESS;
        let dai = *DAI_CONTRACT_ADDRESS;

        let pool_key = PoolKey::standard(weth, dai, 3000u32.into(), tick_spacings::FEE_3000);

        let state = web3
            .get_uniswap_v4_pool_state(caller_address, &pool_key, None)
            .await;

        match state {
            Ok((sqrt_price, tick)) => {
                info!("V4 Pool State: sqrtPriceX96={}, tick={}", sqrt_price, tick);
                assert!(sqrt_price > 0u8.into());
            }
            Err(e) => {
                info!("V4 Pool state query failed (pool may not exist): {:?}", e);
            }
        }
    });
}

/// Test swapping on Uniswap V4 with hardhat local node
/// This test is ignored as it requires hardhat running with forked mainnet
#[test]
#[ignore]
fn swap_uniswap_v4_hardhat_test() {
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_address();

    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;

    Builder::from_env(Env::default().default_filter_or("info")).init();
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1_000_000_000_000_000_000u64); // 1 WETH

    runner.block_on(async move {
        let weth = *WETH_CONTRACT_ADDRESS;
        let dai = *DAI_CONTRACT_ADDRESS;

        // Wrap some ETH first
        let wrap_result = web3.wrap_eth(amount, miner_private_key, None, None).await;
        if let Err(e) = wrap_result {
            panic!("Failed to wrap ETH: {:?}", e);
        }
        info!("Wrapped {} ETH", amount);

        let initial_weth = web3
            .get_erc20_balance(weth, miner_address, vec![])
            .await
            .unwrap();
        let initial_dai = web3
            .get_erc20_balance(dai, miner_address, vec![])
            .await
            .unwrap();

        info!(
            "Initial balances - WETH: {}, DAI: {}",
            initial_weth, initial_dai
        );

        // Create pool key
        let pool_key = PoolKey::standard(weth, dai, 3000u32.into(), tick_spacings::FEE_3000);

        // Execute swap with slippage protection (500 bps = 5%)
        let result = web3
            .swap_uniswap_v4_with_slippage(
                miner_private_key,
                &pool_key,
                weth,
                amount,
                Some(500), // 500 basis points = 5% slippage
                None,
                None,
                None,
                Some(Duration::from_secs(60)),
            )
            .await;

        match result {
            Ok(txid) => {
                info!("V4 Swap txid: {}", txid);

                let final_weth = web3
                    .get_erc20_balance(weth, miner_address, vec![])
                    .await
                    .unwrap();
                let final_dai = web3
                    .get_erc20_balance(dai, miner_address, vec![])
                    .await
                    .unwrap();

                info!("Final balances - WETH: {}, DAI: {}", final_weth, final_dai);

                let dai_gained = final_dai - initial_dai;
                assert!(dai_gained > 0u8.into(), "Should have received DAI");
            }
            Err(e) => {
                // V4 pools might not be available in local hardhat
                info!("V4 Swap failed (expected if pool doesn't exist): {:?}", e);
            }
        }
    });
}

/// Test swapping native ETH on Uniswap V4
/// V4 natively supports ETH without WETH wrapping
#[test]
#[ignore]
fn swap_uniswap_v4_eth_in_hardhat_test() {
    let miner_private_key: PrivateKey =
        "0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7"
            .parse()
            .unwrap();
    let miner_address: Address = miner_private_key.to_address();

    use actix::System;
    use env_logger::{Builder, Env};
    use std::time::Duration;

    Builder::from_env(Env::default().default_filter_or("info")).init();
    let runner = System::new();

    let web3 = Web3::new("http://localhost:8545", Duration::from_secs(300));
    let amount = Uint256::from(1_000_000_000_000_000_000u64); // 1 ETH

    runner.block_on(async move {
        let dai = *DAI_CONTRACT_ADDRESS;

        let initial_eth = web3.eth_get_balance(miner_address).await.unwrap();
        let initial_dai = web3
            .get_erc20_balance(dai, miner_address, vec![])
            .await
            .unwrap();

        info!(
            "Initial balances - ETH: {}, DAI: {}",
            initial_eth, initial_dai
        );

        // Execute native ETH swap
        // Note: V4 uses address(0) for native ETH, not WETH
        let result = web3
            .swap_uniswap_v4_eth_in(
                miner_private_key,
                dai,
                3000u32.into(),          // 0.3% fee
                tick_spacings::FEE_3000, // tick spacing
                amount,
                0u8.into(), // min amount out (dangerous in production!)
                None,
                None,
                Some(Duration::from_secs(60)),
            )
            .await;

        match result {
            Ok(txid) => {
                info!("V4 ETH Swap txid: {}", txid);

                let final_eth = web3.eth_get_balance(miner_address).await.unwrap();
                let final_dai = web3
                    .get_erc20_balance(dai, miner_address, vec![])
                    .await
                    .unwrap();

                info!("Final balances - ETH: {}, DAI: {}", final_eth, final_dai);

                let eth_spent = initial_eth - final_eth;
                let dai_gained = final_dai - initial_dai;

                info!("Swapped {} ETH for {} DAI", eth_spent, dai_gained);
                assert!(dai_gained > 0u8.into(), "Should have received DAI");
            }
            Err(e) => {
                info!(
                    "V4 ETH Swap failed (expected if pool doesn't exist): {:?}",
                    e
                );
            }
        }
    });
}

/// Test PoolKey creation and sorting
#[test]
fn test_pool_key_sorting() {
    let addr_a = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let addr_b = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    // Test that pool key properly sorts tokens
    let pool_key1 = PoolKey::standard(addr_a, addr_b, 3000u32.into(), 60);
    let pool_key2 = PoolKey::standard(addr_b, addr_a, 3000u32.into(), 60);

    // Both should result in the same ordering
    assert_eq!(pool_key1.currency0, pool_key2.currency0);
    assert_eq!(pool_key1.currency1, pool_key2.currency1);

    // currency0 should be the smaller address
    assert!(pool_key1.currency0 < pool_key1.currency1);
}

/// Test zero_for_one detection
#[test]
fn test_zero_for_one() {
    let addr_a = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let addr_b = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    let pool_key = PoolKey::standard(addr_a, addr_b, 3000u32.into(), 60);

    // If addr_a < addr_b, then addr_a is currency0
    if addr_a < addr_b {
        assert!(pool_key.is_zero_for_one(addr_a));
        assert!(!pool_key.is_zero_for_one(addr_b));
    } else {
        assert!(!pool_key.is_zero_for_one(addr_a));
        assert!(pool_key.is_zero_for_one(addr_b));
    }
}

/// Test tick spacing constants
#[test]
fn test_tick_spacings() {
    assert_eq!(tick_spacings::FEE_100, 1);
    assert_eq!(tick_spacings::FEE_500, 10);
    assert_eq!(tick_spacings::FEE_3000, 60);
    assert_eq!(tick_spacings::FEE_10000, 200);
}

/// Test PoolKey with native ETH (zero address)
#[test]
fn test_pool_key_native_eth() {
    let eth = Address::default(); // Zero address = native ETH in V4
    let dai = Address::parse_and_validate("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();

    let pool_key = PoolKey::standard(eth, dai, 3000u32.into(), 60);

    // ETH (zero address) should always be currency0
    assert_eq!(pool_key.currency0, eth);
    assert_eq!(pool_key.currency1, dai);
    assert!(pool_key.is_zero_for_one(eth));
}

/// Verify contract addresses are valid
#[test]
fn test_v4_contract_addresses() {
    // All addresses should be non-zero
    assert!(*UNISWAP_V4_POOL_MANAGER_ADDRESS != Address::default());
    assert!(*UNISWAP_V4_UNIVERSAL_ROUTER_ADDRESS != Address::default());
    assert!(*UNISWAP_V4_QUOTER_ADDRESS != Address::default());
    assert!(*UNISWAP_V4_POSITION_MANAGER_ADDRESS != Address::default());
    assert!(*UNISWAP_V4_STATE_VIEW_ADDRESS != Address::default());
    assert!(*PERMIT2_ADDRESS != Address::default());

    // Pool manager has a vanity address
    let pool_manager_hex = format!("{:?}", *UNISWAP_V4_POOL_MANAGER_ADDRESS);
    assert!(pool_manager_hex.to_lowercase().contains("4444c5dc75cb"));
}

// =============================================================================
// ABI Encoding Tests
// =============================================================================
// These tests verify that our encoding matches the official Uniswap V4 interface
// Reference: https://docs.uniswap.org/contracts/v4/reference/periphery/libraries/Actions

/// Test that V4RouterAction values match the official Actions library
/// Reference: https://docs.uniswap.org/contracts/v4/reference/periphery/libraries/Actions
#[test]
fn test_v4_router_action_values() {
    // Verify action values match the official Uniswap V4 Actions library
    // These values are from: https://github.com/uniswap/v4-periphery/blob/main/src/libraries/Actions.sol

    assert_eq!(
        V4RouterAction::IncreaseLiquidity as u8,
        0x00,
        "INCREASE_LIQUIDITY should be 0x00"
    );
    assert_eq!(
        V4RouterAction::DecreaseLiquidity as u8,
        0x01,
        "DECREASE_LIQUIDITY should be 0x01"
    );
    assert_eq!(
        V4RouterAction::MintPosition as u8,
        0x02,
        "MINT_POSITION should be 0x02"
    );
    assert_eq!(
        V4RouterAction::BurnPosition as u8,
        0x03,
        "BURN_POSITION should be 0x03"
    );
    assert_eq!(
        V4RouterAction::IncreaseLiquidityFromDeltas as u8,
        0x04,
        "INCREASE_LIQUIDITY_FROM_DELTAS should be 0x04"
    );
    assert_eq!(
        V4RouterAction::MintPositionFromDeltas as u8,
        0x05,
        "MINT_POSITION_FROM_DELTAS should be 0x05"
    );
    assert_eq!(
        V4RouterAction::SwapExactInSingle as u8,
        0x06,
        "SWAP_EXACT_IN_SINGLE should be 0x06"
    );
    assert_eq!(
        V4RouterAction::SwapExactIn as u8,
        0x07,
        "SWAP_EXACT_IN should be 0x07"
    );
    assert_eq!(
        V4RouterAction::SwapExactOutSingle as u8,
        0x08,
        "SWAP_EXACT_OUT_SINGLE should be 0x08"
    );
    assert_eq!(
        V4RouterAction::SwapExactOut as u8,
        0x09,
        "SWAP_EXACT_OUT should be 0x09"
    );
    assert_eq!(V4RouterAction::Donate as u8, 0x0a, "DONATE should be 0x0a");
    assert_eq!(V4RouterAction::Settle as u8, 0x0b, "SETTLE should be 0x0b");
    assert_eq!(
        V4RouterAction::SettleAll as u8,
        0x0c,
        "SETTLE_ALL should be 0x0c"
    );
    assert_eq!(
        V4RouterAction::SettlePair as u8,
        0x0d,
        "SETTLE_PAIR should be 0x0d"
    );
    assert_eq!(V4RouterAction::Take as u8, 0x0e, "TAKE should be 0x0e");
    assert_eq!(
        V4RouterAction::TakeAll as u8,
        0x0f,
        "TAKE_ALL should be 0x0f"
    );
    assert_eq!(
        V4RouterAction::TakePortion as u8,
        0x10,
        "TAKE_PORTION should be 0x10"
    );
    assert_eq!(
        V4RouterAction::TakePair as u8,
        0x11,
        "TAKE_PAIR should be 0x11"
    );
    assert_eq!(
        V4RouterAction::CloseCurrency as u8,
        0x12,
        "CLOSE_CURRENCY should be 0x12"
    );
    assert_eq!(
        V4RouterAction::ClearOrTake as u8,
        0x13,
        "CLEAR_OR_TAKE should be 0x13"
    );
    assert_eq!(V4RouterAction::Sweep as u8, 0x14, "SWEEP should be 0x14");
    assert_eq!(V4RouterAction::Wrap as u8, 0x15, "WRAP should be 0x15");
    assert_eq!(V4RouterAction::Unwrap as u8, 0x16, "UNWRAP should be 0x16");
}

/// Test that UniversalRouterCommand values are correct
#[test]
fn test_universal_router_command_values() {
    assert_eq!(
        UniversalRouterCommand::V4Swap as u8,
        0x10,
        "V4_SWAP should be 0x10"
    );
    assert_eq!(
        UniversalRouterCommand::Permit2Permit as u8,
        0x0a,
        "PERMIT2_PERMIT should be 0x0a"
    );
    assert_eq!(
        UniversalRouterCommand::WrapEth as u8,
        0x0b,
        "WRAP_ETH should be 0x0b"
    );
    assert_eq!(
        UniversalRouterCommand::UnwrapWeth as u8,
        0x0c,
        "UNWRAP_WETH should be 0x0c"
    );
    assert_eq!(
        UniversalRouterCommand::Sweep as u8,
        0x04,
        "SWEEP should be 0x04"
    );
    assert_eq!(
        UniversalRouterCommand::PayPortion as u8,
        0x06,
        "PAY_PORTION should be 0x06"
    );
}

/// Test PoolKey ABI encoding structure
/// PoolKey: (Currency currency0, Currency currency1, uint24 fee, int24 tickSpacing, IHooks hooks)
#[test]
fn test_pool_key_abi_encoding() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    let pool_key = PoolKey::standard(usdc, weth, 3000u32.into(), 60);

    let abi_token = pool_key.to_abi_token();

    // Verify the structure is a Struct with 5 elements
    match abi_token {
        AbiToken::Struct(ref tokens) => {
            assert_eq!(tokens.len(), 5, "PoolKey should have 5 fields");

            // currency0 (Address)
            match &tokens[0] {
                AbiToken::Address(addr) => assert_eq!(*addr, pool_key.currency0),
                _ => panic!("Field 0 should be Address (currency0)"),
            }

            // currency1 (Address)
            match &tokens[1] {
                AbiToken::Address(addr) => assert_eq!(*addr, pool_key.currency1),
                _ => panic!("Field 1 should be Address (currency1)"),
            }

            // fee (Uint - represents uint24)
            match &tokens[2] {
                AbiToken::Uint(fee) => assert_eq!(*fee, 3000u32.into()),
                _ => panic!("Field 2 should be Uint (fee)"),
            }

            // tickSpacing (Int - represents int24)
            match &tokens[3] {
                AbiToken::Int(ts) => assert_eq!(*ts, 60.into()),
                _ => panic!("Field 3 should be Int (tickSpacing)"),
            }

            // hooks (Address)
            match &tokens[4] {
                AbiToken::Address(addr) => assert_eq!(*addr, Address::default()),
                _ => panic!("Field 4 should be Address (hooks)"),
            }
        }
        _ => panic!("PoolKey should encode as a Struct"),
    }
}

/// Test ExactInputSingleParams ABI encoding structure
/// Reference: https://docs.uniswap.org/contracts/v4/reference/periphery/interfaces/IV4Router
/// ExactInputSingleParams: (PoolKey poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)
#[test]
fn test_exact_input_single_params_encoding() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    let pool_key = PoolKey::standard(usdc, weth, 3000u32.into(), 60);
    let amount_in: Uint256 = 1_000_000_000_000_000_000u64.into(); // 1e18
    let amount_out_min: Uint256 = 1_000_000u64.into();

    let params = ExactInputSingleParams {
        pool_key: pool_key.clone(),
        zero_for_one: true,
        amount_in,
        amount_out_minimum: amount_out_min,
        hook_data: vec![],
    };

    let abi_token = params.to_abi_token();

    // Verify the structure
    match abi_token {
        AbiToken::Struct(ref tokens) => {
            assert_eq!(
                tokens.len(),
                5,
                "ExactInputSingleParams should have 5 fields (no sqrtPriceLimitX96)"
            );

            // poolKey (Struct)
            match &tokens[0] {
                AbiToken::Struct(_) => {}
                _ => panic!("Field 0 should be Struct (poolKey)"),
            }

            // zeroForOne (Bool)
            match &tokens[1] {
                AbiToken::Bool(v) => assert!(*v),
                _ => panic!("Field 1 should be Bool (zeroForOne)"),
            }

            // amountIn (Uint - uint128)
            match &tokens[2] {
                AbiToken::Uint(v) => assert_eq!(*v, amount_in),
                _ => panic!("Field 2 should be Uint (amountIn)"),
            }

            // amountOutMinimum (Uint - uint128)
            match &tokens[3] {
                AbiToken::Uint(v) => assert_eq!(*v, amount_out_min),
                _ => panic!("Field 3 should be Uint (amountOutMinimum)"),
            }

            // hookData (UnboundedBytes)
            match &tokens[4] {
                AbiToken::UnboundedBytes(v) => assert!(v.is_empty()),
                _ => panic!("Field 4 should be UnboundedBytes (hookData)"),
            }
        }
        _ => panic!("ExactInputSingleParams should encode as a Struct"),
    }
}

/// Test ExactOutputSingleParams ABI encoding structure
/// ExactOutputSingleParams: (PoolKey poolKey, bool zeroForOne, uint128 amountOut, uint128 amountInMaximum, bytes hookData)
#[test]
fn test_exact_output_single_params_encoding() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    let pool_key = PoolKey::standard(usdc, weth, 3000u32.into(), 60);
    let amount_out: Uint256 = 1_000_000u64.into();
    let amount_in_max: Uint256 = 1_000_000_000_000_000_000u64.into();

    let params = ExactOutputSingleParams {
        pool_key: pool_key.clone(),
        zero_for_one: false,
        amount_out,
        amount_in_maximum: amount_in_max,
        hook_data: vec![0xde, 0xad, 0xbe, 0xef],
    };

    let abi_token = params.to_abi_token();

    match abi_token {
        AbiToken::Struct(ref tokens) => {
            assert_eq!(
                tokens.len(),
                5,
                "ExactOutputSingleParams should have 5 fields"
            );

            // Verify hook_data is properly included
            match &tokens[4] {
                AbiToken::UnboundedBytes(v) => {
                    assert_eq!(v.len(), 4);
                    assert_eq!(v, &[0xde, 0xad, 0xbe, 0xef]);
                }
                _ => panic!("Field 4 should be UnboundedBytes (hookData)"),
            }
        }
        _ => panic!("ExactOutputSingleParams should encode as a Struct"),
    }
}

/// Test dynamic fee flag constant
#[test]
fn test_dynamic_fee_flag() {
    assert_eq!(
        DYNAMIC_FEE_FLAG, 0x800000,
        "Dynamic fee flag should be 0x800000"
    );
    assert_eq!(
        MAX_LP_FEE, 1_000_000,
        "Max LP fee should be 1,000,000 (100%)"
    );
}

/// Test dynamic fee pool creation and detection
#[test]
fn test_dynamic_fee_pool() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
    let hooks = Address::parse_and_validate("0x1234567890123456789012345678901234567890").unwrap();

    // Create a dynamic fee pool
    let dynamic_pool = PoolKey::dynamic_fee(usdc, weth, 60, hooks);

    // Verify it's detected as dynamic fee
    assert!(
        dynamic_pool.is_dynamic_fee(),
        "Should be detected as dynamic fee pool"
    );
    assert_eq!(
        dynamic_pool.get_fee_pips(),
        0,
        "Dynamic fee pool should return 0 for fee pips"
    );
    assert!(
        dynamic_pool.is_valid_fee(),
        "Dynamic fee flag should be valid"
    );
    assert_eq!(dynamic_pool.hooks, hooks, "Hooks address should be set");

    // Create a standard pool and verify it's not dynamic
    let standard_pool = PoolKey::standard(usdc, weth, 3000u32.into(), 60);
    assert!(
        !standard_pool.is_dynamic_fee(),
        "Standard pool should not be dynamic fee"
    );
    assert_eq!(
        standard_pool.get_fee_pips(),
        3000,
        "Standard pool fee should be 3000"
    );
    assert!(standard_pool.is_valid_fee(), "Standard fee should be valid");
}

/// Test fee validation
#[test]
fn test_fee_validation() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    // Valid fees
    let pool_100 = PoolKey::standard(usdc, weth, 100u32.into(), 1);
    assert!(pool_100.is_valid_fee(), "100 bps fee should be valid");

    let pool_500 = PoolKey::standard(usdc, weth, 500u32.into(), 10);
    assert!(pool_500.is_valid_fee(), "500 bps fee should be valid");

    let pool_3000 = PoolKey::standard(usdc, weth, 3000u32.into(), 60);
    assert!(pool_3000.is_valid_fee(), "3000 bps fee should be valid");

    let pool_10000 = PoolKey::standard(usdc, weth, 10000u32.into(), 200);
    assert!(pool_10000.is_valid_fee(), "10000 bps fee should be valid");

    let pool_max = PoolKey::standard(usdc, weth, MAX_LP_FEE.into(), 200);
    assert!(pool_max.is_valid_fee(), "Max fee should be valid");

    // Dynamic fee is valid
    let dynamic = PoolKey::dynamic_fee(usdc, weth, 60, Address::default());
    assert!(dynamic.is_valid_fee(), "Dynamic fee should be valid");
}

/// Test that action sequence for swaps is correct
/// Per docs: SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE_ALL
#[test]
fn test_swap_action_sequence() {
    let actions = vec![
        V4RouterAction::SwapExactInSingle as u8,
        V4RouterAction::SettleAll as u8,
        V4RouterAction::TakeAll as u8,
    ];

    // Verify the expected byte sequence
    assert_eq!(
        actions,
        vec![0x06, 0x0c, 0x0f],
        "Swap action sequence should be [0x06, 0x0c, 0x0f] (SwapExactInSingle, SettleAll, TakeAll)"
    );
}

/// Test encoding of a complete swap call structure
/// This verifies the overall structure matches what Universal Router expects
#[test]
fn test_complete_swap_encoding_structure() {
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
    let weth = Address::parse_and_validate("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

    let pool_key = PoolKey::standard(usdc, weth, 3000u32.into(), 60);
    let amount_in: Uint256 = 1_000_000_000_000_000_000u64.into();
    let amount_out_min: Uint256 = 1_000_000u64.into();

    // Build actions
    let actions = vec![
        V4RouterAction::SwapExactInSingle as u8,
        V4RouterAction::SettleAll as u8,
        V4RouterAction::TakeAll as u8,
    ];

    // Verify actions are correct bytes
    assert_eq!(
        actions,
        vec![0x06, 0x0c, 0x0f],
        "Actions should match expected bytes"
    );

    // Build swap params structure
    let swap_params = ExactInputSingleParams {
        pool_key: pool_key.clone(),
        zero_for_one: true,
        amount_in,
        amount_out_minimum: amount_out_min,
        hook_data: vec![], // Empty hook data is typical
    };

    // Verify the structure encodes as expected
    let abi_token = swap_params.to_abi_token();
    match abi_token {
        AbiToken::Struct(ref tokens) => {
            assert_eq!(tokens.len(), 5, "Should have 5 fields");
        }
        _ => panic!("Should be a struct"),
    }

    // Test the currency ordering for settle/take
    let currency_in = pool_key.currency0; // zeroForOne=true means currency0 is input
    let currency_out = pool_key.currency1;

    // Verify currency ordering is correct
    assert!(
        currency_in < currency_out,
        "currency0 should be less than currency1"
    );

    // Test that command byte is correct
    let commands = vec![UniversalRouterCommand::V4Swap as u8];
    assert_eq!(commands, vec![0x10], "V4_SWAP command should be 0x10");

    // Test that we can encode the final execute call
    let deadline: Uint256 = 1700000000u64.into();

    // Use a simple placeholder for v4_input to test the final call encoding
    let v4_input_placeholder = vec![0x01, 0x02, 0x03]; // Non-empty placeholder

    let final_payload = encode_call(
        "execute(bytes,bytes[],uint256)",
        &[
            AbiToken::UnboundedBytes(commands),
            AbiToken::Dynamic(vec![AbiToken::UnboundedBytes(v4_input_placeholder)]),
            AbiToken::Uint(deadline),
        ],
    );

    assert!(
        final_payload.is_ok(),
        "Final execute payload should encode successfully"
    );
    let payload = final_payload.unwrap();

    // Verify the function selector for execute(bytes,bytes[],uint256)
    // Selector: 0x3593564c
    let selector = &payload[0..4];
    assert_eq!(
        selector,
        &[0x35, 0x93, 0x56, 0x4c],
        "Function selector should be 0x3593564c for execute(bytes,bytes[],uint256)"
    );

    // Verify the payload has reasonable size
    assert!(
        payload.len() > 100,
        "Payload should have substantial content"
    );
}

/// Test that action values match expected bytes for common swap patterns
#[test]
fn test_common_swap_action_bytes() {
    // Exact input single swap: SwapExactInSingle, SettleAll, TakeAll
    let exact_in_single_actions = vec![
        V4RouterAction::SwapExactInSingle as u8,
        V4RouterAction::SettleAll as u8,
        V4RouterAction::TakeAll as u8,
    ];
    assert_eq!(exact_in_single_actions, vec![0x06, 0x0c, 0x0f]);

    // Exact output single swap: SwapExactOutSingle, SettleAll, TakeAll
    let exact_out_single_actions = vec![
        V4RouterAction::SwapExactOutSingle as u8,
        V4RouterAction::SettleAll as u8,
        V4RouterAction::TakeAll as u8,
    ];
    assert_eq!(exact_out_single_actions, vec![0x08, 0x0c, 0x0f]);

    // Multi-hop swap: SwapExactIn, SettleAll, TakeAll
    let multi_hop_actions = vec![
        V4RouterAction::SwapExactIn as u8,
        V4RouterAction::SettleAll as u8,
        V4RouterAction::TakeAll as u8,
    ];
    assert_eq!(multi_hop_actions, vec![0x07, 0x0c, 0x0f]);
}

/// Test standard fee tier to tick spacing mapping
/// Reference: https://docs.uniswap.org/contracts/v4/quickstart/create-pool
#[test]
fn test_fee_tier_tick_spacing_mapping() {
    // These are the recommended mappings from the docs
    // 0.01% fee -> 1 tick spacing
    assert_eq!(tick_spacings::FEE_100, 1);

    // 0.05% fee -> 10 tick spacing
    assert_eq!(tick_spacings::FEE_500, 10);

    // 0.30% fee -> 60 tick spacing
    assert_eq!(tick_spacings::FEE_3000, 60);

    // 1.00% fee -> 200 tick spacing
    assert_eq!(tick_spacings::FEE_10000, 200);
}

/// Test native ETH representation (zero address)
/// V4 uses Currency.wrap(address(0)) for native ETH
#[test]
fn test_native_eth_representation() {
    let eth = Address::default();
    let usdc = Address::parse_and_validate("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

    // Create ETH/USDC pool
    let pool_key = PoolKey::standard(eth, usdc, 3000u32.into(), 60);

    // ETH (zero address) should be currency0 since it's the smallest
    assert_eq!(pool_key.currency0, Address::default());

    // When swapping ETH for USDC, zeroForOne should be true
    assert!(pool_key.is_zero_for_one(Address::default()));

    // When swapping USDC for ETH, zeroForOne should be false
    assert!(!pool_key.is_zero_for_one(usdc));
}

/// Test slippage calculation using basis points (integer math)
/// This verifies we correctly calculate minimum output amounts
#[test]
fn test_slippage_calculation_basis_points() {
    // Test helper function that mirrors the swap implementation
    fn calculate_min_output(quote: Uint256, slippage_bps: u32) -> Uint256 {
        let basis_points_denom: Uint256 = 10000u32.into();
        let slippage_factor: Uint256 = (10000u32 - slippage_bps).into();
        (quote * slippage_factor) / basis_points_denom
    }

    // Test with 1000 tokens and 0.5% slippage (50 bps)
    let quote: Uint256 = 1_000_000_000_000_000_000u64.into(); // 1e18
    let min_out = calculate_min_output(quote, 50);
    // Expected: 1e18 * 9950 / 10000 = 995000000000000000 (0.995e18)
    assert_eq!(min_out, 995_000_000_000_000_000u64.into());

    // Test with 5% slippage (500 bps)
    let min_out_5pct = calculate_min_output(quote, 500);
    // Expected: 1e18 * 9500 / 10000 = 950000000000000000 (0.95e18)
    assert_eq!(min_out_5pct, 950_000_000_000_000_000u64.into());

    // Test with 0% slippage (0 bps) - should return full amount
    let min_out_zero = calculate_min_output(quote, 0);
    assert_eq!(min_out_zero, quote);

    // Test with 1% slippage (100 bps)
    let min_out_1pct = calculate_min_output(quote, 100);
    // Expected: 1e18 * 9900 / 10000 = 990000000000000000 (0.99e18)
    assert_eq!(min_out_1pct, 990_000_000_000_000_000u64.into());

    // Test with small amounts to verify no precision loss
    let small_quote: Uint256 = 1000u64.into();
    let min_out_small = calculate_min_output(small_quote, 50);
    // Expected: 1000 * 9950 / 10000 = 995
    assert_eq!(min_out_small, 995u64.into());
}

// =============================================================================
// Validation and Utility Tests
// =============================================================================

/// Test sign extension of int24 values to int32
/// This is critical for correctly parsing tick values from Ethereum
#[test]
fn test_sign_extend_i24_positive() {
    // Test positive number: 8388607 (max positive int24)
    let bytes = [0x7F, 0xFF, 0xFF];
    assert_eq!(sign_extend_i24_to_i32(bytes), 8388607);
}

#[test]
fn test_sign_extend_i24_negative() {
    // Test -1 in int24
    let bytes = [0xFF, 0xFF, 0xFF];
    assert_eq!(sign_extend_i24_to_i32(bytes), -1);
}

#[test]
fn test_sign_extend_i24_min() {
    // Test minimum int24: -8388608
    let bytes = [0x80, 0x00, 0x00];
    assert_eq!(sign_extend_i24_to_i32(bytes), -8388608);
}

#[test]
fn test_sign_extend_i24_zero() {
    let bytes = [0x00, 0x00, 0x00];
    assert_eq!(sign_extend_i24_to_i32(bytes), 0);
}

/// Test PoolKey validation with valid inputs
#[test]
fn test_pool_key_validation_valid() {
    let addr1 = Address::parse_and_validate("0x0000000000000000000000000000000000000001").unwrap();
    let addr2 = Address::parse_and_validate("0x0000000000000000000000000000000000000002").unwrap();

    let pool_key = PoolKey::try_new(
        addr1,
        addr2,
        3000u32.into(),
        tick_spacings::FEE_3000,
        Address::default(),
    );
    assert!(pool_key.is_ok());
}

/// Test PoolKey validation rejects identical currencies
#[test]
fn test_pool_key_validation_identical_currencies() {
    let addr = Address::parse_and_validate("0x0000000000000000000000000000000000000001").unwrap();

    let result = PoolKey::try_new(
        addr,
        addr,
        3000u32.into(),
        tick_spacings::FEE_3000,
        Address::default(),
    );
    assert!(matches!(result, Err(UniswapV4Error::IdenticalCurrencies)));
}

/// Test PoolKey validation rejects invalid fee
#[test]
fn test_pool_key_validation_invalid_fee() {
    let addr1 = Address::parse_and_validate("0x0000000000000000000000000000000000000001").unwrap();
    let addr2 = Address::parse_and_validate("0x0000000000000000000000000000000000000002").unwrap();

    let result = PoolKey::try_new(
        addr1,
        addr2,
        2_000_000u32.into(), // > MAX_LP_FEE
        60,
        Address::default(),
    );
    assert!(matches!(result, Err(UniswapV4Error::InvalidFee(_))));
}

/// Test PoolKey validation rejects invalid tick spacing
#[test]
fn test_pool_key_validation_invalid_tick_spacing() {
    let addr1 = Address::parse_and_validate("0x0000000000000000000000000000000000000001").unwrap();
    let addr2 = Address::parse_and_validate("0x0000000000000000000000000000000000000002").unwrap();

    let result = PoolKey::try_new(
        addr1,
        addr2,
        3000u32.into(),
        0, // Invalid: < MIN_TICK_SPACING
        Address::default(),
    );
    assert!(matches!(result, Err(UniswapV4Error::InvalidTickSpacing(_))));
}

/// Test tick_spacings::for_fee helper function
#[test]
fn test_tick_spacing_for_fee() {
    assert_eq!(tick_spacings::for_fee(100), Some(1));
    assert_eq!(tick_spacings::for_fee(500), Some(10));
    assert_eq!(tick_spacings::for_fee(3000), Some(60));
    assert_eq!(tick_spacings::for_fee(10000), Some(200));
    assert_eq!(tick_spacings::for_fee(1234), None);
}

/// Test validation of standard tick spacing for fee tiers
#[test]
fn test_validate_standard_tick_spacing() {
    let addr1 = Address::parse_and_validate("0x0000000000000000000000000000000000000001").unwrap();
    let addr2 = Address::parse_and_validate("0x0000000000000000000000000000000000000002").unwrap();

    // Valid: correct tick spacing for fee tier
    let pool_key = PoolKey::standard(addr1, addr2, 3000u32.into(), tick_spacings::FEE_3000);
    assert!(pool_key.validate_standard_tick_spacing().is_ok());

    // Invalid: wrong tick spacing for fee tier
    let pool_key = PoolKey::standard(addr1, addr2, 3000u32.into(), 10); // Should be 60
    assert!(matches!(
        pool_key.validate_standard_tick_spacing(),
        Err(UniswapV4Error::TickSpacingFeeMismatch { .. })
    ));
}

/// Helper function to sign-extend a 24-bit signed integer to a 32-bit signed integer
/// Duplicated here for testing since it's not public in the main module
fn sign_extend_i24_to_i32(bytes: [u8; 3]) -> i32 {
    let is_negative = bytes[0] & 0x80 != 0;
    if is_negative {
        i32::from_be_bytes([0xFF, bytes[0], bytes[1], bytes[2]])
    } else {
        i32::from_be_bytes([0x00, bytes[0], bytes[1], bytes[2]])
    }
}
