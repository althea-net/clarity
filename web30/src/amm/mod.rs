//! AMM (Automated Market Maker) interactions for Uniswap V2, V3, and V4
//!
//! This module provides functionality for interacting with various versions of Uniswap
//! decentralized exchanges on Ethereum and compatible networks.

mod uniswapv3;
mod uniswapv4;

#[cfg(test)]
mod uniswapv3_test;
#[cfg(test)]
mod uniswapv4_test;

// Re-export V2 constants
pub use uniswapv3::UNISWAP_V2_ROUTER_ADDRESS;

// Re-export V3 items
pub use uniswapv3::{
    decode_uniswap_v3_sqrt_price, scale_v3_uniswap_sqrt_price, uniswap_v3_sqrt_price_from_amounts,
    uniswap_v3_sqrt_price_from_price, DAI_CONTRACT_ADDRESS, DEFAULT_GAS_LIMIT_MULT,
    SUSDS_CONTRACT_ADDRESS, UNISWAP_STANDARD_POOL_FEES, UNISWAP_V3_FACTORY_ADDRESS,
    UNISWAP_V3_QUOTER_ADDRESS, UNISWAP_V3_ROUTER_ADDRESS, USDC_CONTRACT_ADDRESS,
    USDS_CONTRACT_ADDRESS, USDT_CONTRACT_ADDRESS, WETH_CONTRACT_ADDRESS,
};

// Re-export V4 items
pub use uniswapv4::{
    tick_spacings, ExactInputSingleParams, ExactOutputSingleParams, PoolKey, UniswapV4Error,
    UniversalRouterCommand, V4RouterAction, DYNAMIC_FEE_FLAG, MAX_LP_FEE, MAX_TICK,
    MAX_TICK_SPACING, MIN_TICK, MIN_TICK_SPACING, PERMIT2_ADDRESS, UNISWAP_V4_POOL_MANAGER_ADDRESS,
    UNISWAP_V4_POSITION_MANAGER_ADDRESS, UNISWAP_V4_QUOTER_ADDRESS, UNISWAP_V4_STATE_VIEW_ADDRESS,
    UNISWAP_V4_UNIVERSAL_ROUTER_ADDRESS,
};
