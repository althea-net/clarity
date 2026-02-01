//! Uniswap V4 AMM interactions
//!
//! This module provides functionality for interacting with Uniswap V4's singleton PoolManager
//! architecture. Key differences from V3:
//!
//! - **Singleton Design**: All pools are managed by a single PoolManager contract
//! - **Flash Accounting**: Uses EIP-1153 transient storage for efficient balance tracking
//! - **Hooks**: Customizable logic that can be attached to pool lifecycle events
//! - **Native ETH**: Direct support for native ETH without WETH wrapping
//! - **Dynamic Fees**: Pools can adjust fees dynamically
//!
//! Swaps are performed through the Universal Router which handles the complexity of
//! interacting with the PoolManager.

use crate::types::TransactionRequest;
use crate::{client::Web3, jsonrpc::error::Web3Error, types::SendTxOption};
use clarity::utils::display_uint256_as_address;
use clarity::{
    abi::{encode_call, encode_tokens, AbiToken},
    constants::tt256m1,
    Address, Int256, PrivateKey, Uint256,
};
use std::time::Duration;
use tokio::time::timeout as future_timeout;

use super::uniswapv3::{options_contains_glm, DEFAULT_GAS_LIMIT_MULT};

/// Minimum valid tick value for Uniswap V4 pools
pub const MIN_TICK: i32 = -887272;
/// Maximum valid tick value for Uniswap V4 pools
pub const MAX_TICK: i32 = 887272;
/// Minimum valid tick spacing
pub const MIN_TICK_SPACING: i32 = 1;
/// Maximum valid tick spacing
pub const MAX_TICK_SPACING: i32 = 16383;

lazy_static! {
    /// Uniswap V4 PoolManager singleton contract address on Ethereum mainnet
    /// All V4 pools are managed by this single contract
    pub static ref UNISWAP_V4_POOL_MANAGER_ADDRESS: Address =
        Address::parse_and_validate("0x000000000004444c5dc75cB358380D2e3dE08A90").unwrap();

    /// Uniswap V4 Universal Router address on Ethereum mainnet
    /// This is the recommended entry point for executing swaps
    pub static ref UNISWAP_V4_UNIVERSAL_ROUTER_ADDRESS: Address =
        Address::parse_and_validate("0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af").unwrap();

    /// Uniswap V4 Quoter contract address on Ethereum mainnet
    /// Used for simulating swaps and getting price quotes
    pub static ref UNISWAP_V4_QUOTER_ADDRESS: Address =
        Address::parse_and_validate("0x52F0E24D1c21C8A0cB1e5a5dD6198556BD9E1203").unwrap();

    /// Uniswap V4 Position Manager address on Ethereum mainnet
    pub static ref UNISWAP_V4_POSITION_MANAGER_ADDRESS: Address =
        Address::parse_and_validate("0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e").unwrap();

    /// Uniswap V4 StateView contract address on Ethereum mainnet
    pub static ref UNISWAP_V4_STATE_VIEW_ADDRESS: Address =
        Address::parse_and_validate("0x7fFE42C4a5DEeA5b0feC41C94C136Cf115597227").unwrap();

    /// Permit2 contract address (same across all chains)
    /// Used for token approvals with enhanced safety features
    pub static ref PERMIT2_ADDRESS: Address =
        Address::parse_and_validate("0x000000000022D473030F116dDEE9F6B43aC78BA3").unwrap();
}
/// Universal Router command types for V4 swaps
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalRouterCommand {
    /// Execute a V4 swap operation
    V4Swap = 0x10,
    /// Permit2 permit operation
    Permit2Permit = 0x0a,
    /// Wrap ETH to WETH
    WrapEth = 0x0b,
    /// Unwrap WETH to ETH  
    UnwrapWeth = 0x0c,
    /// Sweep tokens to recipient
    Sweep = 0x04,
    /// Pay a portion of the contract's balance
    PayPortion = 0x06,
}

/// V4 Router action types used within a V4_SWAP command
/// Values from: https://docs.uniswap.org/contracts/v4/reference/periphery/libraries/Actions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4RouterAction {
    /// Increase liquidity on a position
    IncreaseLiquidity = 0x00,
    /// Decrease liquidity on a position
    DecreaseLiquidity = 0x01,
    /// Mint a new position
    MintPosition = 0x02,
    /// Burn an existing position
    BurnPosition = 0x03,
    /// Increase liquidity from deltas
    IncreaseLiquidityFromDeltas = 0x04,
    /// Mint position from deltas
    MintPositionFromDeltas = 0x05,
    /// Swap exact amount of input tokens for output tokens using a single pool
    SwapExactInSingle = 0x06,
    /// Swap exact amount of input tokens for output tokens using multiple pools
    SwapExactIn = 0x07,
    /// Swap input tokens for exact amount of output tokens using a single pool
    SwapExactOutSingle = 0x08,
    /// Swap input tokens for exact amount of output tokens using multiple pools
    SwapExactOut = 0x09,
    /// Donate to the pool
    Donate = 0x0a,
    /// Settle specific amount
    Settle = 0x0b,
    /// Settle all tokens owed to the pool
    SettleAll = 0x0c,
    /// Settle a pair of currencies
    SettlePair = 0x0d,
    /// Take specific amount
    Take = 0x0e,
    /// Take all tokens owed from the pool
    TakeAll = 0x0f,
    /// Take a portion of tokens
    TakePortion = 0x10,
    /// Take a pair of currencies
    TakePair = 0x11,
    /// Close a currency position
    CloseCurrency = 0x12,
    /// Clear or take tokens
    ClearOrTake = 0x13,
    /// Sweep tokens to recipient
    Sweep = 0x14,
    /// Wrap native token
    Wrap = 0x15,
    /// Unwrap wrapped native token
    Unwrap = 0x16,
}

/// PoolKey struct that identifies a V4 pool
/// In V4, pools are identified by this struct rather than a contract address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolKey {
    /// The lower currency of the pool, sorted numerically
    /// For native ETH, use Address::default() (zero address)
    pub currency0: Address,
    /// The higher currency of the pool, sorted numerically
    pub currency1: Address,
    /// The pool LP fee, capped at 1_000_000 (100%)
    /// If the highest bit is 1, the pool has a dynamic fee
    pub fee: Uint256,
    /// Ticks that involve positions must be a multiple of tick spacing
    pub tick_spacing: i32,
    /// The hooks contract address (zero address if no hooks)
    pub hooks: Address,
}

impl PoolKey {
    /// Create a new PoolKey
    ///
    /// Note: currencies will be automatically sorted so currency0 < currency1
    ///
    /// # Panics
    /// This function does not validate inputs. Use `try_new` for validated construction.
    pub fn new(
        token_a: Address,
        token_b: Address,
        fee: Uint256,
        tick_spacing: i32,
        hooks: Address,
    ) -> Self {
        let (currency0, currency1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        Self {
            currency0,
            currency1,
            fee,
            tick_spacing,
            hooks,
        }
    }

    /// Create a new PoolKey with validation
    ///
    /// Validates:
    /// - Currencies are not identical
    /// - Fee is valid (either dynamic flag or <= MAX_LP_FEE)
    /// - Tick spacing is within valid range [1, 16383]
    ///
    /// Note: currencies will be automatically sorted so currency0 < currency1
    pub fn try_new(
        token_a: Address,
        token_b: Address,
        fee: Uint256,
        tick_spacing: i32,
        hooks: Address,
    ) -> Result<Self, UniswapV4Error> {
        // Check currencies are not identical
        if token_a == token_b {
            return Err(UniswapV4Error::IdenticalCurrencies);
        }

        // Validate fee
        let fee_u32: u32 = fee.to_string().parse().unwrap_or(u32::MAX);
        if fee_u32 != DYNAMIC_FEE_FLAG && fee_u32 > MAX_LP_FEE {
            return Err(UniswapV4Error::InvalidFee(fee_u32));
        }

        // Validate tick spacing
        if tick_spacing < MIN_TICK_SPACING || tick_spacing > MAX_TICK_SPACING {
            return Err(UniswapV4Error::InvalidTickSpacing(tick_spacing));
        }

        let (currency0, currency1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        Ok(Self {
            currency0,
            currency1,
            fee,
            tick_spacing,
            hooks,
        })
    }

    /// Create a PoolKey for a standard pool without hooks
    pub fn standard(token_a: Address, token_b: Address, fee: Uint256, tick_spacing: i32) -> Self {
        Self::new(token_a, token_b, fee, tick_spacing, Address::default())
    }

    /// Create a PoolKey for a standard pool without hooks, with validation
    pub fn try_standard(
        token_a: Address,
        token_b: Address,
        fee: Uint256,
        tick_spacing: i32,
    ) -> Result<Self, UniswapV4Error> {
        Self::try_new(token_a, token_b, fee, tick_spacing, Address::default())
    }

    /// Check if this is a swap from currency0 to currency1
    pub fn is_zero_for_one(&self, token_in: Address) -> bool {
        token_in == self.currency0
    }

    /// Check if this pool uses dynamic fees
    pub fn is_dynamic_fee(&self) -> bool {
        // Dynamic fee pools have the highest bit of fee set (0x800000)
        let fee_u32: u32 = self.fee.to_string().parse().unwrap_or(0);
        fee_u32 == DYNAMIC_FEE_FLAG
    }

    /// Create a PoolKey for a dynamic fee pool
    /// Dynamic fee pools must have fee set to exactly 0x800000
    pub fn dynamic_fee(
        token_a: Address,
        token_b: Address,
        tick_spacing: i32,
        hooks: Address,
    ) -> Self {
        Self::new(
            token_a,
            token_b,
            DYNAMIC_FEE_FLAG.into(),
            tick_spacing,
            hooks,
        )
    }

    /// Get the actual fee in pips (basis points * 100)
    /// For dynamic fee pools, this returns 0 as the fee is determined by hooks
    pub fn get_fee_pips(&self) -> u32 {
        if self.is_dynamic_fee() {
            0
        } else {
            self.fee.to_string().parse().unwrap_or(0)
        }
    }

    /// Validate the fee value
    /// Returns true if fee is valid (either dynamic flag or <= MAX_LP_FEE)
    pub fn is_valid_fee(&self) -> bool {
        let fee_u32: u32 = self.fee.to_string().parse().unwrap_or(u32::MAX);
        fee_u32 == DYNAMIC_FEE_FLAG || fee_u32 <= MAX_LP_FEE
    }

    /// Validate the tick spacing value
    /// Returns true if tick spacing is within valid range [1, 16383]
    pub fn is_valid_tick_spacing(&self) -> bool {
        self.tick_spacing >= MIN_TICK_SPACING && self.tick_spacing <= MAX_TICK_SPACING
    }

    /// Validate that the tick spacing matches the expected value for a standard fee tier
    /// Returns Ok(()) if valid, or an error describing the mismatch
    pub fn validate_standard_tick_spacing(&self) -> Result<(), UniswapV4Error> {
        if self.is_dynamic_fee() {
            // Dynamic fee pools can have any valid tick spacing
            return Ok(());
        }

        let fee_u32 = self.get_fee_pips();
        let expected = match fee_u32 {
            100 => Some(tick_spacings::FEE_100),
            500 => Some(tick_spacings::FEE_500),
            3000 => Some(tick_spacings::FEE_3000),
            10000 => Some(tick_spacings::FEE_10000),
            _ => None, // Non-standard fee tier, any valid tick spacing is acceptable
        };

        if let Some(expected_spacing) = expected {
            if self.tick_spacing != expected_spacing {
                return Err(UniswapV4Error::TickSpacingFeeMismatch {
                    fee: fee_u32,
                    tick_spacing: self.tick_spacing,
                    expected: expected_spacing,
                });
            }
        }

        Ok(())
    }

    /// Perform full validation of the PoolKey
    /// Checks fee, tick spacing, and tick spacing/fee tier consistency
    pub fn validate(&self) -> Result<(), UniswapV4Error> {
        // Check currencies are not identical
        if self.currency0 == self.currency1 {
            return Err(UniswapV4Error::IdenticalCurrencies);
        }

        // Validate fee
        if !self.is_valid_fee() {
            let fee_u32: u32 = self.fee.to_string().parse().unwrap_or(u32::MAX);
            return Err(UniswapV4Error::InvalidFee(fee_u32));
        }

        // Validate tick spacing
        if !self.is_valid_tick_spacing() {
            return Err(UniswapV4Error::InvalidTickSpacing(self.tick_spacing));
        }

        // Validate tick spacing matches fee tier (for standard tiers)
        self.validate_standard_tick_spacing()?;

        Ok(())
    }

    /// Encode the PoolKey as ABI tokens for contract calls
    /// PoolKey: (Currency currency0, Currency currency1, uint24 fee, int24 tickSpacing, IHooks hooks)
    pub fn to_abi_token(&self) -> AbiToken {
        // Properly sign-extend tick_spacing from i32 to Int256
        let tick_spacing_i256 = Int256::from(self.tick_spacing);
        AbiToken::Struct(vec![
            AbiToken::Address(self.currency0),
            AbiToken::Address(self.currency1),
            AbiToken::Uint(self.fee), // uint24 is encoded as uint256 in ABI
            AbiToken::Int(tick_spacing_i256), // int24 is encoded as int256 in ABI with proper sign extension
            AbiToken::Address(self.hooks),
        ])
    }
}

/// Dynamic fee flag - when set as the fee, indicates the pool uses dynamic fees
/// Must be exactly 0x800000 for dynamic fee pools
pub const DYNAMIC_FEE_FLAG: u32 = 0x800000;

/// Maximum LP fee (100% = 1_000_000 pips)
pub const MAX_LP_FEE: u32 = 1_000_000;

/// Errors specific to Uniswap V4 operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UniswapV4Error {
    /// The fee value exceeds the maximum allowed (1_000_000)
    InvalidFee(u32),
    /// The tick spacing is out of valid range [1, 16383]
    InvalidTickSpacing(i32),
    /// The tick spacing does not match the expected value for the fee tier
    TickSpacingFeeMismatch {
        fee: u32,
        tick_spacing: i32,
        expected: i32,
    },
    /// Hook address has invalid flags for the specified hooks
    InvalidHookAddress(Address),
    /// The provided deadline is in the past
    DeadlineInPast {
        deadline: Uint256,
        current_time: Uint256,
    },
    /// The pool does not exist or has no liquidity
    PoolNotFound,
    /// Currency addresses are the same
    IdenticalCurrencies,
}

impl std::fmt::Display for UniswapV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UniswapV4Error::InvalidFee(fee) => {
                write!(f, "Invalid fee: {} exceeds maximum {}", fee, MAX_LP_FEE)
            }
            UniswapV4Error::InvalidTickSpacing(ts) => {
                write!(
                    f,
                    "Invalid tick spacing: {} (must be between {} and {})",
                    ts, MIN_TICK_SPACING, MAX_TICK_SPACING
                )
            }
            UniswapV4Error::TickSpacingFeeMismatch {
                fee,
                tick_spacing,
                expected,
            } => {
                write!(
                    f,
                    "Tick spacing {} does not match expected {} for fee tier {}",
                    tick_spacing, expected, fee
                )
            }
            UniswapV4Error::InvalidHookAddress(addr) => {
                write!(f, "Invalid hook address: {}", addr)
            }
            UniswapV4Error::DeadlineInPast {
                deadline,
                current_time,
            } => {
                write!(
                    f,
                    "Deadline {} is in the past (current time: {})",
                    deadline, current_time
                )
            }
            UniswapV4Error::PoolNotFound => {
                write!(f, "Pool does not exist or has no liquidity")
            }
            UniswapV4Error::IdenticalCurrencies => {
                write!(f, "Currency addresses cannot be identical")
            }
        }
    }
}

impl std::error::Error for UniswapV4Error {}

/// Parameters for an exact input single swap
/// Matches IV4Router.ExactInputSingleParams from the official interface
#[derive(Debug, Clone)]
pub struct ExactInputSingleParams {
    /// The pool key identifying the pool
    pub pool_key: PoolKey,
    /// True if swapping token0 for token1
    pub zero_for_one: bool,
    /// The amount of input tokens (uint128 in Solidity)
    pub amount_in: Uint256,
    /// The minimum amount of output tokens (uint128 in Solidity)
    pub amount_out_minimum: Uint256,
    /// Optional hook data
    pub hook_data: Vec<u8>,
}

impl ExactInputSingleParams {
    /// Encode the params as ABI tokens
    /// Matches: (PoolKey poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMinimum, bytes hookData)
    pub fn to_abi_token(&self) -> AbiToken {
        AbiToken::Struct(vec![
            self.pool_key.to_abi_token(),
            AbiToken::Bool(self.zero_for_one),
            AbiToken::Uint(self.amount_in),
            AbiToken::Uint(self.amount_out_minimum),
            AbiToken::UnboundedBytes(self.hook_data.clone()),
        ])
    }
}

/// Parameters for an exact output single swap
/// Matches IV4Router.ExactOutputSingleParams from the official interface
#[derive(Debug, Clone)]
pub struct ExactOutputSingleParams {
    /// The pool key identifying the pool
    pub pool_key: PoolKey,
    /// True if swapping token0 for token1
    pub zero_for_one: bool,
    /// The exact amount of output tokens desired (uint128 in Solidity)
    pub amount_out: Uint256,
    /// The maximum amount of input tokens willing to spend (uint128 in Solidity)
    pub amount_in_maximum: Uint256,
    /// Optional hook data
    pub hook_data: Vec<u8>,
}

impl ExactOutputSingleParams {
    /// Encode the params as ABI tokens
    pub fn to_abi_token(&self) -> AbiToken {
        AbiToken::Struct(vec![
            self.pool_key.to_abi_token(),
            AbiToken::Bool(self.zero_for_one),
            AbiToken::Uint(self.amount_out),
            AbiToken::Uint(self.amount_in_maximum),
            AbiToken::UnboundedBytes(self.hook_data.clone()),
        ])
    }
}

impl Web3 {
    /// Get a price quote from Uniswap V4 for swapping tokens
    ///
    /// This method simulates a swap using the V4 Quoter contract to get the expected output amount.
    /// It does not actually execute any swap.
    ///
    /// # Arguments
    /// * `caller_address` - The address simulating the swap
    /// * `pool_key` - The PoolKey identifying the V4 pool
    /// * `zero_for_one` - True if swapping currency0 for currency1
    /// * `amount_in` - The amount of input tokens
    /// * `sqrt_price_limit_x96` - Optional price limit (0 for no limit)
    /// * `quoter` - Optional quoter address, defaults to mainnet quoter
    ///
    /// # Returns
    /// The expected amount of output tokens
    #[allow(clippy::too_many_arguments)]
    pub async fn get_uniswap_v4_quote(
        &self,
        caller_address: Address,
        pool_key: &PoolKey,
        zero_for_one: bool,
        amount_in: Uint256,
        sqrt_price_limit_x96: Option<Uint256>,
        quoter: Option<Address>,
    ) -> Result<Uint256, Web3Error> {
        let quoter = quoter.unwrap_or(*UNISWAP_V4_QUOTER_ADDRESS);
        let sqrt_price_limit = sqrt_price_limit_x96.unwrap_or_default();

        // QuoteExactInputSingle struct for the quoter
        let params = AbiToken::Struct(vec![
            pool_key.to_abi_token(),
            AbiToken::Bool(zero_for_one),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(sqrt_price_limit),
            AbiToken::Bytes(vec![]), // hookData
        ]);

        let payload = encode_call("quoteExactInputSingle((((address,address,uint24,int24,address),bool,uint128,uint160,bytes)))", &[params])?;

        let result = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, quoter, payload),
                vec![],
                None,
            )
            .await?;

        if result.len() < 32 {
            return Err(Web3Error::BadResponse(
                "Invalid quote response from V4 Quoter".to_string(),
            ));
        }

        // The quoter returns (int128 deltaAmounts, uint160 sqrtPriceX96After, uint32 initializedTicksLoaded)
        // deltaAmounts[1] contains the output amount (negative for tokens going out)
        let amount_out = Uint256::from_be_bytes(&result[0..32]);
        Ok(amount_out)
    }

    /// Execute a swap on Uniswap V4 using the Universal Router
    ///
    /// This method performs an exact input single swap, exchanging a specific amount of
    /// input tokens for as many output tokens as possible.
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the swapper
    /// * `pool_key` - The PoolKey identifying the V4 pool
    /// * `token_in` - The input token address
    /// * `amount_in` - The amount of input tokens to swap
    /// * `amount_out_min` - The minimum acceptable output amount
    /// * `deadline` - Optional deadline timestamp, defaults to 10 minutes from now
    /// * `universal_router` - Optional router address
    /// * `options` - Optional transaction options
    /// * `wait_timeout` - Optional timeout to wait for confirmation
    ///
    /// # Returns
    /// The transaction hash
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap_v4(
        &self,
        eth_private_key: PrivateKey,
        pool_key: &PoolKey,
        token_in: Address,
        amount_in: Uint256,
        amount_out_min: Uint256,
        deadline: Option<Uint256>,
        universal_router: Option<Address>,
        options: Option<Vec<SendTxOption>>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        let router = universal_router.unwrap_or(*UNISWAP_V4_UNIVERSAL_ROUTER_ADDRESS);
        let eth_address = eth_private_key.to_address();
        let zero_for_one = pool_key.is_zero_for_one(token_in);

        // Calculate deadline with validation
        let current_block = self.eth_get_latest_block().await?;
        let current_time = current_block.timestamp;
        let deadline = match deadline {
            None => current_time + (10u64 * 60u64).into(),
            Some(val) => {
                // Validate that deadline is in the future
                if val <= current_time {
                    return Err(Web3Error::BadInput(format!(
                        "Deadline {} is in the past (current time: {})",
                        val, current_time
                    )));
                }
                val
            }
        };

        // Build the Universal Router execute payload
        // Command: V4_SWAP (0x10)
        let commands = vec![UniversalRouterCommand::V4Swap as u8];

        // Build V4 router actions
        let actions = vec![
            V4RouterAction::SwapExactInSingle as u8,
            V4RouterAction::SettleAll as u8,
            V4RouterAction::TakeAll as u8,
        ];

        // Encode the swap params (no sqrtPriceLimitX96 in V4's ExactInputSingleParams)
        let swap_params = ExactInputSingleParams {
            pool_key: pool_key.clone(),
            zero_for_one,
            amount_in,
            amount_out_minimum: amount_out_min,
            hook_data: vec![],
        };

        // Build the params array for each action
        let (currency_in, currency_out) = if zero_for_one {
            (pool_key.currency0, pool_key.currency1)
        } else {
            (pool_key.currency1, pool_key.currency0)
        };

        // Encode params for each action using raw ABI encoding (no function selector)
        // For SWAP_EXACT_IN_SINGLE: encode ExactInputSingleParams
        // Struct: (PoolKey, bool, uint128, uint128, bytes)
        let swap_param_bytes = encode_tokens(&[swap_params.to_abi_token()]);

        // For SETTLE_ALL: encode (currency, maxAmount)
        let settle_param_bytes =
            encode_tokens(&[AbiToken::Address(currency_in), AbiToken::Uint(amount_in)]);

        // For TAKE_ALL: encode (currency, minAmount)
        let take_param_bytes = encode_tokens(&[
            AbiToken::Address(currency_out),
            AbiToken::Uint(amount_out_min),
        ]);

        // Combine actions and params into the V4 swap input using raw encoding
        // Structure: (bytes actions, bytes[] params)
        let v4_input = encode_tokens(&[
            AbiToken::UnboundedBytes(actions),
            AbiToken::Dynamic(vec![
                AbiToken::UnboundedBytes(swap_param_bytes),
                AbiToken::UnboundedBytes(settle_param_bytes),
                AbiToken::UnboundedBytes(take_param_bytes),
            ]),
        ]);

        // Build the final Universal Router execute call
        // This is a proper function call so we use encode_call
        let payload = encode_call(
            "execute(bytes,bytes[],uint256)",
            &[
                AbiToken::UnboundedBytes(commands),
                AbiToken::Dynamic(vec![AbiToken::UnboundedBytes(v4_input)]),
                AbiToken::Uint(deadline),
            ],
        )?;

        // Set up options with gas limit multiplier
        let mut options = options.unwrap_or_default();
        if !options_contains_glm(&options) {
            options.push(SendTxOption::GasLimitMultiplier(DEFAULT_GAS_LIMIT_MULT));
        }

        // Check if we need token approval (for non-native tokens)
        // V4 uses Permit2 for approvals
        if token_in != Address::default() {
            // First approve Permit2 if needed
            let permit2_allowance = self
                .get_erc20_allowance(token_in, eth_address, *PERMIT2_ADDRESS, options.clone())
                .await?;

            if permit2_allowance < amount_in {
                debug!("Approving Permit2 for token_in");
                let nonce = self.eth_get_transaction_count(eth_address).await?;
                let _approval = self
                    .erc20_approve(
                        token_in,
                        tt256m1(), // max value (2^256 - 1)
                        eth_private_key,
                        *PERMIT2_ADDRESS,
                        wait_timeout,
                        options.clone(),
                    )
                    .await?;
                if wait_timeout.is_none() {
                    options.push(SendTxOption::Nonce(nonce + 1u8.into()));
                }
            }

            // Then approve the Universal Router via Permit2
            // This is a simplified approach - production should use Permit2 signatures
            let router_allowance = self
                .get_permit2_allowance(token_in, eth_address, router)
                .await?;

            if router_allowance < amount_in {
                debug!("Approving Universal Router via Permit2");
                let nonce = self.eth_get_transaction_count(eth_address).await?;
                let _approval = self
                    .permit2_approve(
                        token_in,
                        router,
                        amount_in,
                        eth_private_key,
                        wait_timeout,
                        options.clone(),
                    )
                    .await?;
                if wait_timeout.is_none() {
                    options.push(SendTxOption::Nonce(nonce + 1u8.into()));
                }
            }
        }

        // Determine ETH value to send (if swapping native ETH)
        let value = if token_in == Address::default() {
            amount_in
        } else {
            Uint256::from(0u8)
        };

        trace!("V4 swap payload: {:?}", payload);
        let tx = self
            .prepare_transaction(router, payload, value, eth_private_key, options)
            .await?;
        let txid = self.eth_send_raw_transaction(tx.to_bytes()).await?;
        debug!(
            "txid for uniswap v4 swap is {}",
            display_uint256_as_address(txid)
        );

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }

    /// Swap tokens on Uniswap V4 with automatic slippage handling
    ///
    /// This is a convenience method that first gets a quote and then executes
    /// the swap with the specified slippage tolerance.
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the swapper
    /// * `pool_key` - The PoolKey identifying the V4 pool
    /// * `token_in` - The input token address
    /// * `amount_in` - The amount of input tokens to swap
    /// * `slippage_bps` - Maximum slippage tolerance in basis points (e.g., 50 for 0.5%)
    ///                    If None, defaults to 50 bps (0.5%)
    /// * `deadline` - Optional deadline timestamp
    /// * `universal_router` - Optional router address
    /// * `options` - Optional transaction options
    /// * `wait_timeout` - Optional timeout to wait for confirmation
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap_v4_with_slippage(
        &self,
        eth_private_key: PrivateKey,
        pool_key: &PoolKey,
        token_in: Address,
        amount_in: Uint256,
        slippage_bps: Option<u32>,
        deadline: Option<Uint256>,
        universal_router: Option<Address>,
        options: Option<Vec<SendTxOption>>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        // Default to 50 basis points (0.5%) slippage
        let slippage_bps = slippage_bps.unwrap_or(50);
        let caller_address = eth_private_key.to_address();
        let zero_for_one = pool_key.is_zero_for_one(token_in);

        // Get a quote first
        let quote = self
            .get_uniswap_v4_quote(
                caller_address,
                pool_key,
                zero_for_one,
                amount_in,
                None,
                None,
            )
            .await?;

        // Calculate minimum output with slippage using integer math
        // amount_out_min = quote * (10000 - slippage_bps) / 10000
        let basis_points_denom: Uint256 = 10000u32.into();
        let slippage_factor: Uint256 = (10000u32 - slippage_bps).into();
        let amount_out_min = (quote * slippage_factor) / basis_points_denom;

        self.swap_uniswap_v4(
            eth_private_key,
            pool_key,
            token_in,
            amount_in,
            amount_out_min,
            deadline,
            universal_router,
            options,
            wait_timeout,
        )
        .await
    }

    /// Swap native ETH for tokens on Uniswap V4
    ///
    /// V4 natively supports ETH without needing to wrap to WETH first.
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the swapper
    /// * `token_out` - The output token address
    /// * `fee` - The pool fee
    /// * `tick_spacing` - The pool tick spacing
    /// * `amount_in` - The amount of ETH to swap
    /// * `amount_out_min` - The minimum acceptable output amount
    /// * `deadline` - Optional deadline timestamp
    /// * `options` - Optional transaction options
    /// * `wait_timeout` - Optional timeout to wait for confirmation
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap_v4_eth_in(
        &self,
        eth_private_key: PrivateKey,
        token_out: Address,
        fee: Uint256,
        tick_spacing: i32,
        amount_in: Uint256,
        amount_out_min: Uint256,
        deadline: Option<Uint256>,
        options: Option<Vec<SendTxOption>>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        // Use zero address to represent native ETH
        let pool_key = PoolKey::standard(Address::default(), token_out, fee, tick_spacing);

        self.swap_uniswap_v4(
            eth_private_key,
            &pool_key,
            Address::default(), // ETH
            amount_in,
            amount_out_min,
            deadline,
            None,
            options,
            wait_timeout,
        )
        .await
    }

    /// Swap native ETH for tokens on Uniswap V4 with automatic slippage handling
    ///
    /// V4 natively supports ETH without needing to wrap to WETH first.
    /// This method first gets a quote and applies slippage tolerance.
    ///
    /// # Arguments
    /// * `eth_private_key` - The private key of the swapper
    /// * `token_out` - The output token address
    /// * `fee` - The pool fee
    /// * `tick_spacing` - The pool tick spacing
    /// * `amount_in` - The amount of ETH to swap
    /// * `slippage_bps` - Maximum slippage tolerance in basis points (e.g., 50 for 0.5%)
    ///                    If None, defaults to 50 bps (0.5%)
    /// * `deadline` - Optional deadline timestamp
    /// * `options` - Optional transaction options
    /// * `wait_timeout` - Optional timeout to wait for confirmation
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_uniswap_v4_eth_in_with_slippage(
        &self,
        eth_private_key: PrivateKey,
        token_out: Address,
        fee: Uint256,
        tick_spacing: i32,
        amount_in: Uint256,
        slippage_bps: Option<u32>,
        deadline: Option<Uint256>,
        options: Option<Vec<SendTxOption>>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        // Use zero address to represent native ETH
        let pool_key = PoolKey::standard(Address::default(), token_out, fee, tick_spacing);

        self.swap_uniswap_v4_with_slippage(
            eth_private_key,
            &pool_key,
            Address::default(), // ETH
            amount_in,
            slippage_bps,
            deadline,
            None,
            options,
            wait_timeout,
        )
        .await
    }

    /// Get the Permit2 allowance for a token
    pub async fn get_permit2_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call(
            "allowance(address,address,address)",
            &[
                AbiToken::Address(owner),
                AbiToken::Address(token),
                AbiToken::Address(spender),
            ],
        )?;

        let result = self
            .simulate_transaction(
                TransactionRequest::quick_tx(owner, *PERMIT2_ADDRESS, payload),
                vec![],
                None,
            )
            .await?;

        if result.len() < 32 {
            return Ok(Uint256::from(0u8));
        }

        // Permit2 allowance returns (uint160 amount, uint48 expiration, uint48 nonce)
        // We only care about the amount which is the first 20 bytes of the first 32 bytes
        let amount = Uint256::from_be_bytes(&result[12..32]); // uint160
        Ok(amount)
    }

    /// Approve a spender via Permit2
    pub async fn permit2_approve(
        &self,
        token: Address,
        spender: Address,
        amount: Uint256,
        eth_private_key: PrivateKey,
        wait_timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        // Use max expiration for simplicity
        let expiration: Uint256 = Uint256::from(u64::MAX);

        let payload = encode_call(
            "approve(address,address,uint160,uint48)",
            &[
                AbiToken::Address(token),
                AbiToken::Address(spender),
                AbiToken::Uint(amount),
                AbiToken::Uint(expiration),
            ],
        )?;

        let tx = self
            .prepare_transaction(
                *PERMIT2_ADDRESS,
                payload,
                0u8.into(),
                eth_private_key,
                options,
            )
            .await?;
        let txid = self.eth_send_raw_transaction(tx.to_bytes()).await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }

    /// Get pool state from Uniswap V4 StateView
    ///
    /// Returns the current sqrtPriceX96 and tick for a pool
    pub async fn get_uniswap_v4_pool_state(
        &self,
        caller_address: Address,
        pool_key: &PoolKey,
        state_view: Option<Address>,
    ) -> Result<(Uint256, i32), Web3Error> {
        let state_view = state_view.unwrap_or(*UNISWAP_V4_STATE_VIEW_ADDRESS);

        let payload = encode_call(
            "getSlot0((address,address,uint24,int24,address))",
            &[pool_key.to_abi_token()],
        )?;

        let result = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, state_view, payload),
                vec![],
                None,
            )
            .await?;

        if result.len() < 64 {
            return Err(Web3Error::BadResponse(
                "Invalid state response from V4 StateView".to_string(),
            ));
        }

        // Returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)
        let sqrt_price = Uint256::from_be_bytes(&result[12..32]); // uint160

        // Parse int24 tick with proper sign extension
        // int24 is stored in the last 3 bytes of a 32-byte slot
        // We need to sign-extend from 24 bits to 32 bits
        let tick_bytes = &result[32..64];
        let raw_tick_bytes = [tick_bytes[29], tick_bytes[30], tick_bytes[31]];
        let tick = sign_extend_i24_to_i32(raw_tick_bytes);

        Ok((sqrt_price, tick))
    }

    /// Check if a Uniswap V4 pool exists and has liquidity
    ///
    /// Returns Ok(true) if the pool exists and has non-zero liquidity,
    /// Ok(false) if the pool doesn't exist or has no liquidity.
    pub async fn uniswap_v4_pool_exists(
        &self,
        caller_address: Address,
        pool_key: &PoolKey,
        state_view: Option<Address>,
    ) -> Result<bool, Web3Error> {
        match self
            .get_uniswap_v4_pool_state(caller_address, pool_key, state_view)
            .await
        {
            Ok((sqrt_price, _)) => {
                // A pool exists if sqrtPriceX96 is non-zero
                Ok(sqrt_price > Uint256::from(0u8))
            }
            Err(_) => Ok(false),
        }
    }
}

/// Sign-extend a 24-bit signed integer to a 32-bit signed integer
///
/// This is necessary because int24 values from Ethereum are stored in 3 bytes
/// and need proper sign extension when converted to i32.
fn sign_extend_i24_to_i32(bytes: [u8; 3]) -> i32 {
    // Check if the sign bit (bit 23) is set
    let is_negative = bytes[0] & 0x80 != 0;

    if is_negative {
        // Sign extend with 0xFF for negative numbers
        i32::from_be_bytes([0xFF, bytes[0], bytes[1], bytes[2]])
    } else {
        // Positive number, just zero extend
        i32::from_be_bytes([0x00, bytes[0], bytes[1], bytes[2]])
    }
}

/// Standard tick spacings for different fee tiers
pub mod tick_spacings {
    /// 0.01% fee tier tick spacing
    pub const FEE_100: i32 = 1;
    /// 0.05% fee tier tick spacing (stable pairs)
    pub const FEE_500: i32 = 10;
    /// 0.3% fee tier tick spacing (most pairs)
    pub const FEE_3000: i32 = 60;
    /// 1% fee tier tick spacing (exotic pairs)
    pub const FEE_10000: i32 = 200;

    /// Get the expected tick spacing for a standard fee tier
    /// Returns None for non-standard fee tiers
    pub fn for_fee(fee_pips: u32) -> Option<i32> {
        match fee_pips {
            100 => Some(FEE_100),
            500 => Some(FEE_500),
            3000 => Some(FEE_3000),
            10000 => Some(FEE_10000),
            _ => None,
        }
    }

    /// Check if a tick spacing is valid for a given fee tier
    /// Returns true if the tick spacing matches the expected value for the fee,
    /// or if the fee is non-standard (any valid tick spacing is acceptable)
    pub fn is_valid_for_fee(fee_pips: u32, tick_spacing: i32) -> bool {
        match for_fee(fee_pips) {
            Some(expected) => tick_spacing == expected,
            None => {
                tick_spacing >= super::MIN_TICK_SPACING && tick_spacing <= super::MAX_TICK_SPACING
            }
        }
    }
}
