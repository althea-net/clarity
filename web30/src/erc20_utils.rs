//! This module contains utility functions for interacting with ERC20 tokens and contracts
use crate::jsonrpc::error::Web3Error;
use crate::{client::Web3, types::SendTxOption};
use clarity::{abi::encode_call, PrivateKey as EthPrivateKey};
use clarity::{Address, Uint256};
use num_traits::Bounded;
use std::time::Duration;
use tokio::time::timeout as future_timeout;

pub static ERC20_GAS_LIMIT: u128 = 100_000;

impl Web3 {
    /// Checks if any given contract is approved to spend money from any given erc20 contract
    /// using any given address. What exactly this does can be hard to grok, essentially when
    /// you want contract A to be able to spend your erc20 contract funds you need to call 'approve'
    /// on the ERC20 contract with your own address and A's address so that in the future when you call
    /// contract A it can manipulate your ERC20 balances. This function checks if that has already been done.
    pub async fn check_erc20_approved(
        &self,
        erc20: Address,
        own_address: Address,
        target_contract: Address,
    ) -> Result<bool, Web3Error> {
        let payload = encode_call(
            "allowance(address,address)",
            &[own_address.into(), target_contract.into()],
        )?;
        let allowance = self
            .simulate_transaction(erc20, 0u8.into(), payload, own_address, None)
            .await?;

        let allowance = Uint256::from_be_bytes(match allowance.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "erc20 allowance(address, address) failed".to_string(),
                ))
            }
        });

        // Check if the allowance remaining is greater than half of a Uint256- it's as good
        // a test as any.
        Ok(allowance > (Uint256::max_value() / 2u32.into()))
    }

    /// Approves a given contract to spend erc20 funds from the given address from the erc20 contract provided.
    /// What exactly this does can be hard to grok, essentially when you want contract A to be able to spend
    /// your erc20 contract funds you need to call 'approve' on the ERC20 contract with your own address and A's
    /// address so that in the future when you call contract A it can manipulate your ERC20 balances.
    /// This function performs that action and waits for it to complete for up to Timeout duration
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    pub async fn approve_erc20_transfers(
        &self,
        erc20: Address,
        eth_private_key: EthPrivateKey,
        target_contract: Address,
        timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call(
            "approve(address,uint256)",
            &[target_contract.into(), Uint256::max_value().into()],
        )?;

        let txid = self
            .send_transaction(erc20, payload, 0u32.into(), eth_private_key, options)
            .await?;

        // wait for transaction to enter the chain if the user has requested it
        if let Some(timeout) = timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }

    /// Send an erc20 token to the target address, optionally wait until it enters the blockchain
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    /// WARNING: you must specify networkID in situations where a single
    /// node is operating no more than one chain. Otherwise it is possible
    /// for the full node to trick the client into signing transactions
    /// on unintended chains potentially to their benefit
    pub async fn erc20_send(
        &self,
        amount: Uint256,
        recipient: Address,
        erc20: Address,
        sender_private_key: EthPrivateKey,
        wait_timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        // if the user sets a gas limit we should honor it, if they don't we
        // should add the default
        let mut has_gas_limit = false;
        let mut options = options;
        for option in options.iter() {
            if let SendTxOption::GasLimit(_) = option {
                has_gas_limit = true;
                break;
            }
        }
        if !has_gas_limit {
            options.push(SendTxOption::GasLimit(ERC20_GAS_LIMIT.into()));
        }

        let tx_hash = self
            .send_transaction(
                erc20,
                encode_call(
                    "transfer(address,uint256)",
                    &[recipient.into(), amount.into()],
                )?,
                0u32.into(),
                sender_private_key,
                options,
            )
            .await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(tx_hash, timeout, None)).await??;
        }

        Ok(tx_hash)
    }

    /// Queries the `target_address`'s current balance of `erc20`
    ///
    /// See get_erc20_balance_at_height and get_erc20_balance_as_address if you need more
    /// flexibility including historical balances and balances of targets which hold very little ETH
    pub async fn get_erc20_balance(
        &self,
        erc20: Address,
        target_address: Address,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height(erc20, target_address, None)
            .await
    }

    /// Queries the `target_address`'s balance of `erc20` at an optional ethereum `height`
    ///
    /// The latest balance from the current block will be queried if `height` is None
    pub async fn get_erc20_balance_at_height(
        &self,
        erc20: Address,
        target_address: Address,
        height: Option<Uint256>,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height_as_address(None, erc20, target_address, height)
            .await
    }

    /// Queries the `target_address`'s balance of `erc20` using `requester_address` as the
    /// transaction's `from` field
    ///
    /// The `target_address` will be used as `from` if `requester_address` is None
    ///
    /// This is particularly useful if the ERC20 holder has too little ETH for gas fees, e.g. Gravity.sol
    pub async fn get_erc20_balance_as_address(
        &self,
        requester_address: Option<Address>,
        erc20: Address,
        target_address: Address,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height_as_address(requester_address, erc20, target_address, None)
            .await
    }

    /// Queries the `target_address`'s balance of `erc20` at an optional ethereum `height`, using
    /// `requester_address` as the transaction's `from` field
    ///
    /// The `target_address` will be used as `from` if `requester_address` is None
    /// The latest balance from the current block will be queried if `height` is None
    ///
    /// This is particularly useful if the ERC20 holder had too little ETH for gas fees, e.g. Gravity.sol
    pub async fn get_erc20_balance_at_height_as_address(
        &self,
        requester_address: Option<Address>,
        erc20: Address,
        target_address: Address,
        height: Option<Uint256>,
    ) -> Result<Uint256, Web3Error> {
        let requester_address = requester_address.unwrap_or(target_address);
        let payload = encode_call("balanceOf(address)", &[target_address.into()])?;
        let balance = self
            .simulate_transaction(erc20, 0u8.into(), payload, requester_address, height)
            .await?;

        Ok(Uint256::from_be_bytes(match balance.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC20 balance".to_string(),
                ))
            }
        }))
    }

    pub async fn get_erc20_name(
        &self,
        erc20: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("name()", &[])?;
        let name = self
            .simulate_transaction(erc20, 0u8.into(), payload, caller_address, None)
            .await?;

        match String::from_utf8(name) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    pub async fn get_erc20_symbol(
        &self,
        erc20: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("symbol()", &[])?;
        let symbol = self
            .simulate_transaction(erc20, 0u8.into(), payload, caller_address, None)
            .await?;

        match String::from_utf8(symbol) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    pub async fn get_erc20_decimals(
        &self,
        erc20: Address,
        caller_address: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("decimals()", &[])?;
        let decimals = self
            .simulate_transaction(erc20, 0u8.into(), payload, caller_address, None)
            .await?;

        Ok(Uint256::from_be_bytes(match decimals.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC20 decimals".to_string(),
                ))
            }
        }))
    }

    pub async fn get_erc20_supply(
        &self,
        erc20: Address,
        caller_address: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("totalSupply()", &[])?;
        let decimals = self
            .simulate_transaction(erc20, 0u8.into(), payload, caller_address, None)
            .await?;

        Ok(Uint256::from_be_bytes(match decimals.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC20 Total Supply".to_string(),
                ))
            }
        }))
    }
}

#[test]
fn test_erc20_metadata() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let dai_address = "0x6b175474e89094c44da98b954eedeac495271d0f"
        .parse()
        .unwrap();
    // random coinbase address hoping it always has eth to 'pay' for this call
    let caller_address = "0x503828976D22510aad0201ac7EC88293211D23Da"
        .parse()
        .unwrap();
    runner.block_on(async move {
        assert_eq!(
            web3.get_erc20_decimals(dai_address, caller_address)
                .await
                .unwrap(),
            18u8.into()
        );
        let num: Uint256 = 1000u32.into();
        assert!(
            web3.get_erc20_supply(dai_address, caller_address)
                .await
                .unwrap()
                > num
        );
        assert_eq!(
            web3.get_erc20_symbol(dai_address, caller_address)
                .await
                .unwrap(),
            "DAI"
        );
        assert_eq!(
            web3.get_erc20_name(dai_address, caller_address)
                .await
                .unwrap(),
            "Dai Stablecoin"
        );
    })
}
