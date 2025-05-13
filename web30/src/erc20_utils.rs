//! This module contains utility functions for interacting with ERC20 tokens and contracts
use crate::convert_to_event_string;
use crate::jsonrpc::error::Web3Error;
use crate::types::{Log, TransactionRequest};
use crate::{client::Web3, types::SendTxOption};
use clarity::{abi::encode_call, PrivateKey as EthPrivateKey};
use clarity::{Address, Uint256};
use num_traits::Bounded;
use std::time::Duration;
use tokio::time::timeout as future_timeout;

pub static ERC20_GAS_LIMIT: u128 = 100_000;

impl Web3 {
    /// Returns the allowance of `erc20` tokens held by `owner` granted to `spender`
    /// Allowances are commonly used by protocols to manage erc20s on behalf of users,
    /// users simply approve a contract and then call the contract to perform actions
    pub async fn get_erc20_allowance(
        &self,
        erc20: Address,
        owner: Address,
        spender: Address,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call(
            "allowance(address,address)",
            &[owner.into(), spender.into()],
        )?;
        let allowance = self
            .simulate_transaction(
                TransactionRequest::quick_tx(owner, erc20, payload),
                options,
                None,
            )
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
        Ok(allowance)
    }

    /// Checks if `spender` is approved to spend a large amount of `erc20` tokens held by `owner`
    /// Allowances are commonly used by protocols to manage tokens on behalf of users,
    /// users simply approve a contract and then call the contract to perform actions
    ///
    /// Warning: Using this function is bad practice as it encourages excessive allowances. Excess allowances persist after spending
    /// so all uses should be phased out.
    #[deprecated]
    pub async fn check_erc20_approved(
        &self,
        erc20: Address,
        owner: Address,
        spender: Address,
        options: Vec<SendTxOption>,
    ) -> Result<bool, Web3Error> {
        let allowance = self
            .get_erc20_allowance(erc20, owner, spender, options)
            .await?;
        // Check if the allowance remaining is greater than half of a Uint256- it's as good
        // a test as any.
        Ok(allowance > (Uint256::max_value() / 2u32.into()))
    }

    /// Approves `spender` to spend `amount` of `erc20` tokens held by `owner`
    /// Allowances are commonly used by protocols to manage tokens on behalf of users,
    /// users simply approve a contract and then call the contract to perform actions
    /// This function performs that action and waits for it to complete for up to Timeout duration
    pub async fn erc20_approve(
        &self,
        erc20: Address,
        amount: Uint256,
        owner_key: EthPrivateKey,
        spender: Address,
        timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("approve(address,uint256)", &[spender.into(), amount.into()])?;

        let tx = self
            .prepare_transaction(erc20, payload, 0u32.into(), owner_key, options)
            .await?;
        let txid = self.eth_send_raw_transaction(tx.to_bytes()).await?;

        // wait for transaction to enter the chain if the user has requested it
        if let Some(timeout) = timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }

    /// Approves `spender` to spend all `erc20` held by `owner_key`
    /// Allowances are commonly used by protocols to manage tokens on behalf of users,
    /// users simply approve a contract and then call the contract to perform actions
    /// This function performs that action and waits for it to complete for up to Timeout duration
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    ///
    /// Warning: Using this function is bad practice as it encourages excessive allowances. Excess allowances persist after spending
    /// so all uses should be phased out.
    #[deprecated]
    pub async fn approve_erc20_max(
        &self,
        erc20: Address,
        owner_key: EthPrivateKey,
        spender: Address,
        timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        self.erc20_approve(
            erc20,
            Uint256::max_value(),
            owner_key,
            spender,
            timeout,
            options,
        )
        .await
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

        let tx = self
            .prepare_transaction(
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
        let tx_hash = self.eth_send_raw_transaction(tx.to_bytes()).await?;

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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height(erc20, target_address, None, options)
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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height_as_address(None, erc20, target_address, height, options)
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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        self.get_erc20_balance_at_height_as_address(
            requester_address,
            erc20,
            target_address,
            None,
            options,
        )
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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let requester_address = requester_address.unwrap_or(target_address);
        let payload = encode_call("balanceOf(address)", &[target_address.into()])?;
        let balance = self
            .simulate_transaction(
                TransactionRequest::quick_tx(requester_address, erc20, payload),
                options,
                height,
            )
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
        options: Vec<SendTxOption>,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("name()", &[])?;
        let name = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                options,
                None,
            )
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
        options: Vec<SendTxOption>,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("symbol()", &[])?;
        let symbol = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                options,
                None,
            )
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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("decimals()", &[])?;
        let decimals = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                options,
                None,
            )
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
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("totalSupply()", &[])?;
        let supply = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                options,
                None,
            )
            .await?;

        Ok(Uint256::from_be_bytes(match supply.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC20 Total Supply".to_string(),
                ))
            }
        }))
    }

    /// Utility function for generating a events requests filtered specifically for a given ERC20
    /// and a given sender
    pub async fn get_erc20_transfer_events_by_sender(
        &self,
        erc20: Address,
        sender: Address,
        start_block: Uint256,
        end_block: Option<Uint256>,
    ) -> Result<Vec<Log>, Web3Error> {
        let sender = convert_to_event_string(sender);
        self.check_for_events(
            start_block,
            end_block,
            vec![erc20],
            vec![TRANSFER_EVENT_SIG, &sender],
        )
        .await
    }

    /// Utility function for generating a events requests filtered specifically for a given ERC20
    /// and a given destination
    pub async fn get_erc20_transfer_events_by_destination(
        &self,
        erc20: Address,
        destination: Address,
        start_block: Uint256,
        end_block: Option<Uint256>,
    ) -> Result<Vec<Log>, Web3Error> {
        let destination = convert_to_event_string(destination);
        self.check_for_events(
            start_block,
            end_block,
            vec![erc20],
            vec![TRANSFER_EVENT_SIG, "", &destination],
        )
        .await
    }

    /// Utility function for generating a events requests filtered specifically for a given ERC20
    /// and a given source and destination
    pub async fn get_erc20_transfer_events_by_sender_and_destination(
        &self,
        erc20: Address,
        sender: Address,
        destination: Address,
        start_block: Uint256,
        end_block: Option<Uint256>,
    ) -> Result<Vec<Log>, Web3Error> {
        let sender = convert_to_event_string(sender);
        let destination = convert_to_event_string(destination);
        self.check_for_events(
            start_block,
            end_block,
            vec![erc20],
            vec![TRANSFER_EVENT_SIG, &sender, &destination],
        )
        .await
    }

    /// Gets all approval events in the range for a specific erc20 address and a specific owner
    /// approving tranfers
    pub async fn get_erc20_approval_events_by_owner(
        &self,
        erc20: Address,
        src: Address,
        start_block: Uint256,
        end_block: Option<Uint256>,
    ) -> Result<Vec<Log>, Web3Error> {
        let src = convert_to_event_string(src);
        self.check_for_events(
            start_block,
            end_block,
            vec![erc20],
            vec![APPROVE_EVENT_SIG, &src],
        )
        .await
    }
}
/// The event signature for ERC20 transfers
pub const TRANSFER_EVENT_SIG: &str = "Transfer(address,address,uint256)";
/// The event signature for ERC20 approvals
pub const APPROVE_EVENT_SIG: &str = "Approval(address,address,uint256)";

#[cfg(test)]
mod test {
    use super::*;

    #[actix_rt::test]
    async fn test_filtered_erc20_transfer_events() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let dai_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        // random coinbase address hoping it always has eth to 'pay' for this call
        let caller_address = "0xC69d72D8940d66CfC3Aeb06AeBD1F97b64e49E08"
            .parse()
            .unwrap();
        let start_block = 22334091u64.into();
        let end_block = None;
        let logs = web3
            .get_erc20_transfer_events_by_destination(
                dai_address,
                caller_address,
                start_block,
                end_block,
            )
            .await
            .unwrap();
        println!("Logs len {}", logs.len());
        for log in logs.iter() {
            println!("Log: {:?}", log.block_number);
        }
    }

    #[actix_rt::test]
    async fn test_erc20_metadata() {
        let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
        let dai_address = "0x6b175474e89094c44da98b954eedeac495271d0f"
            .parse()
            .unwrap();
        // random coinbase address hoping it always has eth to 'pay' for this call
        let caller_address = "0x503828976D22510aad0201ac7EC88293211D23Da"
            .parse()
            .unwrap();
        assert_eq!(
            web3.get_erc20_decimals(dai_address, caller_address, vec![])
                .await
                .unwrap(),
            18u8.into()
        );
        let num: Uint256 = 1000u32.into();
        assert!(
            web3.get_erc20_supply(dai_address, caller_address, vec![])
                .await
                .unwrap()
                > num
        );
        assert_eq!(
            web3.get_erc20_symbol(dai_address, caller_address, vec![])
                .await
                .unwrap(),
            "DAI"
        );
        assert_eq!(
            web3.get_erc20_name(dai_address, caller_address, vec![])
                .await
                .unwrap(),
            "Dai Stablecoin"
        );
    }
}
