use std::time::{Duration, Instant};

use super::{core::Web3, ETHEREUM_INTRINSIC_GAS};
use crate::{
    jsonrpc::error::Web3Error,
    types::{Data, SendTxOption, TransactionRequest, TransactionResponse},
};
use clarity::{utils::bytes_to_hex_str, Address, PrivateKey, Transaction};
use futures::future::join4;
use num256::Uint256;
use num_traits::ToPrimitive;
use tokio::time::sleep;

// The state altering part of the "eth" namespace of the Web3 API, and convenience functions for transaction generation

impl Web3 {
    pub async fn eth_send_transaction(
        &self,
        transactions: Vec<TransactionRequest>,
    ) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_sendTransaction", transactions, self.timeout)
            .await
    }

    pub async fn eth_call(&self, transaction: TransactionRequest) -> Result<Data, Web3Error> {
        //syncing check
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method("eth_call", (transaction, "latest"), self.timeout)
                    .await
            }
            true => Err(Web3Error::SyncingNode(
                "Cannot perform eth_call".to_string(),
            )),
        }
    }

    pub async fn eth_call_at_height(
        &self,
        transaction: TransactionRequest,
        block: Uint256,
    ) -> Result<Data, Web3Error> {
        let latest_known_block = self.eth_synced_block_number().await?;
        if block <= latest_known_block {
            self.jsonrpc_client
                .request_method(
                    "eth_call",
                    (transaction, format!("{:#x}", block.0)), // THIS IS THE MAGIC I NEEDED
                    self.timeout,
                )
                .await
        } else if self.eth_syncing().await? {
            Err(Web3Error::SyncingNode(
                "Cannot perform eth_call_at_height".to_string(),
            ))
        } else {
            //Invalid block number
            Err(Web3Error::BadInput(
                "Cannot perform eth_call_at_height, block number invalid".to_string(),
            ))
        }
    }

    /// Publishes a prepared transaction and returns the txhash on success. If you want to wait for the transaction
    /// to actually execute on chain, you can use `web3.wait_for_transaction()`
    pub async fn send_prepared_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<Uint256, Web3Error> {
        self.eth_send_raw_transaction(transaction.to_bytes()).await
    }

    pub async fn eth_send_raw_transaction(&self, data: Vec<u8>) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_sendRawTransaction",
                vec![format!("0x{}", bytes_to_hex_str(&data))],
                self.timeout,
            )
            .await
    }

    /// Sends a transaction which changes blockchain state
    /// this function is the same as send_transaction except it sends
    /// a legacy format transaction with higher gas costs.
    /// The result can be immediately published using
    /// `self.send_prepared_transaction(transaction).await`
    pub async fn prepare_legacy_transaction(
        &self,
        to_address: Address,
        data: Vec<u8>,
        value: Uint256,
        own_address: Address,
        secret: PrivateKey,
        options: Vec<SendTxOption>,
    ) -> Result<Transaction, Web3Error> {
        let mut gas_price = None;
        let mut gas_price_multiplier = 1f32;
        let mut gas_limit_multiplier = 1f32;
        let mut gas_limit = None;
        let mut network_id = None;
        let our_balance = self.eth_get_balance(own_address).await?;
        if our_balance.is_zero() || our_balance < ETHEREUM_INTRINSIC_GAS.into() {
            // We only know that the balance is insufficient, we don't know how much gas is needed
            return Err(Web3Error::InsufficientGas {
                balance: our_balance,
                base_gas: ETHEREUM_INTRINSIC_GAS.into(),
                gas_required: ETHEREUM_INTRINSIC_GAS.into(),
            });
        }
        let mut nonce = self.eth_get_transaction_count(own_address).await?;

        for option in options {
            match option {
                SendTxOption::GasPrice(gp) => gas_price = Some(gp),
                SendTxOption::GasPriceMultiplier(gpm) => gas_price_multiplier = gpm,
                SendTxOption::GasLimitMultiplier(glm) => gas_limit_multiplier = glm,
                SendTxOption::GasLimit(gl) => gas_limit = Some(gl),
                SendTxOption::NetworkId(ni) => network_id = Some(ni),
                SendTxOption::Nonce(n) => nonce = n,
                SendTxOption::GasMaxFee(_)
                | SendTxOption::GasPriorityFee(_)
                | SendTxOption::AccessList(_)
                | SendTxOption::GasMaxFeeMultiplier(_) => {
                    return Err(Web3Error::BadInput(
                        "Invalid option for Legacy tx".to_string(),
                    ))
                }
            }
        }

        let mut gas_price = if let Some(gp) = gas_price {
            gp
        } else {
            let gas_price = self.eth_gas_price().await?;
            let f32_gas = gas_price.to_u128();
            if let Some(v) = f32_gas {
                // convert to f32, multiply, then convert back, this
                // will be lossy but you want an exact price you can set it
                ((v as f32 * gas_price_multiplier) as u128).into()
            } else {
                // gas price is insanely high, best effort rounding
                // perhaps we should panic here
                gas_price * (gas_price_multiplier.round() as u128).into()
            }
        };

        let mut gas_limit = if let Some(gl) = gas_limit {
            gl
        } else {
            let gas = self.simulated_gas_price_and_limit(our_balance).await?;
            self.eth_estimate_gas(TransactionRequest::Legacy {
                from: own_address,
                to: to_address,
                nonce: Some(nonce.into()),
                gas_price: Some(gas.price.into()),
                gas: Some(gas.limit.into()),
                value: Some(value.into()),
                data: Some(data.clone().into()),
            })
            .await?
        };

        // multiply limit by gasLimitMultiplier
        let gas_limit_128 = gas_limit.to_u128();
        if let Some(v) = gas_limit_128 {
            gas_limit = ((v as f32 * gas_limit_multiplier) as u128).into()
        } else {
            gas_limit *= (gas_limit_multiplier.round() as u128).into()
        }

        let network_id = if let Some(ni) = network_id {
            ni
        } else {
            self.eth_chainid().await?
        };

        // this is an edge case where we are about to send a transaction that can't possibly
        // be valid, we simply don't have the the funds to pay the full gas amount we are promising
        // this segment computes either the highest valid gas price we can pay or in the post-london
        // chain case errors if we can't meet the minimum fee
        if gas_price * gas_limit > our_balance {
            let base_fee_per_gas = self.get_base_fee_per_gas().await?;
            if let Some(base_fee_per_gas) = base_fee_per_gas {
                if base_fee_per_gas * gas_limit > our_balance {
                    return Err(Web3Error::InsufficientGas {
                        balance: our_balance,
                        base_gas: base_fee_per_gas,
                        gas_required: gas_limit,
                    });
                }
            }
            // this will give some value >= base_fee_per_gas * gas_limit
            // in post-london and some non zero value in pre-london
            gas_price = our_balance / gas_limit;
        }

        let transaction = Transaction::Legacy {
            to: to_address,
            nonce,
            gas_price,
            gas_limit,
            value,
            data,
            signature: None,
        };

        Ok(transaction.sign(&secret, Some(network_id)))
    }

    /// Generates but does not send a transaction which changes blockchain state.
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like gas,
    /// The result can be immediately published using
    /// `self.send_prepared_transaction(transaction).await`
    pub async fn prepare_transaction(
        &self,
        to_address: Address,
        data: Vec<u8>,
        value: Uint256,
        secret: PrivateKey,
        options: Vec<SendTxOption>,
    ) -> Result<Transaction, Web3Error> {
        let mut max_priority_fee_per_gas = 1u8.into();
        let mut gas_limit_multiplier = 1f32;
        let mut gas_limit = None;
        let mut access_list = Vec::new();
        let own_address = secret.to_address();

        let our_balance = self.eth_get_balance(own_address);
        let nonce = self.eth_get_transaction_count(own_address);
        let max_fee_per_gas = self.get_base_fee_per_gas();
        let chain_id = self.eth_chainid();

        // request in parallel
        let (our_balance, nonce, base_fee_per_gas, chain_id) =
            join4(our_balance, nonce, max_fee_per_gas, chain_id).await;

        let (our_balance, mut nonce, base_fee_per_gas, chain_id) =
            (our_balance?, nonce?, base_fee_per_gas?, chain_id?);

        // check if we can send an EIP1559 tx on this chain
        let base_fee_per_gas = match base_fee_per_gas {
            Some(bf) => bf,
            None => return Err(Web3Error::PreLondon),
        };

        // max_fee_per_gas is base gas multiplied by 2, this is a maximum the actual price we pay is determined
        // by the block the transaction enters, if we put the price exactly as the base fee the tx will fail if
        // the price goes up at all in the next block. So some base level multiplier makes sense as a default
        let mut max_fee_per_gas = base_fee_per_gas * 2u8.into();

        if our_balance.is_zero() || our_balance < ETHEREUM_INTRINSIC_GAS.into() {
            // We only know that the balance is insufficient, we don't know how much gas is needed
            return Err(Web3Error::InsufficientGas {
                balance: our_balance,
                base_gas: ETHEREUM_INTRINSIC_GAS.into(),
                gas_required: ETHEREUM_INTRINSIC_GAS.into(),
            });
        }

        for option in options {
            match option {
                SendTxOption::GasMaxFee(gp) | SendTxOption::GasPrice(gp) => max_fee_per_gas = gp,
                SendTxOption::GasPriorityFee(gp) => max_priority_fee_per_gas = gp,
                SendTxOption::GasLimitMultiplier(glm) => gas_limit_multiplier = glm,
                SendTxOption::GasLimit(gl) => gas_limit = Some(gl),
                SendTxOption::Nonce(n) => nonce = n,
                SendTxOption::AccessList(list) => access_list = list,
                SendTxOption::GasPriceMultiplier(gm) | SendTxOption::GasMaxFeeMultiplier(gm) => {
                    let f32_gas = base_fee_per_gas.to_u128();
                    max_fee_per_gas = if let Some(v) = f32_gas {
                        // convert to f32, multiply, then convert back, this
                        // will be lossy but you want an exact price you can set it
                        ((v as f32 * gm) as u128).into()
                    } else {
                        // gas price is insanely high, best effort rounding
                        // perhaps we should panic here
                        base_fee_per_gas * (gm.round() as u128).into()
                    };
                }
                SendTxOption::NetworkId(_) => {
                    return Err(Web3Error::BadInput(
                        "Invalid option for eip1559 tx".to_string(),
                    ))
                }
            }
        }

        let mut transaction = Transaction::Eip1559 {
            chain_id: chain_id.into(),
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: 0u8.into(),
            to: to_address,
            value,
            data,
            signature: None,
            access_list,
        };

        let mut gas_limit = if let Some(gl) = gas_limit {
            gl
        } else {
            self.eth_estimate_gas(TransactionRequest::from_transaction(
                &transaction,
                own_address,
            ))
            .await?
        };

        // multiply limit by gasLimitMultiplier
        let gas_limit_128 = gas_limit.to_u128();
        if let Some(v) = gas_limit_128 {
            gas_limit = ((v as f32 * gas_limit_multiplier) as u128).into()
        } else {
            gas_limit *= (gas_limit_multiplier.round() as u128).into()
        }

        transaction.set_gas_limit(gas_limit);

        // this is an edge case where we are about to send a transaction that can't possibly
        // be valid, we simply don't have the the funds to pay the full gas amount we are promising
        // this segment computes either the highest valid gas price we can pay or in the post-london
        // chain case errors if we can't meet the minimum fee
        if max_fee_per_gas * gas_limit > our_balance {
            if base_fee_per_gas * gas_limit > our_balance {
                return Err(Web3Error::InsufficientGas {
                    balance: our_balance,
                    base_gas: base_fee_per_gas,
                    gas_required: gas_limit,
                });
            }
            // this will give some value >= base_fee_per_gas * gas_limit
            // in post-london and some non zero value in pre-london
            max_fee_per_gas = our_balance / gas_limit;
        }

        transaction.set_max_fee_per_gas(max_fee_per_gas);

        if !transaction.is_valid() {
            return Err(Web3Error::BadInput("About to send invalid tx".to_string()));
        }

        let transaction = transaction.sign(&secret, None);

        if !transaction.is_valid() {
            return Err(Web3Error::BadInput("About to send invalid tx".to_string()));
        }

        // signed transaction is now ready to publish
        Ok(transaction.sign(&secret, None))
    }

    /// Simulates an Ethereum contract call by making a fake transaction and sending it to a special endpoint
    /// this code is executed exactly as if it where an actual transaction executing. This can be used to execute
    /// both getter endpoints on Solidity contracts and to test actual executions. User beware, this function requires
    /// ETH in the caller address to run. Even if you're just trying to call a getter function and never need to actually
    /// run code this faithful simulation will fail if you have no ETH to pay for gas.
    ///
    /// In an attempt to maximize the amount of info you can get with this function gas is computed for you as the maximum
    /// possible value, if you need to get  gas estimation you should use `web3.eth_estimate_gas` instead.
    ///
    /// optionally this data can come from some historic block
    pub async fn simulate_transaction(
        &self,
        mut transaction: TransactionRequest,
        options: Vec<SendTxOption>,
        height: Option<Uint256>,
    ) -> Result<Vec<u8>, Web3Error> {
        let own_address = transaction.get_from();
        let our_balance = self.eth_get_balance(own_address).await?;
        if our_balance.is_zero() || our_balance < ETHEREUM_INTRINSIC_GAS.into() {
            // We only know that the balance is insufficient, we don't know how much gas is needed
            return Err(Web3Error::InsufficientGas {
                balance: our_balance,
                base_gas: ETHEREUM_INTRINSIC_GAS.into(),
                gas_required: ETHEREUM_INTRINSIC_GAS.into(),
            });
        }

        let nonce = self.eth_get_transaction_count(own_address).await?;

        let gas = self.simulated_gas_price_and_limit(our_balance).await?;

        transaction.set_nonce(nonce);
        transaction.set_gas_limit(gas.limit);
        transaction.set_gas_price(gas.price);

        let gas_limit_option_set = options
            .iter()
            .any(|opt| matches!(opt, SendTxOption::GasLimit(_)));

        for option in options {
            match option {
                SendTxOption::GasMaxFee(gp) | SendTxOption::GasPrice(gp) => {
                    transaction.set_gas_price(gp)
                }
                SendTxOption::GasPriorityFee(gp) => transaction.set_priority_fee(gp),
                SendTxOption::GasLimitMultiplier(glm) => {
                    // only apply this if gas limit is set. Otherwise we are using max gas already
                    // and applying a multiplier would likely push us over the balance limit, a multiplier
                    // lower than 1 is fine in this case as it reduces gas
                    if gas_limit_option_set || glm < 1.0 {
                        let f32_gas = gas.limit.to_u128();
                        let val = if let Some(v) = f32_gas {
                            // convert to f32, multiply, then convert back, this
                            // will be lossy but you want an exact price you can set it
                            ((v as f32 * glm) as u128).into()
                        } else {
                            // gas price is insanely high, best effort rounding
                            // perhaps we should panic here
                            gas.price * (glm.round() as u128).into()
                        };
                        transaction.set_gas_limit(val);
                    }
                }
                SendTxOption::GasLimit(gl) => transaction.set_gas_limit(gl),
                SendTxOption::Nonce(n) => transaction.set_nonce(n),
                SendTxOption::AccessList(list) => transaction.set_access_list(list),
                SendTxOption::GasPriceMultiplier(gm) | SendTxOption::GasMaxFeeMultiplier(gm) => {
                    // same reasoning as gas limit multiplier, we are already using max gas for the default gas
                    // price and our balance. So we can't do a higher price unless the gas limit has been set lower
                    // than max
                    if gas_limit_option_set || gm < 1.0 {
                        let f32_gas = gas.price.to_u128();
                        let val = if let Some(v) = f32_gas {
                            // convert to f32, multiply, then convert back, this
                            // will be lossy but you want an exact price you can set it
                            ((v as f32 * gm) as u128).into()
                        } else {
                            // gas price is insanely high, best effort rounding
                            // perhaps we should panic here
                            gas.price * (gm.round() as u128).into()
                        };
                        transaction.set_gas_price(val);
                    }
                }
                SendTxOption::NetworkId(_) => {
                    return Err(Web3Error::BadInput(
                        "Invalid option for eip1559 tx".to_string(),
                    ))
                }
            }
        }

        match height {
            Some(height) => {
                let bytes = match self.eth_call_at_height(transaction, height).await {
                    Ok(val) => val,
                    Err(e) => return Err(e),
                };
                Ok(bytes.0)
            }
            None => {
                let bytes = match self.eth_call(transaction).await {
                    Ok(val) => val,
                    Err(e) => return Err(e),
                };
                Ok(bytes.0)
            }
        }
    }

    /// Waits for a transaction with the given hash to be included in a block
    /// it will wait for at most timeout time and optionally can wait for n
    /// blocks to have passed
    pub async fn wait_for_transaction(
        &self,
        tx_hash: Uint256,
        timeout: Duration,
        blocks_to_wait: Option<Uint256>,
    ) -> Result<TransactionResponse, Web3Error> {
        let start = Instant::now();
        loop {
            sleep(Duration::from_secs(1)).await;
            match self.eth_get_transaction_by_hash(tx_hash).await {
                Ok(maybe_transaction) => {
                    if let Some(transaction) = maybe_transaction {
                        // if no wait time is specified and the tx is in a block return right away
                        if blocks_to_wait.clone().is_none()
                            && transaction.get_block_number().is_some()
                        {
                            return Ok(transaction);
                        }
                        // One the tx is in a block we start waiting here
                        else if let (Some(blocks_to_wait), Some(tx_block)) =
                            (blocks_to_wait, transaction.get_block_number())
                        {
                            let current_block = self.eth_block_number().await?;
                            // we check for underflow, which is possible on testnets
                            if current_block > blocks_to_wait
                                && current_block - blocks_to_wait >= tx_block
                            {
                                return Ok(transaction);
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }

            if Instant::now() - start > timeout {
                return Err(Web3Error::TransactionTimeout);
            }
        }
    }
}
