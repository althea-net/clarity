use crate::jsonrpc::error::Web3Error;
use crate::types::{Block, Log, NewFilter, SyncingStatus, TransactionRequest, TransactionResponse};
use crate::types::{ConciseBlock, TransactionReceipt};
use clarity::rlp::downcast_u64;
use clarity::Address;
use num256::Uint256;
use std::time::Duration;
use std::time::Instant;

use super::core::Web3;

// The query-only part of the "eth" namespace of the Web3 API

impl Web3 {
    pub async fn eth_accounts(&self) -> Result<Vec<Address>, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_accounts", Vec::<String>::new(), self.timeout)
            .await
    }

    /// Returns the EIP155 chain ID used for transaction signing at the current best block. Null is returned if not available.
    pub async fn eth_chainid(&self) -> Result<u64, Web3Error> {
        let ret: Result<Uint256, Web3Error> = self
            .jsonrpc_client
            .request_method("eth_chainId", Vec::<String>::new(), self.timeout)
            .await;
        // there is no actually specified maximum chain id, so in theory we should use Uint256 here, but u64 is much easier to handle
        // from an encoding standpoint
        let value = ret?;
        Ok(downcast_u64(value)?)
    }

    /// Requests logs as provided by a filter, see this guide for some advice on how to use this
    /// https://docs.alchemy.com/docs/deep-dive-into-eth_getlogs
    /// A transaction with a log with topics [A, B] will be matched by the following topic filters:
    /// [] “anything”
    /// [A] “A in first position (and anything after)”
    /// [null, B] “anything in first position AND B in second position (and anything after)”
    /// [A, B] “A in first position AND B in second position (and anything after)”
    /// [[A, B], [A, B]] “(A OR B) in first position AND (A OR B) in second position (and anything after)”
    pub async fn eth_get_logs(&self, new_filter: NewFilter) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_getLogs", vec![new_filter], self.timeout)
            .await
    }

    pub async fn eth_get_transaction_count(&self, address: Address) -> Result<Uint256, Web3Error> {
        //check if the node is still syncing
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method(
                        "eth_getTransactionCount",
                        vec![address.to_string(), "latest".to_string()],
                        self.timeout,
                    )
                    .await
            }
            true => Err(Web3Error::SyncingNode(
                "Cannot perform eth_getTransactionCount".to_string(),
            )),
        }
    }

    /// Get the median gas price over the last 10 blocks. This function does not
    /// simply wrap eth_gasPrice, in post London chains it also requests the base
    /// gas from the previous block and prevents the use of a lower value
    pub async fn eth_gas_price(&self) -> Result<Uint256, Web3Error> {
        match self.eth_syncing().await? {
            false => {
                let median_gas = self
                    .jsonrpc_client
                    .request_method("eth_gasPrice", Vec::<String>::new(), self.timeout)
                    .await?;
                if let Some(gas) = self.get_base_fee_per_gas().await? {
                    if median_gas < gas {
                        Ok(gas)
                    } else {
                        Ok(median_gas)
                    }
                } else {
                    Ok(median_gas)
                }
            }
            _ => Err(Web3Error::SyncingNode(
                "Cannot perform eth_gas_price".to_string(),
            )),
        }
    }

    pub async fn eth_estimate_gas(
        &self,
        mut transaction: TransactionRequest,
    ) -> Result<Uint256, Web3Error> {
        if let Ok(true) = self.eth_syncing().await {
            warn!("Eth Node is still syncing, request may not work if block is not synced");
        }
        let nonce = self
            .eth_get_transaction_count(transaction.get_from())
            .await?;
        let balance = self.eth_get_balance(transaction.get_from()).await?;

        let gas = self.simulated_gas_price_and_limit(balance).await?;

        transaction.set_nonce(nonce);
        transaction.set_gas_limit(gas.limit);
        transaction.set_gas_price(gas.price);

        self.jsonrpc_client
            .request_method("eth_estimateGas", vec![transaction], self.timeout)
            .await
    }

    pub async fn eth_get_balance(&self, address: Address) -> Result<Uint256, Web3Error> {
        //check if the node is still syncing
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method(
                        "eth_getBalance",
                        vec![address.to_string(), "latest".to_string()],
                        self.timeout,
                    )
                    .await
            }
            true => Err(Web3Error::SyncingNode(
                "Cannot perform eth_getBalance".to_string(),
            )),
        }
    }

    /// Returns a bool indicating whether our eth node is currently syncing or not
    pub async fn eth_syncing(&self) -> Result<bool, Web3Error> {
        let res: SyncingStatus = self
            .jsonrpc_client
            .request_method("eth_syncing", Vec::<String>::new(), self.timeout)
            .await?;
        match res {
            SyncingStatus::Syncing { .. } => Ok(true),
            SyncingStatus::NotSyncing(..) => Ok(false),
        }
    }

    /// Returns the code at a given address at the provided block height, or latest if None
    /// If there is no code at the address, will return an empty Vec
    pub async fn eth_get_code(
        &self,
        address: Address,
        height: Option<Uint256>,
    ) -> Result<Vec<u8>, Web3Error> {
        let height = match height {
            Some(h) => format!("{h:#x}"),
            None => "latest".to_string(),
        };
        let res: String = self
            .jsonrpc_client
            .request_method(
                "eth_getCode",
                vec![address.to_string(), height],
                self.timeout,
            )
            .await?;
        let res = clarity::utils::hex_str_to_bytes(&res)?;
        Ok(res)
    }

    /// Retrieves the latest synced block number regardless of state of eth node
    pub async fn eth_synced_block_number(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_blockNumber", Vec::<String>::new(), self.timeout)
            .await
    }

    pub async fn eth_block_number(&self) -> Result<Uint256, Web3Error> {
        match self.eth_syncing().await? {
            false => self.eth_synced_block_number().await,
            true => Err(Web3Error::SyncingNode(
                "Cannot perform eth_block_number".to_string(),
            )),
        }
    }

    pub async fn eth_get_block_by_number(&self, block_number: Uint256) -> Result<Block, Web3Error> {
        let latest_known_block = self.eth_synced_block_number().await?;
        if block_number <= latest_known_block {
            self.jsonrpc_client
                .request_method(
                    "eth_getBlockByNumber",
                    (format!("{block_number:#x}"), true),
                    self.timeout,
                )
                .await
        } else if self.eth_syncing().await? {
            Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_block_by_number".to_string(),
            ))
        } else {
            Err(Web3Error::BadInput(
                "Cannot perform eth_get_block_by_number, block number invalid".to_string(),
            ))
        }
    }

    pub async fn eth_get_concise_block_by_number(
        &self,
        block_number: Uint256,
    ) -> Result<ConciseBlock, Web3Error> {
        let latest_known_block = self.eth_synced_block_number().await?;
        if block_number <= latest_known_block {
            self.jsonrpc_client
                .request_method(
                    "eth_getBlockByNumber",
                    (format!("{block_number:#x}"), false),
                    self.timeout,
                )
                .await
        } else if self.eth_syncing().await? {
            Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_concise_block_by_number".to_string(),
            ))
        } else {
            Err(Web3Error::BadInput(
                "Cannot perform eth_get_concise_block_by_number, block number invalid".to_string(),
            ))
        }
    }

    /// Gets the latest (non finalized) block including tx hashes instead of full tx data
    pub async fn eth_get_latest_block(&self) -> Result<ConciseBlock, Web3Error> {
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method("eth_getBlockByNumber", ("latest", false), self.timeout)
                    .await
            }
            _ => Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_latest_block".to_string(),
            )),
        }
    }

    /// Gets the latest (non finalized) block including full tx data
    pub async fn eth_get_latest_block_full(&self) -> Result<Block, Web3Error> {
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method("eth_getBlockByNumber", ("latest", true), self.timeout)
                    .await
            }
            _ => Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_latest_block".to_string(),
            )),
        }
    }

    /// Gets the latest (finalized) block including tx hashes instead of full tx data
    pub async fn eth_get_finalized_block(&self) -> Result<ConciseBlock, Web3Error> {
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method("eth_getBlockByNumber", ("finalized", false), self.timeout)
                    .await
            }
            _ => Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_latest_block".to_string(),
            )),
        }
    }

    /// Gets the latest (finalized) block including full tx data
    pub async fn eth_get_finalized_block_full(&self) -> Result<Block, Web3Error> {
        match self.eth_syncing().await? {
            false => {
                self.jsonrpc_client
                    .request_method("eth_getBlockByNumber", ("finalized", true), self.timeout)
                    .await
            }
            _ => Err(Web3Error::SyncingNode(
                "Cannot perform eth_get_latest_block".to_string(),
            )),
        }
    }

    pub async fn eth_get_transaction_by_hash(
        &self,
        hash: Uint256,
    ) -> Result<Option<TransactionResponse>, Web3Error> {
        if let Ok(true) = self.eth_syncing().await {
            warn!("Eth node is currently syncing, eth_get_transaction_by_hash may not work if transaction is not synced");
        }

        self.jsonrpc_client
            .request_method(
                "eth_getTransactionByHash",
                // XXX: Technically it doesn't need to be Uint256, but since send_raw_transaction is
                // returning it we'll keep it consistent.
                vec![format!("{hash:#066x}")],
                self.timeout,
            )
            .await
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        hash: Uint256,
    ) -> Result<Option<TransactionReceipt>, Web3Error> {
        if let Ok(true) = self.eth_syncing().await {
            warn!("Eth node is currently syncing, eth_get_transaction_by_receipt may not work if transaction is not synced");
        }

        self.jsonrpc_client
            .request_method(
                "eth_getTransactionReceipt",
                vec![format!("{hash:#066x}")],
                self.timeout,
            )
            .await
    }

    /// Navigates the block request process to properly identify the base fee no matter
    /// what network (xDai or ETH) is being used. Returns `None` if a pre-London fork
    /// network is in use and `Some(base_fee_per_gas)` if a post London network is in
    /// use
    pub async fn get_base_fee_per_gas(&self) -> Result<Option<Uint256>, Web3Error> {
        match self.eth_get_latest_block().await {
            Ok(eth_block) => Ok(eth_block.base_fee_per_gas),
            Err(e) => Err(e),
        }
    }

    /// Waits for the next Ethereum block to be produced
    pub async fn wait_for_next_block(&self, timeout: Duration) -> Result<(), Web3Error> {
        let start = Instant::now();
        let mut last_height: Option<Uint256> = None;
        while Instant::now() - start < timeout {
            match (self.eth_block_number().await, last_height) {
                (Ok(n), None) => last_height = Some(n),
                (Ok(block_height), Some(last_height)) => {
                    if block_height > last_height {
                        return Ok(());
                    }
                }
                // errors should not exit early
                (Err(_), _) => {}
            }
        }
        Err(Web3Error::NoBlockProduced { time: timeout })
    }

    /// Checks if the provided address is a contract by checking if there is code at the address
    /// If there is code at the address it is a contract, if there is no code it is not a contract
    pub async fn check_if_address_is_contract(&self, address: Address) -> Result<bool, Web3Error> {
        match self.eth_get_code(address, None).await {
            Ok(code) => Ok(!code.is_empty()),
            Err(e) => Err(e),
        }
    }
}
