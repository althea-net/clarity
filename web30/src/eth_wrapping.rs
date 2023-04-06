use crate::amm::WETH_CONTRACT_ADDRESS;
use crate::{client::Web3, jsonrpc::error::Web3Error};
use clarity::abi::AbiToken;
use clarity::Address;
use clarity::{abi::encode_call, PrivateKey, Uint256};
use std::time::Duration;
use tokio::time::timeout as future_timeout;

// Performs wrapping and unwrapping of eth, along with balance checking
impl Web3 {
    pub async fn wrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
        weth_address: Option<Address>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        let sig = "deposit()";
        let tokens = [];
        let payload = encode_call(sig, &tokens).unwrap();
        let weth_address = weth_address.unwrap_or(*WETH_CONTRACT_ADDRESS);
        let txid = self
            .send_transaction(weth_address, payload, amount, secret, vec![])
            .await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }
        Ok(txid)
    }

    pub async fn unwrap_eth(
        &self,
        amount: Uint256,
        secret: PrivateKey,
        weth_address: Option<Address>,
        wait_timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        let sig = "withdraw(uint256)";
        let tokens = [AbiToken::Uint(amount)];
        let payload = encode_call(sig, &tokens).unwrap();
        let weth_address = weth_address.unwrap_or(*WETH_CONTRACT_ADDRESS);
        let txid = self
            .send_transaction(weth_address, payload, 0u16.into(), secret, vec![])
            .await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }
        Ok(txid)
    }
}
