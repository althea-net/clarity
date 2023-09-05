use std::time::Duration;

use crate::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{SendTxOption, TransactionRequest},
};
use clarity::{
    abi::{encode_call, AbiToken},
    rlp::{unpack_rlp, RlpToken},
    Address, PrivateKey,
};
use num256::Uint256;
use tokio::time::timeout as future_timeout;

pub const ADD_USER_GAS_LIMIT: u128 = 100_000;

// DB side Idenitity struct
#[derive(Debug, Default, Clone)]
pub struct ClientIdentity {
    pub mesh_ip: String,
    pub eth_address: Address,
    pub wg_public_key: String,
}

impl From<ClientIdentity> for AbiToken {
    fn from(id: ClientIdentity) -> AbiToken {
        AbiToken::Struct(vec![
            AbiToken::String(id.mesh_ip),
            AbiToken::String(id.wg_public_key),
            AbiToken::Address(id.eth_address),
        ])
    }
}

impl Web3 {
    pub async fn add_registered_user(
        &self,
        user: ClientIdentity,
        contract: Address,
        sender_private_key: PrivateKey,
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
            options.push(SendTxOption::GasLimit(ADD_USER_GAS_LIMIT.into()));
        }

        let tx_hash = self
            .send_transaction(
                contract,
                encode_call("add_registered_user((string,string,address))", &[user.into()])?,
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

    pub async fn get_all_registered_users(
        &self,
        contract: Address,
        requester_address: Address,
    ) -> Result<Vec<RlpToken>, Web3Error> {
        let payload = encode_call("get_all_registered_users()", &[])?;
        let res = self
            .simulate_transaction(
                TransactionRequest::quick_tx(requester_address, contract, payload),
                None,
            )
            .await?;

        let res = unpack_rlp(&res)?;

        // Need to add byte parsing here
        Ok(res)
    }

    pub async fn get_registered_client_with_eth_addr(
        &self,
        eth_addr: Address,
        contract: Address,
        requester_address: Address,
    ) -> Result<Vec<RlpToken>, Web3Error> {
        let payload = encode_call(
            "get_registered_client_with_eth_addr(address)",
            &[eth_addr.into()],
        )?;
        let res = self
            .simulate_transaction(
                TransactionRequest::quick_tx(requester_address, contract, payload),
                None,
            )
            .await?;

        let res = unpack_rlp(&res)?;

        // Need to add byte parsing here
        Ok(res)
    }
}
