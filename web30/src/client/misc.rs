use num256::Uint256;

use crate::{
    jsonrpc::error::Web3Error,
    types::{Log, NewFilter},
};

use super::core::Web3;

// Various test chain functions and log watching configurations - likely not used on a full node

impl Web3 {
    pub async fn evm_snapshot(&self) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("evm_snapshot", Vec::<String>::new(), self.timeout)
            .await
    }

    pub async fn evm_revert(&self, snapshot_id: Uint256) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "evm_revert",
                vec![format!("{snapshot_id:#066x}")],
                self.timeout,
            )
            .await
    }

    pub async fn eth_new_filter(&self, new_filter: NewFilter) -> Result<Uint256, Web3Error> {
        self.jsonrpc_client
            .request_method("eth_newFilter", vec![new_filter], self.timeout)
            .await
    }

    pub async fn eth_get_filter_changes(&self, filter_id: Uint256) -> Result<Vec<Log>, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_getFilterChanges",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
            )
            .await
    }

    pub async fn eth_uninstall_filter(&self, filter_id: Uint256) -> Result<bool, Web3Error> {
        self.jsonrpc_client
            .request_method(
                "eth_uninstallFilter",
                vec![format!("{:#x}", filter_id.clone())],
                self.timeout,
            )
            .await
    }
}
