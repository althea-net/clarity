use crate::jsonrpc::error::Web3Error;

use super::core::Web3;

// The "net" namespace of the Web3 API

impl Web3 {
    pub async fn net_version(&self) -> Result<u64, Web3Error> {
        let ret: Result<String, Web3Error> = self
            .jsonrpc_client
            .request_method("net_version", Vec::<String>::new(), self.timeout)
            .await;
        Ok(ret?.parse()?)
    }
}
