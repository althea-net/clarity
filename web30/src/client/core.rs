use std::time::Duration;

use crate::jsonrpc::client::HttpClient;

// Core details and simple functions of the Web3 client

/// The Web3 client which accepts requests and handles communication with the chain over HTTP (JSONRPC)
#[derive(Clone)]
pub struct Web3 {
    pub(crate) url: String,
    pub(crate) jsonrpc_client: HttpClient,
    pub(crate) timeout: Duration,
}

impl Web3 {
    pub fn new(url: &str, timeout: Duration) -> Self {
        Self {
            jsonrpc_client: HttpClient::new(url),
            timeout,
            url: url.to_string(),
        }
    }

    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }

    pub fn get_url(&self) -> String {
        self.url.clone()
    }
}
