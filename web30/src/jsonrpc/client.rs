use crate::jsonrpc::error::Web3Error;
use crate::jsonrpc::request::Request;
use crate::jsonrpc::response::Response;
use crate::mem::get_buffer_size;
use awc::http::header;
use awc::Client;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct HttpClient {
    id_counter: Arc<Mutex<RefCell<u64>>>,
    url: String,
    client: Client,
}

impl HttpClient {
    pub fn new(url: &str) -> Self {
        Self {
            id_counter: Arc::new(Mutex::new(RefCell::new(0u64))),
            url: url.to_string(),
            client: Client::default(),
        }
    }

    fn next_id(&self) -> u64 {
        let counter = self.id_counter.clone();
        let counter = counter.lock().expect("id error");
        let mut value = counter.borrow_mut();
        *value += 1;
        *value
    }

    pub async fn request_method<T, R>(
        &self,
        method: &str,
        params: T,
        timeout: Duration,
    ) -> Result<R, Web3Error>
    where
        R: 'static,
        for<'de> R: Deserialize<'de>,
        T: Serialize,
        T: std::fmt::Debug,
        R: std::fmt::Debug,
    {
        trace!("Making request {} {:?}", method, params);
        let payload = Request::new(self.next_id(), method, params);
        let res = self
            .client
            .post(&self.url)
            .append_header((header::CONTENT_TYPE, "application/json"))
            .timeout(timeout)
            .send_json(&payload)
            .await;
        let mut res = match res {
            Ok(val) => val,
            Err(e) => return Err(Web3Error::FailedToSend(e)),
        };

        trace!("response headers {:?}", res.headers());

        let request_size_limit = get_buffer_size();
        trace!("using buffer size of {}", request_size_limit);
        let body_bytes = match res.body().limit(request_size_limit).await {
            Ok(val) => val,
            Err(e) => {
                return Err(Web3Error::BadResponse(format!(
                    "Size Limit {request_size_limit} Web3 Error {e}"
                )))
            }
        };

        // First parse as generic JSON to enable better error messages
        let json_value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(val) => val,
            Err(e) => {
                let body_str = String::from_utf8_lossy(&body_bytes);
                return Err(Web3Error::BadResponse(format!(
                    "Failed to parse response as JSON: {e}\nRaw response: {body_str}"
                )))
            }
        };

        // Pretty print for debugging
        trace!("Raw JSON response:\n{}", serde_json::to_string_pretty(&json_value).unwrap_or_else(|_| json_value.to_string()));

        #[cfg(feature = "verbose_logging")]
        info!("Raw JSON response:\n{}", serde_json::to_string_pretty(&json_value).unwrap_or_else(|_| json_value.to_string()));

        // Now attempt to deserialize into the expected type
        let decoded: Response<R> = match serde_json::from_value(json_value.clone()) {
            Ok(val) => val,
            Err(e) => {
                return Err(Web3Error::BadResponse(format!(
                    "Failed to deserialize response into expected type: {e}\nJSON response:\n{}",
                    serde_json::to_string_pretty(&json_value).unwrap_or_else(|_| json_value.to_string())
                )))
            }
        };
        //Response<R>
        trace!("got web3 response {:#?}", decoded);
        let data = decoded.data.into_result();
        match data {
            Ok(r) => Ok(r),
            Err(e) => Err(Web3Error::JsonRpcError {
                code: e.code,
                message: e.message,
                data: format!("{:?}", e.data),
            }),
        }
    }
}
