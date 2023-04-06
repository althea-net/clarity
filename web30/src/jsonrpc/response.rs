use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcError<E> {
    pub code: i64,
    pub message: String,
    pub data: Option<E>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ResponseData<R, E> {
    Error { error: JsonRpcError<E> },
    Success { result: R },
}

impl<R, E> ResponseData<R, E> {
    /// Consume response and return value
    pub fn into_result(self) -> Result<R, JsonRpcError<E>> {
        match self {
            ResponseData::Success { result } => Ok(result),
            ResponseData::Error { error } => Err(error),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response<R, E = Value> {
    pub id: Value,
    pub jsonrpc: String,
    #[serde(flatten)]
    pub data: ResponseData<R, E>,
}

#[test]
fn test_response() {
    let response: Response<u64> =
        serde_json::from_str(r#"{"jsonrpc": "2.0", "result": 19, "id": 1}"#).unwrap();
    assert_eq!(response.id.as_u64().unwrap(), 1);
    assert_eq!(response.data.into_result().unwrap(), 19);
}

#[test]
fn test_error() {
    let response: Response<Value> = serde_json::from_str(r#"{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}"#).unwrap();
    assert_eq!(response.id.as_str().unwrap(), "1");
    let err = response.data.into_result().unwrap_err();
    assert_eq!(err.code, -32601);
    assert_eq!(err.message, "Method not found");
}
