#[derive(Serialize, Deserialize, Debug)]
pub struct Request<T> {
    id: u64,
    jsonrpc: String,
    method: String,
    params: T,
}

impl<T> Request<T> {
    pub fn new(id: u64, method: &str, params: T) -> Self {
        Self {
            id,
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        }
    }
}

#[test]
fn req() {
    let req: Request<Vec<u64>> = Request::new(0, "add", vec![2, 2]);
    let _s = serde_json::to_string(&req).unwrap();
}
