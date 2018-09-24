use abi::operation::Operation;

/// The JSON format for a contract’s interface is given by an array of
/// function and/or event descriptions. A function description is a
/// JSON object with the fields
#[derive(Deserialize)]
pub struct Item {
    #[serde(rename = "type", default)]
    pub operation: Operation,
    pub name: String,
    #[serde(default)]
    pub payable: bool,
    #[serde(default)]
    pub constant: bool,
}
