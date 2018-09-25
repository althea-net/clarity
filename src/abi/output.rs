#[derive(Deserialize, PartialEq, Debug)]
pub struct Output {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}
