#[derive(Deserialize, PartialEq, Debug)]
pub struct Input {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default = "Vec::new")]
    pub components: Vec<Input>,
    #[serde(default)]
    pub indexed: bool,
}
