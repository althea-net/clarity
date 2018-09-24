use abi::item::Item;
use failure::Error;
use serde::de::Deserialize;
use serde::de::Deserializer;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde_json;
use std::fmt;
use std::io;

pub struct Contract {
    items: Vec<Item>,
}

impl Contract {
    fn load<T: io::Read>(reader: T) -> Result<Self, Error> {
        serde_json::from_reader(reader).map_err(From::from)
    }
}

impl<'de> Deserialize<'de> for Contract {
    fn deserialize<D>(deserializer: D) -> Result<Contract, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ContractVisitor)
    }
}

struct ContractVisitor;

impl<'a> Visitor<'a> for ContractVisitor {
    type Value = Contract;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("valid abi spec file")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'a>,
    {
        let mut result = Contract { items: Vec::new() };
        while let Some(item) = seq.next_element()? {
            result.items.push(item)
        }

        Ok(result)
    }
}

#[test]
fn decode_contract() {
    use abi::operation::Operation;
    use std::io::BufReader;
    let abi_def = r#"
[
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes"
			},
			{
				"name": "",
				"type": "bool"
			},
			{
				"name": "",
				"type": "uint256[]"
			}
		],
		"name": "sam",
		"outputs": [],
		"payable": false,
		"stateMutability": "pure",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "x",
				"type": "uint32"
			},
			{
				"name": "y",
				"type": "bool"
			}
		],
		"name": "baz",
		"outputs": [
			{
				"name": "r",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "pure",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes3[2]"
			}
		],
		"name": "bar",
		"outputs": [],
		"payable": false,
		"stateMutability": "pure",
		"type": "function"
	},
	{
		"inputs": [
			{
				"name": "",
				"type": "bytes3[2]"
			}
		],
		"name": "bar_defaults",
		"outputs": [],
		"stateMutability": "pure"
	}
]"#.to_owned();

    let contract =
        Contract::load(BufReader::new(abi_def.as_bytes())).expect("Unable to load contract");

    assert_eq!(contract.items.len(), 4);
    let sam = contract.items.get(0).unwrap();
    assert_eq!(sam.name, "sam");
    assert_eq!(sam.operation, Operation::Function);
    assert_eq!(sam.payable, false);
    assert_eq!(sam.constant, true);

    let baz = contract.items.get(1).unwrap();
    assert_eq!(baz.name, "baz");
    assert_eq!(baz.operation, Operation::Function);
    assert_eq!(baz.payable, false);
    assert_eq!(baz.constant, true);

    let bar = contract.items.get(2).unwrap();
    assert_eq!(bar.name, "bar");
    assert_eq!(bar.operation, Operation::Function);
    assert_eq!(bar.payable, false);
    assert_eq!(bar.constant, true);

    let bar_defaults = contract.items.get(3).unwrap();
    assert_eq!(bar_defaults.name, "bar_defaults");
    assert_eq!(bar_defaults.operation, Operation::Function);
    assert_eq!(bar_defaults.payable, false);
    assert_eq!(bar_defaults.constant, false);
}
