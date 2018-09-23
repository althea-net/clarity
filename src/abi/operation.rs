use serde::de::{self, Deserialize, Deserializer, Unexpected, Visitor};
use serde_json;
use std::fmt;

/// Deserializes "type" value from the ABI JSON spec
///
/// https://solidity.readthedocs.io/en/develop/abi-spec.html#abi-json
#[derive(Debug, PartialEq)]
pub enum Operation {
    Function,
    Constructor,
    Event,
    Fallback,
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(OperationVisitor)
    }
}

struct OperationVisitor;

impl<'de> Visitor<'de> for OperationVisitor {
    type Value = Operation;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s == "function" {
            Ok(Operation::Function)
        } else if s == "constructor" {
            Ok(Operation::Constructor)
        } else if s == "event" {
            Ok(Operation::Event)
        } else if s == "fallback" {
            Ok(Operation::Fallback)
        } else {
            Err(de::Error::invalid_value(Unexpected::Str(s), &self))
        }
    }
}

#[test]
fn deserialize_function() {
    let data = r#""function""#;
    let op: Operation = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(op, Operation::Function);
}

#[test]
fn deserialize_event() {
    let data = r#""event""#;
    let op: Operation = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(op, Operation::Event);
}

#[test]
fn deserialize_constructor() {
    let data = r#""constructor""#;
    let op: Operation = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(op, Operation::Constructor);
}

#[test]
fn deserialize_fallback() {
    let data = r#""constructor""#;
    let op: Operation = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(op, Operation::Constructor);
}

#[test]
#[should_panic]
fn deserialize_unknown_string() {
    let data = r#""asdf""#;
    let _op: Operation = serde_json::from_str(data).expect("Unable to parse");
}

#[test]
#[should_panic]
fn deserialize_unknown_type() {
    let data = r#"42"#;
    let _op: Operation = serde_json::from_str(data).expect("Unable to parse");
}
