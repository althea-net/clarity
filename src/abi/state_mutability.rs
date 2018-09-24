use serde::de::Visitor;
use serde::de::{self, Deserialize, Deserializer, Unexpected};
#[cfg(test)]
use serde_json;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum StateMutability {
    /// Specified to not read blockchain state
    Pure,
    /// Specified to not modify the blockchain state
    View,
    /// Function does not accept ether
    Nonpayable,
    /// Function accepts ether
    Payable,
}

impl<'de> Deserialize<'de> for StateMutability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StateMutabilityVisitor)
    }
}

struct StateMutabilityVisitor;

impl<'de> Visitor<'de> for StateMutabilityVisitor {
    type Value = StateMutability;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s == "pure" {
            Ok(StateMutability::Pure)
        } else if s == "view" {
            Ok(StateMutability::View)
        } else if s == "nonpayable" {
            Ok(StateMutability::Nonpayable)
        } else if s == "payable" {
            Ok(StateMutability::Payable)
        } else {
            Err(de::Error::invalid_value(Unexpected::Str(s), &self))
        }
    }
}

#[test]
fn deserialize_pure() {
    let data = r#""pure""#;
    let state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(state, StateMutability::Pure);
}

#[test]
fn deserialize_view() {
    let data = r#""view""#;
    let state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(state, StateMutability::View);
}

#[test]
fn deserialize_nonpayable() {
    let data = r#""nonpayable""#;
    let state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(state, StateMutability::Nonpayable);
}

#[test]
fn deserialize_payable() {
    let data = r#""payable""#;
    let state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
    assert_eq!(state, StateMutability::Payable);
}

#[test]
#[should_panic]
fn deserialize_wrong_type() {
    let data = r#"123"#;
    let _state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
}

#[test]
#[should_panic]
fn deserialize_wrong_value() {
    let data = r#""unknown""#;
    let _state: StateMutability = serde_json::from_str(data).expect("Unable to parse");
}
