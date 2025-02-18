use crate::{ContractInstance, Error, Result};
use alloy_json_abi::{Function, JsonAbi};
use std::collections::BTreeMap;

/// A smart contract interface.
#[derive(Clone, Debug)]
pub struct Interface {
    abi: JsonAbi,
    functions: SelectorHashMap<(String, usize)>,
}

// TODO: events/errors
impl Interface {
    /// Creates a new contract interface from the provided ABI.
    pub fn new(abi: JsonAbi) -> Self {
        let functions = create_mapping(&abi.functions, Function::selector);
        Self { abi, functions }
    }

    /// Returns a reference to the contract's ABI.
    pub const fn abi(&self) -> &JsonAbi {
        &self.abi
    }

    /// Consumes the interface, returning the inner ABI.
    pub fn into_abi(self) -> JsonAbi {
        self.abi
    }

    pub(crate) fn get_from_name(&self, name: &str) -> Result<&Function> {
        self.abi
            .function(name)
            .and_then(|r| r.first())
            .ok_or_else(|| Error::UnknownFunction(name.to_string()))
    }

    pub(crate) fn get_from_selector(&self, selector: &Selector) -> Result<&Function> {
        self.functions
            .get(selector)
            .map(|(name, index)| &self.abi.functions[name][*index])
            .ok_or_else(|| Error::UnknownSelector(*selector))
    }

    /// Create a [`ContractInstance`] from this ABI for a contract at the given address.
    pub const fn connect<P, N>(self, address: Address, provider: P) -> ContractInstance<P, N> {
        ContractInstance::new(address, provider, self)
    }
}

/// Utility function for creating a mapping between a unique signature and a
/// name-index pair for accessing contract ABI items.
fn create_mapping<const N: usize, T, F>(
    elements: &BTreeMap<String, Vec<T>>,
    signature: F,
) -> FbHashMap<N, (String, usize)>
where
    F: Fn(&T) -> FixedBytes<N> + Copy,
{
    elements
        .iter()
        .flat_map(|(name, sub_elements)| {
            sub_elements
                .iter()
                .enumerate()
                .map(move |(index, element)| (signature(element), (name.to_owned(), index)))
        })
        .collect()
}
