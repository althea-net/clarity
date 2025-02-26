use crate::{
    base::{encode_function_data, AbiError, BaseContract},
    call::FunctionCall,
    event::Event,
    event_core::EthEvent,
};
use soliloquy_core::{
    abi::{Abi, Detokenize, Error, EventExt, Function, Tokenize},
    types::{Address, Filter, Selector, ValueOrArray},
};
use std::{fmt::Debug, marker::PhantomData};

// TODO: Make a way for the user to specify the transaction type (EIP1559/Legacy)
use soliloquy_core::types::Eip1559TransactionRequest;
// use soliloquy_core::types::TransactionRequest;

/// `Contract` is a [`ContractInstance`] object
/// This type alias exists to preserve backwards compatibility with
/// less-abstract Contracts.
///
/// For full usage docs, see [`ContractInstance`].
pub type Contract = ContractInstance;

/// A Contract is an abstraction of an executable program on the Ethereum Blockchain.
/// It has code (called byte code) as well as allocated long-term memory
/// (called storage). Every deployed Contract has an address, which is used to connect
/// to it so that it may be sent messages to call its methods.
///
/// A Contract can emit Events, which can be efficiently observed by applications
/// to be notified when a contract has performed specific operation.
///
/// There are two types of methods that can be called on a Contract:
///
/// 1. A Constant method may not add, remove or change any data in the storage,
/// nor log any events, and may only call Constant methods on other contracts.
/// These methods are free (no Ether is required) to call. The result from them
/// may also be returned to the caller. Constant methods are marked as `pure` and
/// `view` in Solidity.
///
/// 2. A Non-Constant method requires a fee (in Ether) to be paid, but may perform
/// any state-changing operation desired, log events, send ether and call Non-Constant
/// methods on other Contracts. These methods cannot return their result to the caller.
/// These methods must be triggered by a transaction, sent by an Externally Owned Account
/// (EOA) either directly or indirectly (i.e. called from another contract), and are
/// required to be mined before the effects are present. Therefore, the duration
/// required for these operations can vary widely, and depend on the transaction
/// gas price, network congestion and miner priority heuristics.
///
/// The Contract API provides simple way to connect to a Contract and call its methods,
/// as functions on a Rust struct, handling all the binary protocol conversion,
/// internal name mangling and topic construction. This allows a Contract object
/// to be used like any standard Rust struct, without having to worry about the
/// low-level details of the Ethereum Virtual Machine or Blockchain.
///
/// The Contract definition (called an Application Binary Interface, or ABI) must
/// be provided to instantiate a contract and the available methods and events will
/// be made available to call by providing their name as a `str` via the [`method`]
/// and [`event`] methods. If non-existing names are given, the function/event call
/// will fail.
///
/// Alternatively, you can _and should_ use the [`abigen`] macro, or the [`Abigen` builder]
/// to generate type-safe bindings to your contracts.
///
/// # Example
///
/// Assuming we already have our contract deployed at `address`, we'll proceed to
/// interact with its methods and retrieve raw logs it has emitted.
///
/// ```no_run
/// use soliloquy_core::{
///     abi::Abi,
///     types::{Address, H256},
/// };
/// use ethers_contract::Contract;
/// use ethers_providers::{Provider, Http};
/// use std::{convert::TryFrom, sync::Arc};
///
/// # async fn foo() -> Result<(), Box<dyn std::error::Error>> {
/// // this is a fake address used just for this example
/// let address = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".parse::<Address>()?;
///
/// // (ugly way to write the ABI inline, you can otherwise read it from a file)
/// let abi: Abi = serde_json::from_str(r#"[{"inputs":[{"internalType":"string","name":"value","type":"string"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"author","type":"address"},{"indexed":true,"internalType":"address","name":"oldAuthor","type":"address"},{"indexed":false,"internalType":"string","name":"oldValue","type":"string"},{"indexed":false,"internalType":"string","name":"newValue","type":"string"}],"name":"ValueChanged","type":"event"},{"inputs":[],"name":"getValue","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lastSender","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"value","type":"string"}],"name":"setValue","outputs":[],"stateMutability":"nonpayable","type":"function"}]"#)?;
///
/// // connect to the network
/// let client = Provider::<Http>::try_from("http://localhost:8545").unwrap();
///
/// // create the contract object at the address
/// let contract = Contract::new(address, abi, Arc::new(client));
///
/// // Calling constant methods is done by calling `call()` on the method builder.
/// // (if the function takes no arguments, then you must use `()` as the argument)
/// let init_value: String = contract
///     .method::<_, String>("getValue", ())?
///     .call()
///     .await?;
///
/// // Non-constant methods are executed via the `send()` call on the method builder.
/// let call = contract
///     .method::<_, H256>("setValue", "hi".to_owned())?;
/// let pending_tx = call.send().await?;
///
/// // `await`ing on the pending transaction resolves to a transaction receipt
/// let receipt = pending_tx.confirmations(6).await?;
///
/// # Ok(())
/// # }
/// ```
///
/// # Event Logging
///
/// Querying structured logs requires you to have defined a struct with the expected
/// datatypes and to have implemented `Detokenize` for it. This boilerplate code
/// is generated for you via the [`abigen`] and [`Abigen` builder] utilities.
//
// Ignore because `ethers-contract-derive` macros do not work in doctests in `ethers-contract`.
/// ```ignore
/// # async fn foo() -> Result<(), Box<dyn std::error::Error>> {
/// use soliloquy_core::{abi::Abi, types::Address};
/// use ethers_contract::{Contract, EthEvent};
/// use ethers_providers::{Provider, Http};
/// use std::{convert::TryFrom, sync::Arc};
/// use soliloquy_core::abi::{Detokenize, Token, InvalidOutputType};
/// # // this is a fake address used just for this example
/// # let address = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".parse::<Address>()?;
/// # let abi: Abi = serde_json::from_str("[]")?;
/// # let client = Provider::<Http>::try_from("http://localhost:8545").unwrap();
/// # let contract = Contract::new(address, abi, Arc::new(client));
///
/// #[derive(Clone, Debug, EthEvent)]
/// struct ValueChanged {
///     old_author: Address,
///     new_author: Address,
///     old_value: String,
///     new_value: String,
/// }
///
/// let logs: Vec<ValueChanged> = contract
///     .event()
///     .from_block(0u64)
///     .query()
///     .await?;
///
/// println!("{:?}", logs);
/// # Ok(())
/// # }
/// ```
///
/// [`abigen`]: macro.abigen.html
/// [`Abigen` builder]: struct.Abigen.html
/// [`event`]: method@crate::ContractInstance::event
/// [`method`]: method@crate::ContractInstance::method
#[derive(Debug)]
pub struct ContractInstance {
    address: Address,
    base_contract: BaseContract,
}

impl std::ops::Deref for ContractInstance {
    type Target = BaseContract;

    fn deref(&self) -> &Self::Target {
        &self.base_contract
    }
}

impl Clone for ContractInstance {
    fn clone(&self) -> Self {
        ContractInstance {
            base_contract: self.base_contract.clone(),
            address: self.address,
        }
    }
}

impl ContractInstance {
    /// Returns the contract's address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns a reference to the contract's ABI.
    pub fn abi(&self) -> &Abi {
        &self.base_contract.abi
    }
}

impl ContractInstance {
    /// Returns an [`Event`] builder for the provided event.
    ///
    /// This function operates in a static context, then it does not require a `self` to reference
    /// to instantiate an [`Event`] builder.
    pub fn event_of_type<D: EthEvent>() -> Event<D> {
        Event {
            filter: Filter::new().event(&D::abi_signature()),
            datatype: PhantomData,
        }
    }
}

impl ContractInstance {
    /// Creates a new contract from the provided client, abi and address
    pub fn new(address: impl Into<Address>, abi: impl Into<BaseContract>) -> Self {
        Self {
            base_contract: abi.into(),
            address: address.into(),
        }
    }

    /// Returns a new contract instance using the provided client
    ///
    /// Clones `self` internally
    #[must_use]
    pub fn connect(&self) -> ContractInstance {
        ContractInstance {
            base_contract: self.base_contract.clone(),
            address: self.address,
        }
    }

    /// Returns a new contract instance using the provided client
    ///
    /// Clones `self` internally
    #[must_use]
    pub fn connect_with(&self) -> ContractInstance {
        ContractInstance {
            base_contract: self.base_contract.clone(),
            address: self.address,
        }
    }
}

impl ContractInstance {
    /// Returns an [`Event`] builder with the provided filter.
    pub fn event_with_filter<D>(&self, filter: Filter) -> Event<D> {
        Event {
            filter: filter.address(ValueOrArray::Value(self.address)),
            datatype: PhantomData,
        }
    }

    /// Returns an [`Event`] builder for the provided event.
    pub fn event<D: EthEvent>(&self) -> Event<D> {
        D::new(Filter::new())
    }

    /// Returns an [`Event`] builder with the provided name.
    pub fn event_for_name<D>(&self, name: &str) -> Result<Event<D>, Error> {
        // get the event's full name
        let event = self.base_contract.abi.event(name)?;
        Ok(self.event_with_filter(Filter::new().event(&event.abi_signature())))
    }

    fn method_func<T: Tokenize, D: Detokenize>(
        &self,
        function: &Function,
        args: T,
    ) -> Result<FunctionCall<D>, AbiError> {
        let data = encode_function_data(function, args)?;

        // TODO: Make a way for functions to create legacy and EIP1559 transactions
        // let tx = TransactionRequest {
        //     to: Some(self.address.into()),
        //     data: Some(data),
        //     ..Default::default()
        // };
        let tx = Eip1559TransactionRequest {
            to: Some(self.address.into()),
            data: Some(data),
            ..Default::default()
        };

        let tx = tx.into();

        Ok(FunctionCall {
            tx,
            block: None,
            function: function.to_owned(),
            datatype: PhantomData,
        })
    }

    /// Returns a transaction builder for the selected function signature. This should be
    /// preferred if there are overloaded functions in your smart contract
    pub fn method_hash<T: Tokenize, D: Detokenize>(
        &self,
        signature: Selector,
        args: T,
    ) -> Result<FunctionCall<D>, AbiError> {
        let function = self
            .base_contract
            .methods
            .get(&signature)
            .map(|(name, index)| &self.base_contract.abi.functions[name][*index])
            .ok_or_else(|| Error::InvalidName(hex::encode(signature)))?;
        self.method_func(function, args)
    }

    /// Returns a transaction builder for the provided function name. If there are
    /// multiple functions with the same name due to overloading, consider using
    /// the `method_hash` method instead, since this will use the first match.
    pub fn method<T: Tokenize, D: Detokenize>(
        &self,
        name: &str,
        args: T,
    ) -> Result<FunctionCall<D>, AbiError> {
        // get the function
        let function = self.base_contract.abi.function(name)?;
        self.method_func(function, args)
    }

    /// Returns a new contract instance at `address`.
    ///
    /// Clones `self` internally
    #[must_use]
    pub fn at<T: Into<Address>>(&self, address: T) -> Self {
        let mut this = self.clone();
        this.address = address.into();
        this
    }
}
