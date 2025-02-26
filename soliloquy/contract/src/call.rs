#![allow(clippy::return_self_not_must_use)]

use crate::{error::ContractRevert, EthError};

use super::base::AbiError;
use soliloquy_core::{
    abi::{Detokenize, Function, InvalidOutputType},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, TransactionRequest, U256,
    },
};
use web30::jsonrpc::error::Web3Error;

use std::{
    borrow::Borrow,
    fmt::Debug,
    future::{Future, IntoFuture},
    marker::PhantomData,
    pin::Pin,
};

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
/// An Error which is thrown when interacting with a smart contract
pub enum ContractError {
    /// Thrown when the ABI decoding fails
    #[error(transparent)]
    DecodingError(#[from] soliloquy_core::abi::Error),

    /// Thrown when the internal BaseContract errors
    #[error(transparent)]
    AbiError(#[from] AbiError),

    /// Thrown when detokenizing an argument
    #[error(transparent)]
    DetokenizationError(#[from] InvalidOutputType),

    /// Contract reverted
    #[error("Contract call reverted with data: {0}")]
    Revert(Bytes),

    /// Thrown during deployment if a constructor argument was passed in the `deploy`
    /// call but a constructor was not present in the ABI
    #[error("constructor is not defined in the ABI")]
    ConstructorError,

    /// Thrown if a contract address is not found in the deployment transaction's
    /// receipt
    #[error("Contract was not deployed")]
    ContractNotDeployed,
}

impl ContractError {
    /// If this `ContractError` is a revert, this method will retrieve a
    /// reference to the underlying revert data. This ABI-encoded data could be
    /// a String, or a custom Solidity error type.
    ///
    /// ## Returns
    ///
    /// `None` if the error is not a revert
    /// `Some(data)` with the revert data, if the error is a revert
    ///
    /// ## Note
    ///
    /// To skip this step, consider using [`ContractError::decode_revert`]
    pub fn as_revert(&self) -> Option<&Bytes> {
        match self {
            ContractError::Revert(data) => Some(data),
            _ => None,
        }
    }

    /// True if the error is a revert, false otherwise
    pub fn is_revert(&self) -> bool {
        matches!(self, ContractError::Revert(_))
    }

    /// Decode revert data into an [`EthError`] type. Returns `None` if
    /// decoding fails, or if this is not a revert
    pub fn decode_revert<Err: EthError>(&self) -> Option<Err> {
        self.as_revert()
            .and_then(|data| Err::decode_with_selector(data))
    }

    /// Decode revert data into a [`ContractRevert`] type. Returns `None` if
    /// decoding fails, or if this is not a revert
    ///
    /// This is intended to be used with error enum outputs from `abigen!`
    /// contracts
    pub fn decode_contract_revert<Err: ContractRevert>(&self) -> Option<Err> {
        self.as_revert()
            .and_then(|data| Err::decode_with_selector(data))
    }
}

impl From<Web3Error> for ContractError {
    fn from(e: Web3Error) -> Self {
        if let Some(data) = e.as_error_response().and_then(Web3Error::JsonRpcError) {
            ContractError::Revert(data)
        } else {
            ContractError::ProviderError { e }
        }
    }
}

/// `ContractCall` is a [`FunctionCall`] object with an [`std::sync::Arc`] middleware.
/// This type alias exists to preserve backwards compatibility with
/// less-abstract Contracts.
///
/// For full usage docs, see [`FunctionCall`].
pub type ContractCall<D> = FunctionCall<D>;

#[derive(Debug)]
#[must_use = "contract calls do nothing unless you `send` or `call` them"]
/// Helper for managing a transaction before submitting it to a node
pub struct FunctionCall<D> {
    /// The raw transaction object
    pub tx: TypedTransaction,
    /// The ABI of the function being called
    pub function: Function,
    /// Optional block number to be used when calculating the transaction's gas and nonce
    pub block: Option<BlockId>,
    pub(crate) datatype: PhantomData<D>,
}

impl<D> Clone for FunctionCall<D> {
    fn clone(&self) -> Self {
        FunctionCall {
            tx: self.tx.clone(),
            function: self.function.clone(),
            block: self.block,
            datatype: self.datatype,
        }
    }
}

impl<D> FunctionCall<D>
where
    D: Detokenize,
{
    /// Sets the `from` field in the transaction to the provided value
    pub fn from<T: Into<Address>>(mut self, from: T) -> Self {
        self.tx.set_from(from.into());
        self
    }

    /// Uses a Legacy transaction instead of an EIP-1559 one to execute the call
    pub fn legacy(mut self) -> Self {
        self.tx = match self.tx {
            TypedTransaction::Eip1559(inner) => {
                let tx: TransactionRequest = inner.into();
                TypedTransaction::Legacy(tx)
            }
            other => other,
        };
        self
    }

    /// Sets the `gas` field in the transaction to the provided value
    pub fn gas<T: Into<U256>>(mut self, gas: T) -> Self {
        self.tx.set_gas(gas);
        self
    }

    /// Sets the `gas_price` field in the transaction to the provided value
    /// If the internal transaction is an EIP-1559 one, then it sets both
    /// `max_fee_per_gas` and `max_priority_fee_per_gas` to the same value
    pub fn gas_price<T: Into<U256>>(mut self, gas_price: T) -> Self {
        self.tx.set_gas_price(gas_price);
        self
    }

    /// Sets the `value` field in the transaction to the provided value
    pub fn value<T: Into<U256>>(mut self, value: T) -> Self {
        self.tx.set_value(value);
        self
    }

    /// Sets the `block` field for sending the tx to the chain
    pub fn block<T: Into<BlockId>>(mut self, block: T) -> Self {
        self.block = Some(block.into());
        self
    }

    /// Sets the `nonce` field in the transaction to the provided value
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.tx.set_nonce(nonce);
        self
    }
}

impl<D> FunctionCall<D>
where
    D: Detokenize,
{
    /// Returns the underlying transaction's ABI encoded data
    pub fn calldata(&self) -> Option<Bytes> {
        self.tx.data().cloned()
    }
}

/// [`FunctionCall`] can be turned into [`Future`] automatically with `.await`.
/// Defaults to calling [`FunctionCall::call`].
impl<D> IntoFuture for FunctionCall<D>
where
    Self: 'static,
    D: Detokenize + Send + Sync,
{
    type Output = Result<D, ContractError>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        #[allow(clippy::redundant_async_block)]
        Box::pin(async move { self.call().await })
    }
}
