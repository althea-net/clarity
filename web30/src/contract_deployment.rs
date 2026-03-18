//! Contract deployment utilities for Web3
//!
//! This module provides high-level APIs for deploying smart contracts to Ethereum networks.
//! It includes a builder pattern for configuring deployments and convenience functions
//! for common deployment scenarios.

use crate::jsonrpc::error::Web3Error;
use clarity::{calculate_contract_address, validate_init_code_size, Address, Transaction, Uint256};

/// Builder for constructing contract deployment transactions.
///
/// This builder provides a fluent API for configuring all aspects of a contract
/// deployment, including init code, constructor arguments, gas parameters, and
/// value to send.
///
/// # Examples
/// ```no_run
/// use web30::contract_deployment::ContractDeploymentBuilder;
/// use clarity::{Address, PrivateKey, Uint256};
///
/// # async fn example() {
/// let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
/// let init_code = vec![0x60, 0x80, 0x60, 0x40]; // Contract bytecode
///
/// let builder = ContractDeploymentBuilder::new(deployer, init_code)
///     .with_value(Uint256::from(1000000u64))
///     .with_gas_limit(Uint256::from(3_000_000u64));
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ContractDeploymentBuilder {
    deployer: Address,
    init_code: Vec<u8>,
    value: Uint256,
    gas_limit: Option<Uint256>,
    gas_price: Option<Uint256>,
    max_fee_per_gas: Option<Uint256>,
    max_priority_fee_per_gas: Option<Uint256>,
    nonce: Option<Uint256>,
    chain_id: Option<u64>,
}

impl ContractDeploymentBuilder {
    /// Create a new contract deployment builder.
    ///
    /// # Arguments
    /// * `deployer` - The address that will deploy the contract
    /// * `init_code` - The contract initialization code (bytecode + constructor args)
    ///
    /// # Examples
    /// ```
    /// use web30::contract_deployment::ContractDeploymentBuilder;
    /// use clarity::Address;
    ///
    /// let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
    /// let init_code = vec![0x60, 0x80];
    /// let builder = ContractDeploymentBuilder::new(deployer, init_code);
    /// ```
    pub fn new(deployer: Address, init_code: Vec<u8>) -> Self {
        Self {
            deployer,
            init_code,
            value: Uint256::from(0u8),
            gas_limit: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            chain_id: None,
        }
    }

    /// Append constructor arguments to the init code.
    ///
    /// Constructor arguments must be ABI-encoded. Use the `clarity::abi` module
    /// to encode arguments properly.
    ///
    /// # Arguments
    /// * `args` - ABI-encoded constructor arguments
    pub fn with_constructor_args(mut self, args: Vec<u8>) -> Self {
        self.init_code.extend(args);
        self
    }

    /// Set the amount of ETH to send with the deployment.
    ///
    /// # Arguments
    /// * `value` - Amount of wei to send
    pub fn with_value(mut self, value: Uint256) -> Self {
        self.value = value;
        self
    }

    /// Set the gas limit for the deployment transaction.
    ///
    /// If not set, gas will be estimated automatically when building the transaction.
    ///
    /// # Arguments
    /// * `gas_limit` - Maximum gas to use
    pub fn with_gas_limit(mut self, gas_limit: Uint256) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set the gas price for legacy or EIP-2930 transactions.
    ///
    /// # Arguments
    /// * `gas_price` - Gas price in wei
    pub fn with_gas_price(mut self, gas_price: Uint256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Set EIP-1559 fee parameters.
    ///
    /// These are used for EIP-1559 transactions instead of gas price.
    ///
    /// # Arguments
    /// * `max_fee` - Maximum total fee per gas
    /// * `max_priority_fee` - Maximum priority fee per gas (tip)
    pub fn with_eip1559_fees(mut self, max_fee: Uint256, max_priority_fee: Uint256) -> Self {
        self.max_fee_per_gas = Some(max_fee);
        self.max_priority_fee_per_gas = Some(max_priority_fee);
        self
    }

    /// Set the nonce explicitly.
    ///
    /// If not set, the nonce will be fetched from the network when needed.
    ///
    /// # Arguments
    /// * `nonce` - Transaction nonce
    pub fn with_nonce(mut self, nonce: Uint256) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the chain ID for the transaction.
    ///
    /// # Arguments
    /// * `chain_id` - Network chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Predict the address where the contract will be deployed.
    ///
    /// This requires that either the nonce is set in the builder, or it's
    /// provided as an argument.
    ///
    /// # Arguments
    /// * `nonce` - Optional nonce to use (overrides builder nonce)
    ///
    /// # Returns
    /// The predicted contract address
    ///
    /// # Examples
    /// ```
    /// use web30::contract_deployment::ContractDeploymentBuilder;
    /// use clarity::{Address, Uint256};
    ///
    /// let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
    /// let init_code = vec![0x60, 0x80];
    /// let builder = ContractDeploymentBuilder::new(deployer, init_code)
    ///     .with_nonce(Uint256::from(5u8));
    ///
    /// let predicted_address = builder.predict_address(None).unwrap();
    /// ```
    pub fn predict_address(&self, nonce: Option<Uint256>) -> Result<Address, Web3Error> {
        let nonce = nonce.or(self.nonce).ok_or_else(|| {
            Web3Error::BadInput("Nonce is required to predict contract address".to_string())
        })?;

        Ok(calculate_contract_address(self.deployer, nonce))
    }

    /// Validate the deployment configuration.
    ///
    /// Checks:
    /// - Init code size is within EIP-3860 limits
    /// - Gas parameters are valid
    ///
    /// # Returns
    /// Ok(()) if valid, or an error describing the issue
    pub fn validate(&self) -> Result<(), Web3Error> {
        // Validate init code size (EIP-3860)
        if !validate_init_code_size(&self.init_code) {
            return Err(Web3Error::BadInput(
                "Init code exceeds maximum size of 49,152 bytes (EIP-3860)".to_string(),
            ));
        }

        // Validate gas parameters
        if let (Some(max_fee), Some(priority_fee)) =
            (self.max_fee_per_gas, self.max_priority_fee_per_gas)
        {
            if priority_fee > max_fee {
                return Err(Web3Error::BadInput(
                    "Max priority fee cannot exceed max fee per gas".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Build an unsigned transaction for the deployment.
    ///
    /// Note: This creates a Legacy transaction. For EIP-1559, use `build_eip1559_transaction`.
    ///
    /// # Arguments
    /// * `nonce` - Transaction nonce
    /// * `gas_limit` - Gas limit (required)
    /// * `gas_price` - Gas price (required for legacy tx)
    ///
    /// # Returns
    /// An unsigned Transaction ready to be signed
    pub fn build_legacy_transaction(
        &self,
        nonce: Uint256,
        gas_limit: Uint256,
        gas_price: Uint256,
    ) -> Result<Transaction, Web3Error> {
        self.validate()?;

        Ok(Transaction::Legacy {
            nonce,
            gas_price,
            gas_limit,
            to: Address::default(), // Zero address for deployment
            value: self.value,
            data: self.init_code.clone(),
            signature: None,
        })
    }

    /// Build an unsigned EIP-1559 transaction for the deployment.
    ///
    /// # Arguments
    /// * `chain_id` - Network chain ID
    /// * `nonce` - Transaction nonce
    /// * `gas_limit` - Gas limit
    /// * `max_fee_per_gas` - Maximum fee per gas
    /// * `max_priority_fee_per_gas` - Maximum priority fee
    ///
    /// # Returns
    /// An unsigned Transaction ready to be signed
    pub fn build_eip1559_transaction(
        &self,
        chain_id: Uint256,
        nonce: Uint256,
        gas_limit: Uint256,
        max_fee_per_gas: Uint256,
        max_priority_fee_per_gas: Uint256,
    ) -> Result<Transaction, Web3Error> {
        self.validate()?;

        Ok(Transaction::Eip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: Address::default(), // Zero address for deployment
            value: self.value,
            data: self.init_code.clone(),
            signature: None,
            access_list: Vec::new(),
        })
    }

    /// Get the deployer address
    pub fn deployer(&self) -> Address {
        self.deployer
    }

    /// Get the init code
    pub fn init_code(&self) -> &[u8] {
        &self.init_code
    }

    /// Get the value to send
    pub fn value(&self) -> Uint256 {
        self.value
    }

    /// Get the configured gas limit
    pub fn gas_limit(&self) -> Option<Uint256> {
        self.gas_limit
    }

    /// Get the configured gas price
    pub fn gas_price(&self) -> Option<Uint256> {
        self.gas_price
    }

    /// Get the configured nonce
    pub fn nonce(&self) -> Option<Uint256> {
        self.nonce
    }

    /// Get the configured chain ID
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80, 0x60, 0x40];

        let builder = ContractDeploymentBuilder::new(deployer, init_code.clone());

        assert_eq!(builder.deployer(), deployer);
        assert_eq!(builder.init_code(), &init_code);
        assert_eq!(builder.value(), Uint256::from(0u8));
    }

    #[test]
    fn test_builder_with_constructor_args() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80];
        let constructor_args = vec![0x00, 0x01, 0x02];

        let builder = ContractDeploymentBuilder::new(deployer, init_code.clone())
            .with_constructor_args(constructor_args.clone());

        let mut expected = init_code;
        expected.extend(constructor_args);
        assert_eq!(builder.init_code(), &expected);
    }

    #[test]
    fn test_builder_fluent_api() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80];

        let builder = ContractDeploymentBuilder::new(deployer, init_code)
            .with_value(Uint256::from(1000u64))
            .with_gas_limit(Uint256::from(3_000_000u64))
            .with_gas_price(Uint256::from(20_000_000_000u64))
            .with_nonce(Uint256::from(5u8))
            .with_chain_id(1);

        assert_eq!(builder.value(), Uint256::from(1000u64));
        assert_eq!(builder.gas_limit(), Some(Uint256::from(3_000_000u64)));
        assert_eq!(builder.gas_price(), Some(Uint256::from(20_000_000_000u64)));
        assert_eq!(builder.nonce(), Some(Uint256::from(5u8)));
        assert_eq!(builder.chain_id(), Some(1));
    }

    #[test]
    fn test_predict_address() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let init_code = vec![0x60, 0x80];

        let builder =
            ContractDeploymentBuilder::new(deployer, init_code).with_nonce(Uint256::from(0u8));

        let predicted = builder.predict_address(None).unwrap();
        let expected: Address = "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
            .parse()
            .unwrap();

        assert_eq!(predicted, expected);
    }

    #[test]
    fn test_predict_address_with_override() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let init_code = vec![0x60, 0x80];

        let builder =
            ContractDeploymentBuilder::new(deployer, init_code).with_nonce(Uint256::from(0u8));

        // Override with nonce 1
        let predicted = builder.predict_address(Some(Uint256::from(1u8))).unwrap();
        let expected: Address = "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"
            .parse()
            .unwrap();

        assert_eq!(predicted, expected);
    }

    #[test]
    fn test_predict_address_no_nonce_error() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let init_code = vec![0x60, 0x80];

        let builder = ContractDeploymentBuilder::new(deployer, init_code);

        let result = builder.predict_address(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_success() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60; 1000]; // 1KB, well within limits

        let builder = ContractDeploymentBuilder::new(deployer, init_code);

        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_init_code_too_large() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60; 50_000]; // 50KB, exceeds limit

        let builder = ContractDeploymentBuilder::new(deployer, init_code);

        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_validate_priority_fee_exceeds_max_fee() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80];

        let builder = ContractDeploymentBuilder::new(deployer, init_code)
            .with_eip1559_fees(Uint256::from(10u8), Uint256::from(20u8)); // priority > max

        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_build_legacy_transaction() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80];

        let builder = ContractDeploymentBuilder::new(deployer, init_code.clone());

        let tx = builder
            .build_legacy_transaction(
                Uint256::from(5u8),
                Uint256::from(3_000_000u64),
                Uint256::from(20_000_000_000u64),
            )
            .unwrap();

        match tx {
            Transaction::Legacy {
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                signature,
            } => {
                assert_eq!(nonce, Uint256::from(5u8));
                assert_eq!(gas_price, Uint256::from(20_000_000_000u64));
                assert_eq!(gas_limit, Uint256::from(3_000_000u64));
                assert_eq!(to, Address::default());
                assert_eq!(value, Uint256::from(0u8));
                assert_eq!(data, init_code);
                assert!(signature.is_none());
            }
            _ => panic!("Expected Legacy transaction"),
        }
    }

    #[test]
    fn test_build_eip1559_transaction() {
        let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".parse().unwrap();
        let init_code = vec![0x60, 0x80];

        let builder = ContractDeploymentBuilder::new(deployer, init_code.clone())
            .with_value(Uint256::from(1000u64));

        let tx = builder
            .build_eip1559_transaction(
                Uint256::from(1u8),
                Uint256::from(5u8),
                Uint256::from(3_000_000u64),
                Uint256::from(30_000_000_000u64),
                Uint256::from(2_000_000_000u64),
            )
            .unwrap();

        match tx {
            Transaction::Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                signature,
                access_list,
            } => {
                assert_eq!(chain_id, Uint256::from(1u8));
                assert_eq!(nonce, Uint256::from(5u8));
                assert_eq!(max_priority_fee_per_gas, Uint256::from(2_000_000_000u64));
                assert_eq!(max_fee_per_gas, Uint256::from(30_000_000_000u64));
                assert_eq!(gas_limit, Uint256::from(3_000_000u64));
                assert_eq!(to, Address::default());
                assert_eq!(value, Uint256::from(1000u64));
                assert_eq!(data, init_code);
                assert!(signature.is_none());
                assert!(access_list.is_empty());
            }
            _ => panic!("Expected EIP1559 transaction"),
        }
    }
}
