# Clarity

[![Latest Version](https://img.shields.io/crates/v/clarity.svg)](https://crates.io/crates/clarity)
[![Documentation](https://docs.rs/clarity/badge.svg)](https://docs.rs/clarity)

A lightweight, cross-compile friendly non-consensus Ethereum client written in Rust. Clarity will assist with the encoding/decoding of transactions, contracts, functions, and arguments.

The goal of Clarity is to be extremely simple and barebones in terms of implementation while maintaining the maximum amount of flexibility and capability.

Our implementation philosophy is that it is up to the developer to understand the [Ethereum ABI](https://docs.soliditylang.org/en/develop/abi-spec.html) at a low level and produce the correct inputs. Clarity prevents foot-gun moments from actually occurring with panics but does not attempt to implement a full ABI parser or contract definition parsing. It's up to the user to provide the right snippets for their function calls and events themselves.

This library is capable of decoding all transactions after Frontier and Homestead hardforks before that some transactions will not pass validation.

## Features

* **Transaction Creation & Signing**: Support for Legacy, EIP-2930, and EIP-1559 transactions
* **ABI Encoding**: Encode function calls and constructor arguments
* **Contract Deployment**: Calculate contract addresses and deploy contracts
* **Address Prediction**: Support for both CREATE and CREATE2 address calculation
* **Transaction Validation**: Comprehensive validation including EIP-3860 init code limits
* **Cross-platform**: Works on any endianness (32/64-bit)

# Web30
[![Latest Version](https://img.shields.io/crates/v/web30.svg)](https://crates.io/crates/web30)
[![Documentation](https://docs.rs/clarity/web30.svg)](https://docs.rs/web30)

Web30 is a equally lightweight rpc client for Ethereum to be paired with Clarity, the goal of this client is to be a minimalist async interface for sending transactions and querying chain state.

## Features

* **Contract Deployment**: High-level API for deploying smart contracts
* **Gas Estimation**: Automatic gas estimation for transactions
* **Transaction Management**: Nonce management and transaction confirmation
* **Web3 RPC**: Essential Ethereum JSON-RPC methods

# Getting Started

## Contract Deployment Example

```rust
use clarity::{PrivateKey, Uint256};
use web30::client::Web3;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let web3 = Web3::new("https://eth.llamarpc.com", Duration::from_secs(30));
    let private_key: PrivateKey = "0x...".parse().unwrap();
    
    // Contract bytecode from solc
    let init_code = hex::decode("608060...").unwrap();
    
    // Deploy contract
    let contract_address = web3.deploy_contract(
        &private_key,
        init_code,
        vec![], // Constructor arguments
        Uint256::from(0u8), // ETH value
        vec![], // Options
    ).await.unwrap();
    
    println!("Contract deployed at: {}", contract_address);
}
```

## Address Prediction Example

```rust
use clarity::{calculate_contract_address, Address, Uint256};

fn main() {
    let deployer: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
        .parse()
        .unwrap();
    let nonce = Uint256::from(5u8);
    
    let contract_address = calculate_contract_address(deployer, nonce);
    println!("Contract will deploy to: {}", contract_address);
}
```

See the `examples/` directory for more detailed examples.

# Ethereum test case status

Currently all Ethereum test cases pass with two exceptions.

* Specs not currently implemented EIP2023 and EIP3860
* tr201506052141PYTHON which is supposed to fail, but Geth accepts as valid
