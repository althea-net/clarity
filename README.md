# Clarity

[![Latest Version](https://img.shields.io/crates/v/clarity.svg)](https://crates.io/crates/clarity)
[![Documentation](https://docs.rs/clarity/badge.svg)](https://docs.rs/clarity)

A lightweight, cross-compile friendly non-consensus Ethereum client written in Rust. Clarity will assist with the encoding/decoding of transactions, contracts, functions, and arguments.

The goal of Clarity is to be extremely simple and barebones in terms of implementation while maintaining the maximum amount of flexibility and capability.

Our implementation philosophy is that it is up to the developer to understand the [Ethereum ABI](https://docs.soliditylang.org/en/develop/abi-spec.html) at a low level and produce the correct inputs. Clarity prevents foot-gun moments from actually occurring with panics but does not attempt to implement a full ABI parser or contract definition parsing. It's up to the user to provide the right snippets for their function calls and events themselves.

This library is capable of decoding all transactions after Frontier and Homestead hardforks before that some transactions will not pass validation.

# Web30

[![Latest Version](https://img.shields.io/crates/v/web30.svg)](https://crates.io/crates/web30)
[![Documentation](https://docs.rs/clarity/web30.svg)](https://docs.rs/web30)

Web30 is a equally lightweight rpc client for Ethereum to be paired with Clarity, the goal of this client is to be a minimalist async interface for sending transactions and querying chain state.

# Soliloquy

Soliloquy is the Solidity interaction layer for Clarity and Web30. It features elements copied from the alloy ecosystem like a solidity compatible macro for automatically generating objects to interact with Contracts from Rust.

# Getting Started

See the docs for the API and some usage examples.

# Ethereum test case status

Currently all Ethereum test cases pass with two exceptions.

* Specs not currently implemented EIP2023 and EIP3860
* tr201506052141PYTHON which is supposed to fail, but Geth accepts as valid
