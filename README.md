# Clarity

[![Latest Version](https://img.shields.io/crates/v/clarity.svg)](https://crates.io/crates/clarity)
[![Documentation](https://docs.rs/clarity/badge.svg)](https://docs.rs/clarity)

A lightweight, cross-compile friendly non-consensus Ethereum client written in Rust. Clarity will assist with the encoding/decoding of transactions, contracts, functions, and arguments.

The goal of Clarity is to be extremely simple and barebones in terms of implementation while maintaining the maximum amount of flexibility and capability.

Our implementation philosophy is that it is up to the developer to understand the [Ethereum ABI](https://docs.soliditylang.org/en/develop/abi-spec.html) at a low level and produce the correct inputs. Clarity prevents foot-gun moments from actually occurring with panics but does not attempt to implement a full ABI parser or contract definition parsing. It's up to the user to provide the right snippets for their function calls and events themselves.

This library is capable of decoding all transactions after Frontier and Homestead hardforks before that some transactions will not pass validation.

# Getting Started

See the docs for the API and some usage examples.

# Ethereum test case status

Update fix Ethereum test fixtures v8.0.5 4/201 cases failing. There are many consensus test cases that this suite passes but not in a functional way since this isn't a consensus participating client.

Requires improvements to our gas and op code parsing

    TransactionTests/ttGasLimit/TransactionWithHighGas.json@>=Constantinople,EIP158,Byzantium,EIP150,Homestead@invalid

The value in these tests is not exactly secp256k1n but is instead 2^255, double check tests are correct

    TransactionTests/ttRSValue/TransactionWithSvalueHigh.json@>=Homestead@invalid
    TransactionTests/ttRSValue/TransactionWithSvalueLargerThan_c_secp256k1n_x05.json@>=Homestead@invalid

The V value in this test seems to be a perfectly valid 28, parsing error on our end?

    TransactionTests/ttVValue/V_overflow64bitSigned.json@EIP158,Byzantium,Homestead,EIP150,>=Constantinople@invalid
