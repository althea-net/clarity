# Clarity

[![Build Status](https://travis-ci.org/althea-net/clarity.svg?branch=master)](https://travis-ci.org/althea-net/clarity)
[![Latest Version](https://img.shields.io/crates/v/clarity.svg)](https://crates.io/crates/clarity)
[![Documentation](https://docs.rs/clarity/badge.svg)](https://docs.rs/clarity)

A lightweight, cross-compile friendly Ethereum client written in Rust.

# Getting Started

See the docs for the API and some usage examples.

# TODO

Update tests/fixtures submodule to Ethereum v7.0.1 and fix the 19 failing conditions

    TransactionTests/ttEIP2028/DataTestSufficientGas2028.json@>=Istanbul@valid
    TransactionTests/ttGasLimit/TransactionWithHighGas.json@>=Constantinople,EIP158,Byzantium,EIP150,Homestead@invalid
    TransactionTests/ttGasLimit/TransactionWithHihghGasLimit63m1.json@Byzantium,>=Constantinople,EIP158@valid
    TransactionTests/ttRSValue/TransactionWithSvalueHigh.json@>=Homestead@invalid
    TransactionTests/ttRSValue/TransactionWithSvalueLargerThan_c_secp256k1n_x05.json@>=Homestead@invalid
    TransactionTests/ttSignature/Vitalik_1.json@EIP158,Byzantium,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_10.json@>=Constantinople,Byzantium,EIP158@valid
    TransactionTests/ttSignature/Vitalik_11.json@>=Constantinople,EIP158,Byzantium@valid
    TransactionTests/ttSignature/Vitalik_2.json@EIP158,Byzantium,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_3.json@Byzantium,EIP158,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_4.json@Byzantium,EIP158,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_5.json@Byzantium,>=Constantinople,EIP158@valid
    TransactionTests/ttSignature/Vitalik_6.json@Byzantium,EIP158,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_7.json@>=Constantinople,EIP158,Byzantium@valid
    TransactionTests/ttSignature/Vitalik_8.json@Byzantium,EIP158,>=Constantinople@valid
    TransactionTests/ttSignature/Vitalik_9.json@>=Constantinople,EIP158,Byzantium@valid
    TransactionTests/ttVValue/V_equals37.json@EIP158,Byzantium,>=Constantinople@valid
    TransactionTests/ttVValue/V_equals38.json@>=Constantinople,Byzantium,EIP158@valid
    TransactionTests/ttVValue/V_overflow64bitSigned.json@EIP158,Homestead,EIP150,>=Constantinople,Byzantium@invalid
