# Clarity

[![Build Status](https://travis-ci.org/althea-mesh/clarity.svg?branch=master)](https://travis-ci.org/althea-mesh/clarity)

Clarity is a Lightweight Ethereum transaction generation library written in Rust designed to run on IOT devices with ram and storage in the single to double digit megabytes.

It was not originally our intention to build a new client of any sort. There are many existing clients Geth, Parity, Aleth, surely at least one would be appropriate?

There are a number of very common development assumptions in desktop Ethereum clients.

- assembly optimized cryptography instructions
- the existance of an FPU
- 64 bit integer size
- little endian byteorder

These are universally valid assumptions on modern desktops, phones, and tablets. So they
sneak into dependencies, or dependencies of dependencies without anyone noticing. Attempting to patch or review the entire dependency tree of any major client was sisyphean.

Clarity's design philospohy is as follows

- maximize architecture portability by using pure Rust
- keep the feature set small and easy to use
- Testing against a large variety of architectures as standard practice

## Usage
