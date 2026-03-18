//! Contract deployment utilities
//!
//! This module provides functions for calculating contract addresses and working with
//! contract deployment transactions on Ethereum.
//!
//! ## Address Calculation
//!
//! Ethereum uses two methods for calculating contract addresses:
//!
//! ### CREATE (Traditional)
//! The contract address is calculated from the deployer's address and nonce:
//! ```text
//! address = keccak256(rlp([sender_address, sender_nonce]))[12:]
//! ```
//!
//! ### CREATE2 (EIP-1014)
//! The contract address is calculated deterministically from:
//! - Deployer address
//! - A salt value
//! - The initialization code hash
//!
//! ```text
//! address = keccak256(0xff ++ sender_address ++ salt ++ keccak256(init_code))[12:]
//! ```

use crate::address::Address;
use crate::rlp::{pack_rlp, RlpToken};
use num256::Uint256;
use sha3::{Digest, Keccak256};

/// Calculate the contract address that will be created using the CREATE opcode.
///
/// This function implements the standard Ethereum contract address derivation
/// algorithm based on the deployer's address and their transaction nonce.
///
/// # Formula
/// ```text
/// address = keccak256(rlp([deployer_address, nonce]))[12:]
/// ```
///
/// # Arguments
/// * `deployer` - The address that will deploy the contract
/// * `nonce` - The nonce of the deployer at deployment time
///
/// # Returns
/// The 20-byte address where the contract will be deployed
///
/// # Examples
/// ```
/// use clarity::{Address, Uint256};
/// use clarity::contract::calculate_contract_address;
///
/// let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0".parse().unwrap();
/// let nonce = Uint256::from(0u8);
/// let contract_addr = calculate_contract_address(deployer, nonce);
/// assert_eq!(
///     contract_addr,
///     "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d".parse().unwrap()
/// );
/// ```
pub fn calculate_contract_address(deployer: Address, nonce: Uint256) -> Address {
    // RLP encode [address, nonce]
    let rlp_data = pack_rlp(vec![
        RlpToken::String(deployer.as_bytes().to_vec()),
        RlpToken::from(nonce),
    ]);

    // Hash the RLP encoded data
    let hash = Keccak256::digest(&rlp_data);

    // Take the last 20 bytes as the address
    Address::from_slice(&hash[12..]).expect("Slice is exactly 20 bytes")
}

/// Calculate the contract address that will be created using the CREATE2 opcode (EIP-1014).
///
/// CREATE2 allows for deterministic contract addresses that don't depend on the deployer's
/// nonce, making them predictable before deployment.
///
/// # Formula
/// ```text
/// address = keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]
/// ```
///
/// # Arguments
/// * `deployer` - The address that will deploy the contract
/// * `salt` - A 32-byte value chosen by the deployer
/// * `init_code_hash` - The keccak256 hash of the contract's initialization code
///
/// # Returns
/// The 20-byte address where the contract will be deployed
///
/// # Examples
/// ```
/// use clarity::{Address, Uint256};
/// use clarity::contract::calculate_contract_address_create2;
///
/// let deployer: Address = "0x0000000000000000000000000000000000000000".parse().unwrap();
/// let salt = [0u8; 32];
/// let init_code_hash = [0u8; 32];
/// let contract_addr = calculate_contract_address_create2(deployer, salt, init_code_hash);
/// ```
pub fn calculate_contract_address_create2(
    deployer: Address,
    salt: [u8; 32],
    init_code_hash: [u8; 32],
) -> Address {
    // Build: 0xff ++ address ++ salt ++ init_code_hash
    let mut data = Vec::with_capacity(85);
    data.push(0xff);
    data.extend_from_slice(deployer.as_bytes());
    data.extend_from_slice(&salt);
    data.extend_from_slice(&init_code_hash);

    // Hash the concatenated data
    let hash = Keccak256::digest(&data);

    // Take the last 20 bytes as the address
    Address::from_slice(&hash[12..]).expect("Slice is exactly 20 bytes")
}

/// Hash the contract initialization code using Keccak256.
///
/// This is a helper function for use with CREATE2, as the init code hash
/// is required for address calculation.
///
/// # Arguments
/// * `init_code` - The contract's initialization code (bytecode + constructor args)
///
/// # Returns
/// The 32-byte keccak256 hash of the init code
///
/// # Examples
/// ```
/// use clarity::contract::hash_init_code;
///
/// let init_code = vec![0x60, 0x80, 0x60, 0x40]; // Simple bytecode
/// let hash = hash_init_code(&init_code);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash_init_code(init_code: &[u8]) -> [u8; 32] {
    let hash = Keccak256::digest(init_code);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Validate that init code size is within EIP-3860 limits.
///
/// EIP-3860 limits the maximum init code size to 49,152 bytes (0xc000).
/// This prevents DOS attacks via extremely large contract deployments.
///
/// # Arguments
/// * `init_code` - The initialization code to validate
///
/// # Returns
/// `true` if the init code size is valid, `false` otherwise
///
/// # Examples
/// ```
/// use clarity::contract::validate_init_code_size;
///
/// let valid_code = vec![0u8; 1000]; // 1KB is fine
/// assert!(validate_init_code_size(&valid_code));
///
/// let invalid_code = vec![0u8; 50_000]; // Too large
/// assert!(!validate_init_code_size(&invalid_code));
/// ```
pub fn validate_init_code_size(init_code: &[u8]) -> bool {
    const MAX_INIT_CODE_SIZE: usize = 49_152; // 0xc000 bytes
    init_code.len() <= MAX_INIT_CODE_SIZE
}

/// Calculate the EIP-3860 init code gas cost.
///
/// EIP-3860 charges 2 gas per 32-byte word of init code.
/// This is charged on top of the regular data gas costs.
///
/// # Arguments
/// * `init_code_size` - The size of the init code in bytes
///
/// # Returns
/// The gas cost for the init code
///
/// # Examples
/// ```
/// use clarity::contract::calculate_init_code_gas;
/// use clarity::Uint256;
///
/// let gas = calculate_init_code_gas(100); // 100 bytes
/// assert_eq!(gas, Uint256::from(8u8)); // 4 words * 2 gas
/// ```
pub fn calculate_init_code_gas(init_code_size: usize) -> Uint256 {
    const GAS_PER_WORD: u64 = 2;
    const WORD_SIZE: usize = 32;

    // Calculate number of words, rounding up
    let words = init_code_size.div_ceil(WORD_SIZE);
    Uint256::from(words as u64) * Uint256::from(GAS_PER_WORD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_hex_str;

    #[test]
    fn test_calculate_contract_address_nonce_0() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let nonce = Uint256::from(0u8);
        let expected: Address = "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
            .parse()
            .unwrap();

        let result = calculate_contract_address(deployer, nonce);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_contract_address_nonce_1() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let nonce = Uint256::from(1u8);
        let expected: Address = "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"
            .parse()
            .unwrap();

        let result = calculate_contract_address(deployer, nonce);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_contract_address_nonce_2() {
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let nonce = Uint256::from(2u8);
        let expected: Address = "0xf778b86fa74e846c4f0a1fbd1335fe81c00a0c91"
            .parse()
            .unwrap();

        let result = calculate_contract_address(deployer, nonce);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_contract_address_high_nonce() {
        // Test with a larger nonce value
        let deployer: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse()
            .unwrap();
        let nonce = Uint256::from(1000u32);

        // Should not panic and should return a valid address
        let result = calculate_contract_address(deployer, nonce);
        assert_eq!(result.as_bytes().len(), 20);
    }

    #[test]
    fn test_calculate_contract_address_create2_zero() {
        // Test vector from EIP-1014
        let deployer: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let salt = [0u8; 32];
        let init_code_hash = [0u8; 32];
        let expected: Address = "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38"
            .parse()
            .unwrap();

        let result = calculate_contract_address_create2(deployer, salt, init_code_hash);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_contract_address_create2_custom() {
        let deployer: Address = "0xdeadbeef00000000000000000000000000000000"
            .parse()
            .unwrap();
        let salt = [0u8; 32];
        let init_code_hash = [0u8; 32];
        let expected: Address = "0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e"
            .parse()
            .unwrap();

        let result = calculate_contract_address_create2(deployer, salt, init_code_hash);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_contract_address_create2_different_salt() {
        let deployer: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let mut salt = [0u8; 32];
        salt[31] = 1; // Different salt
        let init_code_hash = [0u8; 32];

        let result1 = calculate_contract_address_create2(deployer, [0u8; 32], init_code_hash);
        let result2 = calculate_contract_address_create2(deployer, salt, init_code_hash);

        // Different salts should produce different addresses
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_hash_init_code() {
        let init_code = vec![0x60, 0x80, 0x60, 0x40, 0x52];
        let hash = hash_init_code(&init_code);

        // Should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Should be deterministic
        let hash2 = hash_init_code(&init_code);
        assert_eq!(hash, hash2);

        // Different code should produce different hash
        let different_code = vec![0x60, 0x80, 0x60, 0x40, 0x53];
        let hash3 = hash_init_code(&different_code);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash_init_code_empty() {
        let init_code = vec![];
        let hash = hash_init_code(&init_code);
        assert_eq!(hash.len(), 32);

        // Empty input should produce known hash
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(bytes_to_hex_str(&hash), expected);
    }

    #[test]
    fn test_validate_init_code_size_valid() {
        let code = vec![0u8; 1000]; // 1KB
        assert!(validate_init_code_size(&code));

        let code = vec![0u8; 49_152]; // Exactly at limit
        assert!(validate_init_code_size(&code));
    }

    #[test]
    fn test_validate_init_code_size_invalid() {
        let code = vec![0u8; 49_153]; // One byte over
        assert!(!validate_init_code_size(&code));

        let code = vec![0u8; 100_000]; // Way over
        assert!(!validate_init_code_size(&code));
    }

    #[test]
    fn test_validate_init_code_size_empty() {
        let code = vec![];
        assert!(validate_init_code_size(&code));
    }

    #[test]
    fn test_calculate_init_code_gas() {
        // 0 bytes = 0 words = 0 gas
        assert_eq!(calculate_init_code_gas(0), Uint256::from(0u8));

        // 1-32 bytes = 1 word = 2 gas
        assert_eq!(calculate_init_code_gas(1), Uint256::from(2u8));
        assert_eq!(calculate_init_code_gas(32), Uint256::from(2u8));

        // 33-64 bytes = 2 words = 4 gas
        assert_eq!(calculate_init_code_gas(33), Uint256::from(4u8));
        assert_eq!(calculate_init_code_gas(64), Uint256::from(4u8));

        // 100 bytes = 4 words = 8 gas
        assert_eq!(calculate_init_code_gas(100), Uint256::from(8u8));

        // 1000 bytes = 32 words = 64 gas
        assert_eq!(calculate_init_code_gas(1000), Uint256::from(64u8));
    }

    #[test]
    fn test_calculate_init_code_gas_max_size() {
        // Max init code size (49,152 bytes) = 1536 words = 3072 gas
        assert_eq!(calculate_init_code_gas(49_152), Uint256::from(3072u64));
    }
}
