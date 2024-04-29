//! This module contains utility functions for interacting with ERC721 tokens and contracts
use crate::jsonrpc::error::Web3Error;
use crate::types::TransactionRequest;
use crate::{client::Web3, types::SendTxOption};
use clarity::constants::zero_address;
use clarity::Address as EthAddress;
use clarity::{abi::encode_call, PrivateKey as EthPrivateKey};
use clarity::{abi::AbiToken, Address, Uint256};
use std::time::Duration;
use tokio::time::timeout as future_timeout;

pub static ERC721_GAS_LIMIT: u128 = 100_000;

impl Web3 {
    /// Executes EIP-721 getApproved(uint256 _tokenId) external view returns (address)
    /// Checks if any given contract is approved to spend money from any given erc721 contract
    /// using any given address. What exactly this does can be hard to grok, essentially when
    /// you want contract A to be able to spend your erc721 contract funds you need to call 'approve'
    /// on the ERC721 contract with your own address and A's address so that in the future when you call
    /// contract A it can move the ERC721 token. This function checks if that has already been done.
    pub async fn check_erc721_approved(
        &self,
        erc721: Address,
        own_address: Address,
        token_id: Uint256,
    ) -> Result<Option<EthAddress>, Web3Error> {
        let payload = encode_call("getApproved(uint256)", &[AbiToken::Uint(token_id)])?;

        let val = self
            .simulate_transaction(
                TransactionRequest::quick_tx(own_address, erc721, payload),
                None,
            )
            .await?;

        let mut data: [u8; 20] = Default::default();
        data.copy_from_slice(&val[12..]);
        let owner_address = EthAddress::from_slice(&data);

        match owner_address {
            Ok(address_response) => {
                if address_response == zero_address() {
                    Ok(None)
                } else {
                    Ok(Some(address_response))
                }
            }
            Err(e) => Err(Web3Error::BadResponse(e.to_string())),
        }
    }

    /// Executes EIP-721 approve(address,uint256)
    /// Approves `spender` to transfer the `erc721` token with id `token_id` held by `owner`.
    /// Allowances are used by protocols to manage tokens on the user's behalf, users first approve a contract
    /// to spend their tokens and then call the desired contract function.
    /// This function performs that action and waits for it to complete for up to `timeout` duration
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    pub async fn approve_erc721_transfers(
        &self,
        erc721: Address,
        owner_key: EthPrivateKey,
        spender: Address,
        token_id: Uint256,
        timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        // function approve(address _approved, uint256 _tokenId)
        let payload = encode_call(
            "approve(address,uint256)",
            &[spender.into(), AbiToken::Uint(token_id)],
        )?;

        let tx = self
            .prepare_transaction(erc721, payload, 0u32.into(), owner_key, options)
            .await?;
        let txid = self.eth_send_raw_transaction(tx.to_bytes()).await?;

        // wait for transaction to enter the chain if the user has requested it
        if let Some(timeout) = timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }

    /// Approves `to_approve` to transfer any tokens owned by `approver` on the `erc721_address` contract
    /// Allowances are used by protocols to manage tokens on the user's behalf, users first approve a contract
    /// to spend their tokens and then call the desired contract function.
    /// This function performs that action for all held tokens and waits for it to complete for up to `timeout` duration
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    pub async fn approve_erc721_for_all(
        &self,
        erc721_address: EthAddress,
        approver: EthPrivateKey,
        to_approve: EthAddress,
        timeout: Option<Duration>,
    ) -> Result<Uint256, Web3Error> {
        // ABI: setApprovalForAll(address operator, bool _approved) external
        let payload = clarity::abi::encode_call(
            "setApprovalForAll(address,bool)",
            &[to_approve.into(), true.into()],
        )?;

        let tx = self
            .prepare_transaction(erc721_address, payload, 0u8.into(), approver, vec![])
            .await?;
        let txid = self.eth_send_raw_transaction(tx.to_bytes()).await?;

        // wait for transaction to enter the chain if the user has requested it
        if let Some(timeout) = timeout {
            future_timeout(timeout, self.wait_for_transaction(txid, timeout, None)).await??;
        }

        Ok(txid)
    }
    /// Executes EIP-721 transferFrom(address _from, address _to, uint256 _tokenId)
    /// Send an erc721 token to the target address, optionally wait until it enters the blockchain
    /// `options` takes a vector of `SendTxOption` for configuration
    /// unlike the lower level eth_send_transaction() this call builds
    /// the transaction abstracting away details like chain id, gas,
    /// and network id.
    /// WARNING: you must specify networkID in situations where a single
    /// node is operating no more than one chain. Otherwise it is possible
    /// for the full node to trick the client into signing transactions
    /// on unintended chains potentially to their benefit
    pub async fn erc721_send(
        &self,
        recipient: Address,
        erc721: Address,
        token_id: Uint256,
        sender_private_key: EthPrivateKey,
        wait_timeout: Option<Duration>,
        options: Vec<SendTxOption>,
    ) -> Result<Uint256, Web3Error> {
        let sender_address = sender_private_key.to_address();

        let mut has_gas_limit = false;
        let mut options = options;
        for option in options.iter() {
            if let SendTxOption::GasLimit(_) = option {
                has_gas_limit = true;
                break;
            }
        }
        if !has_gas_limit {
            options.push(SendTxOption::GasLimit(ERC721_GAS_LIMIT.into()));
        }
        let tx = self
            .prepare_transaction(
                erc721,
                encode_call(
                    "transferFrom(address,address,uint256)",
                    &[
                        sender_address.into(),
                        recipient.into(),
                        AbiToken::Uint(token_id),
                    ],
                )?,
                0u32.into(),
                sender_private_key,
                options,
            )
            .await?;
        let tx_hash = self.eth_send_raw_transaction(tx.to_bytes()).await?;

        if let Some(timeout) = wait_timeout {
            future_timeout(timeout, self.wait_for_transaction(tx_hash, timeout, None)).await??;
        }

        Ok(tx_hash)
    }

    /// Executes EIP-721 name() external view returns (string _name)
    /// Here we make a call using the EIP-721 standard, it will return a
    /// string representing ERC721 name or Web3Error::ContractCallError
    pub async fn get_erc721_name(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("name()", &[])?;
        let name = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc721, payload),
                None,
            )
            .await?;

        match String::from_utf8(name) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    /// Executes EIP-721 symbol() external view returns (string _symbol)
    /// Here we make a call using the EIP-721 standard, it will return a
    /// string representing ERC721 symbol or Web3Error::ContractCallError
    pub async fn get_erc721_symbol(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("symbol()", &[])?;
        let symbol = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc721, payload),
                None,
            )
            .await?;

        match String::from_utf8(symbol) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    /// Executes EIP-721 totalSupply() external view returns (uint256)
    /// Here we make a call using the EIP-721 standard, it will return a
    /// Uint256 representing ERC721 supply or Web3Error::ContractCallError
    pub async fn get_erc721_supply(
        &self,
        erc721: Address,
        caller_address: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("totalSupply()", &[])?;
        let decimals = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc721, payload),
                None,
            )
            .await?;

        Ok(Uint256::from_be_bytes(match decimals.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC721 Total Supply".to_string(),
                ))
            }
        }))
    }

    /// Executes EIP-721 tokenURI(uint256 _tokenId) external view returns (string);
    /// Here we make a call using the EIP-721 standard, it will return a
    /// string representing ERC721 URI or Web3Error::ContractCallError
    pub async fn get_erc721_uri(
        &self,
        erc721: Address,
        caller_address: Address,
        token_id: Uint256,
    ) -> Result<String, Web3Error> {
        let payload = encode_call("tokenURI(uint256)", &[AbiToken::Uint(token_id)])?;
        let symbol = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc721, payload),
                None,
            )
            .await?;

        match String::from_utf8(symbol) {
            Ok(mut val) => {
                // the value returned is actually in Ethereum ABI encoded format
                // stripping control characters is an easy way to strip off the encoding
                val.retain(|v| !v.is_control());
                let val = val.trim().to_string();
                Ok(val)
            }
            Err(_e) => Err(Web3Error::ContractCallError(
                "name is not valid utf8".to_string(),
            )),
        }
    }

    /// Executes EIP-721 ownerOf(uint256 _tokenId) external view returns (address)
    /// Here we make a call using the EIP-721 standard, it will return a
    /// string representing ERC721 owner or Web3Error::ContractCallError
    pub async fn get_erc721_owner_of(
        &self,
        erc721: Address,
        own_address: Address,
        token_id: Uint256,
    ) -> Result<EthAddress, Web3Error> {
        let payload = encode_call("ownerOf(uint256)", &[AbiToken::Uint(token_id)])?;

        let val = self
            .simulate_transaction(
                TransactionRequest::quick_tx(own_address, erc721, payload),
                None,
            )
            .await?;

        let mut data: [u8; 20] = Default::default();
        data.copy_from_slice(&val[12..]);
        let owner_address = EthAddress::from_slice(&data);

        match owner_address {
            Ok(address_response) => Ok(address_response),
            Err(e) => Err(Web3Error::BadResponse(e.to_string())),
        }
    }
}

#[test]
fn test_erc721_metadata() {
    use actix::System;
    let runner = System::new();
    let web3 = Web3::new("https://eth.althea.net", Duration::from_secs(30));
    let bayc_address = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D"
        .parse()
        .unwrap();
    // random coinbase address hoping it always has eth to 'pay' for this call
    let caller_address = "0x503828976D22510aad0201ac7EC88293211D23Da"
        .parse()
        .unwrap();
    let token_id = 1039_i32;
    let token_id_uint = Uint256::from_be_bytes(&token_id.to_be_bytes());
    let token_id_uri = ":ipfs://QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/1039";
    runner.block_on(async move {
        let num: Uint256 = 1000u32.into();
        assert!(
            web3.get_erc721_supply(bayc_address, caller_address)
                .await
                .unwrap()
                > num
        );
        assert_eq!(
            web3.get_erc721_symbol(bayc_address, caller_address)
                .await
                .unwrap(),
            "BAYC"
        );
        assert_eq!(
            web3.get_erc721_name(bayc_address, caller_address)
                .await
                .unwrap(),
            "BoredApeYachtClub"
        );
        assert_eq!(
            web3.get_erc721_uri(bayc_address, caller_address, token_id_uint)
                .await
                .unwrap(),
            token_id_uri
        );
    })
}
