use clarity::{abi::encode_call, utils::bytes_to_hex_str, Address};
use num256::Uint256;
use num_traits::ToPrimitive;

use crate::{
    client::Web3,
    jsonrpc::error::Web3Error,
    types::{Eip712Domain, TransactionRequest},
};

impl Web3 {
    /// Calls the `nonces()` function on the ERC20 (implementing ERC2612) contract for use with the permit function.
    pub async fn get_erc20_nonces(
        &self,
        erc20: Address,
        owner: Address,
        caller_address: Address,
    ) -> Result<Uint256, Web3Error> {
        let payload = encode_call("nonces(address)", &[owner.into()])?;
        let nonces = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                None,
            )
            .await?;

        Ok(Uint256::from_be_bytes(match nonces.get(0..32) {
            Some(val) => val,
            None => {
                return Err(Web3Error::ContractCallError(
                    "Bad response from ERC20 Nonces".to_string(),
                ))
            }
        }))
    }

    /// Calls the `eip712Domain()` function on the ERC20 (implementing ERC5267) contract for use with the permit function.
    pub async fn get_eip712_domain(
        &self,
        erc20: Address,
        caller_address: Address,
    ) -> Result<Eip712Domain, Web3Error> {
        let payload = encode_call("eip712Domain()", &[])?;
        let domain_res = self
            .simulate_transaction(
                TransactionRequest::quick_tx(caller_address, erc20, payload),
                None,
            )
            .await?;
        if domain_res.len() < 32 {
            return Err(Web3Error::ContractCallError(
                "Bad response from ERC20 eip712Domain".to_string(),
            ));
        }
        debug!("eip712Domain response: {:?}", bytes_to_hex_str(&domain_res));
        let fields = u8::from_be_bytes(domain_res[0..1].try_into().unwrap());
        let chain_id = if fields & (1 << 2) != 0 {
            Some(Uint256::from_be_bytes(
                domain_res[96..128].try_into().unwrap(),
            ))
        } else {
            None
        };
        let verifying_contract = if fields & (1 << 3) != 0 {
            Some(Address::from_slice(&domain_res[140..160]).unwrap())
        } else {
            None
        };
        let salt: Option<[u8; 32]> = if fields & (1 << 4) != 0 {
            Some(domain_res[160..192].try_into().unwrap())
        } else {
            None
        };
        let name = if fields & 1 != 0 {
            let name_offset = Uint256::from_be_bytes(domain_res[32..64].try_into().unwrap());
            let name_offset = name_offset.to_usize().unwrap();
            let name_len = Uint256::from_be_bytes(&domain_res[name_offset..name_offset + 32]);
            let (name_start, name_end) = (
                name_offset + 32,
                name_offset + 32 + name_len.to_usize().unwrap(),
            );
            Some(String::from_utf8(domain_res[name_start..name_end].to_vec()).unwrap())
        } else {
            None
        };

        let version = if fields & (1 << 1) != 0 {
            let version_offset = Uint256::from_be_bytes(domain_res[64..96].try_into().unwrap());
            let version_offset = version_offset.to_usize().unwrap();
            let version_len =
                Uint256::from_be_bytes(&domain_res[version_offset..version_offset + 32]);
            let (version_start, version_end) = (
                version_offset + 32,
                version_offset + 32 + version_len.to_usize().unwrap(),
            );
            Some(String::from_utf8(domain_res[version_start..version_end].to_vec()).unwrap())
        } else {
            None
        };

        let extensions = if fields & (1 << 5) != 0 {
            let extensions_offset =
                Uint256::from_be_bytes(domain_res[192..224].try_into().unwrap());
            let extensions_offset = extensions_offset.to_usize().unwrap();
            let extensions_len =
                Uint256::from_be_bytes(&domain_res[extensions_offset..extensions_offset + 32]);
            let extensions_len = extensions_len.to_usize().unwrap();
            if extensions_len > 0 {
                let extensions_start = extensions_offset + 32;
                let mut xtensions = vec![];
                for i in 0..extensions_len {
                    let extension = Uint256::from_be_bytes(
                        &domain_res[extensions_start + (i * 32)..extensions_start + (i * 32) + 32],
                    );
                    xtensions.push(extension);
                }
                Some(xtensions)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Eip712Domain {
            name,
            version,
            chainId: chain_id,
            verifyingContract: verifying_contract,
            salt,
            extensions,
        })
    }
}
