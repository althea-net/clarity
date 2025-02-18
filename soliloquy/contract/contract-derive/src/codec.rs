//! Helper functions for deriving `EthAbiType`

use quote::quote;
use soliloquy_core::macros::soliloquy_core_crate;
use syn::DeriveInput;

/// Generates the `AbiEncode` + `AbiDecode` implementation
pub fn derive_codec_impl(input: &DeriveInput) -> proc_macro2::TokenStream {
    let name = &input.ident;
    let soliloquy_core = soliloquy_core_crate();

    quote! {
        impl #soliloquy_core::abi::AbiDecode for #name {
            fn decode(bytes: impl AsRef<[u8]>) -> ::core::result::Result<Self, #soliloquy_core::abi::AbiError> {
                fn _decode(bytes: &[u8]) -> ::core::result::Result<#name, #soliloquy_core::abi::AbiError> {
                    let #soliloquy_core::abi::ParamType::Tuple(params) =
                        <#name as #soliloquy_core::abi::AbiType>::param_type() else { unreachable!() };
                    let min_len: usize = params.iter().map(#soliloquy_core::abi::minimum_size).sum();
                    if bytes.len() < min_len {
                        Err(#soliloquy_core::abi::AbiError::DecodingError(#soliloquy_core::abi::ethabi::Error::InvalidData))
                    } else {
                        let tokens = #soliloquy_core::abi::decode(&params, bytes)?;
                        let tuple = #soliloquy_core::abi::Token::Tuple(tokens);
                        let this = <#name as #soliloquy_core::abi::Tokenizable>::from_token(tuple)?;
                        Ok(this)
                    }
                }

                _decode(bytes.as_ref())
            }
        }

        impl #soliloquy_core::abi::AbiEncode for #name {
            fn encode(self) -> ::std::vec::Vec<u8> {
                let tokens = #soliloquy_core::abi::Tokenize::into_tokens(self);
                #soliloquy_core::abi::encode(&tokens)
            }
        }
    }
}
