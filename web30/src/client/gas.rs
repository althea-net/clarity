use super::core::Web3;
use crate::jsonrpc::error::Web3Error;
use num256::Uint256;
use std::cmp::min;

// Gas simulation

pub struct SimulatedGas {
    pub limit: Uint256,
    pub price: Uint256,
}

impl Web3 {
    /// Geth and parity behave differently for the Estimate gas call or eth_call()
    /// Parity / OpenEthereum will allow you to specify no gas price
    /// and no gas amount the estimate gas call will then return the
    /// amount of gas the transaction would take. This is reasonable behavior
    /// from an endpoint that's supposed to let you estimate gas usage
    ///
    /// The gas price is of course irrelevant unless someone goes out of their
    /// way to design a contract that fails a low gas prices. Geth and Parity
    /// can't simulate an actual transaction market accurately.
    ///
    /// Geth on the other hand insists that you provide a gas price of at least
    /// 7 post London hardfork in order to respond. This seems to be because Geth
    /// simply tosses your transaction into the actual execution code, so no gas
    /// instantly fails.
    ///
    /// If this value is too low Geth will fail, if this value is higher than
    /// your balance Geth will once again fail. So Geth at this juncture won't
    /// tell you what the transaction would cost, just that you can't afford it.
    ///
    /// Max possible gas price is Uint 32 max, Geth will print warnings above 25mil
    /// gas, hardhat will error above 12.45 mil gas. So we select the minimum of these
    ///
    /// This function will navigate all these restrictions in order to give you the
    /// maximum valid gas possible for any simulated call
    pub async fn simulated_gas_price_and_limit(
        &self,
        balance: Uint256,
    ) -> Result<SimulatedGas, Web3Error> {
        const GAS_LIMIT: u128 = 12450000;
        let gas_price = self.eth_gas_price().await?;
        let limit = min(GAS_LIMIT.into(), balance / gas_price);
        Ok(SimulatedGas {
            limit,
            price: gas_price,
        })
    }
}
