//! Route discovery for Uniswap V3 multi-hop swaps
//!
//! This module provides functionality to discover potential swap paths between
//! two tokens using common intermediary tokens like WETH, USDC, USDT, and DAI.

use clarity::Address;

use super::uniswapv3::{
    DAI_CONTRACT_ADDRESS, USDC_CONTRACT_ADDRESS, USDT_CONTRACT_ADDRESS, WETH_CONTRACT_ADDRESS,
};

/// Represents a single hop in a swap path, combining a token address with the fee tier
/// for the pool used to swap from the previous token to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapHop {
    /// The token address for this hop
    pub token: Address,
    /// The pool fee tier in hundredths of basis points (e.g., 3000 = 0.3%)
    /// For the first token in a path, this is the fee to reach the second token
    pub fee: u32,
}

impl SwapHop {
    /// Create a new SwapHop with the given token address and fee tier
    pub fn new(token: Address, fee: u32) -> Self {
        Self { token, fee }
    }
}

/// A complete swap route from input token to output token
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRoute {
    /// The input token address
    pub token_in: Address,
    /// The sequence of hops to reach the output token
    /// Each hop contains the next token and the fee for that pool
    pub hops: Vec<SwapHop>,
}

impl SwapRoute {
    /// Returns the number of intermediate hops (0 for direct swap, 1 for one intermediary, etc.)
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Returns the output token address
    pub fn token_out(&self) -> Option<Address> {
        self.hops.last().map(|h| h.token)
    }

    /// Converts this route to separate token and fee arrays for use with encode_v3_path
    pub fn to_tokens_and_fees(&self) -> (Vec<Address>, Vec<u32>) {
        let mut tokens = Vec::with_capacity(self.hops.len() + 1);
        let mut fees = Vec::with_capacity(self.hops.len());

        tokens.push(self.token_in);
        for hop in &self.hops {
            fees.push(hop.fee);
            tokens.push(hop.token);
        }

        (tokens, fees)
    }

    /// Converts this route to a path of SwapHops (token + fee pairs)
    pub fn to_path(&self) -> Vec<SwapHop> {
        self.hops.clone()
    }

    /// Creates a SwapRoute from separate token and fee arrays
    pub fn from_tokens_and_fees(tokens: &[Address], fees: &[u32]) -> Option<Self> {
        if tokens.len() < 2 || tokens.len() != fees.len() + 1 {
            return None;
        }

        let token_in = tokens[0];
        let hops: Vec<SwapHop> = tokens[1..]
            .iter()
            .zip(fees.iter())
            .map(|(&token, &fee)| SwapHop::new(token, fee))
            .collect();

        Some(Self { token_in, hops })
    }
}

/// Common intermediary tokens used for routing on Ethereum mainnet
pub fn get_common_intermediary_tokens() -> Vec<Address> {
    vec![
        *WETH_CONTRACT_ADDRESS,
        *USDC_CONTRACT_ADDRESS,
        *USDT_CONTRACT_ADDRESS,
        *DAI_CONTRACT_ADDRESS,
    ]
}

/// Standard Uniswap V3 fee tiers
pub fn get_standard_fees() -> Vec<u32> {
    vec![3000, 500, 100, 10000]
}

/// Generates all potential swap routes between two tokens using common intermediary tokens.
///
/// This function generates routes of up to 2 hops deep:
/// - 0 hops: Direct swap (token_in -> token_out)
/// - 1 hop: Through one intermediary (token_in -> intermediary -> token_out)
/// - 2 hops: Through two intermediaries (token_in -> intermediary_a -> intermediary_b -> token_out)
///
/// Routes are ordered by hop count (direct routes first), making it efficient to try
/// simpler routes before more complex ones.
///
/// # Arguments
/// * `token_in` - The input token address
/// * `token_out` - The output token address
///
/// # Returns
/// A vector of potential swap routes, ordered by complexity (fewer hops first)
pub fn generate_potential_routes(token_in: Address, token_out: Address) -> Vec<SwapRoute> {
    generate_routes_by_hop_count(token_in, token_out).concat()
}

/// Generates potential routes grouped by hop count.
///
/// Returns routes organized in three vectors:
/// - Index 0: Direct routes (0 intermediate hops)
/// - Index 1: Single-hop routes (1 intermediary)
/// - Index 2: Two-hop routes (2 intermediaries)
pub fn generate_routes_by_hop_count(token_in: Address, token_out: Address) -> [Vec<SwapRoute>; 3] {
    let intermediaries = get_common_intermediary_tokens();
    let fees = get_standard_fees();

    let mut direct_routes = Vec::new();
    let mut one_hop_routes = Vec::new();
    let mut two_hop_routes = Vec::new();

    // 0-hop: Direct routes
    for &fee in &fees {
        direct_routes.push(SwapRoute {
            token_in,
            hops: vec![SwapHop::new(token_out, fee)],
        });
    }

    // 1-hop: Routes through one intermediary
    for &intermediary in &intermediaries {
        if intermediary == token_in || intermediary == token_out {
            continue;
        }

        for &fee1 in &fees {
            for &fee2 in &fees {
                one_hop_routes.push(SwapRoute {
                    token_in,
                    hops: vec![
                        SwapHop::new(intermediary, fee1),
                        SwapHop::new(token_out, fee2),
                    ],
                });
            }
        }
    }

    // 2-hop: Routes through two intermediaries
    for (i, &intermediary_a) in intermediaries.iter().enumerate() {
        if intermediary_a == token_in || intermediary_a == token_out {
            continue;
        }

        for (j, &intermediary_b) in intermediaries.iter().enumerate() {
            if i == j || intermediary_b == token_in || intermediary_b == token_out {
                continue;
            }

            for &fee1 in &fees {
                for &fee2 in &fees {
                    for &fee3 in &fees {
                        two_hop_routes.push(SwapRoute {
                            token_in,
                            hops: vec![
                                SwapHop::new(intermediary_a, fee1),
                                SwapHop::new(intermediary_b, fee2),
                                SwapHop::new(token_out, fee3),
                            ],
                        });
                    }
                }
            }
        }
    }

    [direct_routes, one_hop_routes, two_hop_routes]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_token_a() -> Address {
        Address::parse_and_validate("0x1111111111111111111111111111111111111111").unwrap()
    }

    fn test_token_b() -> Address {
        Address::parse_and_validate("0x2222222222222222222222222222222222222222").unwrap()
    }

    #[test]
    fn test_swap_hop_creation() {
        let token = test_token_a();
        let hop = SwapHop::new(token, 3000);
        assert_eq!(hop.token, token);
        assert_eq!(hop.fee, 3000);
    }

    #[test]
    fn test_swap_route_hop_count() {
        let route = SwapRoute {
            token_in: test_token_a(),
            hops: vec![SwapHop::new(test_token_b(), 3000)],
        };
        assert_eq!(route.hop_count(), 1);

        let route_with_intermediary = SwapRoute {
            token_in: test_token_a(),
            hops: vec![
                SwapHop::new(*WETH_CONTRACT_ADDRESS, 3000),
                SwapHop::new(test_token_b(), 500),
            ],
        };
        assert_eq!(route_with_intermediary.hop_count(), 2);
    }

    #[test]
    fn test_swap_route_token_out() {
        let route = SwapRoute {
            token_in: test_token_a(),
            hops: vec![
                SwapHop::new(*WETH_CONTRACT_ADDRESS, 3000),
                SwapHop::new(test_token_b(), 500),
            ],
        };
        assert_eq!(route.token_out(), Some(test_token_b()));
    }

    #[test]
    fn test_swap_route_to_tokens_and_fees() {
        let route = SwapRoute {
            token_in: test_token_a(),
            hops: vec![
                SwapHop::new(*WETH_CONTRACT_ADDRESS, 3000),
                SwapHop::new(test_token_b(), 500),
            ],
        };

        let (tokens, fees) = route.to_tokens_and_fees();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], test_token_a());
        assert_eq!(tokens[1], *WETH_CONTRACT_ADDRESS);
        assert_eq!(tokens[2], test_token_b());
        assert_eq!(fees, vec![3000, 500]);
    }

    #[test]
    fn test_swap_route_from_tokens_and_fees() {
        let tokens = vec![test_token_a(), *WETH_CONTRACT_ADDRESS, test_token_b()];
        let fees = vec![3000, 500];

        let route = SwapRoute::from_tokens_and_fees(&tokens, &fees).unwrap();
        assert_eq!(route.token_in, test_token_a());
        assert_eq!(route.hops.len(), 2);
        assert_eq!(route.hops[0].token, *WETH_CONTRACT_ADDRESS);
        assert_eq!(route.hops[0].fee, 3000);
        assert_eq!(route.hops[1].token, test_token_b());
        assert_eq!(route.hops[1].fee, 500);
    }

    #[test]
    fn test_swap_route_roundtrip() {
        let original = SwapRoute {
            token_in: test_token_a(),
            hops: vec![
                SwapHop::new(*WETH_CONTRACT_ADDRESS, 3000),
                SwapHop::new(*USDC_CONTRACT_ADDRESS, 500),
                SwapHop::new(test_token_b(), 100),
            ],
        };

        let (tokens, fees) = original.to_tokens_and_fees();
        let reconstructed = SwapRoute::from_tokens_and_fees(&tokens, &fees).unwrap();
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_from_tokens_and_fees_invalid_lengths() {
        // Too few tokens
        assert!(SwapRoute::from_tokens_and_fees(&[test_token_a()], &[]).is_none());

        // Mismatched lengths
        assert!(
            SwapRoute::from_tokens_and_fees(&[test_token_a(), test_token_b()], &[3000, 500])
                .is_none()
        );
    }

    #[test]
    fn test_generate_potential_routes_direct() {
        let routes = generate_potential_routes(test_token_a(), test_token_b());

        // First routes should be direct (0 intermediate hops)
        let direct_routes: Vec<_> = routes.iter().filter(|r| r.hop_count() == 1).collect();
        assert_eq!(direct_routes.len(), 4); // 4 fee tiers

        for route in direct_routes {
            assert_eq!(route.token_in, test_token_a());
            assert_eq!(route.token_out(), Some(test_token_b()));
        }
    }

    #[test]
    fn test_generate_potential_routes_one_hop() {
        let routes = generate_potential_routes(test_token_a(), test_token_b());

        // 1-hop routes should have 2 hops total (through one intermediary)
        let one_hop_routes: Vec<_> = routes.iter().filter(|r| r.hop_count() == 2).collect();

        // 4 intermediaries * 4 fee tiers * 4 fee tiers = 64 routes total
        // (4 intermediaries, each with 4*4=16 fee combinations)
        assert_eq!(one_hop_routes.len(), 64); // 4 intermediaries * 16 fee combos

        for route in &one_hop_routes {
            assert_eq!(route.token_in, test_token_a());
            assert_eq!(route.token_out(), Some(test_token_b()));
            // First hop should be to an intermediary (not the output)
            assert_ne!(route.hops[0].token, test_token_b());
            // Intermediary should be one of the common tokens
            let intermediaries = get_common_intermediary_tokens();
            assert!(intermediaries.contains(&route.hops[0].token));
        }
    }

    #[test]
    fn test_generate_potential_routes_two_hops() {
        let routes = generate_potential_routes(test_token_a(), test_token_b());

        // 2-hop routes should have 3 hops total (through two intermediaries)
        let two_hop_routes: Vec<_> = routes.iter().filter(|r| r.hop_count() == 3).collect();

        // Should have routes with two different intermediaries
        assert!(!two_hop_routes.is_empty());

        for route in &two_hop_routes {
            assert_eq!(route.token_in, test_token_a());
            assert_eq!(route.token_out(), Some(test_token_b()));
            // First two hops should be to intermediaries
            assert_ne!(route.hops[0].token, test_token_b());
            assert_ne!(route.hops[1].token, test_token_b());
            // The two intermediaries should be different
            assert_ne!(route.hops[0].token, route.hops[1].token);
        }
    }

    #[test]
    fn test_generate_routes_by_hop_count() {
        let [direct, one_hop, two_hop] =
            generate_routes_by_hop_count(test_token_a(), test_token_b());

        // Verify counts
        assert_eq!(direct.len(), 4); // 4 fee tiers
        assert!(!one_hop.is_empty());
        assert!(!two_hop.is_empty());

        // Verify all routes in each category have correct hop count
        for route in &direct {
            assert_eq!(route.hop_count(), 1);
        }
        for route in &one_hop {
            assert_eq!(route.hop_count(), 2);
        }
        for route in &two_hop {
            assert_eq!(route.hop_count(), 3);
        }
    }

    #[test]
    fn test_routes_exclude_input_output_as_intermediary() {
        // Use WETH as the input token
        let routes = generate_potential_routes(*WETH_CONTRACT_ADDRESS, test_token_b());

        for route in &routes {
            for hop in &route.hops {
                // No intermediary should be the input token
                if hop.token != test_token_b() {
                    assert_ne!(hop.token, *WETH_CONTRACT_ADDRESS);
                }
            }
        }
    }

    #[test]
    fn test_routes_contain_valid_fee_tiers() {
        let routes = generate_potential_routes(test_token_a(), test_token_b());
        let valid_fees = get_standard_fees();

        for route in &routes {
            for hop in &route.hops {
                assert!(
                    valid_fees.contains(&hop.fee),
                    "Invalid fee tier: {}",
                    hop.fee
                );
            }
        }
    }

    #[test]
    fn test_routes_paths_are_valid() {
        let routes = generate_potential_routes(test_token_a(), test_token_b());

        for route in &routes {
            let (tokens, fees) = route.to_tokens_and_fees();

            // tokens.len() should be fees.len() + 1
            assert_eq!(
                tokens.len(),
                fees.len() + 1,
                "Invalid path: tokens.len() ({}) != fees.len() ({}) + 1",
                tokens.len(),
                fees.len()
            );

            // First token should be token_in
            assert_eq!(tokens[0], test_token_a());

            // Last token should be token_out
            assert_eq!(tokens[tokens.len() - 1], test_token_b());

            // No consecutive duplicate tokens
            for i in 0..tokens.len() - 1 {
                assert_ne!(
                    tokens[i],
                    tokens[i + 1],
                    "Consecutive duplicate tokens at index {}: {:?}",
                    i,
                    tokens[i]
                );
            }
        }
    }
}
