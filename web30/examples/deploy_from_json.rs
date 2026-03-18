/// Example: Deploy a contract from a compiled JSON artifact
///
/// Deploys a Solidity contract using its compiled JSON artifact (Hardhat / Truffle / Foundry)
/// and the web30 contract deployment API.
///
/// USAGE:
///   cargo run --example deploy_from_json -- \
///     --json-path /path/to/Contract.json \
///     --rpc-url http://localhost:8545 \
///     --private-key 0x... \
///     [--constructor-args arg1,arg2,...]
///
/// The JSON file should contain:
///   - "bytecode": The contract creation bytecode (0x-prefixed hex string)
///   - "abi" (optional): Used for encoding constructor arguments
///
/// Constructor arguments should be provided as comma-separated values.
/// The script will attempt to parse them based on the ABI constructor types.
///
/// For array arguments, separate elements with a semicolon, e.g.:
///   --constructor-args "0xOwner,0xAddr1;0xAddr2;0xAddr3"
use clarity::abi::{encode_tokens, AbiToken};
use clarity::{Address, Int256, PrivateKey, Uint256};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use web30::client::Web3;
use web30::types::SendTxOption;

#[derive(Debug)]
struct DeployConfig {
    json_path: PathBuf,
    rpc_url: String,
    private_key: PrivateKey,
    constructor_args: Vec<String>,
    gas_limit: Option<Uint256>,
    gas_price: Option<Uint256>,
}

impl DeployConfig {
    fn from_args() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();

        let mut json_path = None;
        let mut rpc_url = None;
        let mut private_key = None;
        let mut constructor_args = Vec::new();
        let mut gas_limit = None;
        let mut gas_price = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--json-path" | "-j" => {
                    i += 1;
                    if i < args.len() {
                        json_path = Some(PathBuf::from(&args[i]));
                    }
                }
                "--rpc-url" | "-r" => {
                    i += 1;
                    if i < args.len() {
                        rpc_url = Some(args[i].clone());
                    }
                }
                "--private-key" | "-k" => {
                    i += 1;
                    if i < args.len() {
                        private_key = Some(
                            args[i]
                                .parse()
                                .map_err(|e| format!("Invalid private key: {}", e))?,
                        );
                    }
                }
                "--constructor-args" | "-c" => {
                    i += 1;
                    if i < args.len() {
                        constructor_args = args[i].split(',').map(|s| s.to_string()).collect();
                    }
                }
                "--gas-limit" | "-g" => {
                    i += 1;
                    if i < args.len() {
                        gas_limit = Some(
                            args[i]
                                .parse()
                                .map_err(|e| format!("Invalid gas limit: {}", e))?,
                        );
                    }
                }
                "--gas-price" | "-p" => {
                    i += 1;
                    if i < args.len() {
                        gas_price = Some(
                            args[i]
                                .parse()
                                .map_err(|e| format!("Invalid gas price: {}", e))?,
                        );
                    }
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {
                    return Err(format!("Unknown argument: {}", args[i]));
                }
            }
            i += 1;
        }

        Ok(DeployConfig {
            json_path: json_path.ok_or("Missing required argument: --json-path")?,
            rpc_url: rpc_url.ok_or("Missing required argument: --rpc-url")?,
            private_key: private_key.ok_or("Missing required argument: --private-key")?,
            constructor_args,
            gas_limit,
            gas_price,
        })
    }
}

fn print_help() {
    println!("Deploy Contract from JSON Artifact");
    println!();
    println!("USAGE:");
    println!("  cargo run --example deploy_from_json -- [OPTIONS]");
    println!();
    println!("REQUIRED OPTIONS:");
    println!("  -j, --json-path <PATH>        Path to compiled contract JSON file");
    println!("  -r, --rpc-url <URL>           Ethereum RPC endpoint URL");
    println!("  -k, --private-key <KEY>       Private key for deployment (0x-prefixed)");
    println!();
    println!("OPTIONAL:");
    println!("  -c, --constructor-args <ARGS> Comma-separated constructor arguments");
    println!("                                Use semicolons for array elements: addr1;addr2");
    println!("  -g, --gas-limit <AMOUNT>      Gas limit for deployment");
    println!("  -p, --gas-price <AMOUNT>      Gas price in wei");
    println!("  -h, --help                    Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("  # Deploy a simple no-arg contract");
    println!("  cargo run --example deploy_from_json -- \\");
    println!("    --json-path ./MyContract.json \\");
    println!("    --rpc-url http://localhost:8545 \\");
    println!(
        "    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    );
    println!();
    println!("  # Deploy LiquidInfrastructureGlobalWhitelist with constructor args");
    println!("  cargo run --example deploy_from_json -- \\");
    println!("    --json-path ./LiquidInfrastructureGlobalWhitelist.json \\");
    println!("    --rpc-url http://localhost:8545 \\");
    println!("    --private-key 0x... \\");
    println!("    --constructor-args \"0xOwnerAddress,0xMember1;0xMember2\"");
}

fn parse_bytecode(json: &Value) -> Result<Vec<u8>, String> {
    let bytecode_str = json["bytecode"]
        .as_str()
        // Foundry / forge artifact layout
        .or_else(|| json["bytecode"]["object"].as_str())
        // Hardhat compiled artifact layout
        .or_else(|| json["data"]["bytecode"]["object"].as_str())
        .ok_or("No bytecode field found in JSON. Expected 'bytecode' (string or object with 'object' key).")?;

    // Remove 0x prefix if present
    let bytecode_str = bytecode_str.strip_prefix("0x").unwrap_or(bytecode_str);

    hex::decode(bytecode_str).map_err(|e| format!("Invalid bytecode hex: {}", e))
}

fn parse_constructor_abi(json: &Value) -> Option<Vec<Value>> {
    let abi = json["abi"].as_array()?;

    for item in abi {
        if item["type"].as_str()? == "constructor" {
            return Some(item["inputs"].as_array()?.clone());
        }
    }

    None
}

fn encode_constructor_args(abi_inputs: &[Value], args: &[String]) -> Result<Vec<u8>, String> {
    if abi_inputs.len() != args.len() {
        return Err(format!(
            "Constructor expects {} argument(s), got {}.\nExpected types: {}",
            abi_inputs.len(),
            args.len(),
            abi_inputs
                .iter()
                .map(|i| format!(
                    "{} ({})",
                    i["name"].as_str().unwrap_or("?"),
                    i["type"].as_str().unwrap_or("?")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if args.is_empty() {
        return Ok(Vec::new());
    }

    let mut tokens = Vec::new();

    for (input, arg) in abi_inputs.iter().zip(args.iter()) {
        let type_str = input["type"]
            .as_str()
            .ok_or_else(|| "Missing type in ABI input".to_string())?;

        let token = parse_token(type_str, arg)?;
        tokens.push(token);
    }

    Ok(encode_tokens(&tokens))
}

fn parse_token(type_str: &str, value: &str) -> Result<AbiToken, String> {
    match type_str {
        "address" => {
            let addr: Address = value
                .parse()
                .map_err(|e| format!("Invalid address '{}': {}", value, e))?;
            Ok(AbiToken::Address(addr))
        }
        "bool" => {
            let b = match value.trim() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => return Err(format!("Invalid bool '{}': expected true/false/1/0", other)),
            };
            Ok(AbiToken::Bool(b))
        }
        "string" => Ok(AbiToken::String(value.to_string())),
        "bytes" => {
            let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
                .map_err(|e| format!("Invalid bytes '{}': {}", value, e))?;
            Ok(AbiToken::UnboundedBytes(bytes))
        }
        t if t.starts_with("bytes") => {
            // Fixed bytesN
            let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
                .map_err(|e| format!("Invalid bytesN '{}': {}", value, e))?;
            Ok(AbiToken::Bytes(bytes))
        }
        t if t.starts_with("uint") => {
            let num: Uint256 = value
                .parse()
                .map_err(|e| format!("Invalid uint '{}': {}", value, e))?;
            Ok(AbiToken::Uint(num))
        }
        t if t.starts_with("int") => {
            let num: Int256 = value
                .parse()
                .map_err(|e| format!("Invalid int '{}': {}", value, e))?;
            Ok(AbiToken::Int(num))
        }
        t if t.ends_with("[]") => {
            // Array elements separated by semicolons, e.g. "0xAddr1;0xAddr2"
            // An empty string means an empty array.
            let base_type = &t[..t.len() - 2];
            if value.trim().is_empty() {
                return Ok(AbiToken::Dynamic(vec![]));
            }
            let elements: Result<Vec<AbiToken>, _> = value
                .split(';')
                .map(|v| parse_token(base_type, v.trim()))
                .collect();
            Ok(AbiToken::Dynamic(elements?))
        }
        _ => Err(format!(
            "Unsupported ABI type: '{}'. Supported: address, bool, string, bytes, bytesN, uint*, int*, T[]",
            type_str
        )),
    }
}

fn main() {
    let runner = actix::System::new();
    let exit_code = runner.block_on(async_main());
    std::process::exit(exit_code);
}

async fn async_main() -> i32 {
    let config = match DeployConfig::from_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!();
            print_help();
            return 1;
        }
    };

    println!("🚀 Contract Deployment Tool");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Read and parse JSON file
    println!("📄 Reading contract JSON: {}", config.json_path.display());
    let json_content = match fs::read_to_string(&config.json_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to read JSON file: {}", e);
            return 1;
        }
    };

    let json: Value = match serde_json::from_str(&json_content) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("❌ Failed to parse JSON: {}", e);
            return 1;
        }
    };

    // Print contract name if available
    if let Some(name) = json["contractName"].as_str() {
        println!("✓ Contract: {}", name);
    }

    // Extract bytecode
    let bytecode = match parse_bytecode(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ {}", e);
            return 1;
        }
    };
    println!("✓ Bytecode loaded: {} bytes", bytecode.len());

    // Parse constructor arguments if provided
    let encoded_constructor_args = if !config.constructor_args.is_empty() {
        println!("📝 Processing constructor arguments...");
        match parse_constructor_abi(&json) {
            Some(abi_inputs) => {
                match encode_constructor_args(&abi_inputs, &config.constructor_args) {
                    Ok(args) => {
                        println!("✓ Constructor args encoded: {} bytes", args.len());
                        args
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to encode constructor arguments: {}", e);
                        return 1;
                    }
                }
            }
            None => {
                eprintln!("⚠️  Warning: Constructor args provided but no constructor found in ABI");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    println!(
        "✓ Init code: {} bytecode + {} constructor arg bytes",
        bytecode.len(),
        encoded_constructor_args.len()
    );
    println!();

    // Connect to Ethereum node
    println!("🔗 Connecting to: {}", config.rpc_url);
    let web3 = Web3::new(&config.rpc_url, Duration::from_secs(30));

    // Get deployer address
    let deployer = config.private_key.to_address();
    println!("👤 Deployer address: {}", deployer);

    // Get current nonce
    let nonce = match web3.eth_get_transaction_count(deployer).await {
        Ok(n) => {
            println!("✓ Current nonce: {}", n);
            n
        }
        Err(e) => {
            eprintln!("❌ Failed to get nonce: {}", e);
            return 1;
        }
    };

    // Predict contract address before sending any transaction
    let predicted_address = clarity::contract::calculate_contract_address(deployer, nonce);
    println!("📍 Predicted contract address: {}", predicted_address);
    println!();

    // Estimate gas if not provided
    let gas_limit = match config.gas_limit {
        Some(limit) => {
            println!("⛽ Using provided gas limit: {}", limit);
            limit
        }
        None => {
            println!("⛽ Estimating gas...");
            match web3
                .estimate_deploy_gas(
                    deployer,
                    bytecode.clone(),
                    encoded_constructor_args.clone(),
                    0u32.into(),
                )
                .await
            {
                Ok(estimate) => {
                    // Add 20% buffer to avoid out-of-gas on edge cases
                    let gas_with_buffer = estimate * 120u32.into() / 100u32.into();
                    println!(
                        "✓ Estimated gas: {} (using {} with 20% buffer)",
                        estimate, gas_with_buffer
                    );
                    gas_with_buffer
                }
                Err(e) => {
                    eprintln!("❌ Gas estimation failed: {}", e);
                    eprintln!("   Provide --gas-limit to skip estimation");
                    return 1;
                }
            }
        }
    };

    // Build SendTxOptions
    let mut options: Vec<SendTxOption> = vec![SendTxOption::GasLimit(gas_limit)];
    if let Some(price) = config.gas_price {
        options.push(SendTxOption::GasPrice(price));
    }

    println!();
    println!("🚢 Deploying contract...");

    // deploy_contract handles signing, broadcast, and waiting for confirmation internally
    let contract_address = match web3
        .deploy_contract(
            &config.private_key,
            bytecode,
            encoded_constructor_args,
            0u32.into(),
            options,
        )
        .await
    {
        Ok(addr) => {
            println!("✓ Deployed and confirmed!");
            addr
        }
        Err(e) => {
            eprintln!("❌ Deployment failed: {}", e);
            return 1;
        }
    };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ DEPLOYMENT SUCCESSFUL");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📍 Contract address: {}", contract_address);

    if contract_address == predicted_address {
        println!("✓ Address matches prediction");
    } else {
        println!(
            "⚠️  Address differs from prediction {} (nonce may have changed)",
            predicted_address
        );
    }
    println!();
    0
}
