//! MPC Wallet CLI
//!
//! Command-line tool for testing MPC agent wallet functionality.

use anyhow::Result;
use clap::{Parser, Subcommand};
use mpc_wallet_core::{
    ChainType, SessionConfig,
    keygen::run_dkg,
    mpc::MemoryRelay,
    policy::{PolicyConfig, PolicyEngine, SpendingLimits},
    storage::{EncryptedKeyShare, EncryptedMemoryStore, KeyShareStore, generate_encryption_key},
};
use std::sync::Arc;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "mpc-wallet")]
#[command(about = "MPC Agent Wallet CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate new wallet key shares (local simulation)
    Keygen {
        /// Output format (json, hex)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Show information about the wallet
    Info,

    /// Test policy engine
    TestPolicy {
        /// Transaction amount in ETH
        #[arg(short, long, default_value = "1.0")]
        amount: String,

        /// Recipient address
        #[arg(
            short,
            long,
            default_value = "0x1234567890123456789012345678901234567890"
        )]
        to: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .pretty()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { format } => {
            run_keygen_simulation(&format).await?;
        }
        Commands::Info => {
            show_info();
        }
        Commands::TestPolicy { amount, to } => {
            test_policy(&amount, &to)?;
        }
    }

    Ok(())
}

async fn run_keygen_simulation(format: &str) -> Result<()> {
    info!("Running local DKG simulation for all 3 parties...");

    let relay = Arc::new(MemoryRelay::with_timeout(10000));

    // Create configurations for all three parties
    let configs: Vec<SessionConfig> = (0..3)
        .map(|party_id| {
            let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
            config.session_id = rand::random();
            config
        })
        .collect();

    // Use same session ID for all
    let session_id = configs[0].session_id;
    let configs: Vec<SessionConfig> = (0..3)
        .map(|party_id| {
            let mut config = SessionConfig::new_agent_wallet(party_id).unwrap();
            config.session_id = session_id;
            config
        })
        .collect();

    // Run DKG for all parties concurrently
    let handles: Vec<_> = configs
        .into_iter()
        .map(|config| {
            let r = Arc::clone(&relay);
            tokio::spawn(async move { run_dkg(&config, r.as_ref()).await })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await??;
        results.push(result);
    }

    // Display results
    let public_key = hex::encode(&results[0].public_key);
    let eth_address = &results[0].eth_address;

    println!("\nDKG completed successfully!\n");
    println!("Public Key: 0x{}", public_key);
    println!("Ethereum Address: {}", eth_address);
    println!("\nKey shares generated for:");

    for result in &results {
        println!(
            "  - {} (Party {}): share_id={}",
            result.share.role, result.share.party_id, result.share.metadata.share_id
        );
    }

    // Encrypt and store shares
    let encryption_key = generate_encryption_key();
    let store = EncryptedMemoryStore::new();

    for result in &results {
        let encrypted = EncryptedKeyShare::encrypt(&result.share, &encryption_key)?;
        store
            .store(&result.share.metadata.share_id, &encrypted)
            .await?;
    }

    println!("\nKey shares encrypted and stored");

    if format == "json" {
        let output = serde_json::json!({
            "public_key": format!("0x{}", public_key),
            "eth_address": eth_address,
            "shares": results.iter().map(|r| {
                serde_json::json!({
                    "party_id": r.share.party_id,
                    "role": r.share.role.to_string(),
                    "share_id": r.share.metadata.share_id,
                })
            }).collect::<Vec<_>>(),
        });
        println!("\nJSON Output:");
        println!("{}", serde_json::to_string_pretty(&output)?);
    }

    Ok(())
}

fn show_info() {
    println!("MPC Agent Wallet v{}", mpc_wallet_core::VERSION);
    println!();
    println!("Configuration:");
    println!(
        "  Parties: {} (Agent, User, Recovery)",
        mpc_wallet_core::N_PARTIES
    );
    println!(
        "  Threshold: {}-of-{}",
        mpc_wallet_core::THRESHOLD,
        mpc_wallet_core::N_PARTIES
    );
    println!();
    println!("Supported Chains:");
    println!("  - EVM (Ethereum, Polygon, Arbitrum, etc.)");
    println!("  - Solana (planned)");
    println!("  - Bitcoin (planned)");
    println!();
    println!("Policy Features:");
    println!("  - Per-transaction spending limits");
    println!("  - Daily/weekly spending limits");
    println!("  - Address whitelist/blacklist");
    println!("  - Time window restrictions");
    println!("  - Contract interaction restrictions");
}

fn test_policy(amount: &str, to: &str) -> Result<()> {
    println!("Testing policy engine...\n");

    // Parse amount to wei
    let amount_wei: u128 = if amount.contains('.') {
        let parts: Vec<&str> = amount.split('.').collect();
        let whole: u128 = parts[0].parse()?;
        let mut decimal = parts[1].to_string();
        while decimal.len() < 18 {
            decimal.push('0');
        }
        decimal.truncate(18);
        let frac: u128 = decimal.parse()?;
        whole * 10u128.pow(18) + frac
    } else {
        amount.parse()?
    };

    // Create policy with limits
    let limits = SpendingLimits::with_per_tx(10u128.pow(18), "ETH") // 1 ETH per tx
        .daily(5 * 10u128.pow(18)); // 5 ETH daily

    let config = PolicyConfig::default()
        .with_spending_limits(ChainType::Evm, limits)
        .with_blacklist(vec!["0xBAD".to_string()]);

    let engine = PolicyEngine::new(config);

    // Create test transaction
    let tx = mpc_wallet_core::TransactionRequest::new(ChainType::Evm, to, amount_wei.to_string());

    println!("Transaction:");
    println!("  To: {}", to);
    println!("  Amount: {} ETH ({} wei)", amount, amount_wei);
    println!();

    // Evaluate
    let decision = engine.evaluate(&tx)?;

    match decision {
        mpc_wallet_core::PolicyDecision::Approve => {
            println!("[APPROVED] Policy Decision: APPROVED");
        }
        mpc_wallet_core::PolicyDecision::Reject { reason } => {
            println!("[REJECTED] Policy Decision: REJECTED");
            println!("   Reason: {}", reason);
        }
        mpc_wallet_core::PolicyDecision::RequireAdditionalApproval { reason } => {
            println!("[WARNING] Policy Decision: ADDITIONAL APPROVAL REQUIRED");
            println!("   Reason: {}", reason);
        }
    }

    Ok(())
}
