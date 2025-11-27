//! Identity commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{IdentityArgs, IdentityAction, ZhtpCli, format_output};
use serde_json::json;
use chrono;
use uuid;

pub async fn handle_identity_command(args: IdentityArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::builder()
        .http1_only()  // Force HTTP/1.1 to avoid version parsing issues
        .build()?;
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        IdentityAction::Create { name } => {
            println!("Creating new ZHTP DID identity: {}", name);
            
            // Use the correct API format that matches the working PowerShell command
            let request_body = json!({
                "identity_type": "human",
                "display_name": name,
                "recovery_options": [
                    format!("recovery_phrase_{}", name.to_lowercase()),
                    format!("backup_phrase_{}", chrono::Utc::now().timestamp())
                ],
                "initial_wallet_type": "citizen_wallet"
            });
            
            let response = client
                .post(&format!("{}/identity/create", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                // Extract key information from the successful response
                if let Some(did) = result.get("did") {
                    println!("DID Created Successfully!");
                    println!("DID: {}", did.as_str().unwrap_or("N/A"));
                }
                if let Some(identity_id) = result.get("identity_id") {
                    println!("Identity ID: {}", identity_id.as_str().unwrap_or("N/A"));
                }
                if let Some(primary_wallet) = result.get("primary_wallet_id") {
                    println!("Primary Wallet: {}", primary_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(blockchain) = result.get("blockchain") {
                    if let Some(tx_hash) = blockchain.get("transaction_hash") {
                        println!("Blockchain TX: {}", tx_hash.as_str().unwrap_or("N/A"));
                    }
                    if let Some(status) = blockchain.get("registration_status") {
                        println!("Status: {}", status.as_str().unwrap_or("N/A"));
                    }
                }
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to create DID identity: {} - {}", status, error_text);
            }
        }
        IdentityAction::CreateDid { name, identity_type, recovery_options } => {
            println!("Creating zero-knowledge DID identity: {}", name);
            println!("🔖 Identity Type: {}", identity_type);
            
            // Use provided recovery options or generate defaults
            let final_recovery_options = if recovery_options.is_empty() {
                vec![
                    format!("recovery_phrase_{}", name.to_lowercase()),
                    format!("backup_phrase_{}", chrono::Utc::now().timestamp()),
                    format!("emergency_recovery_{}", uuid::Uuid::new_v4().to_string()[..8].to_string())
                ]
            } else {
                recovery_options
            };
            
            let request_body = json!({
                "identity_type": identity_type,
                "display_name": name,
                "recovery_options": final_recovery_options,
                "initial_wallet_type": "citizen_wallet"
            });
            
            println!("Recovery options configured: {} phrases", final_recovery_options.len());
            
            let response = client
                .post(&format!("{}/identity/create", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                println!("Zero-Knowledge DID Created Successfully!");
                
                // Extract and display comprehensive DID information
                if let Some(did) = result.get("did") {
                    println!("DID: {}", did.as_str().unwrap_or("N/A"));
                }
                if let Some(identity_id) = result.get("identity_id") {
                    println!("Identity ID: {}", identity_id.as_str().unwrap_or("N/A"));
                }
                
                // Wallet information
                if let Some(primary_wallet) = result.get("primary_wallet_id") {
                    println!("Primary Wallet: {}", primary_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(ubi_wallet) = result.get("ubi_wallet_id") {
                    println!("🎁 UBI Wallet: {}", ubi_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(savings_wallet) = result.get("savings_wallet_id") {
                    println!("🏦 Savings Wallet: {}", savings_wallet.as_str().unwrap_or("N/A"));
                }
                
                // DAO registration
                if let Some(dao_reg) = result.get("dao_registration") {
                    if let Some(voting_power) = dao_reg.get("voting_power") {
                        println!(" DAO Voting Power: {}", voting_power);
                    }
                }
                
                // UBI registration
                if let Some(ubi_reg) = result.get("ubi_registration") {
                    if let Some(daily_amount) = ubi_reg.get("daily_amount") {
                        println!("Daily UBI: {} ZHTP", daily_amount.as_u64().unwrap_or(0) as f64 / 1_000_000_000_000_000_000.0);
                    }
                }
                
                // Blockchain status
                if let Some(blockchain) = result.get("blockchain") {
                    if let Some(tx_hash) = blockchain.get("transaction_hash") {
                        println!("Blockchain TX: {}", tx_hash.as_str().unwrap_or("N/A"));
                    }
                    if let Some(status) = blockchain.get("registration_status") {
                        println!("Registration Status: {}", status.as_str().unwrap_or("N/A"));
                    }
                }
                
                println!(" Full Web4 citizen onboarding completed!");
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nComplete Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to create zero-knowledge DID: {} - {}", status, error_text);
            }
        }
        IdentityAction::Verify { identity_id } => {
            println!("Verifying ZHTP identity: {}", identity_id);
            
            let request_body = json!({
                "identity_data": {
                    "identity_id": identity_id,
                    "verification_requested": true
                },
                "verification_level": "Standard"
            });
            
            let response = client
                .post(&format!("{}/identity/verify", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                // Extract verification results
                if let Some(verified) = result.get("verified") {
                    if verified.as_bool().unwrap_or(false) {
                        println!("Identity verification successful!");
                    } else {
                        println!("Identity verification failed!");
                    }
                }
                if let Some(score) = result.get("verification_score") {
                    println!("Verification Score: {}", score);
                }
                if let Some(level) = result.get("verification_level") {
                    println!(" Security Level: {}", level.as_str().unwrap_or("N/A"));
                }
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to verify identity: {} - {}", status, error_text);
            }
        }
        IdentityAction::List => {
            println!("Listing ZHTP identities from blockchain...");

            // Since there's no direct list endpoint, we'll get blockchain status
            // and show identity information from there
            let response = client
                .get(&format!("{}/blockchain/block", base_url))
                .header("Accept", "application/json")
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;

                println!("Blockchain Identity Status:");
                if let Some(height) = result.get("latest_height") {
                    println!("Latest Block: {}", height);
                }

                // For now, show a message about checking server logs for created identities
                println!("To see created identities, check the server logs for DID creation events");
                println!("   or use 'zhtp blockchain stats' to see blockchain statistics");

                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nBlockchain Status:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to get blockchain status: {} - {}", status, error_text);
            }
        }
        IdentityAction::RestoreFromSeeds {
            primary_seed,
            ubi_seed,
            savings_seed,
            display_name,
            password,
        } => {
            println!("🔓 Restoring full citizen identity from seed phrases...");
            println!("   Display Name: {}", display_name);

            // Parse seed phrases (split by spaces)
            let primary_words: Vec<String> = primary_seed.split_whitespace().map(|s| s.to_string()).collect();
            let ubi_words: Vec<String> = ubi_seed.split_whitespace().map(|s| s.to_string()).collect();
            let savings_words: Vec<String> = savings_seed.split_whitespace().map(|s| s.to_string()).collect();

            // Validate word counts
            if primary_words.len() != 20 {
                println!("❌ Error: Primary wallet seed phrase must have exactly 20 words (got {})", primary_words.len());
                return Ok(());
            }
            if ubi_words.len() != 20 {
                println!("❌ Error: UBI wallet seed phrase must have exactly 20 words (got {})", ubi_words.len());
                return Ok(());
            }
            if savings_words.len() != 20 {
                println!("❌ Error: Savings wallet seed phrase must have exactly 20 words (got {})", savings_words.len());
                return Ok(());
            }

            let request_body = json!({
                "primary_seed_phrase": primary_words,
                "ubi_seed_phrase": ubi_words,
                "savings_seed_phrase": savings_words,
                "password": password,
                "display_name": display_name,
            });

            let response = client
                .post(&format!("{}/identity/restore/seed", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;

                println!("✓ Identity restored successfully!");

                if let Some(identity_id) = result.get("identity_id") {
                    println!("   Identity ID: {}", identity_id.as_str().unwrap_or("N/A"));
                }
                if let Some(wallets) = result.get("wallets") {
                    if let Some(primary) = wallets.get("primary") {
                        if let Some(id) = primary.get("id") {
                            println!("   Primary Wallet: {}", id.as_str().unwrap_or("N/A"));
                        }
                    }
                    if let Some(ubi) = wallets.get("ubi") {
                        if let Some(id) = ubi.get("id") {
                            println!("   UBI Wallet: {}", id.as_str().unwrap_or("N/A"));
                        }
                    }
                    if let Some(savings) = wallets.get("savings") {
                        if let Some(id) = savings.get("id") {
                            println!("   Savings Wallet: {}", id.as_str().unwrap_or("N/A"));
                        }
                    }
                }

                println!("\n Full citizen identity restored with all 3 wallets!");
                println!("   - Primary wallet for daily spending");
                println!("   - UBI wallet for universal basic income");
                println!("   - Savings wallet for long-term storage");

                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("❌ Failed to restore identity: {} - {}", status, error_text);
            }
        }
        IdentityAction::VerifySeed { seed_phrase, wallet_type } => {
            println!("🔍 Verifying seed phrase...");

            let words: Vec<String> = seed_phrase.split_whitespace().map(|s| s.to_string()).collect();

            if words.len() != 20 {
                println!("❌ Error: Seed phrase must have exactly 20 words (got {})", words.len());
                return Ok(());
            }

            let request_body = json!({
                "seed_phrase": words,
                "wallet_type": wallet_type,
            });

            let response = client
                .post(&format!("{}/identity/seed/verify", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;

                if let Some(status) = result.get("status") {
                    if status.as_str() == Some("seed_valid") {
                        println!("✓ Seed phrase is VALID");
                    } else {
                        println!("❌ Seed phrase is INVALID");
                    }
                }

                if let Some(checksum_valid) = result.get("checksum_valid") {
                    println!("   Checksum: {}", if checksum_valid.as_bool().unwrap_or(false) { "✓ Valid" } else { "❌ Invalid" });
                }
                if let Some(entropy) = result.get("entropy_sufficient") {
                    println!("   Entropy: {}", if entropy.as_bool().unwrap_or(false) { "✓ Sufficient" } else { "❌ Insufficient" });
                }
                if let Some(score) = result.get("strength_score") {
                    println!("   Strength Score: {}", score);
                }

                if let Some(errors) = result.get("errors") {
                    if let Some(err_arr) = errors.as_array() {
                        if !err_arr.is_empty() {
                            println!("\n❌ Errors:");
                            for err in err_arr {
                                println!("   - {}", err.as_str().unwrap_or("Unknown error"));
                            }
                        }
                    }
                }

                if let Some(warnings) = result.get("warnings") {
                    if let Some(warn_arr) = warnings.as_array() {
                        if !warn_arr.is_empty() {
                            println!("\n⚠️  Warnings:");
                            for warn in warn_arr {
                                println!("   - {}", warn.as_str().unwrap_or("Unknown warning"));
                            }
                        }
                    }
                }

                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("❌ Failed to verify seed phrase: {} - {}", status, error_text);
            }
        }
        IdentityAction::ExportSeeds { identity_id, password, output } => {
            println!("⚠️  WARNING: Exporting seed phrases is DANGEROUS!");
            println!("   Anyone with these seed phrases can control your wallets.");
            println!("   Store them securely offline.");
            println!();
            println!("🔓 Exporting seed phrases for identity: {}", identity_id);

            let request_body = json!({
                "identity_id": identity_id,
                "password": password,
            });

            let response = client
                .get(&format!("{}/identity/{}/seeds", base_url, identity_id))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .query(&[("password", password)])
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;

                if let Some(seed_phrases) = result.get("seed_phrases") {
                    println!("\n════════════════════════════════════════════════════════");
                    println!("                    SEED PHRASES");
                    println!("════════════════════════════════════════════════════════");

                    if let Some(primary) = seed_phrases.get("primary_wallet") {
                        if let Some(words) = primary.get("words") {
                            if let Some(word_arr) = words.as_array() {
                                let word_strs: Vec<String> = word_arr.iter().filter_map(|w| w.as_str().map(|s| s.to_string())).collect();
                                println!("\nPRIMARY WALLET:");
                                println!("   {}", word_strs.join(" "));
                            }
                        }
                    }

                    if let Some(ubi) = seed_phrases.get("ubi_wallet") {
                        if let Some(words) = ubi.get("words") {
                            if let Some(word_arr) = words.as_array() {
                                let word_strs: Vec<String> = word_arr.iter().filter_map(|w| w.as_str().map(|s| s.to_string())).collect();
                                println!("\nUBI WALLET:");
                                println!("   {}", word_strs.join(" "));
                            }
                        }
                    }

                    if let Some(savings) = seed_phrases.get("savings_wallet") {
                        if let Some(words) = savings.get("words") {
                            if let Some(word_arr) = words.as_array() {
                                let word_strs: Vec<String> = word_arr.iter().filter_map(|w| w.as_str().map(|s| s.to_string())).collect();
                                println!("\nSAVINGS WALLET:");
                                println!("   {}", word_strs.join(" "));
                            }
                        }
                    }

                    println!("\n════════════════════════════════════════════════════════");
                    println!("⚠️  CRITICAL SECURITY NOTICE:");
                    println!("   • Write down these phrases in the exact order shown");
                    println!("   • Store in multiple secure, offline locations");
                    println!("   • Never share, email, or store digitally");
                    println!("   • Loss of these phrases = permanent loss of wallet access");
                    println!("════════════════════════════════════════════════════════");

                    // Save to file if output path provided
                    if let Some(output_path) = output {
                        use std::fs;
                        let formatted = serde_json::to_string_pretty(&result)?;
                        fs::write(&output_path, formatted)?;
                        println!("\n✓ Seed phrases saved to: {}", output_path);
                        println!("   (Ensure this file is stored securely!)");
                    }
                }

                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("❌ Failed to export seed phrases: {} - {}", status, error_text);
                if status == 401 {
                    println!("   (Invalid password or unauthorized)");
                }
            }
        }
    }

    Ok(())
}
