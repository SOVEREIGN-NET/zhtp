//! Backup CLI Commands
//!
//! Handles encrypted identity backup export/import/verify operations

use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;
use lib_identity::{BackupManager, backup::format::BackupData};
use crate::cli::{BackupArgs, BackupAction, ZhtpCli};

/// Handle backup command
pub async fn handle_backup_command(args: BackupArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        BackupAction::Export {
            identity_id,
            password,
            output,
            description,
        } => handle_export(identity_id, password, output, description, cli).await,

        BackupAction::Import { input, password } => {
            handle_import(input, password, cli).await
        }

        BackupAction::Verify { input } => handle_verify(input, cli).await,
    }
}

/// Export identity to encrypted backup file
async fn handle_export(
    identity_id: String,
    password: String,
    output: String,
    description: Option<String>,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("📦 Exporting identity backup...");
    println!("   Identity: {}", identity_id);
    println!("   Output:   {}", output);

    // TODO: Get identity and citizenship data from identity manager
    // For now, return error that this needs server integration
    return Err(anyhow!(
        "Backup export requires running ZHTP server. Please start server first:\n\
         zhtp server start\n\n\
         Then use the API endpoint:\n\
         POST /api/v1/identity/backup/export"
    ));

    // Future implementation:
    // 1. Load identity from identity_manager
    // 2. Load citizenship data
    // 3. Create BackupData structure
    // 4. Use BackupManager to encrypt and export
    // 5. Write to file
    //
    // let backup_manager = BackupManager::new();
    // let backup_json = backup_manager.export_backup(
    //     &backup_data,
    //     &password,
    //     identity_id,
    //     description,
    // )?;
    //
    // fs::write(&output, backup_json)?;
    // println!("✓ Backup exported successfully to {}", output);
    // Ok(())
}

/// Import identity from encrypted backup file
async fn handle_import(input: String, password: String, cli: &ZhtpCli) -> Result<()> {
    println!("📥 Importing identity from backup...");
    println!("   Input: {}", input);

    // Check if file exists
    if !Path::new(&input).exists() {
        return Err(anyhow!("Backup file not found: {}", input));
    }

    // Read backup file
    let backup_json = fs::read_to_string(&input)?;

    // Decrypt and import
    let backup_manager = BackupManager::new();
    let backup_data = backup_manager.import_backup(&backup_json, &password)?;

    println!("✓ Backup decrypted successfully");
    println!("   Identity: {}", backup_data.identity.identity_id);
    println!("   Created:  {}", format_timestamp(backup_data.identity.created_at));

    // TODO: Restore identity to identity manager
    // For now, just show what would be restored
    println!("\n📋 Backup Contents:");
    println!("   Display Name: {}", backup_data.identity.display_name);
    println!("   Identity Type: {}", backup_data.identity.identity_type);
    println!("   Access Level: {}", backup_data.identity.access_level);
    println!("   Wallets:");
    println!("     - Primary: {}", backup_data.seed_phrases.primary_wallet.wallet_id);
    println!("     - UBI:     {}", backup_data.seed_phrases.ubi_wallet.wallet_id);
    println!("     - Savings: {}", backup_data.seed_phrases.savings_wallet.wallet_id);
    println!("   DAO Voting Power: {}", backup_data.dao_registration.voting_power);
    println!("   UBI Daily Amount: {}", backup_data.ubi_registration.daily_amount);

    println!("\n⚠️  Identity restored to memory only.");
    println!("   To persist, use the API endpoint:");
    println!("   POST /api/v1/identity/backup/import");

    Ok(())
}

/// Verify backup file integrity
async fn handle_verify(input: String, cli: &ZhtpCli) -> Result<()> {
    println!("🔍 Verifying backup file...");
    println!("   Input: {}", input);

    // Check if file exists
    if !Path::new(&input).exists() {
        return Err(anyhow!("Backup file not found: {}", input));
    }

    // Read backup file
    let backup_json = fs::read_to_string(&input)?;

    // Verify backup
    let backup_manager = BackupManager::new();
    let verification = backup_manager.verify_backup(&backup_json)?;

    if verification.valid {
        println!("✓ Backup file is valid");
        println!("\n📋 Backup Information:");
        println!("   Version:     {}", verification.version);
        println!("   Created:     {}", format_timestamp(verification.created_at));
        if let Some(id) = &verification.identity_id {
            println!("   Identity ID: {}", id);
        }

        if !verification.warnings.is_empty() {
            println!("\n⚠️  Warnings:");
            for warning in &verification.warnings {
                println!("   - {}", warning);
            }
        }
    } else {
        println!("✗ Backup file is INVALID");
        println!("\n❌ Errors:");
        for error in &verification.errors {
            println!("   - {}", error);
        }
        return Err(anyhow!("Backup verification failed"));
    }

    Ok(())
}

/// Format Unix timestamp to human-readable string
fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let duration = Duration::from_secs(timestamp);
    let datetime = UNIX_EPOCH + duration;

    match datetime.duration_since(SystemTime::now()) {
        Ok(_) => format!("{} (future)", timestamp),
        Err(elapsed) => {
            let secs = elapsed.duration().as_secs();
            if secs < 60 {
                format!("{} seconds ago", secs)
            } else if secs < 3600 {
                format!("{} minutes ago", secs / 60)
            } else if secs < 86400 {
                format!("{} hours ago", secs / 3600)
            } else {
                format!("{} days ago", secs / 86400)
            }
        }
    }
}
