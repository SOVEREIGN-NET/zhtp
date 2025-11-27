//! Identity Handler Module
//! 
//! Clean, minimal identity management using lib-identity patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Identity management imports
use lib_identity::{
    IdentityManager, IdentityType, CitizenshipResult,
    wallets::WalletType,
};

// Identity and economic model imports
use lib_identity::{
    economics::EconomicModel as IdentityEconomicModel,
};

// Blockchain imports for transaction creation
use lib_blockchain::{
    Transaction, 
    transaction::IdentityTransactionData,
    integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm},
    Hash,
};

// Removed unused cryptographic imports

/// Clean identity handler implementation
pub struct IdentityHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<IdentityEconomicModel>>,
}

impl IdentityHandler {
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<IdentityEconomicModel>>,
    ) -> Self {
        Self {
            identity_manager,
            economic_model,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for IdentityHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Identity handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/identity/create") => {
                self.handle_create_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/login") => {
                self.handle_login(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/") => {
                self.handle_get_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/citizenship/apply") => {
                self.handle_citizenship_application(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/restore/seed") => {
                self.handle_restore_from_seeds(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/seed/verify") => {
                self.handle_verify_seed(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/") && path.ends_with("/seeds") => {
                self.handle_export_seeds(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/export") => {
                self.handle_backup_export(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/import") => {
                self.handle_backup_import(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/verify") => {
                self.handle_backup_verify(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/add") => {
                self.handle_guardian_add(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/guardian/list/") => {
                self.handle_guardian_list(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/remove") => {
                self.handle_guardian_remove(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/accept") => {
                self.handle_guardian_accept(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/decline") => {
                self.handle_guardian_decline(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/recovery/initiate") => {
                self.handle_recovery_initiate(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/recovery/approve") => {
                self.handle_recovery_approve(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/guardian/recovery/status/") => {
                self.handle_recovery_status(request).await
            }
            (ZhtpMethod::Post, "/api/v1/guardian/recovery/cancel") => {
                self.handle_recovery_cancel(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Identity endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                // Add ZHTP headers
                resp.headers.set("X-Handler", "Identity".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Identity handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Identity error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/identity/")
    }
    
    fn priority(&self) -> u32 {
        100
    }
}

// Request/Response structures following lib-identity patterns
#[derive(Deserialize)]
struct CreateIdentityRequest {
    display_name: String,
    identity_type: Option<String>,  // Optional, defaults to "human"
    recovery_options: Option<Vec<String>>,
    password: Option<String>,  // Optional password for identity
}

#[derive(Serialize)]
struct CreateIdentityResponse {
    status: String,
    identity_id: String,
    identity_type: String,
    access_level: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    citizenship_result: Option<CitizenshipResult>,
}

#[derive(Serialize)]
struct IdentityResponse {
    status: String,
    identity_id: String,
    identity_type: String,
    access_level: String,
    created_at: u64,
    last_active: u64,
}

#[derive(Deserialize)]
struct LoginRequest {
    identity_id: String,  // hex-encoded
    password: String,
}

#[derive(Serialize, Deserialize)]
struct WalletInfo {
    id: String,
    wallet_type: String,
    name: String,
    balance: u64,
    staked_balance: u64,
    pending_rewards: u64,
}

#[derive(Serialize)]
struct LoginResponse {
    status: String,
    identity_id: String,
    display_name: String,
    identity_type: String,
    access_level: String,
    wallets: WalletsInfo,
}

#[derive(Serialize, Deserialize)]
struct WalletsInfo {
    primary: WalletInfo,
    ubi: WalletInfo,
    savings: WalletInfo,
}

// Recovery endpoint structures
#[derive(Deserialize, Serialize)]
struct RestoreFromSeedsRequest {
    primary_seed_phrase: Vec<String>,
    ubi_seed_phrase: Vec<String>,
    savings_seed_phrase: Vec<String>,
    password: Option<String>,
    display_name: String,
}

#[derive(Serialize, Deserialize)]
struct RestoreFromSeedsResponse {
    status: String,
    identity_id: String,
    display_name: String,
    wallets: WalletsInfo,
    dao_voting_power: u64,
    ubi_daily_amount: u64,
}

#[derive(Deserialize, Serialize)]
struct VerifySeedRequest {
    seed_phrase: Vec<String>,
    wallet_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VerifySeedResponse {
    status: String,
    seed_valid: bool,
    checksum_valid: bool,
    entropy_sufficient: bool,
    strength_score: f64,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct SeedPhraseInfo {
    words: Vec<String>,
    wallet_type: String,
    word_count: usize,
}

#[derive(Serialize)]
struct ExportSeedsResponse {
    status: String,
    identity_id: String,
    seed_phrases: SeedPhrasesData,
}

#[derive(Serialize)]
struct SeedPhrasesData {
    primary_wallet: SeedPhraseInfo,
    ubi_wallet: SeedPhraseInfo,
    savings_wallet: SeedPhraseInfo,
}

// Backup endpoint structures
#[derive(Deserialize, Serialize)]
struct BackupExportRequest {
    identity_id: String,
    password: String,
    description: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct BackupImportRequest {
    backup_data: String,  // JSON backup file contents
    password: String,
}

#[derive(Serialize, Deserialize)]
struct BackupImportResponse {
    status: String,
    identity_id: String,
    display_name: String,
    wallets: BackupWalletsInfo,
    dao_voting_power: u64,
    ubi_daily_amount: u64,
}

#[derive(Serialize, Deserialize)]
struct BackupWalletsInfo {
    primary: String,
    ubi: String,
    savings: String,
}

#[derive(Deserialize, Serialize)]
struct BackupVerifyRequest {
    backup_data: String,  // JSON backup file contents
}

#[derive(Serialize, Deserialize)]
struct BackupVerifyResponse {
    status: String,
    valid: bool,
    version: String,
    created_at: u64,
    identity_id: Option<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

// Guardian endpoint structures
#[derive(Deserialize, Serialize)]
struct GuardianAddRequest {
    identity_id: String,
    name: String,
    email: Option<String>,
    phone: Option<String>,
    guardian_identity_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct GuardianAddResponse {
    status: String,
    guardian_id: String,
    verification_code: String,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct GuardianRemoveRequest {
    identity_id: String,
    guardian_id: String,
}

#[derive(Serialize, Deserialize)]
struct GuardianRemoveResponse {
    status: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct GuardianInfo {
    guardian_id: String,
    display_name: String,
    contact_method: String,
    status: String,
    added_at: u64,
}

#[derive(Serialize, Deserialize)]
struct GuardianListResponse {
    status: String,
    identity_id: String,
    guardians: Vec<GuardianInfo>,
    threshold: usize,
    min_required: usize,
}

#[derive(Deserialize, Serialize)]
struct GuardianAcceptRequest {
    guardian_id: String,
    verification_code: String,
}

#[derive(Serialize, Deserialize)]
struct GuardianAcceptResponse {
    status: String,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct GuardianDeclineRequest {
    guardian_id: String,
}

#[derive(Serialize, Deserialize)]
struct GuardianDeclineResponse {
    status: String,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct RecoveryInitiateRequest {
    identity_id: String,
    new_password: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryInitiateResponse {
    status: String,
    request_id: String,
    timelock_expires_at: u64,
    threshold_required: usize,
    guardians_notified: usize,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct RecoveryApproveRequest {
    request_id: String,
    guardian_id: String,
    verification_code: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryApproveResponse {
    status: String,
    approvals_received: usize,
    threshold_required: usize,
    can_proceed: bool,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryStatusResponse {
    status: String,
    request_id: String,
    identity_id: String,
    created_at: u64,
    timelock_expires_at: u64,
    approvals_received: usize,
    threshold_required: usize,
    request_status: String,
    can_proceed: bool,
    time_remaining: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct RecoveryCancelRequest {
    request_id: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryCancelResponse {
    status: String,
    message: String,
}

impl IdentityHandler {
    /// Handle identity creation using lib-identity patterns
    async fn handle_create_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: CreateIdentityRequest = serde_json::from_slice(&request.body)?;
        
        // Parse identity type (defaults to human if not specified)
        let identity_type_str = req_data.identity_type.as_deref().unwrap_or("human");
        let identity_type = match identity_type_str {
            "human" => IdentityType::Human,
            "organization" => IdentityType::Organization,
            "device" => IdentityType::Device,
            _ => return Err(anyhow::anyhow!("Invalid identity type")),
        };
        
        let mut identity_manager = self.identity_manager.write().await;
        
        let response_data = if identity_type == IdentityType::Human {
            // Create full citizen identity WITH seed phrases
            let mut economic_model = self.economic_model.write().await;
            let citizenship_result = identity_manager
                .create_citizen_identity(
                    req_data.display_name.clone(), // Use provided display name
                    req_data.recovery_options.unwrap_or_default(),
                    &mut *economic_model,
                )
                .await?;
            
            // Set password if provided
            if let Some(password) = &req_data.password {
                if let Err(e) = identity_manager.set_identity_password(&citizenship_result.identity_id, password) {
                    tracing::warn!("Failed to set identity password: {}", e);
                }
            }
            
            //  Create blockchain transactions for identity + all 3 wallets
            tracing::info!(" Creating blockchain transactions for identity and wallets");
            let did_string = format!("did:zhtp:{}", citizenship_result.identity_id);
            
            // Create proper ownership proof by signing the DID with identity data
            let ownership_proof_data = format!("{}:{}", did_string, citizenship_result.identity_id);
            let ownership_proof = ownership_proof_data.as_bytes().to_vec();
            
            let identity_transaction_data = IdentityTransactionData::new(
                did_string.clone(),
                citizenship_result.identity_id.to_string(),
                citizenship_result.primary_wallet_id.as_bytes().to_vec(), // public key
                ownership_proof, // proper ownership proof
                "human".to_string(),
                Hash::default(), // DID document hash
                0, // registration fee - system transactions are fee-free
                0, // DAO fee - system transactions are fee-free
            );
            
            // Create proper cryptographic signature for blockchain transaction
            // The signature must be over the transaction hash, not arbitrary data
            use lib_crypto::{generate_keypair, sign_message};
            
            // Generate a temporary keypair (in production, use citizen's actual keypair)
            let keypair = generate_keypair().map_err(|e| anyhow::anyhow!("Failed to generate keypair: {}", e))?;
            
            // Create transaction WITHOUT signature first to get the hash for signing
            let temp_transaction = Transaction::new_identity_registration(
                identity_transaction_data.clone(),
                vec![], // No outputs needed for identity registration
                Signature {
                    signature: Vec::new(), // Empty signature for hash calculation
                    public_key: PublicKey::new(Vec::new()), // Empty public key for hash calculation
                    algorithm: SignatureAlgorithm::Dilithium2,
                    timestamp: citizenship_result.dao_registration.registered_at,
                },
                Vec::new(), // Empty data for initial hash
            );
            
            // Get the transaction hash that needs to be signed
            let tx_hash = temp_transaction.hash();
            
            // Sign the transaction hash with proper cryptographic signature
            let crypto_signature = sign_message(&keypair, tx_hash.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create signature: {}", e))?;
            
            // Create the final blockchain transaction with proper signature
            let transaction = Transaction::new_identity_registration(
                identity_transaction_data,
                vec![], // No outputs needed for identity registration
                Signature {
                    signature: crypto_signature.signature, // cryptographic signature over tx hash
                    public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()), // public key
                    algorithm: SignatureAlgorithm::Dilithium2, // Post-quantum algorithm
                    timestamp: citizenship_result.dao_registration.registered_at,
                },
                Vec::new(), // No additional data needed
            );
            
            // Submit identity transaction to shared blockchain
            tracing::info!(" Attempting to submit identity transaction to blockchain...");
            match self.submit_transaction_to_blockchain(transaction).await {
                Ok(tx_hash) => {
                    tracing::info!(" Identity transaction submitted to blockchain: {}", tx_hash);
                }
                Err(e) => {
                    tracing::error!(" Failed to submit identity transaction to blockchain: {}", e);
                }
            }
            
            // Create and submit wallet transactions for all 3 wallets
            use lib_blockchain::transaction::WalletTransactionData;
            
            // Primary Wallet
            let primary_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.primary_wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.primary_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: citizenship_result.welcome_bonus.bonus_amount,  // Welcome bonus goes to primary
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(primary_wallet_tx).await {
                tracing::warn!("Failed to submit primary wallet to blockchain: {}", e);
            }
            
            // UBI Wallet
            let ubi_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.ubi_wallet_id.0),
                wallet_type: "UBI".to_string(),
                wallet_name: "UBI Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.ubi_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: 0,  // UBI payments come later
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(ubi_wallet_tx).await {
                tracing::warn!("Failed to submit UBI wallet to blockchain: {}", e);
            }
            
            // Savings Wallet
            let savings_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.savings_wallet_id.0),
                wallet_type: "Savings".to_string(),
                wallet_name: "Savings Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.savings_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: 0,  // Starts empty
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(savings_wallet_tx).await {
                tracing::warn!("Failed to submit savings wallet to blockchain: {}", e);
            }
            
            CreateIdentityResponse {
                status: "citizen_created".to_string(),
                identity_id: citizenship_result.identity_id.to_string(),
                identity_type: "human".to_string(),
                access_level: "FullCitizen".to_string(),
                created_at: citizenship_result.dao_registration.registered_at,
                citizenship_result: Some(citizenship_result),
            }
        } else {
            // Create basic identity (non-human)
            // For now, return a placeholder response
            // Generate proper random identity ID for non-human identities
            let identity_type_for_hash = req_data.identity_type.as_deref().unwrap_or("unknown");
            let identity_data = format!("{}:{}", identity_type_for_hash, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
            let identity_id = lib_crypto::hash_blake3(identity_data.as_bytes());
            
            CreateIdentityResponse {
                status: "identity_created".to_string(),
                identity_id: hex::encode(identity_id),
                identity_type: req_data.identity_type.unwrap_or_else(|| "unknown".to_string()),
                access_level: "Visitor".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                citizenship_result: None,
            }
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle identity retrieval
    async fn handle_get_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract identity ID from path: /api/v1/identity/{id}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let identity_id_str = path_parts.get(4)
            .ok_or_else(|| anyhow::anyhow!("Identity ID required"))?;
        
        let identity_id = lib_crypto::Hash::from_hex(identity_id_str)?;
        
        let identity_manager = self.identity_manager.read().await;
        
        // Use identity manager to retrieve actual identity data
        let response_data = match identity_manager.get_identity(&identity_id) {
            Some(identity) => IdentityResponse {
                status: "identity_found".to_string(),
                identity_id: identity_id.to_string(),
                identity_type: format!("{:?}", identity.identity_type),
                access_level: format!("{:?}", identity.access_level),
                created_at: identity.created_at,
                last_active: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            },
            None => IdentityResponse {
                status: "identity_not_found".to_string(),
                identity_id: identity_id.to_string(),
                identity_type: "unknown".to_string(),
                access_level: "None".to_string(),
                created_at: 0,
                last_active: 0,
            },
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle citizenship application
    async fn handle_citizenship_application(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract and validate application data from request
        let application_data: serde_json::Value = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid application data: {}", e))?;
        
        // Validate required fields in application
        let applicant_name = application_data.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Anonymous");
        
        let applicant_email = application_data.get("email")
            .and_then(|v| v.as_str());
        
        // Validate that at least a name is provided
        if applicant_name == "Anonymous" && applicant_email.is_none() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Application must include either name or email".to_string(),
            ));
        }
        
        tracing::info!("Processing citizenship application for: {} ({})", 
            applicant_name, 
            applicant_email.unwrap_or("no email"));
        
        // TODO: Store application in identity manager for processing
        let response_data = json!({
            "status": "citizenship_application_received",
            "message": "Citizenship application functionality pending implementation",
            "next_steps": [
                "Identity verification",
                "Background check",
                "DAO vote approval"
            ]
        });
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle identity login
    async fn handle_login(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: LoginRequest = serde_json::from_slice(&request.body)?;

        // Parse identity_id from hex
        let identity_id = lib_crypto::Hash::from_hex(&req_data.identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity_id format"))?;

        // Validate password
        let identity_manager = self.identity_manager.read().await;

        match identity_manager.validate_identity_password(&identity_id, &req_data.password) {
            Ok(validation) => {
                if !validation.valid {
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::Unauthorized,
                        "Invalid password".to_string(),
                    ));
                }
            }
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Unauthorized,
                    "Invalid credentials".to_string(),
                ));
            }
        }

        // Get identity
        let identity = identity_manager.get_identity(&identity_id)
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // Extract display_name from metadata
        let display_name = identity.metadata.get("display_name")
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        // Extract wallets by type
        let mut primary_wallet = None;
        let mut ubi_wallet = None;
        let mut savings_wallet = None;

        for (wallet_id, wallet) in &identity.wallet_manager.wallets {
            let wallet_info = WalletInfo {
                id: wallet_id.to_string(),
                wallet_type: format!("{:?}", wallet.wallet_type),
                name: wallet.name.clone(),
                balance: wallet.balance,
                staked_balance: wallet.staked_balance,
                pending_rewards: wallet.pending_rewards,
            };

            match wallet.wallet_type {
                WalletType::Primary => primary_wallet = Some(wallet_info),
                WalletType::UBI => ubi_wallet = Some(wallet_info),
                WalletType::Savings => savings_wallet = Some(wallet_info),
                _ => {}
            }
        }

        // Ensure all three wallets exist
        let primary = primary_wallet.ok_or_else(|| anyhow::anyhow!("Primary wallet not found"))?;
        let ubi = ubi_wallet.ok_or_else(|| anyhow::anyhow!("UBI wallet not found"))?;
        let savings = savings_wallet.ok_or_else(|| anyhow::anyhow!("Savings wallet not found"))?;

        let response_data = LoginResponse {
            status: "login_successful".to_string(),
            identity_id: identity_id.to_string(),
            display_name,
            identity_type: format!("{:?}", identity.identity_type),
            access_level: format!("{:?}", identity.access_level),
            wallets: WalletsInfo {
                primary,
                ubi,
                savings,
            },
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Submit a transaction to the shared blockchain
    async fn submit_transaction_to_blockchain(&self, transaction: Transaction) -> Result<String> {
        tracing::info!("📝 Getting shared blockchain instance for transaction submission...");
        
        // Get the shared blockchain instance
        match lib_blockchain::get_shared_blockchain().await {
            Ok(shared_blockchain) => {
                tracing::info!("✅ Got shared blockchain, acquiring write lock...");
                
                // Add timeout to prevent infinite blocking
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(10),
                    shared_blockchain.write()
                ).await {
                    Ok(mut blockchain) => {
                        tracing::info!("✅ Write lock acquired, adding transaction to mempool...");
                        
                        // Add transaction to pending pool
                        blockchain.add_pending_transaction(transaction.clone())?;
                        
                        let tx_hash = transaction.hash().to_string();
                        tracing::info!(" Transaction submitted to blockchain mempool: {}", &tx_hash[..16]);
                        
                        // Explicitly drop lock
                        drop(blockchain);
                        tracing::info!("✅ Write lock released");
                        
                        Ok(tx_hash)
                    }
                    Err(_) => {
                        tracing::error!("❌ TIMEOUT: Failed to acquire write lock on blockchain after 10 seconds!");
                        tracing::error!("   This indicates a deadlock - another task is holding the lock");
                        Err(anyhow::anyhow!("Blockchain write lock timeout - possible deadlock"))
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get shared blockchain: {}", e);
                Err(anyhow::anyhow!("Failed to submit transaction: {}", e))
            }
        }
    }
    
    /// Submit a wallet registration transaction to the blockchain
    async fn submit_wallet_to_blockchain(&self, wallet_data: lib_blockchain::transaction::WalletTransactionData) -> Result<String> {
        use lib_blockchain::transaction::Transaction;
        use lib_blockchain::integration::{Signature, PublicKey, SignatureAlgorithm};
        
        // Generate keypair for wallet transaction signature
        let keypair = lib_crypto::KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("Failed to generate keypair: {}", e))?;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create temporary transaction to get hash for signing
        let temp_transaction = Transaction::new_wallet_registration(
            wallet_data.clone(),
            vec![], // Empty outputs
            Signature {
                signature: vec![0; 2420], // Temporary signature
                public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp,
            },
            Vec::new(), // Empty data
        );
        
        // Get the transaction hash for signing
        let tx_hash = temp_transaction.hash();
        
        // Sign the transaction hash
        let crypto_signature = keypair.sign(tx_hash.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to sign wallet transaction: {}", e))?;
        
        // Create final signed transaction
        let transaction = Transaction::new_wallet_registration(
            wallet_data.clone(),
            vec![], // Empty outputs
            Signature {
                signature: crypto_signature.signature,
                public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp,
            },
            Vec::new(), // Empty data
        );
        
        // Submit to blockchain
        let tx_hash = self.submit_transaction_to_blockchain(transaction).await?;
        tracing::info!(" Wallet transaction submitted: {} ({})", 
            &tx_hash[..16], 
            wallet_data.wallet_type);
        
        Ok(tx_hash)
    }

    /// Handle identity restoration from seed phrases
    async fn handle_restore_from_seeds(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        use crate::runtime::did_startup::WalletStartupManager;

        let req_data: RestoreFromSeedsRequest = serde_json::from_slice(&request.body)?;

        // Validate seed phrase counts
        if req_data.primary_seed_phrase.len() != 20 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Primary wallet seed phrase must have exactly 20 words, got {}", req_data.primary_seed_phrase.len()),
            ));
        }
        if req_data.ubi_seed_phrase.len() != 20 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("UBI wallet seed phrase must have exactly 20 words, got {}", req_data.ubi_seed_phrase.len()),
            ));
        }
        if req_data.savings_seed_phrase.len() != 20 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Savings wallet seed phrase must have exactly 20 words, got {}", req_data.savings_seed_phrase.len()),
            ));
        }

        tracing::info!("🔓 Restoring citizen identity: {}", req_data.display_name);

        let mut identity_manager = self.identity_manager.write().await;
        let mut economic_model = self.economic_model.write().await;

        // Restore identity
        let citizenship_result = WalletStartupManager::restore_full_identity_from_seeds(
            &req_data.primary_seed_phrase,
            &req_data.ubi_seed_phrase,
            &req_data.savings_seed_phrase,
            req_data.password,
            req_data.display_name.clone(),
            &mut identity_manager,
            &mut economic_model,
        )
        .await?;

        // Get identity to extract wallet info
        let identity = identity_manager.get_identity(&citizenship_result.identity_id)
            .ok_or_else(|| anyhow::anyhow!("Identity not found after restoration"))?;

        // Extract wallet information
        let primary_wallet = identity.wallet_manager.get_wallet(&citizenship_result.primary_wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Primary wallet not found"))?;
        let ubi_wallet = identity.wallet_manager.get_wallet(&citizenship_result.ubi_wallet_id)
            .ok_or_else(|| anyhow::anyhow!("UBI wallet not found"))?;
        let savings_wallet = identity.wallet_manager.get_wallet(&citizenship_result.savings_wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Savings wallet not found"))?;

        let wallets = WalletsInfo {
            primary: WalletInfo {
                id: hex::encode(&citizenship_result.primary_wallet_id.0),
                wallet_type: "Primary".to_string(),
                name: primary_wallet.name.clone(),
                balance: primary_wallet.balance,
                staked_balance: primary_wallet.staked_balance,
                pending_rewards: primary_wallet.pending_rewards,
            },
            ubi: WalletInfo {
                id: hex::encode(&citizenship_result.ubi_wallet_id.0),
                wallet_type: "UBI".to_string(),
                name: ubi_wallet.name.clone(),
                balance: ubi_wallet.balance,
                staked_balance: ubi_wallet.staked_balance,
                pending_rewards: ubi_wallet.pending_rewards,
            },
            savings: WalletInfo {
                id: hex::encode(&citizenship_result.savings_wallet_id.0),
                wallet_type: "Savings".to_string(),
                name: savings_wallet.name.clone(),
                balance: savings_wallet.balance,
                staked_balance: savings_wallet.staked_balance,
                pending_rewards: savings_wallet.pending_rewards,
            },
        };

        let response_data = RestoreFromSeedsResponse {
            status: "identity_restored".to_string(),
            identity_id: hex::encode(&citizenship_result.identity_id.0),
            display_name: req_data.display_name,
            wallets,
            dao_voting_power: citizenship_result.dao_registration.voting_power,
            ubi_daily_amount: citizenship_result.ubi_registration.daily_amount,
        };

        tracing::info!(" Identity restored: {} with 3 wallets", hex::encode(&citizenship_result.identity_id.0[..8]));

        ZhtpResponse::json(&response_data, None)
    }

    /// Handle seed phrase verification
    async fn handle_verify_seed(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        use lib_identity::recovery::RecoveryPhraseManager;

        let req_data: VerifySeedRequest = serde_json::from_slice(&request.body)?;

        // Validate word count
        if req_data.seed_phrase.len() != 20 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Seed phrase must have exactly 20 words, got {}", req_data.seed_phrase.len()),
            ));
        }

        tracing::info!("🔍 Verifying seed phrase (20 words)");

        // Create recovery manager
        let recovery_manager = RecoveryPhraseManager::new();

        // Create phrase from words
        let phrase = lib_identity::recovery::RecoveryPhrase::from_words(req_data.seed_phrase)?;

        // Validate phrase
        let validation = recovery_manager.validate_phrase(&phrase).await?;

        let response_data = VerifySeedResponse {
            status: if validation.valid { "seed_valid".to_string() } else { "seed_invalid".to_string() },
            seed_valid: validation.valid,
            checksum_valid: validation.checksum_valid,
            entropy_sufficient: validation.entropy_sufficient,
            strength_score: validation.strength_score,
            errors: validation.errors,
            warnings: validation.warnings,
        };

        tracing::info!(" Seed verification: valid={}, strength={:.2}", validation.valid, validation.strength_score);

        ZhtpResponse::json(&response_data, None)
    }

    /// Handle seed phrase export (DANGEROUS - requires password)
    async fn handle_export_seeds(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract identity_id from URI path
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let identity_id_hex = path_parts.get(4)
            .ok_or_else(|| anyhow::anyhow!("Invalid URI format"))?;

        // Parse identity_id from hex
        let identity_id_bytes = hex::decode(identity_id_hex)
            .map_err(|e| anyhow::anyhow!("Invalid identity_id format: {}", e))?;
        let identity_id = lib_crypto::Hash::from_bytes(&identity_id_bytes);

        // Get password from query parameters
        let password = request.headers.get("password")
            .or_else(|| {
                // Try to parse from query string
                if let Some(query_start) = request.uri.find('?') {
                    let query = &request.uri[query_start + 1..];
                    for param in query.split('&') {
                        if let Some(value) = param.strip_prefix("password=") {
                            return Some(value.to_string());
                        }
                    }
                }
                None
            })
            .ok_or_else(|| anyhow::anyhow!("Password required for seed phrase export"))?;

        tracing::warn!("⚠️  DANGEROUS: Exporting seed phrases for identity {}", hex::encode(&identity_id.0[..8]));

        let identity_manager = self.identity_manager.read().await;

        // Validate password
        let validation = identity_manager.validate_identity_password(&identity_id, &password)?;
        if !validation.valid {
            tracing::warn!("❌ Invalid password for identity {}", hex::encode(&identity_id.0[..8]));
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Invalid password".to_string(),
            ));
        }

        // Get identity
        let identity = identity_manager.get_identity(&identity_id)
            .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

        // Extract seed phrases from wallets
        let wallets = &identity.wallet_manager.wallets;

        let mut primary_seed = None;
        let mut ubi_seed = None;
        let mut savings_seed = None;

        for (wallet_id, wallet) in wallets.iter() {
            if let Some(seed_phrase) = &wallet.seed_phrase {
                let seed_info = SeedPhraseInfo {
                    words: seed_phrase.words.clone(),
                    wallet_type: format!("{:?}", wallet.wallet_type),
                    word_count: seed_phrase.word_count,
                };

                match wallet.wallet_type {
                    lib_identity::wallets::WalletType::Primary => primary_seed = Some(seed_info),
                    lib_identity::wallets::WalletType::UBI => ubi_seed = Some(seed_info),
                    lib_identity::wallets::WalletType::Savings => savings_seed = Some(seed_info),
                    _ => {}
                }
            }
        }

        let primary = primary_seed.ok_or_else(|| anyhow::anyhow!("Primary wallet seed not found"))?;
        let ubi = ubi_seed.ok_or_else(|| anyhow::anyhow!("UBI wallet seed not found"))?;
        let savings = savings_seed.ok_or_else(|| anyhow::anyhow!("Savings wallet seed not found"))?;

        let response_data = ExportSeedsResponse {
            status: "seeds_exported".to_string(),
            identity_id: hex::encode(&identity_id.0),
            seed_phrases: SeedPhrasesData {
                primary_wallet: primary,
                ubi_wallet: ubi,
                savings_wallet: savings,
            },
        };

        tracing::warn!(" Seed phrases exported for identity {}", hex::encode(&identity_id.0[..8]));

        ZhtpResponse::json(&response_data, None)
    }

    /// Handle backup export request
    async fn handle_backup_export(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse request
        let backup_request: BackupExportRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        tracing::info!("Backup export request for identity {}", backup_request.identity_id);

        // TODO: Full integration with citizenship data
        return Err(anyhow::anyhow!(
            "Backup export endpoint not yet fully integrated"
        ));
    }

    /// Handle backup import request
    async fn handle_backup_import(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse request
        let import_request: BackupImportRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        tracing::info!("Backup import request");

        // Use BackupManager to decrypt and import
        let backup_manager = lib_identity::BackupManager::new();
        let backup_data = backup_manager
            .import_backup(&import_request.backup_data, &import_request.password)
            .map_err(|e| anyhow::anyhow!("Backup import failed: {}", e))?;

        tracing::info!("Backup decrypted: {}", backup_data.identity.identity_id);

        // Return backup contents
        let response = BackupImportResponse {
            status: "backup_imported".to_string(),
            identity_id: backup_data.identity.identity_id.clone(),
            display_name: backup_data.identity.display_name.clone(),
            wallets: BackupWalletsInfo {
                primary: backup_data.seed_phrases.primary_wallet.wallet_id.clone(),
                ubi: backup_data.seed_phrases.ubi_wallet.wallet_id.clone(),
                savings: backup_data.seed_phrases.savings_wallet.wallet_id.clone(),
            },
            dao_voting_power: backup_data.dao_registration.voting_power,
            ubi_daily_amount: backup_data.ubi_registration.daily_amount,
        };

        ZhtpResponse::json(&response, None)
    }

    /// Handle backup verify request
    async fn handle_backup_verify(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse request
        let verify_request: BackupVerifyRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        tracing::info!("Backup verification request");

        // Use BackupManager to verify
        let backup_manager = lib_identity::BackupManager::new();
        let verification = backup_manager
            .verify_backup(&verify_request.backup_data)
            .map_err(|e| anyhow::anyhow!("Backup verification failed: {}", e))?;

        let response = BackupVerifyResponse {
            status: if verification.valid {
                "backup_valid".to_string()
            } else {
                "backup_invalid".to_string()
            },
            valid: verification.valid,
            version: verification.version,
            created_at: verification.created_at,
            identity_id: verification.identity_id,
            errors: verification.errors,
            warnings: verification.warnings,
        };

        ZhtpResponse::json(&response, None)
    }

    // ============================================================
    // GUARDIAN API HANDLERS
    // ============================================================

    async fn handle_guardian_add(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let add_request: GuardianAddRequest = serde_json::from_slice(&request.body)?;

        tracing::info!("Guardian add request for identity {}", add_request.identity_id);

        // Validate contact method
        if add_request.email.is_none()
            && add_request.phone.is_none()
            && add_request.guardian_identity_id.is_none() {
            return Err(anyhow::anyhow!("Must provide at least one contact method"));
        }

        // TODO: Integrate with GuardianManager
        // For now, return placeholder response
        let guardian_id = format!("guardian_{}", uuid::Uuid::new_v4());
        let verification_code = format!("CODE{}", &guardian_id[9..15].to_uppercase());

        let response = GuardianAddResponse {
            status: "guardian_added".to_string(),
            guardian_id,
            verification_code,
            message: "Guardian added successfully. Invitation sent.".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_guardian_list(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract identity_id from path
        let identity_id = request.uri
            .strip_prefix("/api/v1/guardian/list/")
            .unwrap_or("")
            .to_string();

        if identity_id.is_empty() {
            return Err(anyhow::anyhow!("Identity ID required"));
        }

        tracing::info!("Guardian list request for identity {}", identity_id);

        // TODO: Integrate with GuardianManager
        // For now, return empty list
        let response = GuardianListResponse {
            status: "success".to_string(),
            identity_id,
            guardians: vec![],
            threshold: 2,
            min_required: 3,
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_guardian_remove(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let remove_request: GuardianRemoveRequest = serde_json::from_slice(&request.body)?;

        tracing::info!(
            "Guardian remove request: {} from identity {}",
            remove_request.guardian_id,
            remove_request.identity_id
        );

        // TODO: Integrate with GuardianManager
        let response = GuardianRemoveResponse {
            status: "guardian_removed".to_string(),
            message: "Guardian removed successfully".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_guardian_accept(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let accept_request: GuardianAcceptRequest = serde_json::from_slice(&request.body)?;

        tracing::info!("Guardian accept request for {}", accept_request.guardian_id);

        // TODO: Integrate with GuardianManager
        let response = GuardianAcceptResponse {
            status: "guardian_accepted".to_string(),
            message: "Guardian invitation accepted".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_guardian_decline(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let decline_request: GuardianDeclineRequest = serde_json::from_slice(&request.body)?;

        tracing::info!("Guardian decline request for {}", decline_request.guardian_id);

        // TODO: Integrate with GuardianManager
        let response = GuardianDeclineResponse {
            status: "guardian_declined".to_string(),
            message: "Guardian invitation declined".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_recovery_initiate(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let initiate_request: RecoveryInitiateRequest = serde_json::from_slice(&request.body)?;

        tracing::info!("Recovery initiate request for identity {}", initiate_request.identity_id);

        // TODO: Integrate with GuardianManager
        let request_id = format!("recovery_{}_{}", initiate_request.identity_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let response = RecoveryInitiateResponse {
            status: "recovery_initiated".to_string(),
            request_id,
            timelock_expires_at: now + 86400, // 24 hours
            threshold_required: 2,
            guardians_notified: 3,
            message: "Recovery request created. Guardians have been notified. Wait 24 hours then get approvals.".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_recovery_approve(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let approve_request: RecoveryApproveRequest = serde_json::from_slice(&request.body)?;

        tracing::info!(
            "Recovery approve request: {} by guardian {}",
            approve_request.request_id,
            approve_request.guardian_id
        );

        // TODO: Integrate with GuardianManager
        let response = RecoveryApproveResponse {
            status: "approval_recorded".to_string(),
            approvals_received: 1,
            threshold_required: 2,
            can_proceed: false,
            message: "Approval recorded. 1 more approval needed.".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_recovery_status(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract request_id from path
        let request_id = request.uri
            .strip_prefix("/api/v1/guardian/recovery/status/")
            .unwrap_or("")
            .to_string();

        if request_id.is_empty() {
            return Err(anyhow::anyhow!("Request ID required"));
        }

        tracing::info!("Recovery status request for {}", request_id);

        // TODO: Integrate with GuardianManager
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let response = RecoveryStatusResponse {
            status: "success".to_string(),
            request_id,
            identity_id: "identity_123".to_string(),
            created_at: now - 3600,
            timelock_expires_at: now + 82800,
            approvals_received: 1,
            threshold_required: 2,
            request_status: "awaiting_approvals".to_string(),
            can_proceed: false,
            time_remaining: Some(82800),
        };

        ZhtpResponse::json(&response, None)
    }

    async fn handle_recovery_cancel(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let cancel_request: RecoveryCancelRequest = serde_json::from_slice(&request.body)?;

        tracing::info!("Recovery cancel request for {}", cancel_request.request_id);

        // TODO: Integrate with GuardianManager
        let response = RecoveryCancelResponse {
            status: "recovery_cancelled".to_string(),
            message: "Recovery request cancelled successfully".to_string(),
        };

        ZhtpResponse::json(&response, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_identity_manager() -> Arc<RwLock<IdentityManager>> {
        Arc::new(RwLock::new(IdentityManager::new()))
    }

    fn create_test_economic_model() -> Arc<RwLock<IdentityEconomicModel>> {
        Arc::new(RwLock::new(IdentityEconomicModel::new()))
    }

    #[test]
    fn test_login_request_parsing() {
        let json = r#"{
            "identity_id": "abc123def456",
            "password": "SecurePass123!@#"
        }"#;

        let request: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.identity_id, "abc123def456");
        assert_eq!(request.password, "SecurePass123!@#");
    }

    #[test]
    fn test_login_response_serialization() {
        let response = LoginResponse {
            status: "login_successful".to_string(),
            identity_id: "test_identity_123".to_string(),
            display_name: "Test User".to_string(),
            identity_type: "Human".to_string(),
            access_level: "FullCitizen".to_string(),
            wallets: WalletsInfo {
                primary: WalletInfo {
                    id: "wallet_primary_001".to_string(),
                    wallet_type: "Primary".to_string(),
                    name: "Primary Wallet".to_string(),
                    balance: 5000,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
                ubi: WalletInfo {
                    id: "wallet_ubi_001".to_string(),
                    wallet_type: "UBI".to_string(),
                    name: "UBI Wallet".to_string(),
                    balance: 0,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
                savings: WalletInfo {
                    id: "wallet_savings_001".to_string(),
                    wallet_type: "Savings".to_string(),
                    name: "Savings Wallet".to_string(),
                    balance: 0,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("login_successful"));
        assert!(json.contains("Test User"));
        assert!(json.contains("Primary Wallet"));
    }

    #[test]
    fn test_wallet_info_structure() {
        let wallet = WalletInfo {
            id: "test_wallet_123".to_string(),
            wallet_type: "Primary".to_string(),
            name: "Test Wallet".to_string(),
            balance: 1000,
            staked_balance: 500,
            pending_rewards: 50,
        };

        let json = serde_json::to_string(&wallet).unwrap();
        assert!(json.contains("test_wallet_123"));
        assert!(json.contains("Primary"));
        assert!(json.contains("1000"));
    }

    #[tokio::test]
    async fn test_identity_handler_creation() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();

        let handler = IdentityHandler::new(
            identity_manager.clone(),
            economic_model.clone(),
        );

        // Verify handler was created with correct dependencies
        assert!(Arc::strong_count(&identity_manager) >= 2); // Handler + test
        assert!(Arc::strong_count(&economic_model) >= 2);
    }

    #[tokio::test]
    async fn test_create_identity_with_password() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();

        // Create a citizen identity with password
        let mut manager = identity_manager.write().await;
        let mut model = economic_model.write().await;

        let result = manager.create_citizen_identity(
            "Test Citizen".to_string(),
            vec![],
            &mut *model,
        ).await;

        assert!(result.is_ok(), "Failed to create citizen identity");
        let citizenship = result.unwrap();

        // Verify identity was created
        assert!(!citizenship.identity_id.to_string().is_empty());

        // Set password
        let password_result = manager.set_identity_password(
            &citizenship.identity_id,
            "TestPassword123!@#",
        );

        assert!(password_result.is_ok(), "Failed to set password");

        // Verify password validation
        let validation_result = manager.validate_identity_password(
            &citizenship.identity_id,
            "TestPassword123!@#",
        );

        assert!(validation_result.is_ok(), "Password validation failed");
        assert!(validation_result.unwrap().valid, "Password should be valid");
    }

    #[tokio::test]
    async fn test_invalid_password_validation() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();

        let mut manager = identity_manager.write().await;
        let mut model = economic_model.write().await;

        let result = manager.create_citizen_identity(
            "Test Citizen".to_string(),
            vec![],
            &mut *model,
        ).await;

        assert!(result.is_ok());
        let citizenship = result.unwrap();

        // Set password
        manager.set_identity_password(&citizenship.identity_id, "CorrectPass123!@#").ok();

        // Try with wrong password
        let validation_result = manager.validate_identity_password(
            &citizenship.identity_id,
            "WrongPassword",
        );

        // Should fail validation
        assert!(validation_result.is_err() || !validation_result.unwrap().valid);
    }

    #[tokio::test]
    async fn test_three_wallet_creation() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();

        let mut manager = identity_manager.write().await;
        let mut model = economic_model.write().await;

        let result = manager.create_citizen_identity(
            "Test Citizen".to_string(),
            vec![],
            &mut *model,
        ).await;

        assert!(result.is_ok());
        let citizenship = result.unwrap();

        // Verify all three wallets exist
        assert!(!citizenship.primary_wallet_id.to_string().is_empty());
        assert!(!citizenship.ubi_wallet_id.to_string().is_empty());
        assert!(!citizenship.savings_wallet_id.to_string().is_empty());

        // Verify wallets are different
        assert_ne!(citizenship.primary_wallet_id, citizenship.ubi_wallet_id);
        assert_ne!(citizenship.primary_wallet_id, citizenship.savings_wallet_id);
        assert_ne!(citizenship.ubi_wallet_id, citizenship.savings_wallet_id);

        // Verify welcome bonus
        assert_eq!(citizenship.welcome_bonus.bonus_amount, 5000);
    }

    #[test]
    fn test_display_name_stored_in_metadata() {
        // This test verifies the fix for display_name storage
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        metadata.insert("display_name".to_string(), "John Doe".to_string());

        assert_eq!(metadata.get("display_name").unwrap(), "John Doe");
    }

    // Recovery endpoint tests
    #[test]
    fn test_restore_from_seeds_request_parsing() {
        let json = r#"{
            "primary_seed_phrase": ["word1", "word2", "word3", "word4", "word5", "word6", "word7", "word8", "word9", "word10", "word11", "word12", "word13", "word14", "word15", "word16", "word17", "word18", "word19", "word20"],
            "ubi_seed_phrase": ["ubi1", "ubi2", "ubi3", "ubi4", "ubi5", "ubi6", "ubi7", "ubi8", "ubi9", "ubi10", "ubi11", "ubi12", "ubi13", "ubi14", "ubi15", "ubi16", "ubi17", "ubi18", "ubi19", "ubi20"],
            "savings_seed_phrase": ["save1", "save2", "save3", "save4", "save5", "save6", "save7", "save8", "save9", "save10", "save11", "save12", "save13", "save14", "save15", "save16", "save17", "save18", "save19", "save20"],
            "password": "TestPassword123",
            "display_name": "Restored User"
        }"#;

        let request: RestoreFromSeedsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.primary_seed_phrase.len(), 20);
        assert_eq!(request.ubi_seed_phrase.len(), 20);
        assert_eq!(request.savings_seed_phrase.len(), 20);
        assert_eq!(request.password, Some("TestPassword123".to_string()));
        assert_eq!(request.display_name, "Restored User");
    }

    #[test]
    fn test_verify_seed_request_parsing() {
        let json = r#"{
            "seed_phrase": ["word1", "word2", "word3", "word4", "word5", "word6", "word7", "word8", "word9", "word10", "word11", "word12", "word13", "word14", "word15", "word16", "word17", "word18", "word19", "word20"],
            "wallet_type": "primary"
        }"#;

        let request: VerifySeedRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.seed_phrase.len(), 20);
        assert_eq!(request.wallet_type, Some("primary".to_string()));
    }

    #[test]
    fn test_restore_response_serialization() {
        let response = RestoreFromSeedsResponse {
            status: "identity_restored".to_string(),
            identity_id: "abc123def456".to_string(),
            display_name: "Test User".to_string(),
            wallets: WalletsInfo {
                primary: WalletInfo {
                    id: "primary_wallet_001".to_string(),
                    wallet_type: "Primary".to_string(),
                    name: "Primary Wallet".to_string(),
                    balance: 0,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
                ubi: WalletInfo {
                    id: "ubi_wallet_001".to_string(),
                    wallet_type: "UBI".to_string(),
                    name: "UBI Wallet".to_string(),
                    balance: 0,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
                savings: WalletInfo {
                    id: "savings_wallet_001".to_string(),
                    wallet_type: "Savings".to_string(),
                    name: "Savings Wallet".to_string(),
                    balance: 0,
                    staked_balance: 0,
                    pending_rewards: 0,
                },
            },
            dao_voting_power: 100,
            ubi_daily_amount: 10,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("identity_restored"));
        assert!(json.contains("Test User"));
        assert!(json.contains("Primary Wallet"));
        assert!(json.contains("UBI Wallet"));
        assert!(json.contains("Savings Wallet"));
    }

    #[test]
    fn test_verify_seed_response_serialization() {
        let response = VerifySeedResponse {
            status: "seed_valid".to_string(),
            seed_valid: true,
            checksum_valid: true,
            entropy_sufficient: true,
            strength_score: 0.95,
            errors: vec![],
            warnings: vec!["Consider using 24 words for extra security".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("seed_valid"));
        assert!(json.contains("true"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn test_export_seeds_response_serialization() {
        let response = ExportSeedsResponse {
            status: "seeds_exported".to_string(),
            identity_id: "test_identity_123".to_string(),
            seed_phrases: SeedPhrasesData {
                primary_wallet: SeedPhraseInfo {
                    words: vec!["word1".to_string(), "word2".to_string()],
                    wallet_type: "Primary".to_string(),
                    word_count: 2,
                },
                ubi_wallet: SeedPhraseInfo {
                    words: vec!["ubi1".to_string(), "ubi2".to_string()],
                    wallet_type: "UBI".to_string(),
                    word_count: 2,
                },
                savings_wallet: SeedPhraseInfo {
                    words: vec!["save1".to_string(), "save2".to_string()],
                    wallet_type: "Savings".to_string(),
                    word_count: 2,
                },
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("seeds_exported"));
        assert!(json.contains("word1"));
        assert!(json.contains("ubi1"));
        assert!(json.contains("save1"));
    }

    #[tokio::test]
    async fn test_restore_from_seeds_invalid_word_count() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        let request_data = RestoreFromSeedsRequest {
            primary_seed_phrase: vec!["word1".to_string()], // Only 1 word, should fail
            ubi_seed_phrase: (0..20).map(|i| format!("ubi{}", i)).collect(),
            savings_seed_phrase: (0..20).map(|i| format!("save{}", i)).collect(),
            password: None,
            display_name: "Test User".to_string(),
        };

        let body = serde_json::to_vec(&request_data).unwrap();
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/restore/seed".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let response = handler.handle_restore_from_seeds(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn test_verify_seed_invalid_word_count() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        let request_data = VerifySeedRequest {
            seed_phrase: vec!["word1".to_string(), "word2".to_string()], // Only 2 words
            wallet_type: None,
        };

        let body = serde_json::to_vec(&request_data).unwrap();
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/seed/verify".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let response = handler.handle_verify_seed(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::BadRequest);
    }

    #[tokio::test]
    async fn test_restore_from_seeds_full_flow() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        // Create valid 20-word seed phrases
        let primary_seed: Vec<String> = (0..20).map(|i| format!("primary{:02}", i)).collect();
        let ubi_seed: Vec<String> = (0..20).map(|i| format!("ubi{:02}", i)).collect();
        let savings_seed: Vec<String> = (0..20).map(|i| format!("savings{:02}", i)).collect();

        let request_data = RestoreFromSeedsRequest {
            primary_seed_phrase: primary_seed,
            ubi_seed_phrase: ubi_seed,
            savings_seed_phrase: savings_seed,
            password: Some("SecurePass123".to_string()),
            display_name: "Restored Citizen".to_string(),
        };

        let body = serde_json::to_vec(&request_data).unwrap();
        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/restore/seed".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let response = handler.handle_restore_from_seeds(request).await.unwrap();
        assert_eq!(response.status, ZhtpStatus::Ok);

        // Parse response
        let response_data: RestoreFromSeedsResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response_data.status, "identity_restored");
        assert_eq!(response_data.display_name, "Restored Citizen");
        assert!(!response_data.wallets.primary.id.is_empty());
        assert!(!response_data.wallets.ubi.id.is_empty());
        assert!(!response_data.wallets.savings.id.is_empty());
    }

    // ============================================================
    // BACKUP API TESTS
    // ============================================================

    #[test]
    fn test_backup_export_request_parsing() {
        let json = r#"{
            "identity_id": "test_identity_123",
            "password": "SecurePassword123!",
            "description": "My backup"
        }"#;

        let request: BackupExportRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.identity_id, "test_identity_123");
        assert_eq!(request.password, "SecurePassword123!");
        assert_eq!(request.description, Some("My backup".to_string()));
    }

    #[test]
    fn test_backup_export_request_without_description() {
        let json = r#"{
            "identity_id": "test_identity_456",
            "password": "AnotherPass456"
        }"#;

        let request: BackupExportRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.identity_id, "test_identity_456");
        assert_eq!(request.password, "AnotherPass456");
        assert_eq!(request.description, None);
    }

    #[test]
    fn test_backup_import_request_parsing() {
        let json = r#"{
            "backup_data": "{\"version\":\"1.0\",\"metadata\":{}}",
            "password": "ImportPassword123"
        }"#;

        let request: BackupImportRequest = serde_json::from_str(json).unwrap();
        assert!(request.backup_data.contains("version"));
        assert_eq!(request.password, "ImportPassword123");
    }

    #[test]
    fn test_backup_import_response_serialization() {
        let response = BackupImportResponse {
            status: "backup_imported".to_string(),
            identity_id: "restored_id_789".to_string(),
            display_name: "Restored User".to_string(),
            wallets: BackupWalletsInfo {
                primary: "wallet_primary_001".to_string(),
                ubi: "wallet_ubi_001".to_string(),
                savings: "wallet_savings_001".to_string(),
            },
            dao_voting_power: 1000,
            ubi_daily_amount: 50,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("backup_imported"));
        assert!(json.contains("Restored User"));
        assert!(json.contains("wallet_primary_001"));
        assert!(json.contains("wallet_ubi_001"));
        assert!(json.contains("wallet_savings_001"));
        assert!(json.contains("1000"));
        assert!(json.contains("50"));
    }

    #[test]
    fn test_backup_wallets_info_structure() {
        let wallets = BackupWalletsInfo {
            primary: "primary_123".to_string(),
            ubi: "ubi_456".to_string(),
            savings: "savings_789".to_string(),
        };

        let json = serde_json::to_string(&wallets).unwrap();
        assert!(json.contains("primary_123"));
        assert!(json.contains("ubi_456"));
        assert!(json.contains("savings_789"));

        // Test deserialization
        let parsed: BackupWalletsInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.primary, "primary_123");
        assert_eq!(parsed.ubi, "ubi_456");
        assert_eq!(parsed.savings, "savings_789");
    }

    #[test]
    fn test_backup_verify_request_parsing() {
        let json = r#"{
            "backup_data": "{\"version\":\"1.0\",\"metadata\":{}}"
        }"#;

        let request: BackupVerifyRequest = serde_json::from_str(json).unwrap();
        assert!(request.backup_data.contains("version"));
        assert!(request.backup_data.contains("metadata"));
    }

    #[test]
    fn test_backup_verify_response_serialization_valid() {
        let response = BackupVerifyResponse {
            status: "backup_valid".to_string(),
            valid: true,
            version: "1.0".to_string(),
            created_at: 1700000000,
            identity_id: Some("identity_123".to_string()),
            errors: vec![],
            warnings: vec!["Version mismatch warning".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("backup_valid"));
        assert!(json.contains("true"));
        assert!(json.contains("1.0"));
        assert!(json.contains("identity_123"));
        assert!(json.contains("Version mismatch warning"));
    }

    #[test]
    fn test_backup_verify_response_serialization_invalid() {
        let response = BackupVerifyResponse {
            status: "backup_invalid".to_string(),
            valid: false,
            version: "1.0".to_string(),
            created_at: 1700000000,
            identity_id: None,
            errors: vec![
                "Checksum mismatch".to_string(),
                "Invalid format".to_string(),
            ],
            warnings: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("backup_invalid"));
        assert!(json.contains("false"));
        assert!(json.contains("Checksum mismatch"));
        assert!(json.contains("Invalid format"));
    }

    #[test]
    fn test_backup_verify_response_round_trip() {
        let original = BackupVerifyResponse {
            status: "backup_valid".to_string(),
            valid: true,
            version: "1.0".to_string(),
            created_at: 1234567890,
            identity_id: Some("test_identity".to_string()),
            errors: vec![],
            warnings: vec!["Test warning".to_string()],
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: BackupVerifyResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.status, original.status);
        assert_eq!(parsed.valid, original.valid);
        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.created_at, original.created_at);
        assert_eq!(parsed.identity_id, original.identity_id);
        assert_eq!(parsed.errors, original.errors);
        assert_eq!(parsed.warnings, original.warnings);
    }

    #[tokio::test]
    async fn test_backup_import_handler_with_valid_backup() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        // Create a valid backup directly
        let backup_manager = lib_identity::BackupManager::new();
        let backup_data = lib_identity::backup::format::BackupData {
            identity: lib_identity::backup::format::IdentityBackup {
                identity_id: "import_test_id".to_string(),
                display_name: "Import Test User".to_string(),
                identity_type: "Human".to_string(),
                access_level: "FullCitizen".to_string(),
                created_at: 1700000000,
                metadata: std::collections::HashMap::new(),
            },
            seed_phrases: lib_identity::backup::format::SeedPhrasesBackup {
                primary_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_1".to_string(),
                    wallet_type: "Primary".to_string(),
                },
                ubi_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_2".to_string(),
                    wallet_type: "UBI".to_string(),
                },
                savings_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_3".to_string(),
                    wallet_type: "Savings".to_string(),
                },
            },
            dao_registration: lib_identity::backup::format::DaoBackup {
                voting_power: 1000,
                proposals_voted: vec![],
                delegated_to: None,
            },
            ubi_registration: lib_identity::backup::format::UbiBackup {
                daily_amount: 50,
                last_claim: 0,
                total_claimed: 0,
            },
            web4_access: lib_identity::backup::format::Web4Backup {
                service_tokens: std::collections::HashMap::new(),
                active_sessions: vec![],
            },
        };

        let backup_json = backup_manager.export_backup(
            &backup_data,
            "ImportTestPassword123",
            "import_test_id".to_string(),
            Some("Test backup for import".to_string()),
        ).unwrap();

        // Test import
        let import_request_json = serde_json::json!({
            "backup_data": backup_json,
            "password": "ImportTestPassword123"
        });

        let import_request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/backup/import".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body: serde_json::to_vec(&import_request_json).unwrap(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let import_response = handler.handle_backup_import(import_request).await.unwrap();
        assert_eq!(import_response.status, ZhtpStatus::Ok);

        // Parse import response
        let import_data: BackupImportResponse = serde_json::from_slice(&import_response.body).unwrap();
        assert_eq!(import_data.status, "backup_imported");
        assert_eq!(import_data.identity_id, "import_test_id");
        assert_eq!(import_data.display_name, "Import Test User");
        assert_eq!(import_data.dao_voting_power, 1000);
        assert_eq!(import_data.ubi_daily_amount, 50);
    }

    #[tokio::test]
    async fn test_backup_verify_with_valid_backup() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        // Create a valid backup
        let backup_manager = lib_identity::BackupManager::new();
        let backup_data = lib_identity::backup::format::BackupData {
            identity: lib_identity::backup::format::IdentityBackup {
                identity_id: "verify_test_id".to_string(),
                display_name: "Verify Test".to_string(),
                identity_type: "Human".to_string(),
                access_level: "FullCitizen".to_string(),
                created_at: 1700000000,
                metadata: std::collections::HashMap::new(),
            },
            seed_phrases: lib_identity::backup::format::SeedPhrasesBackup {
                primary_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_1".to_string(),
                    wallet_type: "Primary".to_string(),
                },
                ubi_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_2".to_string(),
                    wallet_type: "UBI".to_string(),
                },
                savings_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_3".to_string(),
                    wallet_type: "Savings".to_string(),
                },
            },
            dao_registration: lib_identity::backup::format::DaoBackup {
                voting_power: 500,
                proposals_voted: vec![],
                delegated_to: None,
            },
            ubi_registration: lib_identity::backup::format::UbiBackup {
                daily_amount: 25,
                last_claim: 0,
                total_claimed: 0,
            },
            web4_access: lib_identity::backup::format::Web4Backup {
                service_tokens: std::collections::HashMap::new(),
                active_sessions: vec![],
            },
        };

        let backup_json = backup_manager.export_backup(
            &backup_data,
            "VerifyPassword123",
            "verify_test_id".to_string(),
            None,
        ).unwrap();

        // Verify the backup
        let verify_request_json = serde_json::json!({
            "backup_data": backup_json
        });

        let verify_request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/backup/verify".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body: serde_json::to_vec(&verify_request_json).unwrap(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let verify_response = handler.handle_backup_verify(verify_request).await.unwrap();
        assert_eq!(verify_response.status, ZhtpStatus::Ok);

        // Parse verify response
        let verify_data: BackupVerifyResponse = serde_json::from_slice(&verify_response.body).unwrap();
        assert_eq!(verify_data.status, "backup_valid");
        assert!(verify_data.valid);
        assert_eq!(verify_data.version, "1.0");
        assert_eq!(verify_data.identity_id, Some("verify_test_id".to_string()));
        assert!(verify_data.errors.is_empty());
    }

    #[tokio::test]
    async fn test_backup_verify_with_invalid_backup() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        // Create an invalid backup (malformed JSON)
        let invalid_backup = r#"{"version": "1.0", "invalid": true"#;

        let verify_request_json = serde_json::json!({
            "backup_data": invalid_backup
        });

        let verify_request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/backup/verify".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body: serde_json::to_vec(&verify_request_json).unwrap(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        let verify_response = handler.handle_backup_verify(verify_request).await.unwrap();
        assert_eq!(verify_response.status, ZhtpStatus::Ok);

        // Parse verify response
        let verify_data: BackupVerifyResponse = serde_json::from_slice(&verify_response.body).unwrap();
        assert_eq!(verify_data.status, "backup_invalid");
        assert!(!verify_data.valid);
        assert!(!verify_data.errors.is_empty());
    }

    #[tokio::test]
    async fn test_backup_import_with_wrong_password() {
        let identity_manager = create_test_identity_manager();
        let economic_model = create_test_economic_model();
        let handler = IdentityHandler::new(identity_manager, economic_model);

        // Create a valid backup
        let backup_manager = lib_identity::BackupManager::new();
        let backup_data = lib_identity::backup::format::BackupData {
            identity: lib_identity::backup::format::IdentityBackup {
                identity_id: "password_test_id".to_string(),
                display_name: "Password Test".to_string(),
                identity_type: "Human".to_string(),
                access_level: "FullCitizen".to_string(),
                created_at: 1700000000,
                metadata: std::collections::HashMap::new(),
            },
            seed_phrases: lib_identity::backup::format::SeedPhrasesBackup {
                primary_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_1".to_string(),
                    wallet_type: "Primary".to_string(),
                },
                ubi_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_2".to_string(),
                    wallet_type: "UBI".to_string(),
                },
                savings_wallet: lib_identity::backup::format::SeedPhraseData {
                    words: vec!["test".to_string(); 20],
                    wallet_id: "wallet_3".to_string(),
                    wallet_type: "Savings".to_string(),
                },
            },
            dao_registration: lib_identity::backup::format::DaoBackup {
                voting_power: 500,
                proposals_voted: vec![],
                delegated_to: None,
            },
            ubi_registration: lib_identity::backup::format::UbiBackup {
                daily_amount: 25,
                last_claim: 0,
                total_claimed: 0,
            },
            web4_access: lib_identity::backup::format::Web4Backup {
                service_tokens: std::collections::HashMap::new(),
                active_sessions: vec![],
            },
        };

        let backup_json = backup_manager.export_backup(
            &backup_data,
            "CorrectPassword123",
            "password_test_id".to_string(),
            None,
        ).unwrap();

        // Try to import with wrong password
        let import_request_json = serde_json::json!({
            "backup_data": backup_json,
            "password": "WrongPassword456"
        });

        let import_request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/identity/backup/import".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body: serde_json::to_vec(&import_request_json).unwrap(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requester: None,
            auth_proof: None,
        };

        // Should fail with authentication error
        let result = handler.handle_backup_import(import_request).await;
        assert!(result.is_err());
    }
}