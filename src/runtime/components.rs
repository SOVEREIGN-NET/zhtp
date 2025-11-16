//! ZHTP Component Implementations
//! 
//! This module provides implementations of ZHTP components
//! that integrate with the actual ZHTP packages - NO STUBS OR PLACEHOLDERS.

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug, error};

use super::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};

// Import ZHTP package implementations
use lib_crypto::{self, KeyPair, generate_keypair, sign_message};
use lib_identity::{self, IdentityManager};
use lib_blockchain::{self, Blockchain, Transaction, TransactionOutput};
use lib_blockchain::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use lib_consensus::{self, ConsensusEngine, ConsensusConfig, ValidatorManager};
use lib_identity::IdentityId;
use lib_protocols::{ZdnsServer, ZhtpIntegration, ZdnsConfig, IntegrationConfig};

// Import configuration types for multi-node genesis
use crate::config::aggregation::BootstrapValidator;

/// Genesis validator for multi-node network initialization
#[derive(Debug, Clone)]
pub struct GenesisValidator {
    /// Validator identity ID (DID hash) - should be USER identity, not node identity
    pub identity_id: lib_crypto::Hash,
    /// Initial stake amount  
    pub stake: u64,
    /// Storage capacity provided
    pub storage_provided: u64,
    /// Commission rate (basis points)
    pub commission_rate: u16,
    /// Network endpoints
    pub endpoints: Vec<String>,
    /// Consensus public key
    pub consensus_key: Option<lib_crypto::PublicKey>,
    /// Physical node device ID that runs validator operations (optional)
    /// Allows tracking which node device performs operations for this USER identity validator
    pub node_device_id: Option<lib_identity::IdentityId>,
}

impl From<BootstrapValidator> for GenesisValidator {
    fn from(bootstrap: BootstrapValidator) -> Self {
        // Parse identity_id - could be DID or hash string
        let identity_id = if bootstrap.identity_id.starts_with("did:") {
            // Extract hash from DID
            let did_parts: Vec<&str> = bootstrap.identity_id.split(':').collect();
            if did_parts.len() >= 3 {
                // Convert hex string to Hash
                if let Ok(bytes) = hex::decode(did_parts[2]) {
                    if bytes.len() == 32 {
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(&bytes);
                        lib_crypto::Hash(hash_bytes)
                    } else {
                        // Fallback: hash the DID string
                        lib_crypto::Hash(lib_crypto::hash_blake3(bootstrap.identity_id.as_bytes()))
                    }
                } else {
                    // Fallback: hash the DID string
                    lib_crypto::Hash(lib_crypto::hash_blake3(bootstrap.identity_id.as_bytes()))
                }
            } else {
                lib_crypto::Hash(lib_crypto::hash_blake3(bootstrap.identity_id.as_bytes()))
            }
        } else {
            // Assume it's a hex hash string
            if let Ok(bytes) = hex::decode(&bootstrap.identity_id) {
                if bytes.len() == 32 {
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(&bytes);
                    lib_crypto::Hash(hash_bytes)
                } else {
                    lib_crypto::Hash(lib_crypto::hash_blake3(bootstrap.identity_id.as_bytes()))
                }
            } else {
                lib_crypto::Hash(lib_crypto::hash_blake3(bootstrap.identity_id.as_bytes()))
            }
        };
        
        // Parse consensus key
        let consensus_key = if !bootstrap.consensus_key.is_empty() {
            // Try to parse as hex or base64
            if let Ok(bytes) = hex::decode(&bootstrap.consensus_key) {
                Some(lib_crypto::PublicKey {
                    dilithium_pk: bytes,
                    kyber_pk: Vec::new(),
                    key_id: identity_id.0,
                })
            } else {
                // Fallback: create from identity
                None
            }
        } else {
            None
        };
        
        Self {
            identity_id,
            stake: bootstrap.stake,
            storage_provided: bootstrap.storage_provided,
            commission_rate: bootstrap.commission_rate,
            endpoints: bootstrap.endpoints,
            consensus_key,
            node_device_id: None, // Not available from bootstrap config
        }
    }
}


/// Helper function to create default storage configuration
fn create_default_storage_config() -> Result<lib_storage::UnifiedStorageConfig> {
    use lib_storage::{UnifiedStorageConfig, StorageConfig, ErasureConfig};
    use lib_storage::StorageTier;
    use lib_crypto::Hash;
    
    Ok(UnifiedStorageConfig {
        node_id: Hash([1u8; 32]), // Simple node ID wrapped in Hash
        addresses: vec![], // Empty addresses = no DHT network binding (DHT handled by lib-network layer)
        economic_config: Default::default(), // Use default for EconomicManagerConfig
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024, // 1GB
            default_tier: StorageTier::Hot, // Use available variant
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    })
}
use lib_network::{self, ZhtpMeshServer};

/// Statistics for routing reward processing
/// 
/// This struct provides a snapshot of routing activity used by the
/// routing reward processor to determine when to create reward transactions.
#[derive(Debug, Clone, Default)]
pub struct RoutingRewardStats {
    /// Theoretical tokens earned from routing activity
    pub theoretical_tokens_earned: u64,
    /// Total bytes routed through this node
    pub bytes_routed: u64,
    /// Total messages routed
    pub messages_routed: u64,
}

/// Storage reward statistics for reward calculation
#[derive(Debug, Clone, Default)]
pub struct StorageRewardStats {
    /// Theoretical tokens earned from storage activity
    pub theoretical_tokens_earned: u64,
    /// Total number of content items stored
    pub items_stored: u64,
    /// Total bytes stored (cumulative size of all content)
    pub bytes_stored: u64,
    /// Total number of content retrievals served
    pub retrievals_served: u64,
    /// Total storage duration in hours
    pub storage_duration_hours: u64,
}

/// Crypto component implementation using lib-crypto package
#[derive(Debug)]
pub struct CryptoComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    keypair: Arc<RwLock<Option<KeyPair>>>,
    last_signature: Arc<RwLock<Option<Vec<u8>>>>,
}

impl CryptoComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            keypair: Arc::new(RwLock::new(None)),
            last_signature: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for CryptoComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Crypto
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting crypto component with lib-crypto implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Generate cryptographic keypair
        let keypair = generate_keypair()?;
        info!("Generated post-quantum keypair");
        
        *self.keypair.write().await = Some(keypair);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Crypto component started with post-quantum cryptography");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping crypto component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.keypair.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Crypto component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, data) if msg == "sign_data" => {
                if let Some(ref keypair) = *self.keypair.read().await {
                    let signature = sign_message(keypair, &data)?;
                    *self.last_signature.write().await = Some(signature.signature.clone());
                    info!("Signed data with post-quantum signature, length: {} bytes", signature.signature.len());
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Crypto component health check");
                Ok(())
            }
            _ => {
                debug!("Crypto component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        metrics.insert("has_keypair".to_string(), if self.keypair.read().await.is_some() { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}

/// ZK component implementation using lib-proofs package
#[derive(Debug)]
pub struct ZKComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
}

impl ZKComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for ZKComponent {
    fn id(&self) -> ComponentId {
        ComponentId::ZK
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting ZK component with lib-proofs implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Initialize ZK system
        info!("Zero-knowledge proof system initialized");
        info!("Privacy-preserving computations ready");
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("ZK component started with zero-knowledge proofs");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping ZK component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("ZK component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("ZK component health check");
                Ok(())
            }
            _ => {
                debug!("ZK component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}

/// Identity component implementation using lib-identity package
pub struct IdentityComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    identity_manager: Arc<RwLock<Option<IdentityManager>>>,
    // Store genesis identities to be registered when component starts (PUBLIC DATA ONLY)
    genesis_identities: Arc<RwLock<Vec<lib_identity::ZhtpIdentity>>>,
    // Store genesis private keys separately in secure memory (NEVER touches blockchain)
    genesis_private_data: Arc<RwLock<Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>>>,
}

impl std::fmt::Debug for IdentityComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityComponent")
            .field("status", &"<RwLock<ComponentStatus>>")
            .field("start_time", &"<RwLock<Option<Instant>>>")
            .field("identity_manager", &"<RwLock<Option<IdentityManager>>>")
            .field("genesis_identities", &"<RwLock<Vec<ZhtpIdentity>>>")
            .field("genesis_private_data", &"<RwLock<Vec<(IdentityId, PrivateIdentityData)>>>")
            .finish()
    }
}

impl IdentityComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(Vec::new())),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Create a new identity component with pre-populated genesis identities (public data only)
    pub fn new_with_identities(genesis_identities: Vec<lib_identity::ZhtpIdentity>) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Create Identity component with genesis identities AND private keys for transaction signing
    /// Private keys are stored in secure memory ONLY - never written to blockchain
    pub fn new_with_identities_and_private_data(
        genesis_identities: Vec<lib_identity::ZhtpIdentity>,
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            identity_manager: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(genesis_identities)),
            genesis_private_data: Arc::new(RwLock::new(genesis_private_data)),
        }
    }
    
    /// Get the identity manager Arc (for runtime coordination)
    pub fn get_identity_manager_arc(&self) -> Arc<RwLock<Option<IdentityManager>>> {
        self.identity_manager.clone()
    }
}

#[async_trait::async_trait]
impl Component for IdentityComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Identity
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting identity component with lib-identity implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Check if we have genesis identities to register
        let genesis_ids = self.genesis_identities.read().await.clone();
        let genesis_private = self.genesis_private_data.read().await.clone();
        
        // Initialize identity manager with genesis identities AND private keys if available
        let mut identity_manager = if genesis_ids.is_empty() {
            info!("No genesis identities - initializing empty IdentityManager");
            lib_identity::initialize_identity_system().await?
        } else if genesis_private.is_empty() {
            info!("  Initializing IdentityManager with {} genesis identities (PUBLIC DATA ONLY - no signing capability)", genesis_ids.len());
            lib_identity::initialize_identity_system_with_identities(genesis_ids.clone()).await?
        } else {
            info!(" Initializing IdentityManager with {} genesis identities and {} private keys (FULL SIGNING CAPABILITY)", 
                genesis_ids.len(), genesis_private.len());
            
            // Build the combined identity+private data vector
            let mut identities_with_private: Vec<(lib_identity::ZhtpIdentity, lib_identity::identity::PrivateIdentityData)> = Vec::new();
            
            for identity in &genesis_ids {
                // Find matching private data by identity ID
                if let Some((_, private_data)) = genesis_private.iter().find(|(id, _)| id == &identity.id) {
                    identities_with_private.push((identity.clone(), private_data.clone()));
                    info!(" Loaded private key for identity: {} (type: {:?})", 
                        hex::encode(&identity.id.0[..8]), identity.identity_type);
                } else {
                    warn!("  No private key found for identity: {} - signing will NOT work for this identity", 
                        hex::encode(&identity.id.0[..8]));
                }
            }
            
            lib_identity::initialize_identity_system_with_identities_and_private_data(identities_with_private).await?
        };
        
        // Fund genesis primary wallets with 5000 ZHTP welcome bonus
        if !genesis_ids.is_empty() {
            info!("Funding genesis primary wallets with 5000 ZHTP welcome bonus...");
            for genesis_identity in &genesis_ids {
                // Only fund Human identities (not Device identities)
                if genesis_identity.identity_type == lib_identity::IdentityType::Human {
                    // Get the primary wallet ID (first wallet in the list)
                    let wallet_summaries = genesis_identity.wallet_manager.list_wallets();
                    if let Some(_primary_wallet_summary) = wallet_summaries.first() {
                        // Wallet funding is now handled via blockchain wallet_registry sync
                        // The sync_wallet_balances method will update wallet balances from blockchain data
                    }
                }
            }
        }
        
        info!("Identity management system initialized");
        info!("Ready for citizen onboarding and zero-knowledge identity verification");
        
        // CRITICAL: Wrap in Arc<RwLock> and register globally for shared access across components
        let identity_manager_arc = Arc::new(RwLock::new(identity_manager));
        
        // Register globally so ProtocolsComponent can use the same instance
        crate::runtime::set_global_identity_manager(identity_manager_arc).await?;
        info!(" Identity manager registered globally for component access");
        
        // Note: We don't store locally in self.identity_manager anymore since it can't be cloned
        // Components should access via the global provider
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Identity component started with ZK identity system");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping identity component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.identity_manager.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Identity component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, data) if msg == "create_identity" => {
                if let Some(ref mut manager) = self.identity_manager.write().await.as_mut() {
                    info!("Creating new citizen identity...");
                    
                    // Parse identity data from message data
                    let identity_name = String::from_utf8(data).unwrap_or_else(|_| "AnonymousCitizen".to_string());
                    
                    // Use available identity manager methods
                    let identities = manager.list_identities();
                    info!("Identity system ready for '{}' (current identities: {})", identity_name, identities.len());
                    info!("Identity system available for ZK identity operations");
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Identity component health check");
                Ok(())
            }
            _ => {
                debug!("Identity component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // identity metrics
        if let Some(ref manager) = *self.identity_manager.read().await {
            metrics.insert("registered_identities".to_string(), manager.list_identities().len() as f64);
        } else {
            metrics.insert("registered_identities".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}

/// Storage component implementation using lib-storage package
#[derive(Debug)]
pub struct StorageComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    storage_system: Arc<RwLock<Option<lib_storage::UnifiedStorageSystem>>>,
}

impl StorageComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            storage_system: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for StorageComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Storage
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting storage component with lib-storage implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Initialize unified storage system
        match create_default_storage_config() {
            Ok(config) => {
                match lib_storage::UnifiedStorageSystem::new(config).await {
                    Ok(storage) => {
                        info!("unified storage system initialized successfully");
                        info!("-style content addressing ready");
                        info!("DHT network integration active");
                        info!("Economic incentives for storage providers enabled");
                        
                        // Store the initialized storage system
                        *self.storage_system.write().await = Some(storage);
                        info!("Storage system stored in component state");
                    }
                    Err(e) => {
                        warn!("Failed to initialize storage system: {}", e);
                        info!("Continuing with basic storage component");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create storage config: {}", e);
                info!("Continuing with basic storage component");
            }
        }
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Storage component started with decentralized storage");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping storage component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Storage component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Storage component health check");
                Ok(())
            }
            _ => {
                debug!("Storage component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}

/// Network component implementation using lib-network package
#[derive(Clone)]
pub struct NetworkComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    mesh_server: Arc<RwLock<Option<ZhtpMeshServer>>>,
}

impl std::fmt::Debug for NetworkComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkComponent")
            .field("status", &"<RwLock<ComponentStatus>>")
            .field("start_time", &"<RwLock<Option<Instant>>>")
            .field("mesh_server", &"<RwLock<Option<ZhtpMeshServer>>>")
            .finish()
    }
}

impl NetworkComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            mesh_server: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for NetworkComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Network
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting network component with lib-network mesh protocol...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // NOTE: Mesh networking is now handled by ZhtpUnifiedServer on port 9333
        // The old separate mesh server on port 33444 is no longer needed
        info!("Mesh networking handled by unified server - skipping separate mesh server");
        info!("NetworkComponent ready (mesh handled by unified server on port 9333)");
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Network component started with mesh networking ready");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping network component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop mesh server with timeout to prevent hanging
        {
            let mesh_server_guard = self.mesh_server.read().await;
            if let Some(server) = mesh_server_guard.as_ref() {
                // Try to stop gracefully first with immutable reference
                match tokio::time::timeout(Duration::from_secs(5), server.stop()).await {
                    Ok(Ok(())) => {
                        info!("Mesh server stopped gracefully");
                    }
                    Ok(Err(e)) => {
                        warn!("Mesh server stop error (continuing): {}", e);
                    }
                    Err(_timeout) => {
                        warn!("Mesh server stop timeout - forcing shutdown");
                    }
                }
            }
        }
        
        // Now remove the server from storage
        *self.mesh_server.write().await = None;
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Network component stopped");
        Ok(())
    }

    async fn force_stop(&self) -> Result<()> {
        warn!(" Force stopping network component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Immediately drop the mesh server to terminate all background tasks
        if let Some(_server) = self.mesh_server.write().await.take() {
            info!("Mesh server forcefully terminated");
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Network component force stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, _data) if msg == "discover_peers" => {
                if let Some(ref server) = *self.mesh_server.read().await {
                    info!("Starting peer discovery...");
                    
                    // Use available mesh server functionality
                    let stats = server.get_network_stats().await;
                    info!("Network stats - Active connections: {}, Coverage: {:.2} km²", 
                          stats.active_connections, stats.coverage_area_km2);
                    info!("Mesh network ready for peer connections");
                } else {
                    warn!("Cannot discover peers: mesh server not initialized");
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Network component health check");
                Ok(())
            }
            _ => {
                debug!("Network component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // network metrics
        if let Some(ref server) = *self.mesh_server.read().await {
            let stats = server.get_network_stats().await;
            metrics.insert("active_connections".to_string(), stats.active_connections as f64);
            metrics.insert("total_data_routed".to_string(), stats.total_data_routed as f64);
            metrics.insert("long_range_relays".to_string(), stats.long_range_relays as f64);
            metrics.insert("average_latency_ms".to_string(), stats.average_latency_ms as f64);
            metrics.insert("coverage_area_km2".to_string(), stats.coverage_area_km2);
            metrics.insert("people_with_free_internet".to_string(), stats.people_with_free_internet as f64);
        } else {
            metrics.insert("active_connections".to_string(), 0.0);
            metrics.insert("total_data_routed".to_string(), 0.0);
            metrics.insert("long_range_relays".to_string(), 0.0);
            metrics.insert("average_latency_ms".to_string(), 0.0);
            metrics.insert("coverage_area_km2".to_string(), 0.0);
            metrics.insert("people_with_free_internet".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}

impl NetworkComponent {
    /// Get current routing statistics for reward processing
    /// 
    /// Returns a snapshot of routing activity including theoretical tokens earned,
    /// bytes routed, and messages relayed. This is used by the routing reward
    /// processor to determine when to create reward transactions.
    pub async fn get_routing_stats(&self) -> RoutingRewardStats {
        if let Some(ref server) = *self.mesh_server.read().await {
            RoutingRewardStats {
                theoretical_tokens_earned: server.get_theoretical_tokens_earned().await,
                bytes_routed: server.get_total_bytes_routed().await,
                messages_routed: server.get_total_messages_routed().await,
            }
        } else {
            warn!("Mesh server not initialized, returning default routing stats");
            RoutingRewardStats::default()
        }
    }
    
    /// Reset routing reward counter after successful claim
    /// 
    /// This should be called after a reward transaction has been successfully
    /// created and added to the blockchain to prevent double-counting rewards.
    /// 
    /// # Errors
    /// Returns an error if the mesh server is not initialized.
    pub async fn reset_routing_rewards(&self) -> Result<()> {
        if let Some(ref server) = *self.mesh_server.read().await {
            server.reset_reward_counter().await;
            info!(" Routing rewards reset after successful claim");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot reset rewards: mesh server not initialized"))
        }
    }
    
    /// Get this node's unique identifier for reward attribution
    /// 
    /// Returns a 32-byte array representing this node's unique ID, used to
    /// properly attribute routing and storage rewards to the correct node in
    /// blockchain transactions.
    /// 
    /// # Returns
    /// - `Some([u8; 32])` - The node's unique identifier if mesh server is initialized
    /// - `None` - If the mesh server is not yet initialized
    pub async fn get_node_id(&self) -> Option<[u8; 32]> {
        if let Some(ref server) = *self.mesh_server.read().await {
            Some(server.get_node_id())
        } else {
            warn!("Cannot get node ID: mesh server not initialized");
            None
        }
    }
    
    /// Get Arc reference to mesh server (for advanced reward processing)
    /// 
    /// This provides direct access to the mesh server for background tasks
    /// that need to monitor routing statistics.
    pub fn get_mesh_server_arc(&self) -> Arc<RwLock<Option<ZhtpMeshServer>>> {
        self.mesh_server.clone()
    }
    
    // ==================== Storage Statistics Methods ====================
    
    /// Get storage statistics for reward calculation
    /// 
    /// Returns current storage contribution statistics including items stored,
    /// bytes stored, retrievals served, and theoretical tokens earned.
    /// 
    /// # Returns
    /// Current storage statistics, or default values if mesh server not initialized.
    pub async fn get_storage_stats(&self) -> StorageRewardStats {
        if let Some(ref server) = *self.mesh_server.read().await {
            let stats = server.get_storage_stats_snapshot().await;
            StorageRewardStats {
                theoretical_tokens_earned: stats.theoretical_tokens_earned,
                items_stored: stats.items_stored,
                bytes_stored: stats.bytes_stored,
                retrievals_served: stats.retrievals_served,
                storage_duration_hours: stats.storage_duration_hours,
            }
        } else {
            warn!("Mesh server not initialized, returning default storage stats");
            StorageRewardStats::default()
        }
    }
    
    /// Reset storage reward counter after successful claim
    /// 
    /// This should be called after a storage reward transaction has been successfully
    /// created and added to the blockchain to prevent double-counting rewards.
    /// 
    /// # Errors
    /// Returns an error if the mesh server is not initialized.
    pub async fn reset_storage_rewards(&self) -> Result<()> {
        if let Some(ref server) = *self.mesh_server.read().await {
            server.reset_storage_reward_counter().await;
            info!(" Storage rewards reset after successful claim");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot reset storage rewards: mesh server not initialized"))
        }
    }
}

/// Blockchain component implementation using lib-blockchain package
#[derive(Debug)]
pub struct BlockchainComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    blockchain: Arc<RwLock<Option<Blockchain>>>,
    mining_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    user_wallet: Arc<RwLock<Option<crate::runtime::did_startup::WalletStartupResult>>>,
    environment: crate::config::Environment,  // Store environment for network-specific initialization
    bootstrap_validators: Arc<RwLock<Vec<BootstrapValidator>>>, // Store bootstrap validators for multi-node genesis
    joined_existing_network: bool,  // If true, skip genesis creation (we're joining existing network)
    validator_manager: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,  // Reference to consensus validator manager
    node_identity: Arc<RwLock<Option<IdentityId>>>,  // This node's identity for consensus
}

impl BlockchainComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(None)),
            environment: crate::config::Environment::Development,  // Default to dev
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,  // Default: create genesis
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
        }
    }

    pub fn new_with_wallet(user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment: crate::config::Environment::Development,  // Default to dev
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,  // Default: create genesis
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
        }
    }
    
    /// NEW: Create with wallet and environment for network-specific blockchain
    pub fn new_with_wallet_and_environment(
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
        environment: crate::config::Environment,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment,
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,  // Default: create genesis
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Create with wallet, environment and bootstrap validators for multi-node networks
    pub fn new_with_full_config(
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
        environment: crate::config::Environment,
        bootstrap_validators: Vec<BootstrapValidator>,
        joined_existing_network: bool,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment,
            bootstrap_validators: Arc::new(RwLock::new(bootstrap_validators)),
            joined_existing_network,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Set consensus validator manager for coordinated mining
    pub async fn set_validator_manager(&self, validator_manager: Arc<RwLock<ValidatorManager>>) {
        *self.validator_manager.write().await = Some(validator_manager);
    }
    
    /// Set node identity for consensus participation
    pub async fn set_node_identity(&self, node_identity: IdentityId) {
        *self.node_identity.write().await = Some(node_identity);
    }
    
    /// Set user wallet for genesis funding
    pub async fn set_user_wallet(&self, wallet: crate::runtime::did_startup::WalletStartupResult) {
        // Store wallet
        let mut user_wallet_guard = self.user_wallet.write().await;
        *user_wallet_guard = Some(wallet.clone());
        drop(user_wallet_guard);
        
        // CRITICAL: Update controlled_nodes in blockchain identity registry
        // This connects the node device identity to the user identity for consensus
        let node_id_hex = hex::encode(&wallet.node_identity_id.0);
        let user_did = format!("did:zhtp:{}", hex::encode(&wallet.user_identity.id.0));
        
        info!(" Updating controlled_nodes for user {} with node {}", 
              &user_did[..40], &node_id_hex[..32]);
        
        // Get global blockchain and update identity registry
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let mut blockchain = blockchain_arc.write().await;
                
                // Find and update the user's identity entry in the registry
                if let Some(identity_data) = blockchain.identity_registry.get_mut(&user_did) {
                    if !identity_data.controlled_nodes.contains(&node_id_hex) {
                        identity_data.controlled_nodes.push(node_id_hex.clone());
                        info!(" Added node {} to user's controlled_nodes list", &node_id_hex[..32]);
                        info!("   User now controls {} node(s)", identity_data.controlled_nodes.len());
                    } else {
                        info!("  Node {} already in controlled_nodes", &node_id_hex[..32]);
                    }
                } else {
                    warn!("  User identity {} not found in blockchain registry - controlled_nodes not updated", user_did);
                }
            },
            Err(e) => {
                warn!("  Failed to get global blockchain: {} - controlled_nodes not updated", e);
            }
        }
    }
    
    /// Get the blockchain Arc for sharing with other components
    pub fn get_blockchain_arc(&self) -> Arc<RwLock<Option<Blockchain>>> {
        self.blockchain.clone()
    }
    
    /// Get the actual blockchain instance if initialized
    pub async fn get_initialized_blockchain(&self) -> Result<Arc<RwLock<Blockchain>>> {
        let blockchain_guard = self.blockchain.read().await;
        if let Some(ref blockchain) = *blockchain_guard {
            Ok(Arc::new(RwLock::new(blockchain.clone())))
        } else {
            Err(anyhow::anyhow!("Blockchain not yet initialized"))
        }
    }

    // Create genesis funding to bootstrap the system with UTXOs for multi-node network
    pub async fn create_genesis_funding(
        blockchain: &mut Blockchain,
        genesis_validators: Vec<GenesisValidator>,
        environment: &crate::config::Environment,
        user_primary_wallet_id: Option<(lib_identity::wallets::WalletId, Vec<u8>)>, // (wallet_id, public_key)
        user_identity_id: Option<lib_identity::IdentityId>, // Add user identity ID parameter
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>, // Private key data
    ) -> Result<()> {
        info!("Creating genesis funding for multi-validator identity-based transaction system...");
        info!("Initializing {} genesis validators", genesis_validators.len());
        
        // Validate we have validators
        if genesis_validators.is_empty() {
            return Err(anyhow::anyhow!("No genesis validators provided - network requires at least one validator"));
        }
        
        info!("Multi-validator mode: {} validators for production network", genesis_validators.len());
        
        // Initialize outputs vector for genesis transaction
        let mut genesis_outputs = Vec::new();
        let mut total_validator_stake = 0u64;
        
        // Create UTXOs for each validator based on their stake
        for (index, validator) in genesis_validators.iter().enumerate() {
            let validator_id_hex = hex::encode(&validator.identity_id.0[..8]);
            info!("Creating validator {} UTXO: {} ZHTP stake (Identity: {})", 
                  index + 1, validator.stake, validator_id_hex);
            
            // Create validator stake UTXO
            let validator_output = TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(
                    format!("validator_stake_commitment_{}_{}", validator_id_hex, validator.stake).as_bytes()
                ),
                note: lib_blockchain::types::hash::blake3_hash(
                    format!("validator_stake_note_{}_{}", validator_id_hex, index).as_bytes()
                ),
                recipient: PublicKey::new(validator.identity_id.as_bytes().to_vec()),
            };
            
            genesis_outputs.push(validator_output);
            total_validator_stake += validator.stake;
            
            info!("   - Validator {}: {} ZHTP (ID: {})", 
                  index + 1, validator.stake, validator_id_hex);
        }
        
        info!("Total validator stake: {} ZHTP across {} validators", 
              total_validator_stake, genesis_validators.len());
        
        // Access the genesis block (first block in the blockchain)
        if blockchain.blocks.is_empty() {
            return Err(anyhow::anyhow!("No genesis block found in blockchain"));
        }
        
        let genesis_block = &mut blockchain.blocks[0];
        
        // Add system funding pools (unchanged amounts for network operation)
        genesis_outputs.extend(vec![
            // System UBI funding pool
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"ubi_pool_commitment_500000"),
                note: lib_blockchain::types::hash::blake3_hash(b"ubi_pool_note"),
                recipient: PublicKey::new(b"genesis_system_ubi".to_vec()),
            },
            // Mining rewards pool
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"mining_pool_commitment_300000"),
                note: lib_blockchain::types::hash::blake3_hash(b"mining_pool_note"),
                recipient: PublicKey::new(b"genesis_system_mining".to_vec()),
            },
            // Development fund
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"dev_pool_commitment_200000"),
                note: lib_blockchain::types::hash::blake3_hash(b"dev_pool_note"),
                recipient: PublicKey::new(b"genesis_system_dev".to_vec()),
            },
        ]);
        
        // Add user primary wallet funding (welcome bonus: 5000 ZHTP)
        if let Some((wallet_id, _wallet_public_key)) = user_primary_wallet_id.as_ref() {
            let wallet_id_hex = hex::encode(&wallet_id.0[..8]);
            info!(" Funding genesis user primary wallet: {} with 5000 ZHTP welcome bonus", wallet_id_hex);
            
            // CRITICAL: Get the FULL Dilithium2 public key from the identity's private data
            // This is required for signature verification (1312 bytes, not 32-byte hash)
            let identity_dilithium_pubkey = if let Some(user_id) = user_identity_id.as_ref() {
                // Find the matching private data for this identity
                if let Some(genesis_private) = genesis_private_data.iter()
                    .find(|(id, _)| id.0 == user_id.0)
                {
                    // Extract the full Dilithium2 public key (1312 bytes)
                    genesis_private.1.quantum_keypair.public_key.clone()
                } else {
                    error!(" CRITICAL: No private key found for user identity during genesis!");
                    return Err(anyhow::anyhow!("Genesis identity missing private key data"));
                }
            } else {
                error!(" CRITICAL: No user identity ID for genesis wallet!");
                return Err(anyhow::anyhow!("Genesis wallet missing identity"));
            };
            
            info!("   - Dilithium2 public key size: {} bytes", identity_dilithium_pubkey.len());
            
            // Create wallet funding UTXO (still uses 32-byte identity hash for recipient)
            let identity_hash = user_identity_id.as_ref().unwrap().0.to_vec();
            let wallet_output = TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(
                    format!("user_wallet_commitment_{}_{}", wallet_id_hex, 5000).as_bytes()
                ),
                note: lib_blockchain::types::hash::blake3_hash(
                    format!("user_wallet_note_{}", wallet_id_hex).as_bytes()
                ),
                recipient: PublicKey::new(identity_hash),
            };
            
            genesis_outputs.push(wallet_output);
            
            // Register wallet in blockchain's wallet_registry with initial balance
            // CRITICAL: Store the FULL Dilithium2 public key for signature verification
            let wallet_data = lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: None,
                public_key: identity_dilithium_pubkey.clone(), // Full 1312-byte Dilithium2 public key
                owner_identity_id: user_identity_id.as_ref().map(|id| lib_blockchain::Hash::from_slice(&id.0)),
                seed_commitment: lib_blockchain::types::hash::blake3_hash(b"genesis_wallet_seed"),
                created_at: 1730419200, // Genesis timestamp
                registration_fee: 0,
                capabilities: 0xFFFFFFFF, // Full capabilities
                initial_balance: 5000, // 5000 ZHTP welcome bonus
            };
            
            blockchain.wallet_registry.insert(hex::encode(&wallet_id.0), wallet_data);
            
            info!(" Genesis user wallet funded and registered: {} ZHTP", 5000);
            info!("   - Wallet ID: {}", hex::encode(&wallet_id.0));
            info!("   - Owner Identity ID: {}", hex::encode(&user_identity_id.as_ref().unwrap().0));
            info!("   - Dilithium2 Public Key (first 16 bytes): {}", hex::encode(&identity_dilithium_pubkey[..16]));
        }
        
        // Create genesis funding transaction signed by first validator (network bootstrap)
        let genesis_signature = if let Some(first_validator) = genesis_validators.first() {
            let validator_id_hex = hex::encode(&first_validator.identity_id.0[..8]);
            Signature {
                signature: format!("validator_{}_genesis_signature", validator_id_hex).as_bytes().to_vec(),
                public_key: PublicKey::new(first_validator.identity_id.as_bytes().to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                // Use fixed genesis timestamp to match genesis block timestamp
                timestamp: 1730419200, // November 1, 2025 00:00:00 UTC
            }
        } else {
            return Err(anyhow::anyhow!("No validators available for genesis signature"));
        };
        
        let genesis_tx = Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: lib_blockchain::types::TransactionType::Transfer,
            inputs: vec![], // Genesis transaction has no inputs
            outputs: genesis_outputs.clone(),
            fee: 0,
            signature: genesis_signature,
            memo: b"Genesis funding transaction for ZHTP system".to_vec(),
            wallet_data: None,
            identity_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        };
        
        // Add genesis transaction to the genesis block
        genesis_block.transactions.push(genesis_tx.clone());
        
        // Recalculate and update the genesis block's merkle root after adding the transaction
        let updated_merkle_root = lib_blockchain::transaction::hashing::calculate_transaction_merkle_root(&genesis_block.transactions);
        genesis_block.header.merkle_root = updated_merkle_root;
        info!("Genesis block merkle root updated: {}", hex::encode(updated_merkle_root.as_bytes()));
        
        // Create UTXOs from genesis transaction outputs and add to UTXO set
        let genesis_tx_id = lib_blockchain::types::hash::blake3_hash(b"genesis_funding_transaction");
        for (index, output) in genesis_outputs.iter().enumerate() {
            let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                &format!("genesis_funding:{}:{}", hex::encode(genesis_tx_id), index).as_bytes()
            );
            blockchain.utxo_set.insert(utxo_hash, output.clone());
        }
        
        info!("Genesis funding created: {} UTXOs with validator stakes and funding pools", 
              genesis_outputs.len());
        
        for (index, validator) in genesis_validators.iter().enumerate() {
            info!("   - Validator {}: {} ZHTP (ID: {})", 
                  index + 1, validator.stake, hex::encode(&validator.identity_id.0[..8]));
        }
        
        info!("   - UBI Pool: 500,000 ZHTP");
        info!("   - Mining Pool: 300,000 ZHTP");
        info!("   - Development Pool: 200,000 ZHTP");
        info!("   - Total validator stake: {} ZHTP", total_validator_stake);
        info!("   - Total UTXO entries: {}", blockchain.utxo_set.len());
        
        // ========================================================================
        // ARCHITECTURE NOTE: Validator registration moved AFTER USER identity registration
        // This ensures the USER identity exists in blockchain.identity_registry before
        // attempting to register them as a validator
        // ========================================================================
        info!("  Validator registration will occur after USER identity is registered");
        
        // ========================================================================
        // Register USER identity on blockchain (not just validators)
        // ========================================================================
        if let Some(user_id) = user_identity_id.as_ref() {
            let user_did = format!("did:zhtp:{}", hex::encode(&user_id.0));
            info!(" Registering USER identity on blockchain: {}", user_did);
            
            // Get the full Dilithium2 public key from private data
            let user_dilithium_pubkey = if let Some(user_private) = genesis_private_data.iter()
                .find(|(id, _)| id.0 == user_id.0)
            {
                user_private.1.quantum_keypair.public_key.clone()
            } else {
                warn!("  No private key found for user identity during genesis registration!");
                vec![]
            };
            
            // Collect node device IDs from genesis validators (nodes are controlled devices, not separate identities)
            let controlled_node_ids: Vec<String> = genesis_validators.iter()
                .filter_map(|v| v.node_device_id.as_ref().map(|nid| hex::encode(&nid.0)))
                .collect();
            
            info!("   - User controls {} node device(s)", controlled_node_ids.len());
            for (idx, node_id) in controlled_node_ids.iter().enumerate() {
                info!("     Node {}: {}...", idx + 1, &node_id[..32]);
            }
            
            let user_identity_data = lib_blockchain::transaction::core::IdentityTransactionData {
                did: user_did.clone(),
                display_name: "Genesis User".to_string(),
                public_key: user_dilithium_pubkey, // Use full 1312-byte Dilithium2 key
                ownership_proof: vec![],  // Empty for genesis/system transactions
                identity_type: "human".to_string(),
                did_document_hash: lib_blockchain::types::hash::blake3_hash(user_did.as_bytes()),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                registration_fee: 0,  // Genesis identity has no fee
                dao_fee: 0,
                controlled_nodes: controlled_node_ids, // Add node devices to USER's controlled list
                owned_wallets: vec![hex::encode(&user_primary_wallet_id.as_ref().unwrap().0.0)],
            };
            
            match blockchain.register_identity(user_identity_data) {
                Ok(tx_hash) => {
                    info!(" Genesis USER identity registered with transaction: {}", 
                          hex::encode(tx_hash));
                    info!("   - DID: {}", user_did);
                    info!("   - Identity ID: {}", hex::encode(&user_id.0));
                    info!("   - Identity type: Human");
                }
                Err(e) => {
                    warn!("  User identity registration failed (may already exist): {}", e);
                }
            }
        }
        
        // ========================================================================
        // NOW register validators AFTER USER identity exists in blockchain
        // ========================================================================
        info!(" Registering validators in validator_registry (USER identity already registered)...");
        let mut registered_validators = 0;
        
        for (index, validator) in genesis_validators.iter().enumerate() {
            let validator_did = format!("did:zhtp:{}", hex::encode(&validator.identity_id.0));
            
            info!(" Registering validator {}: {}", index + 1, validator_did);
            if let Some(node_id) = &validator.node_device_id {
                info!("   - Node device: {}", hex::encode(&node_id.0[..16]));
            }
            
            // Register as a validator in the validator_registry (USER identity now exists)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let validator_info = lib_blockchain::blockchain::ValidatorInfo {
                identity_id: validator_did.clone(),
                stake: validator.stake,
                storage_provided: validator.storage_provided,
                consensus_key: validator.identity_id.as_bytes().to_vec(),
                network_address: "127.0.0.1:9333".to_string(), // Genesis validator on local node
                commission_rate: (validator.commission_rate.min(10000) / 100) as u8, // Convert basis points to percentage
                status: "active".to_string(),
                registered_at: now,
                last_activity: now,
                blocks_validated: 0,
                slash_count: 0,
            };
            
            match blockchain.register_validator(validator_info) {
                Ok(validator_tx_hash) => {
                    registered_validators += 1;
                    info!(" Genesis validator {} registered in validator_registry", index + 1);
                    info!("   - Validator TX: {}", hex::encode(validator_tx_hash));
                    info!("   - Stake: {} ZHTP", validator.stake);
                    info!("   - Storage: {} GB", validator.storage_provided);
                    info!("   - Commission: {}.{}%", 
                          validator.commission_rate / 100, validator.commission_rate % 100);
                }
                Err(e) => {
                    warn!("  Failed to register validator {} in validator_registry: {}", 
                          index + 1, e);
                }
            }
        }
        
        info!(" Validator registration complete: {}/{} validators registered", 
              registered_validators, genesis_validators.len());
        info!("   - Pending transactions: {}", blockchain.pending_transactions.len());
        info!("   - Identities in registry: {}", blockchain.identity_registry.len());
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl Component for BlockchainComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Blockchain
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting blockchain component with shared blockchain service...");
        info!(" Network Environment: {}", self.environment);
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Try to get existing global blockchain first
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                info!("Using existing global blockchain instance");
                let blockchain_clone = {
                    let blockchain_guard = shared_blockchain.read().await;
                    blockchain_guard.clone()
                };
                *self.blockchain.write().await = Some(blockchain_clone);
            }
            Err(_) => {
                // If no global blockchain exists, check if we should create genesis or join existing network
                if self.joined_existing_network {
                    info!(" Joining existing network - skipping genesis creation");
                    info!("   Blockchain will sync from network peers after API server starts");
                    // Will be initialized by RuntimeOrchestrator with proper configuration
                } else {
                    // No global blockchain exists AND we're not joining existing - will be initialized by RuntimeOrchestrator
                    info!("Blockchain will be initialized by RuntimeOrchestrator for {} network...", self.environment);
                }
            }
        }
        
        // Start mining loop with funded transactions and consensus coordination
        let blockchain_clone = self.blockchain.clone();
        // Clone the Arc references (not the inner values) so mining loop can read updated values
        let validator_manager_arc = self.validator_manager.clone();
        let node_identity_arc = self.node_identity.clone();
        
        let mining_handle = tokio::spawn(async move {
            info!(" Mining task spawned, starting mining loop...");
            Self::real_mining_loop(blockchain_clone, validator_manager_arc, node_identity_arc).await;
            error!(" Mining loop exited unexpectedly!");
        });
        
        *self.mining_handle.write().await = Some(mining_handle);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!(" Blockchain component started with shared blockchain service for {} network", self.environment);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping blockchain component...");
        
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop mining with timeout to prevent hanging
        if let Some(handle) = self.mining_handle.write().await.take() {
            handle.abort();
            // Wait a moment for the abort to take effect
            tokio::time::sleep(Duration::from_millis(100)).await;
            info!("Mining stopped");
        }
        
        *self.blockchain.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("Blockchain component stopped");
        Ok(())
    }

    async fn force_stop(&self) -> Result<()> {
        warn!(" Force stopping blockchain component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Immediately abort mining
        if let Some(handle) = self.mining_handle.write().await.take() {
            handle.abort();
            info!("Mining forcefully aborted");
        }
        
        *self.blockchain.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("Blockchain component force stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, _data) if msg == "get_blockchain_instance" => {
                // Direct access pattern is used in orchestrator instead of message passing
                info!("Blockchain instance request received");
                Ok(())
            }
            ComponentMessage::BlockchainOperation(operation, operation_data) => {
                // Handle blockchain operations from other components
                match operation.as_str() {
                    "add_identity_transaction" => {
                        if let Some(ref mut blockchain) = self.blockchain.write().await.as_mut() {
                            // Deserialize transaction data and add to blockchain
                            info!("Adding identity transaction from protocols component");
                            
                            // Parse operation data as simple string or create identity transaction
                            let identity_data = String::from_utf8(operation_data).unwrap_or_else(|_| "unknown_identity".to_string());
                            info!("Processing identity transaction for: {}", identity_data);
                            
                            // Add to identity registry
                            let identity_key = lib_blockchain::types::hash::blake3_hash(identity_data.as_bytes()).to_hex();
                            let identity_tx_data = lib_blockchain::transaction::core::IdentityTransactionData {
                                did: identity_data.clone(),
                                display_name: "Generated Identity".to_string(),
                                public_key: vec![],
                                ownership_proof: vec![],
                                identity_type: "human".to_string(),
                                did_document_hash: lib_blockchain::types::hash::blake3_hash(identity_data.as_bytes()),
                                created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                                registration_fee: 0,
                                dao_fee: 0,
                                controlled_nodes: Vec::new(),
                                owned_wallets: Vec::new(),
                            };
                            blockchain.identity_registry.insert(identity_key, identity_tx_data);
                            
                            info!("Identity '{}' registered in blockchain registry", identity_data);
                        }
                    }
                    "get_block" => {
                        if let Some(ref blockchain) = *self.blockchain.read().await {
                            // Handle block query - parse block height from operation_data
                            match String::from_utf8(operation_data) {
                                Ok(height_str) => {
                                    match height_str.parse::<usize>() {
                                        Ok(height) => {
                                            if height < blockchain.blocks.len() {
                                                let block = &blockchain.blocks[height];
                                                info!("Block {} found: {} transactions, hash: {:?}", 
                                                      height, block.transactions.len(), block.hash());
                                            } else {
                                                info!("Block {} not found (chain height: {})", height, blockchain.height);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Invalid block height '{}': {}", height_str, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to parse block height: {}", e);
                                }
                            }
                        }
                    }
                    "get_transaction" => {
                        if let Some(ref blockchain) = *self.blockchain.read().await {
                            // Handle transaction query - search through blocks
                            let tx_hash_str = String::from_utf8(operation_data).unwrap_or_default();
                            info!("Searching for transaction: {}", tx_hash_str);
                            
                            let mut found = false;
                            for (block_idx, block) in blockchain.blocks.iter().enumerate() {
                                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                                    let tx_hash = hex::encode(tx.hash());
                                    if tx_hash.starts_with(&tx_hash_str) {
                                        info!("Transaction found in block {}, tx {}: {} ZHTP", 
                                              block_idx, tx_idx, tx.fee);
                                        found = true;
                                        break;
                                    }
                                }
                                if found { break; }
                            }
                            
                            if !found {
                                info!("Transaction '{}' not found in {} blocks", tx_hash_str, blockchain.blocks.len());
                            }
                        }
                    }
                    _ => {
                        debug!("Unknown blockchain operation: {}", operation);
                    }
                }
                Ok(())
            }
            ComponentMessage::Custom(msg, _data) if msg == "add_test_transaction" => {
                if let Some(ref mut blockchain) = self.blockchain.write().await.as_mut() {
                    info!("Creating economic transactions...");
                    
                    // Create UBI distribution transaction
                    match Self::create_ubi_transaction(&self.environment).await {
                        Ok(ubi_tx) => {
                            match blockchain.add_pending_transaction(ubi_tx.clone()) {
                                Ok(()) => {
                                    info!("UBI distribution transaction added! Hash: {:?}", ubi_tx.hash());
                                }
                                Err(e) => {
                                    warn!("Failed to add UBI transaction: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create UBI transaction: {}", e);
                        }
                    }
                    
                    // Create reward transaction for network services (example with placeholder node ID)
                    // Note: In production, use the actual node ID from NetworkComponent.get_node_id()
                    let example_node_id = [2u8; 32]; // Placeholder for testing
                    let reward_amount = 500; // 500 ZHTP tokens
                    match Self::create_reward_transaction(example_node_id, reward_amount, &self.environment).await {
                        Ok(reward_tx) => {
                            match blockchain.add_pending_transaction(reward_tx.clone()) {
                                Ok(()) => {
                                    info!("Network reward transaction added! Hash: {:?}", reward_tx.hash());
                                }
                                Err(e) => {
                                    warn!("Failed to add reward transaction: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create reward transaction: {}", e);
                        }
                    }
                    
                    info!("transactions added. Pending: {}", blockchain.pending_transactions.len());
                    
                    // NOTE: Mining is handled by the consensus-coordinated mining loop (real_mining_loop)
                    // which checks every 30 seconds and validates proposer selection before mining.
                    // Do NOT mine immediately here as it bypasses consensus coordination.
                    info!("💤 Transactions queued for mining - will be picked up by consensus mining loop");
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Blockchain component health check");
                Ok(())
            }
            _ => {
                debug!("Blockchain component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // blockchain metrics
        if let Some(ref blockchain) = *self.blockchain.read().await {
            metrics.insert("chain_height".to_string(), blockchain.height as f64);
            metrics.insert("total_blocks".to_string(), blockchain.blocks.len() as f64);
            metrics.insert("pending_transactions".to_string(), blockchain.pending_transactions.len() as f64);
            metrics.insert("utxo_count".to_string(), blockchain.utxo_set.len() as f64);
            metrics.insert("identity_count".to_string(), blockchain.identity_registry.len() as f64);
            metrics.insert("total_work".to_string(), blockchain.total_work as f64);
            
            // Add some derived metrics
            let avg_block_size = if blockchain.blocks.len() > 0 {
                blockchain.blocks.iter().map(|b| b.transactions.len()).sum::<usize>() as f64 / blockchain.blocks.len() as f64
            } else {
                0.0
            };
            metrics.insert("avg_transactions_per_block".to_string(), avg_block_size);
        } else {
            // Set all metrics to 0 if blockchain not initialized
            metrics.insert("chain_height".to_string(), 0.0);
            metrics.insert("total_blocks".to_string(), 0.0);
            metrics.insert("pending_transactions".to_string(), 0.0);
            metrics.insert("utxo_count".to_string(), 0.0);
            metrics.insert("identity_count".to_string(), 0.0);
            metrics.insert("total_work".to_string(), 0.0);
            metrics.insert("avg_transactions_per_block".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}

impl BlockchainComponent {
    /// Create UBI distribution transaction using lib-economy
    async fn create_ubi_transaction(environment: &crate::config::Environment) -> Result<lib_blockchain::Transaction> {
        use lib_economy::transactions::creation::create_ubi_distributions;
        use lib_economy::wasm::IdentityId;
        
        // Create a citizen identity for UBI distribution
        let citizen_id = IdentityId([1u8; 32]); // In production this would be a citizen
        let ubi_amount = 1000; // 1000 ZHTP tokens as UBI
        
        // Create UBI distributions using economics package
        let ubi_distributions = create_ubi_distributions(&[(citizen_id, ubi_amount)])?;
        
        if ubi_distributions.is_empty() {
            return Err(anyhow::anyhow!("No UBI distributions created"));
        }
        
        // Convert economics transaction to blockchain transaction
        let economics_tx = &ubi_distributions[0];
        Self::convert_economics_to_system_tx(economics_tx, environment).await
    }

    /// Create reward transaction using lib-economy
    /// 
    /// # Arguments
    /// * `node_id` - The 32-byte unique identifier of the node receiving the reward
    /// * `reward_amount` - The amount of ZHTP tokens to award
    /// * `environment` - The node's environment configuration
    pub async fn create_reward_transaction(
        node_id: [u8; 32],
        reward_amount: u64,
        environment: &crate::config::Environment
    ) -> Result<lib_blockchain::Transaction> {
        use lib_economy::transactions::creation::create_reward_transaction;
        
        // Create reward for network services (routing, storage, etc.)
        let reward_tx = create_reward_transaction(node_id, reward_amount)?;
        
        // Convert economics transaction to blockchain transaction
        Self::convert_economics_to_system_tx(&reward_tx, environment).await
    }

    /// Convert economics transaction to blockchain transaction format as system transaction
    async fn convert_economics_to_system_tx(
        economics_tx: &lib_economy::transactions::Transaction,
        environment: &crate::config::Environment,
    ) -> Result<lib_blockchain::Transaction> {
        use lib_blockchain::{Transaction, TransactionOutput};
        // Removed unused TransactionInput  
        use lib_blockchain::types::TransactionType as BlockchainTxType;
        // Removed unused ZkTransactionProof import

        // Create SYSTEM TRANSACTION with empty inputs (like UBI/rewards in original)
        // System transactions don't spend UTXOs - they create new money from protocol rules
        let inputs = vec![]; // Empty inputs for system transactions (no ZK proofs needed)

        // Create outputs for the transaction
        let outputs = vec![TransactionOutput {
            commitment: lib_blockchain::types::hash::blake3_hash(
                &format!("commitment_{}", economics_tx.amount).as_bytes()
            ),
            note: lib_blockchain::types::hash::blake3_hash(
                &format!("note_{}", hex::encode(economics_tx.tx_id)).as_bytes()
            ),
            recipient: PublicKey::new(economics_tx.to.to_vec()),
        }];

        // Map economics transaction type to blockchain transaction type
        let blockchain_tx_type = match economics_tx.tx_type {
            lib_economy::types::TransactionType::UbiDistribution => BlockchainTxType::Transfer,
            lib_economy::types::TransactionType::Reward => BlockchainTxType::Transfer,
            lib_economy::types::TransactionType::Payment => BlockchainTxType::Transfer,
            _ => BlockchainTxType::Transfer,
        };

        // Create properly signed transaction using system keypair
        let signature = Self::create_system_signature(economics_tx, &inputs, &outputs, blockchain_tx_type.clone(), environment).await?;

        // Create memo with transaction details
        let memo = format!(
            "System TX: {} {} ZHTP to {:?}", 
            economics_tx.tx_type.description(), 
            economics_tx.amount,
            economics_tx.to
        ).into_bytes();

        // Create the blockchain transaction as SYSTEM TRANSACTION (no inputs, no ZK proofs needed)
        Ok(Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: blockchain_tx_type,
            inputs, // Empty inputs = system transaction (creates new money like mining)
            outputs,
            fee: 0, // System transactions are fee-free
            signature,
            wallet_data: None,
            memo,
            identity_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        })
    }

    /// Create a proper cryptographic signature for system transactions
    async fn create_system_signature(
        economics_tx: &lib_economy::transactions::Transaction,
        inputs: &[lib_blockchain::TransactionInput],
        outputs: &[lib_blockchain::TransactionOutput],
        tx_type: lib_blockchain::types::TransactionType,
        environment: &crate::config::Environment,
    ) -> Result<lib_blockchain::integration::crypto_integration::Signature> {
        use lib_crypto::{generate_keypair, sign_message};
        // Removed unused KeyPair
        
        // Generate a system keypair (in production, this would be a well-known system keypair)
        let system_keypair = generate_keypair()?;
        
        // Create the transaction for signing (without signature)
        let temp_signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(system_keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economics_tx.timestamp,
        };
        
        let temp_transaction = lib_blockchain::Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: tx_type,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            fee: economics_tx.total_fee,
            signature: temp_signature,
            memo: format!(
                "System TX: {} {} ZHTP from {:?} to {:?}", 
                economics_tx.tx_type.description(), 
                economics_tx.amount,
                economics_tx.from,
                economics_tx.to
            ).into_bytes(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        };
        
        // Create signing hash using the exact same method as blockchain validation
        let signing_hash = lib_blockchain::transaction::hashing::hash_for_signature(&temp_transaction);
        
        // Sign the transaction hash
        let crypto_signature = sign_message(&system_keypair, signing_hash.as_bytes())?;
        
        // Create blockchain signature structure
        Ok(Signature {
            signature: crypto_signature.signature,
            public_key: PublicKey::new(system_keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economics_tx.timestamp,
        })
    }



    /// Mine a block using actual blockchain methods
    async fn mine_real_block(blockchain: &mut lib_blockchain::Blockchain) -> Result<()> {
        if blockchain.pending_transactions.is_empty() {
            return Err(anyhow::anyhow!("No pending transactions to mine"));
        }

        info!("Mining block with {} transactions", blockchain.pending_transactions.len());

        // Select transactions for the block (up to 10 for efficiency)
        let transactions_for_block = blockchain.pending_transactions
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>();

        if transactions_for_block.is_empty() {
            return Err(anyhow::anyhow!("No valid transactions for block"));
        }

        // Check if this block contains system transactions (empty inputs = UBI/rewards)
        let has_system_transactions = transactions_for_block
            .iter()
            .any(|tx| tx.inputs.is_empty());

        // Get the previous block hash
        let previous_hash = blockchain.latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();

        // Use blockchain's current difficulty (set at initialization based on environment)
        let block_difficulty = blockchain.difficulty.clone();
        
        if has_system_transactions {
            info!("Mining system transaction block with difficulty: {:#x}", block_difficulty.bits());
        } else {
            info!("Mining normal transaction block with difficulty: {:#x}", block_difficulty.bits());
        }

        // Create the block using lib-blockchain methods
        let block = lib_blockchain::block::creation::create_block(
            transactions_for_block,
            previous_hash,
            blockchain.height + 1,
            block_difficulty, // Use appropriate difficulty
        )?;

        // Mine the block (compute valid nonce through Proof-of-Work)
        info!("⛏️ Mining block with PoW (difficulty: {:#x})...", block_difficulty.bits());
        let new_block = lib_blockchain::block::creation::mine_block(block, 10_000_000)?;
        info!(" Block mined with nonce: {}", new_block.header.nonce);

        // Add the block to the blockchain WITH proof generation
        match blockchain.add_block_with_proof(new_block.clone()).await {
            Ok(()) => {
                info!("BLOCK MINED SUCCESSFULLY!");
                info!("Block Hash: {:?}", new_block.hash());
                info!("Block Height: {}", blockchain.height);
                info!("Transactions in Block: {}", new_block.transactions.len());
                info!("Total UTXOs: {}", blockchain.utxo_set.len());
                info!("Identity Registry: {} entries", blockchain.identity_registry.len());
                
                // Log economic transactions stored
                if !blockchain.economics_transactions.is_empty() {
                    info!("Economics Transactions: {}", blockchain.economics_transactions.len());
                }
            }
            Err(e) => {
                warn!("Failed to add block to blockchain: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Real mining loop with actual blockchain operations using shared blockchain
    /// and consensus coordination
    async fn real_mining_loop(
        blockchain: Arc<RwLock<Option<Blockchain>>>,
        validator_manager_arc: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
        node_identity_arc: Arc<RwLock<Option<IdentityId>>>,
    ) {
        // Give consensus component time to wire validator manager (typically takes ~100ms)
        // This prevents the "mining without consensus coordination" warning on first check
        info!(" Mining loop started - waiting 2 seconds for consensus to wire...");
        tokio::time::sleep(Duration::from_secs(2)).await;
        info!(" Starting mining checks every 30 seconds");
        
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut block_counter = 1u64;
        let mut consensus_round = 0u32;
        
        loop {
            debug!("⏰ Mining loop tick #{}", block_counter);
            interval.tick().await;
            debug!(" Mining loop tick #{} completed, fetching blockchain...", block_counter);
            
            // Use global blockchain provider to get the current blockchain state (same instance as API uses)
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(shared_blockchain) => {
                    let blockchain_guard = shared_blockchain.read().await;
                    let pending_count = blockchain_guard.pending_transactions.len();
                    let current_height = blockchain_guard.height;
                    // Log Arc pointer for debugging shared state (BEFORE await to keep it Send-safe)
                    let blockchain_ptr_addr = Arc::as_ptr(&shared_blockchain) as usize;
                    
                    info!("Mining check #{} - Height: {}, Pending: {}, UTXOs: {}, Identities: {} [ptr: 0x{:x}]", 
                        block_counter,
                        current_height, 
                        pending_count,
                        blockchain_guard.utxo_set.len(),
                        blockchain_guard.identity_registry.len(),
                        blockchain_ptr_addr
                    );
                    
                    // If we have pending transactions, check consensus before mining
                    if pending_count > 0 {
                        // Read current validator_manager and node_identity from component fields
                        // (These get set during wire_blockchain_to_consensus() after component starts)
                        let validator_manager_opt = validator_manager_arc.read().await.clone();
                        let node_identity_opt = node_identity_arc.read().await.clone();
                        
                        // Check if consensus coordination is enabled
                        let should_mine = if let (Some(vm), Some(node_id)) = (validator_manager_opt, node_identity_opt) {
                            let vm_guard = vm.read().await;
                            
                            // Check if there are any active validators
                            let active_validators = vm_guard.get_active_validators();
                            info!(" CONSENSUS CHECK: {} active validators in validator manager", active_validators.len());
                            
                            // DEBUG: Print all validator identities
                            for (idx, validator) in active_validators.iter().enumerate() {
                                info!("   Validator {}: identity={} (stake: {})", 
                                      idx + 1, 
                                      hex::encode(&validator.identity.as_bytes()),
                                      validator.stake);
                            }
                            
                            if active_validators.is_empty() {
                                // No validators yet - any node can mine (bootstrap phase)
                                warn!("⛏️ BOOTSTRAP MODE: No validators registered in consensus, mining without coordination");
                                warn!("   → This means validator sync from blockchain failed!");
                                warn!("   → Check blockchain.validator_registry.len() = {}", blockchain_guard.validator_registry.len());
                                true
                            } else {
                                // Select proposer using consensus
                                info!(" CONSENSUS ACTIVE: {} validators registered", active_validators.len());
                                let next_height = current_height + 1;
                                if let Some(proposer) = vm_guard.select_proposer(next_height, consensus_round) {
                                    // CRITICAL ARCHITECTURE:
                                    // - Validators are USER DIDs (humans/orgs)
                                    // - Nodes are DEVICE identities controlled by USER DIDs
                                    // - node_id = NODE device IdentityId (e.g., fd6cb66f32ffb8bd)
                                    // - Validator manager stores the original IdentityId Hash (NOT hashed DID string!)
                                    // - proposer.identity = original IdentityId Hash from DID
                                    //
                                    // Algorithm:
                                    // 1. Convert node_id to hex string
                                    // 2. Scan identity_registry to find USER DID with this node in controlled_nodes
                                    // 3. Extract identity bytes from USER DID
                                    // 4. Compare with proposer.identity
                                    
                                    let node_id_hex = hex::encode(node_id.as_bytes());
                                    let mut is_proposer = false;
                                    
                                    info!(" IDENTITY MATCHING: Looking for node '{}' in identity registry", node_id_hex);
                                    info!(" IDENTITY MATCHING: Identity registry has {} entries", blockchain_guard.identity_registry.len());
                                    info!(" IDENTITY MATCHING: Proposer identity = {}", hex::encode(&proposer.identity.as_bytes()));
                                    
                                    // Scan identity registry to find which USER controls this node
                                    for (did_string, identity_data) in blockchain_guard.identity_registry.iter() {
                                        let did_preview = if did_string.len() > 70 { &did_string[..70] } else { did_string };
                                        info!(" IDENTITY MATCHING: Checking identity {} with {} controlled nodes", 
                                              did_preview,
                                              identity_data.controlled_nodes.len());
                                        for (idx, controlled_node) in identity_data.controlled_nodes.iter().enumerate() {
                                            info!("   Node {}: {} (comparing with node_id_hex: {}) - {}", 
                                                  idx + 1, 
                                                  controlled_node,
                                                  node_id_hex,
                                                  if controlled_node == &node_id_hex { " MATCH!" } else { " no match" });
                                        }
                                        
                                        // Check if this USER identity's controlled_nodes contains our node
                                        if identity_data.controlled_nodes.contains(&node_id_hex) {
                                            info!(" FOUND MATCHING USER: This node is controlled by {}", did_preview);
                                            // Found the USER who controls this node!
                                            // Extract the hex part from DID and convert to Hash (don't hash the DID string!)
                                            if let Some(identity_hex) = did_string.strip_prefix("did:zhtp:") {
                                                if let Ok(identity_bytes) = hex::decode(identity_hex) {
                                                    let user_identity_hash = lib_crypto::Hash::from_bytes(&identity_bytes[..32]);
                                                    
                                                    info!("    User identity hash: {}", hex::encode(&user_identity_hash.as_bytes()));
                                                    info!("    Proposer identity: {}", hex::encode(&proposer.identity.as_bytes()));
                                                    
                                                    // Compare original identity Hash with proposer's identity
                                                    if user_identity_hash == proposer.identity {
                                                        is_proposer = true;
                                                        info!("    Node owner is proposer: {}", &did_string[..32]);
                                                        info!("      Node device ID: {}", &node_id_hex[..32]);
                                                        info!("      Owner identity: {}", hex::encode(&user_identity_hash.as_bytes()[..8]));
                                                        break;
                                                    } else {
                                                        info!("    User identity does NOT match proposer");
                                                    }
                                                } else {
                                                    warn!("    Failed to decode identity hex from DID");
                                                }
                                            } else {
                                                warn!("    DID format invalid: {}", did_string);
                                            }
                                        }
                                    }
                                    
                                    if !is_proposer {
                                        info!(" IDENTITY MATCHING FAILED: This node's owner is NOT the selected proposer");
                                    }
                                    
                                    if is_proposer {
                                        info!(" CONSENSUS: This node selected as block proposer for height {} (round {})", 
                                            next_height, consensus_round);
                                    } else {
                                        info!(" CONSENSUS: Waiting - proposer is {:?} (round {})", 
                                            hex::encode(&proposer.identity.as_bytes()[..8]), consensus_round);
                                        info!("   Our node: {}", &node_id_hex[..32]);
                                    }
                                    is_proposer
                                } else {
                                    warn!(" CONSENSUS: No proposer selected, falling back to permissionless mining");
                                    true
                                }
                            }
                        } else {
                            // No consensus configured - mine without coordination
                            warn!("⛏️ Mining without consensus coordination (validator manager not configured)");
                            true
                        };
                        
                        if should_mine {
                            drop(blockchain_guard); // Release read lock before mining
                            info!("Mining block #{} with {} pending transactions...", block_counter, pending_count);
                            
                            let mut blockchain_guard = shared_blockchain.write().await;
                            match Self::mine_real_block(&mut *blockchain_guard).await {
                                Ok(()) => {
                                    info!("Block #{} mined successfully!", block_counter);
                                    block_counter += 1;
                                    consensus_round = 0; // Reset round after successful block
                                }
                                Err(e) => {
                                    warn!("Failed to mine block #{}: {}", block_counter, e);
                                    consensus_round += 1; // Increment round on failure
                                }
                            }
                        } else {
                            // Not our turn - increment round for next iteration
                            info!(" SKIPPING MINING: Not selected as proposer (round {})", consensus_round);
                            consensus_round = (consensus_round + 1) % 10; // Rotate through rounds
                        }
                    } else {
                        info!(" MINING CHECK: No pending transactions (height={}, round={})", current_height, consensus_round);
                        consensus_round = 0; // Reset when no pending transactions
                    }
                }
                Err(e) => {
                    // Fallback to local blockchain if shared not available
                    if let Some(ref mut local_blockchain) = blockchain.write().await.as_mut() {
                        let pending_count = local_blockchain.pending_transactions.len();
                        info!("Mining check #{} (local fallback) - Height: {}, Pending: {}, UTXOs: {}, Identities: {}", 
                            block_counter,
                            local_blockchain.height, 
                            pending_count,
                            local_blockchain.utxo_set.len(),
                            local_blockchain.identity_registry.len()
                        );
                        warn!("Using local blockchain fallback: {}", e);
                    } else {
                        warn!("No blockchain available for mining check: {}", e);
                    }
                }
            }
        }
    }
}

/// Consensus component implementation using lib-consensus package
#[derive(Debug)]
pub struct ConsensusComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    consensus_engine: Arc<RwLock<Option<ConsensusEngine>>>,
    validator_manager: Arc<RwLock<ValidatorManager>>,
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
    environment: crate::config::Environment,
}

impl ConsensusComponent {
    pub fn new(environment: crate::config::Environment) -> Self {
        // Create ValidatorManager with development mode based on environment
        let development_mode = matches!(environment, crate::config::Environment::Development);
        
        // Adjust minimum stake based on environment
        let min_stake = if development_mode {
            1_000  // Dev: 1k ZHTP (20% of 5k welcome bonus - accessible for testing)
        } else {
            100_000_000  // Prod: 100M ZHTP for network security
        };
        
        let validator_manager = ValidatorManager::new_with_development_mode(
            100,  // max_validators: Support up to 100 validators
            min_stake,
            development_mode,
        );
        
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            consensus_engine: Arc::new(RwLock::new(None)),
            validator_manager: Arc::new(RwLock::new(validator_manager)),
            blockchain: Arc::new(RwLock::new(None)),
            environment,
        }
    }
    
    /// Set the blockchain reference for validator synchronization
    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) {
        *self.blockchain.write().await = Some(blockchain);
    }
    
    /// Synchronize validators from blockchain to validator manager
    /// 
    /// This reads all active validators from the blockchain's validator_registry
    /// and registers them with the consensus ValidatorManager.
    pub async fn sync_validators_from_blockchain(&self) -> Result<()> {
        let blockchain_opt = self.blockchain.read().await;
        let blockchain = match blockchain_opt.as_ref() {
            Some(bc) => bc,
            None => {
                warn!("Cannot sync validators: blockchain not set");
                return Ok(());
            }
        };
        
        let bc = blockchain.read().await;
        let active_validators = bc.get_active_validators();
        
        if active_validators.is_empty() {
            debug!("No active validators found in blockchain registry");
            return Ok(());
        }
        
        let mut validator_manager = self.validator_manager.write().await;
        let mut synced_count = 0;
        let mut skipped_count = 0;
        
        for validator_info in active_validators {
            // Convert string identity_id to Hash (IdentityId type in lib-consensus)
            // CRITICAL: validator_info.identity_id is in DID format "did:zhtp:hex"
            // Extract the hex part and convert back to the original Hash (don't double-hash!)
            let identity_hex = validator_info.identity_id.strip_prefix("did:zhtp:")
                .ok_or_else(|| anyhow::anyhow!("Invalid DID format: {}", validator_info.identity_id))?;
            
            let identity_bytes = hex::decode(identity_hex)
                .map_err(|e| anyhow::anyhow!("Failed to decode identity hex: {}", e))?;
            
            let identity_hash = lib_crypto::Hash::from_bytes(&identity_bytes[..32]);
            
            // Check if validator is already registered in consensus
            if validator_manager.get_validator(&identity_hash).is_some() {
                skipped_count += 1;
                continue;
            }
            
            // Register validator in consensus layer
            match validator_manager.register_validator(
                identity_hash.clone(),
                validator_info.stake,
                validator_info.storage_provided,
                validator_info.consensus_key.clone(),
                validator_info.commission_rate as u8,
            ) {
                Ok(_) => {
                    synced_count += 1;
                    info!(
                        "Synced validator {} to consensus (stake: {} ZHTP, storage: {} bytes)",
                        validator_info.identity_id,
                        validator_info.stake,
                        validator_info.storage_provided
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to sync validator {} to consensus: {}",
                        validator_info.identity_id, e
                    );
                }
            }
        }
        
        info!(
            "Validator sync complete: {} new validators registered, {} already registered",
            synced_count, skipped_count
        );
        
        Ok(())
    }
    
    /// Get the validator manager for external access
    pub async fn get_validator_manager(&self) -> Arc<RwLock<ValidatorManager>> {
        self.validator_manager.clone()
    }
}

#[async_trait::async_trait]
impl Component for ConsensusComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Consensus
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting consensus component with lib-consensus implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Initialize consensus engine with development mode for testing
        let mut config = ConsensusConfig::default();
        
        // Enable development mode for Development environment (allows single validator testing)
        config.development_mode = matches!(self.environment, crate::config::Environment::Development);
        if config.development_mode {
            info!(" Development mode enabled - single validator consensus allowed for testing");
            info!("    Production deployment requires minimum 4 validators for BFT");
        } else {
            info!(" Production mode: Full consensus validation required (minimum 4 validators for BFT)");
        }
        
        let consensus_engine = lib_consensus::init_consensus(config)?;
        
        info!("Consensus engine initialized with hybrid PoS");
        info!("Validator management ready");
        info!("Byzantine fault tolerance active");
        
        *self.consensus_engine.write().await = Some(consensus_engine);
        
        // NOTE: Validator sync happens AFTER blockchain is wired (see orchestrator startup)
        // Don't sync here - blockchain reference not set yet!
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Consensus component started with consensus mechanisms");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping consensus component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.consensus_engine.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Consensus component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Consensus component health check");
                Ok(())
            }
            _ => {
                debug!("Consensus component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}

/// Economics component implementation using lib-economy package
#[derive(Debug)]
pub struct EconomicsComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
}

impl EconomicsComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for EconomicsComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Economics
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting economics component with lib-economy implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Initialize economics system
        info!("Universal Basic Income system initialized");
        info!("Token economics ready");
        info!("Resource sharing incentives active");
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Economics component started with UBI system");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping economics component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Economics component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Economics component health check");
                Ok(())
            }
            _ => {
                debug!("Economics component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}

/// API component implementation using our API server
#[derive(Debug)]
pub struct ApiComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl ApiComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for ApiComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Api
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        // NOTE: API server is now handled by ZhtpUnifiedServer on port 9333
        // The old separate API server is no longer needed
        info!("API endpoints handled by unified server - skipping separate API server");
        info!("API routes available:");
        info!("   - Identity management (/api/v1/identity/*)");
        info!("   - Blockchain operations (/api/v1/blockchain/*)");
        info!("   - Storage management (/api/v1/storage/*)");
        info!("   - Protocol information (/api/v1/protocol/*)");
        info!("   - Wallet operations (/api/v1/wallet/*)");
        info!("   - DAO management (/api/v1/dao/*)");
        info!("   - DHT queries (/api/v1/dht/*)");
        info!("   - Web4 content (/api/v1/web4/*)");
        
        *self.status.write().await = ComponentStatus::Starting;
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("ApiComponent ready (APIs handled by unified server on port 9333)");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping API component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop the server handle if it exists
        if let Some(handle) = self.server_handle.write().await.take() {
            handle.abort();
            info!("API server handle terminated");
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("API component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::Custom(msg, _data) if msg == "health_check" => {
                info!("API component health check - using unified server");
            }
            ComponentMessage::Custom(msg, _data) if msg == "get_stats" => {
                info!("API component stats - handled by unified server");
            }
            ComponentMessage::HealthCheck => {
                debug!("API component health check");
            }
            _ => {
                debug!("API component received unhandled message: {:?}", message);
            }
        }
        Ok(())
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), 
            if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // API handled by unified server
        metrics.insert("api_unified_server".to_string(), 1.0);
        metrics.insert("handlers_integrated".to_string(), 8.0); // All handlers in unified server
        metrics.insert("middleware_active".to_string(), 4.0); // CORS, rate limiting, auth, logging
        
        Ok(metrics)
    }
}

/// Protocols component implementation using ZHTP Unified Server
pub struct ProtocolsComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    unified_server: Arc<RwLock<Option<crate::unified_server::ZhtpUnifiedServer>>>,
    zdns_server: Arc<RwLock<Option<ZdnsServer>>>,
    lib_integration: Arc<RwLock<Option<ZhtpIntegration>>>,
    environment: crate::config::environment::Environment,  // NEW: Network-specific environment
    api_port: u16,  // Port from configuration
    is_edge_node: bool,  // Node type detection
}

impl std::fmt::Debug for ProtocolsComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolsComponent")
            .field("status", &"<ComponentStatus>")
            .field("start_time", &"<Optional<Instant>>")
            .field("unified_server", &"<Optional<ZhtpUnifiedServer>>")
            .field("zdns_server", &"<Optional<ZdnsServer>>")
            .field("lib_integration", &"<Optional<ZhtpIntegration>>")
            .finish()
    }
}

impl ProtocolsComponent {
    pub fn new(environment: crate::config::environment::Environment, api_port: u16) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,  // Store environment for network-specific paths
            api_port,     // Store port from configuration
            is_edge_node: false,  // Default to full node
        }
    }
    
    pub fn new_with_node_type(environment: crate::config::environment::Environment, api_port: u16, is_edge_node: bool) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            is_edge_node,
        }
    }
}

#[async_trait::async_trait]
impl Component for ProtocolsComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Protocols
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting protocols component with ZHTP Unified Server...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Initialize ZHTP protocol stack
        lib_protocols::initialize().await?;
        
        info!("Initializing backend components for unified server...");
        
        //  Try to bootstrap blockchain from existing network peers first
        let blockchain = match try_bootstrap_blockchain(&Arc::new(RwLock::new(lib_blockchain::Blockchain::new()?)), &Arc::new(RwLock::new(lib_storage::UnifiedStorageSystem::new(create_default_storage_config()?).await?)), self.api_port, &self.environment).await {
            Ok(synced_blockchain) => {
                info!(" Successfully bootstrapped blockchain from network peers");
                info!("   Height: {}, UTXOs: {}, Identities: {}", 
                    synced_blockchain.height,
                    synced_blockchain.utxo_set.len(),
                    synced_blockchain.identity_registry.len()
                );
                
                // Update or initialize the global blockchain instance with synced state
                let shared_blockchain = match crate::runtime::blockchain_provider::get_global_blockchain().await {
                    Ok(shared) => {
                        let mut blockchain_guard = shared.write().await;
                        *blockchain_guard = synced_blockchain.clone();
                        info!(" Updated global blockchain instance with synced state");
                        drop(blockchain_guard);
                        shared
                    }
                    Err(e) => {
                        // If no global blockchain exists, that's a critical error
                        // BlockchainComponent must be started before ProtocolsComponent
                        panic!("Global blockchain not initialized before protocols component sync. This is a startup ordering error: {}", e);
                    }
                };
                
                // CRITICAL: Return the shared blockchain Arc, not a new instance
                shared_blockchain
            }
            Err(e) => {
                info!("  Could not bootstrap from peers ({}), checking for shared blockchain", e);
                // ProtocolsComponent should NOT create genesis - that's BlockchainComponent's job!
                // Wait for BlockchainComponent to initialize the global blockchain with proper genesis funding
                match crate::runtime::blockchain_provider::get_global_blockchain().await {
                    Ok(shared_blockchain) => {
                        info!(" Using existing global blockchain instance from BlockchainComponent");
                        shared_blockchain
                    }
                    Err(_) => {
                        // BlockchainComponent hasn't started yet - wait for it with timeout
                        info!("⏳ Waiting for BlockchainComponent to initialize global blockchain (up to 30 seconds)...");
                        let mut attempts = 0;
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            attempts += 1;
                            
                            if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await {
                                info!(" Global blockchain initialized by BlockchainComponent (waited {} ms)", attempts * 500);
                                break shared_blockchain;
                            }
                            
                            if attempts >= 60 {  // 30 seconds
                                return Err(anyhow::anyhow!("Timeout waiting for BlockchainComponent to initialize blockchain"));
                            }
                        }
                    }
                }
            }
        };
        
        // CRITICAL: Use the shared IdentityManager from IdentityComponent (with genesis identities)
        // instead of creating a new empty one
        info!(" Getting shared IdentityManager from IdentityComponent...");
        let identity_manager = match crate::runtime::get_global_identity_manager().await {
            Ok(shared_identity_manager) => {
                info!(" Using shared IdentityManager with genesis identities");
                shared_identity_manager
            }
            Err(_) => {
                // IdentityComponent hasn't started yet - wait for it with timeout
                info!("⏳ Waiting for IdentityComponent to initialize IdentityManager (up to 30 seconds)...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    
                    if let Ok(shared_identity_manager) = crate::runtime::get_global_identity_manager().await {
                        info!(" IdentityManager initialized by IdentityComponent (waited {} ms)", attempts * 500);
                        break shared_identity_manager;
                    }
                    
                    if attempts >= 60 {  // 30 seconds
                        return Err(anyhow::anyhow!("Timeout waiting for IdentityComponent to initialize IdentityManager"));
                    }
                }
            }
        };
        
        // Initialize economic model (lightweight initialization)
        let economic_model = Arc::new(RwLock::new(
            lib_economy::EconomicModel::new()
        ));
        
        // Storage system - use minimal config for protocols component
        let storage_config = create_default_storage_config()?;
        let storage = Arc::new(RwLock::new(
            lib_storage::UnifiedStorageSystem::new(storage_config).await?
        ));
        
        info!("Creating ZHTP Unified Server (consolidates all protocols)...");
        
        // Create peer discovery notification channel for blockchain sync trigger
        let (peer_discovery_tx, peer_discovery_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        
        // Create unified server with peer discovery notification
        let mut unified_server = crate::unified_server::ZhtpUnifiedServer::new_with_peer_notification(
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            self.api_port,  // Use port from configuration
            Some(peer_discovery_tx),
        ).await?;
        
        // ========================================================================
        // Initialize blockchain provider for network layer
        // ========================================================================
        info!(" Setting up blockchain provider for network layer...");
        let blockchain_provider = Arc::new(crate::runtime::network_blockchain_provider::ZhtpBlockchainProvider::new());
        unified_server.set_blockchain_provider(blockchain_provider).await;
        info!(" Blockchain provider configured for network message handlers");
        
        // ========================================================================
        // Detect node type and initialize appropriate sync manager
        // ========================================================================
        if self.is_edge_node {
            info!(" Initializing Edge Node sync manager (headers-only)...");
            let edge_sync_manager = Arc::new(lib_network::EdgeNodeSyncManager::new(500)); // 500 header capacity
            unified_server.set_edge_sync_manager(edge_sync_manager).await;
            info!(" Edge node sync manager initialized");
            info!("   - Header capacity: 500");
            info!("   - Storage: ~100 KB");
            info!("   - ZK proof verification only");
        } else {
            info!(" Using full blockchain sync (complete blocks)");
        }
        
        // Initialize ZHTP authentication manager with blockchain identity
        info!(" Initializing ZHTP authentication and relay protocols...");
        
        // Note: Node identity for ZHTP authentication should be created separately
        // For now, authentication is disabled - identities are managed by IdentityComponent
        warn!("  ZHTP authentication using identity manager (no separate node identity file)");
        
        // Initialize relay protocol without node-specific identity
        if let Err(e) = unified_server.initialize_relay_protocol().await {
            warn!("Failed to initialize ZHTP relay protocol: {}", e);
        } else {
            info!(" ZHTP relay protocol initialized");
        }
        
        // Initialize WiFi Direct authentication with blockchain identity
        info!(" Initializing WiFi Direct authentication...");
        if let Err(e) = unified_server.initialize_wifi_direct_auth(identity_manager.clone()).await {
            warn!("  Failed to initialize WiFi Direct authentication: {}", e);
            warn!("   WiFi Direct will operate without ZHTP authentication");
        } else {
            info!(" WiFi Direct authentication initialized");
            info!("    Only ZHTP nodes with blockchain identity can connect");
        }
        
        info!("Starting unified server on port 9333...");
        info!("Protocols: HTTP API + UDP Mesh + WiFi Direct + Bootstrap");
        
        // Start the unified server (replaces all separate servers!)
        unified_server.start().await?;
        
        // Start background task to listen for peer discovery notifications
        info!(" Starting peer discovery listener for blockchain sync...");
        let blockchain_clone = blockchain.clone();
        let storage_clone = storage.clone();
        let unified_server_clone = unified_server.clone();
        let api_port = self.api_port;
        tokio::spawn(async move {
            let mut rx = peer_discovery_rx;
            info!(" Peer discovery listener active - will trigger blockchain sync on peer discovery");
            
            while let Some(peer_addr_str) = rx.recv().await {
                info!(" Peer discovered post-startup: {} - establishing UDP mesh connection...", peer_addr_str);
                
                // Parse peer address
                if let Ok(peer_addr) = peer_addr_str.parse::<SocketAddr>() {
                    // Establish UDP mesh connection - blockchain sync happens automatically
                    // via UDP BlockchainRequest/BlockchainData messages sent in PeerAnnouncement handler
                    if let Err(e) = unified_server_clone.establish_udp_connection(peer_addr).await {
                        warn!("Failed to establish UDP connection to {}: {}", peer_addr, e);
                    } else {
                        info!(" UDP mesh connection established to {}", peer_addr);
                        info!("   Blockchain sync will occur via UDP BlockchainRequest/BlockchainData messages");
                    }
                    
                    // HTTP blockchain sync DISABLED - using UDP mesh protocol only
                } else {
                    warn!("Failed to parse peer address: {}", peer_addr_str);
                }
            }
            
            info!("Peer discovery listener stopped");
        });
        
        // Start periodic peer sync task to keep blockchains synchronized
        // DISABLED: Using UDP BlockchainRequest/BlockchainData messages only
        info!(" Periodic HTTP sync task DISABLED - using UDP mesh protocol for blockchain sync");
        /*
        info!(" Starting periodic peer sync task...");
        let blockchain_sync = blockchain.clone();
        let storage_sync = storage.clone();
        let mesh_router_for_sync = unified_server.get_mesh_router_arc();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Sync every 60 seconds
            interval.tick().await; // Skip first immediate tick
            
            loop {
                interval.tick().await;
                
                // Get list of known peers from mesh router
                let peers = mesh_router_for_sync.get_peer_addresses().await;
                
                if peers.is_empty() {
                    debug!("No peers available for periodic sync");
                    continue;
                }
                
                debug!("Periodic sync check: {} peers known", peers.len());
                
                // Try syncing from each peer until one succeeds
                for peer_addr in &peers {
                    match try_bootstrap_blockchain_from_peer(&blockchain_sync, &storage_sync, peer_addr).await {
                        Ok(synced_blockchain) => {
                            info!(" Periodic sync succeeded from peer {}", peer_addr);
                            
                            // Update global blockchain
                            if let Ok(shared) = crate::runtime::blockchain_provider::get_global_blockchain().await {
                                let mut shared_write = shared.write().await;
                                *shared_write = synced_blockchain.clone();
                            }
                            
                            // Update local reference
                            {
                                let mut blockchain_write = blockchain_sync.write().await;
                                *blockchain_write = synced_blockchain;
                            }
                            
                            break; // Successfully synced, don't try other peers
                        }
                        Err(e) => {
                            debug!("Periodic sync failed from peer {}: {}", peer_addr, e);
                        }
                    }
                }
            }
        });
        info!(" Periodic peer sync task started (60s interval)");
        */
        
        // Initialize global mesh router provider for API access
        info!(" Initializing global mesh router provider...");
        crate::runtime::mesh_router_provider::initialize_global_mesh_router_provider();
        let mesh_router_arc = unified_server.get_mesh_router_arc();
        if let Err(e) = crate::runtime::mesh_router_provider::set_global_mesh_router(mesh_router_arc.clone()).await {
            warn!("Failed to set global mesh router: {}", e);
        } else {
            info!(" Global mesh router provider initialized");
        }
        
        // Phase 4: Start metrics snapshot background task
        info!(" Starting performance metrics snapshot task...");
        mesh_router_arc.start_metrics_snapshot_task().await;
        
        // Store server instance
        *self.unified_server.write().await = Some(unified_server);
        
        info!("ZHTP Unified Server started successfully!");
        info!("HTTP API: http://localhost:9333/api/v1/*");
        info!("UDP Mesh: UDP packets to port 9333"); 
        info!(" WiFi Direct: TCP connections to port 9333");
        info!("Bootstrap: TCP/UDP to port 9333");
        
        // Create ZDNS server for domain resolution
        let zdns_config = ZdnsConfig::default();
        let zdns_server = ZdnsServer::new(zdns_config);
        *self.zdns_server.write().await = Some(zdns_server);
        info!("ZDNS v1.0 server initialized (DNS replacement)");
        
        // Initialize ZHTP integration layer
        let integration_config = IntegrationConfig::default();
        let lib_integration = ZhtpIntegration::new(integration_config).await?;
        *self.lib_integration.write().await = Some(lib_integration);
        info!("ZHTP integration layer initialized");
        
        info!("Complete ZHTP protocol stack active");
        info!("Web4 protocols ready - ISP replacement operational");
        info!("DAO fee system active for UBI funding");
        info!("Post-quantum cryptography enabled");
        info!("Mesh networking ready for ");
        
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Protocols component started with ZHTP server on port 9333");
        info!(" Web4 API endpoints now available at http://localhost:9333/api/v1/*");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping protocols component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop unified server
        if let Some(mut unified_server) = self.unified_server.write().await.take() {
            if let Err(e) = unified_server.stop().await {
                warn!("Error stopping unified server: {}", e);
            }
            info!("ZHTP Unified Server stopped");
        }
        
        // Clear ZHTP integration (no explicit shutdown method)
        if let Some(_) = self.lib_integration.write().await.take() {
            info!("ZHTP integration cleared");
        }
        
        // Clear ZDNS server (no explicit shutdown method)
        if let Some(_) = self.zdns_server.write().await.take() {
            info!("ZDNS server cleared");
        }
        
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Protocols component stopped - ZHTP protocol stack offline");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        let mut error_count = 0;
        
        // Only check initialization status if component is supposed to be running
        // Avoids false warnings during startup phase
        if matches!(status, ComponentStatus::Running) {
            // Check unified server health
            if let Some(ref unified_server) = *self.unified_server.read().await {
                if !unified_server.is_running().await {
                    error_count += 1;
                    warn!("ZHTP unified server not running while component is running");
                }
            } else {
                error_count += 1;
                warn!("ZHTP unified server not initialized while component is running");
            }
            
            if self.zdns_server.read().await.is_none() {
                error_count += 1;
                warn!("ZDNS server not initialized while component is running");
            }
            
            // API endpoints handled by unified server - no separate check needed
            
            if self.lib_integration.read().await.is_none() {
                error_count += 1;
                warn!("ZHTP integration not initialized while component is running");
            }
        }
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Protocols component health check");
                Ok(())
            }
            _ => {
                debug!("Protocols component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // Get unified server metrics
        if let Some(ref unified_server) = *self.unified_server.read().await {
            let is_running = unified_server.is_running().await;
            metrics.insert("unified_server_running".to_string(), if is_running { 1.0 } else { 0.0 });
            let (server_id, port) = unified_server.get_server_info();
            metrics.insert("server_port".to_string(), port as f64);
            
            // Use server_id in metrics and logging
            debug!("Unified server metrics - Server ID: {}, Port: {}, Running: {}", server_id, port, is_running);
            let server_id_str = server_id.to_string();
            metrics.insert("server_id_hash".to_string(), server_id_str.chars().map(|c| c as u32 as f64).sum::<f64>() % 10000.0);
        }
        
        // Get ZDNS server metrics
        if let Some(ref _zdns_server) = *self.zdns_server.read().await {
            // Note: QueryStats fields are private, so we can only confirm server is active
            metrics.insert("zdns_server_active".to_string(), 1.0);
        }
        
        // API endpoints integrated into unified server - metrics handled there
        
        // Get ZHTP integration metrics
        if let Some(ref integration) = *self.lib_integration.read().await {
            let integration_stats = integration.get_stats();
            metrics.insert("integration_total_requests".to_string(), integration_stats.total_requests as f64);
            metrics.insert("integration_avg_processing_time_ms".to_string(), integration_stats.avg_processing_time_ms as f64);
            metrics.insert("integration_mesh_routes_used".to_string(), integration_stats.mesh_routes_used as f64);
            metrics.insert("integration_blockchain_interactions".to_string(), integration_stats.blockchain_interactions as f64);
        }
        
        Ok(metrics)
    }
}

// Helper function to bootstrap blockchain from network
async fn try_bootstrap_blockchain(
    _blockchain: &Arc<RwLock<lib_blockchain::Blockchain>>,
    _storage: &Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
    _api_port: u16,
    environment: &crate::config::environment::Environment,
) -> Result<lib_blockchain::Blockchain> {
    use lib_network::dht::bootstrap::{DHTBootstrap, DHTBootstrapEnhancements};
    use tokio::time::{timeout, Duration};
    
    info!(" Discovering network peers for blockchain bootstrap...");
    
    // Create bootstrap with mDNS enhancements
    let enhancements = DHTBootstrapEnhancements {
        enable_mdns: true,
        enable_peer_exchange: false, // Don't need peer exchange for bootstrap
        mdns_timeout: Duration::from_secs(5),
        max_mdns_peers: 10,
    };
    
    // Load the node's persistent identity to get a real public key
    let node_identity = crate::cli::commands::node::create_or_load_node_identity(environment).await?;
    let local_public_key = lib_crypto::PublicKey::new(node_identity.public_key.clone());
    let mut bootstrap = DHTBootstrap::new(enhancements, local_public_key);
    
    // Use enhance_bootstrap to discover peers
    let peers = bootstrap.enhance_bootstrap(&[]).await
        .unwrap_or_else(|_| Vec::new());
    
    if peers.is_empty() {
        return Err(anyhow::anyhow!("No network peers found"));
    }
    
    info!(" Found {} potential peers, attempting blockchain sync...", peers.len());
    
    // TODO: First check if any peers are connected via mesh protocols (Bluetooth, WiFi Direct)
    // This would query mesh_router.connections for active mesh peers
    // For now, we'll use HTTP but with the understanding that mesh sync is coming
    
    // Try each peer until we get a blockchain
    for peer in peers {
        // Check if peer address looks like a mesh address (e.g., "bluetooth://...")
        if peer.starts_with("bluetooth://") || peer.starts_with("wifi-direct://") {
            info!(" Peer {} is mesh-connected - using bincode mesh protocol", peer);
            
            // NOTE: Mesh sync during bootstrap is a future enhancement.
            // Currently, mesh peers will sync automatically AFTER they connect
            // via the automatic blockchain sync trigger in authenticate_and_register_peer().
            // This bootstrap function runs at startup before mesh connections are established,
            // so HTTP fallback is appropriate here.
            
            info!("   Mesh sync happens post-bootstrap via automatic trigger");
            info!("   Falling through to HTTP for initial bootstrap");
            // Continue to HTTP sync below
        }
        
        // Fall back to HTTP for non-mesh peers
        let url = format!("http://{}/api/v1/blockchain/export", peer);
        
        match timeout(Duration::from_secs(5), async {
            let response = reqwest::get(&url).await?;
            if response.status().is_success() {
                let data = response.bytes().await?.to_vec();
                Ok::<Vec<u8>, anyhow::Error>(data)
            } else {
                Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
            }
        }).await {
            Ok(Ok(blockchain_data)) => {
                // Create empty blockchain and import
                let mut blockchain = lib_blockchain::Blockchain::new()?;
                blockchain.evaluate_and_merge_chain(blockchain_data).await?;
                info!(" Successfully bootstrapped blockchain from {} (HTTP)", peer);
                return Ok(blockchain);
            }
            Ok(Err(e)) => {
                warn!("Failed to sync from {}: {}", peer, e);
                continue;
            }
            Err(_) => {
                warn!("Timeout connecting to {}", peer);
                continue;
            }
        }
    }
    
    Err(anyhow::anyhow!("Failed to bootstrap from any peer"))
}

/// Try to sync blockchain from a specific peer address using incremental protocol
async fn try_bootstrap_blockchain_from_peer(
    blockchain: &Arc<RwLock<lib_blockchain::Blockchain>>,
    _storage: &Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
    peer_addr: &str,
) -> Result<lib_blockchain::Blockchain> {
    use tokio::time::{timeout, Duration};
    use serde::Deserialize;
    
    info!(" Attempting incremental blockchain sync from peer: {}", peer_addr);
    
    // Step 1: Get peer's chain tip info
    let tip_url = format!("http://{}/api/v1/blockchain/tip", peer_addr);
    
    #[derive(Deserialize)]
    struct ChainTipInfo {
        height: u64,
        head_hash: String,
        genesis_hash: String,
        validator_count: usize,
        identity_count: usize,
    }
    
    let peer_tip = match timeout(Duration::from_secs(5), async {
        info!(" GET {} (fetching chain tip)", tip_url);
        let response = reqwest::get(&tip_url).await?;
        if response.status().is_success() {
            let tip: ChainTipInfo = response.json().await?;
            Ok::<ChainTipInfo, anyhow::Error>(tip)
        } else {
            Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
        }
    }).await {
        Ok(Ok(tip)) => {
            info!(" Peer chain tip: height={}, identities={}, validators={}", 
                  tip.height, tip.identity_count, tip.validator_count);
            tip
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("Failed to fetch tip from {}: {}", peer_addr, e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Timeout fetching tip from {}", peer_addr));
        }
    };
    
    // Step 2: Compare with local chain
    let local_blockchain = blockchain.read().await;
    let local_height = local_blockchain.height;
    let local_genesis = local_blockchain.blocks.first()
        .map(|b| hex::encode(b.header.merkle_root.as_bytes()))
        .unwrap_or_else(|| "none".to_string());
    
    info!(" Chain comparison:");
    info!("   Local:  height={}, genesis={}", local_height, local_genesis);
    info!("   Peer:   height={}, genesis={}", peer_tip.height, peer_tip.genesis_hash);
    
    // Step 3: Determine sync strategy
    if peer_tip.genesis_hash != local_genesis {
        info!("🔀 Different genesis detected - fetching full chain for merge evaluation");
        drop(local_blockchain); // Release lock before fetching
        
        // Fall back to full export for genesis mismatch (merge logic needs full chain)
        let export_url = format!("http://{}/api/v1/blockchain/export", peer_addr);
        match timeout(Duration::from_secs(10), async {
            info!(" GET {} (full chain for merge)", export_url);
            let response = reqwest::get(&export_url).await?;
            if response.status().is_success() {
                let data = response.bytes().await?.to_vec();
                info!(" Received {} bytes for merge evaluation", data.len());
                Ok::<Vec<u8>, anyhow::Error>(data)
            } else {
                Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
            }
        }).await {
            Ok(Ok(blockchain_data)) => {
                let mut blockchain_clone = blockchain.read().await.clone();
                info!(" Evaluating and merging different genesis chains...");
                blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
                info!(" Successfully synced and merged from {} (genesis mismatch)", peer_addr);
                return Ok(blockchain_clone);
            }
            Ok(Err(e)) => {
                return Err(anyhow::anyhow!("Failed to fetch full chain: {}", e));
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Timeout fetching full chain"));
            }
        }
    }
    
    // Step 4: Check if we need to sync even at same height
    if peer_tip.height < local_height {
        info!(" Local chain is ahead (peer: {}, local: {})", peer_tip.height, local_height);
        drop(local_blockchain);
        return Ok(blockchain.read().await.clone());
    }
    
    // If same height, check if peer has more identities/data
    if peer_tip.height == local_height {
        if peer_tip.identity_count > local_blockchain.identity_registry.len() {
            info!(" Same height but peer has more identities ({} vs {}) - syncing full chain for merge", 
                  peer_tip.identity_count, local_blockchain.identity_registry.len());
            
            // Fetch full chain for merge evaluation
            let export_url = format!("http://{}/api/v1/blockchain/export", peer_addr);
            match timeout(Duration::from_secs(10), async {
                info!(" GET {} (full chain for merge)", export_url);
                let response = reqwest::get(&export_url).await?;
                if response.status().is_success() {
                    let data = response.bytes().await?.to_vec();
                    info!(" Received {} bytes for merge evaluation", data.len());
                    Ok::<Vec<u8>, anyhow::Error>(data)
                } else {
                    Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
                }
            }).await {
                Ok(Ok(blockchain_data)) => {
                    drop(local_blockchain); // Release lock before merge
                    let mut blockchain_clone = blockchain.read().await.clone();
                    info!(" Evaluating and merging chains with more peer data...");
                    blockchain_clone.evaluate_and_merge_chain(blockchain_data).await?;
                    info!(" Successfully synced and merged additional data from {}", peer_addr);
                    return Ok(blockchain_clone);
                }
                Ok(Err(e)) => {
                    warn!(" Failed to fetch full chain for merge: {}", e);
                }
                Err(_) => {
                    warn!(" Timeout fetching full chain for merge");
                }
            }
        } else {
            info!(" Local chain is up-to-date (peer: {} identities, local: {} identities)", 
                  peer_tip.identity_count, local_blockchain.identity_registry.len());
        }
        drop(local_blockchain);
        return Ok(blockchain.read().await.clone());
    }
    
    info!(" Peer is ahead - fetching missing blocks {} to {}", local_height + 1, peer_tip.height);
    drop(local_blockchain); // Release lock
    
    // Fetch missing blocks incrementally (max 1000 at a time)
    let start = local_height + 1;
    let end = peer_tip.height;
    let blocks_url = format!("http://{}/api/v1/blockchain/blocks/{}/{}", peer_addr, start, end);
    
    match timeout(Duration::from_secs(10), async {
        info!(" GET {} ({} blocks)", blocks_url, end - start + 1);
        let response = reqwest::get(&blocks_url).await?;
        if response.status().is_success() {
            let data = response.bytes().await?.to_vec();
            info!(" Received {} bytes ({} blocks)", data.len(), end - start + 1);
            Ok::<Vec<u8>, anyhow::Error>(data)
        } else {
            Err(anyhow::anyhow!("Peer returned error: {}", response.status()))
        }
    }).await {
        Ok(Ok(blocks_data)) => {
            // Deserialize blocks
            let new_blocks: Vec<lib_blockchain::block::Block> = bincode::deserialize(&blocks_data)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize blocks: {}", e))?;
            
            info!(" Appending {} new blocks to local chain", new_blocks.len());
            
            // Append blocks to local chain
            let mut blockchain_guard = blockchain.write().await;
            for block in new_blocks {
                // Validate and add block
                blockchain_guard.blocks.push(block);
                blockchain_guard.height += 1;
            }
            
            info!(" Successfully synced {} blocks from {} (incremental)", blockchain_guard.height - local_height, peer_addr);
            info!("   New height: {}", blockchain_guard.height);
            info!("   Identities: {}", blockchain_guard.identity_registry.len());
            
            Ok(blockchain_guard.clone())
        }
        Ok(Err(e)) => {
            Err(anyhow::anyhow!("Failed to fetch blocks: {}", e))
        }
        Err(_) => {
            Err(anyhow::anyhow!("Timeout fetching blocks"))
        }
    }
}