//! Runtime Orchestration System
//! 
//! Coordinates the lifecycle and interactions of all ZHTP components

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};

use super::config::NodeConfig;
// Removed ZK coordinator - using unified lib-proofs system directly

pub mod components;
pub mod shared_blockchain;
pub mod shared_dht;
pub mod blockchain_provider;
pub mod identity_manager_provider;
pub mod network_blockchain_provider;
pub mod mesh_router_provider;
pub mod did_startup;
pub mod routing_rewards;
pub mod storage_rewards;
pub mod reward_orchestrator;
#[cfg(test)]
pub mod test_api_integration;

pub use components::*;
pub use shared_blockchain::*;
pub use shared_dht::*;
pub use blockchain_provider::{initialize_global_blockchain_provider, set_global_blockchain};
pub use identity_manager_provider::{initialize_global_identity_manager_provider, set_global_identity_manager, get_global_identity_manager};
pub use network_blockchain_provider::ZhtpBlockchainProvider;
pub use mesh_router_provider::{initialize_global_mesh_router_provider, set_global_mesh_router, get_broadcast_metrics};

/// Component status information
#[derive(Debug, Clone, PartialEq)]
pub enum ComponentStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error(String),
    Registered,
    Failed,
}

/// Component health metrics
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub status: ComponentStatus,
    pub last_heartbeat: Instant,
    pub error_count: u64,
    pub restart_count: u64,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f32,
}

/// Inter-component message types
#[derive(Debug, Clone)]
pub enum ComponentMessage {
    // Lifecycle messages
    Start,
    Stop,
    Restart,
    HealthCheck,
    
    // Network messages
    PeerConnected(String),
    PeerDisconnected(String),
    NetworkUpdate(String),
    
    // Blockchain messages
    BlockMined(String),
    TransactionReceived(String),
    
    // Identity messages
    IdentityCreated(String),
    IdentityUpdated(String),
    
    // Storage messages
    FileStored(String),
    FileRequested(String),
    
    // Economics messages
    UbiPayment(String, u64),
    DaoProposal(String),
    
    // Blockchain access messages
    GetBlockchain,
    GetBlockchainResponse(Arc<RwLock<Option<lib_blockchain::Blockchain>>>),
    BlockchainOperation(String, Vec<u8>),
    
    // Custom messages
    Custom(String, Vec<u8>),
}

/// Component identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ComponentId {
    Crypto,
    ZK,
    Identity,
    Storage,
    Network,
    Blockchain,
    Consensus,
    Economics,
    Protocols,
    Api,
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentId::Crypto => write!(f, "crypto"),
            ComponentId::ZK => write!(f, "zk"),
            ComponentId::Identity => write!(f, "identity"),
            ComponentId::Storage => write!(f, "storage"),
            ComponentId::Network => write!(f, "network"),
            ComponentId::Blockchain => write!(f, "blockchain"),
            ComponentId::Consensus => write!(f, "consensus"),
            ComponentId::Economics => write!(f, "economics"),
            ComponentId::Protocols => write!(f, "protocols"),
            ComponentId::Api => write!(f, "api"),
        }
    }
}

/// Component interface trait
#[async_trait::async_trait]
pub trait Component: Send + Sync + std::fmt::Debug {
    /// Component identifier
    fn id(&self) -> ComponentId;
    
    /// Start the component
    async fn start(&self) -> Result<()>;
    
    /// Stop the component
    async fn stop(&self) -> Result<()>;
    
    /// Force stop the component (for emergency shutdown)
    async fn force_stop(&self) -> Result<()> {
        // Default implementation just calls regular stop
        self.stop().await
    }
    

    
    /// Check component health
    async fn health_check(&self) -> Result<ComponentHealth>;
    
    /// Handle inter-component messages
    async fn handle_message(&self, message: ComponentMessage) -> Result<()>;
    
    /// Get component metrics
    async fn get_metrics(&self) -> Result<HashMap<String, f64>>;
    
    /// Downcast to Any for type-specific access
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Runtime orchestrator that manages all ZHTP components
#[derive(Clone)]
pub struct RuntimeOrchestrator {
    config: NodeConfig,
    components: Arc<RwLock<HashMap<ComponentId, Arc<dyn Component>>>>,
    component_health: Arc<RwLock<HashMap<ComponentId, ComponentHealth>>>,
    message_bus: Arc<Mutex<mpsc::UnboundedSender<(ComponentId, ComponentMessage)>>>,
    shutdown_signal: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    startup_order: Vec<ComponentId>,
    shared_blockchain: Arc<RwLock<Option<SharedBlockchainService>>>,
    user_wallet: Arc<RwLock<Option<crate::runtime::did_startup::WalletStartupResult>>>,
    
    // Genesis identities to be registered with IdentityManager on startup (PUBLIC DATA ONLY)
    genesis_identities: Arc<RwLock<Vec<lib_identity::ZhtpIdentity>>>,
    
    // Genesis private keys to be securely added to IdentityManager (NEVER touches blockchain)
    genesis_private_data: Arc<RwLock<Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>>>,
    
    // Track if we joined an existing network (vs creating genesis)
    joined_existing_network: Arc<RwLock<bool>>,
    
    // Unified reward orchestrator
    reward_orchestrator: Arc<RwLock<Option<Arc<reward_orchestrator::RewardOrchestrator>>>>,
    
    // Node type detection
    is_edge_node: Arc<RwLock<bool>>,
    
    // Edge node configuration
    edge_max_headers: Arc<RwLock<usize>>,
}

impl RuntimeOrchestrator {
    /// Create a new runtime orchestrator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        
        // Spawn shutdown monitor task
        let shutdown_monitor = tokio::spawn(async move {
            if let Some(_shutdown_signal) = shutdown_rx.recv().await {
                tracing::info!("Shutdown signal received, initiating graceful shutdown");
            }
        });
        
        // Store shutdown monitor handle for cleanup
        let _shutdown_handle = shutdown_monitor;
        // Detect node type from config
        // Edge nodes are constrained devices that:
        // 1. Don't validate blocks (validator_enabled = false)
        // 2. Don't run smart contracts (resource constrained)
        // 3. Don't host storage for others (hosted_storage_gb = 0 or very small)
        //
        // Note: blockchain_storage_gb is NOT counted - it grows dynamically
        // Note: personal_storage_gb is NOT counted - user's own data
        let hosted_storage = if config.storage_config.hosted_storage_gb > 0 {
            config.storage_config.hosted_storage_gb
        } else {
            // Backward compatibility: use old storage_capacity_gb field
            config.storage_config.storage_capacity_gb
        };
        
        let is_edge_node = !config.consensus_config.validator_enabled 
            && !config.blockchain_config.smart_contracts
            && hosted_storage < 100;  // Less than 100 GB hosted storage = edge node
        
        let orchestrator = Self {
            config,
            components: Arc::new(RwLock::new(HashMap::new())),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            message_bus: Arc::new(Mutex::new(message_tx)),
            shutdown_signal: Arc::new(Mutex::new(Some(shutdown_tx))),
            shared_blockchain: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(Vec::new())),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: Arc::new(RwLock::new(false)),
            reward_orchestrator: Arc::new(RwLock::new(None)),
            is_edge_node: Arc::new(RwLock::new(is_edge_node)),
            edge_max_headers: Arc::new(RwLock::new(500)),  // Default 500 headers (~100 KB)
            startup_order: vec![
                ComponentId::Crypto,      // Foundation layer
                ComponentId::ZK,          // Zero-knowledge proofs
                ComponentId::Identity,    // Identity management
                ComponentId::Storage,     // Distributed storage
                ComponentId::Network,     // Mesh networking
                ComponentId::Blockchain,  // Blockchain layer
                ComponentId::Consensus,   // Consensus mechanism
                ComponentId::Economics,   // Economic incentives
                ComponentId::Protocols,   // High-level protocols (includes ZHTP server with comprehensive handlers)
            ],
        };

        // Start message handling task
        let components_clone = orchestrator.components.clone();
        tokio::spawn(async move {
            while let Some((component_id, message)) = message_rx.recv().await {
                let components = components_clone.read().await;
                if let Some(component) = components.get(&component_id) {
                    if let Err(e) = component.handle_message(message).await {
                        error!("Component {} failed to handle message: {}", component_id, e);
                    }
                }
            }
        });

        // Start health monitoring task
        let health_clone = orchestrator.component_health.clone();
        let components_clone = orchestrator.components.clone();
        let health_interval = orchestrator.config.integration_settings.health_check_interval_ms;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(health_interval));
            loop {
                interval.tick().await;
                
                let components = components_clone.read().await;
                let mut health = health_clone.write().await;
                
                for (id, component) in components.iter() {
                    match component.health_check().await {
                        Ok(health_info) => {
                            health.insert(id.clone(), health_info);
                        }
                        Err(e) => {
                            warn!("Health check failed for {}: {}", id, e);
                            let error_health = ComponentHealth {
                                status: ComponentStatus::Error(e.to_string()),
                                last_heartbeat: Instant::now(),
                                error_count: health.get(id).map(|h| h.error_count + 1).unwrap_or(1),
                                restart_count: health.get(id).map(|h| h.restart_count).unwrap_or(0),
                                uptime: health.get(id).map(|h| h.uptime).unwrap_or(Duration::ZERO),
                                memory_usage: 0,
                                cpu_usage: 0.0,
                            };
                            health.insert(id.clone(), error_health);
                        }
                    }
                }
            }
        });

        info!("Runtime orchestrator initialized with {} components", orchestrator.startup_order.len());
        Ok(orchestrator)
    }

    /// Get configuration for runtime operations
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Register a component with the orchestrator
    pub async fn register_component(&self, component: Arc<dyn Component>) -> Result<()> {
        let id = component.id();
        info!("Registering component: {}", id);
        
        let mut components = self.components.write().await;
        components.insert(id.clone(), component);
        
        // Initialize health tracking
        let mut health = self.component_health.write().await;
        health.insert(id.clone(), ComponentHealth {
            status: ComponentStatus::Stopped,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime: Duration::ZERO,
            memory_usage: 0,
            cpu_usage: 0.0,
        });
        
        debug!("Component {} registered successfully", id);
        Ok(())
    }

    /// Register all component instances (with singleton guard)
    pub async fn register_all_components(&self) -> Result<()> {
        // Check if components are already registered to prevent duplicate registration
        {
            let components = self.components.read().await;
            if !components.is_empty() {
                info!("Components already registered, skipping duplicate registration");
                return Ok(());
            }
        }
        
        info!("Registering all ZHTP component instances...");
        
        // Import all component types
        use crate::runtime::components::{
            CryptoComponent, ZKComponent, IdentityComponent, StorageComponent, 
            NetworkComponent, BlockchainComponent, ConsensusComponent, 
            EconomicsComponent, ProtocolsComponent, ApiComponent
        };
        
        // Register components in dependency order
        self.register_component(Arc::new(CryptoComponent::new())).await?;
        self.register_component(Arc::new(ZKComponent::new())).await?;
        
        // Create Identity component with genesis identities AND private keys if available
        let genesis_identities = self.genesis_identities.read().await.clone();
        let genesis_private_data = self.genesis_private_data.read().await.clone();
        
        if genesis_identities.is_empty() {
            info!("Registering Identity component without genesis identities");
            self.register_component(Arc::new(IdentityComponent::new())).await?;
        } else {
            info!(" Registering Identity component with {} genesis identities and {} private keys", 
                genesis_identities.len(), genesis_private_data.len());
            self.register_component(Arc::new(
                IdentityComponent::new_with_identities_and_private_data(genesis_identities, genesis_private_data)
            )).await?;
        }
        
        self.register_component(Arc::new(StorageComponent::new())).await?;
        self.register_component(Arc::new(NetworkComponent::new())).await?;
        // Pass user wallet, environment AND bootstrap validators to blockchain component for proper network initialization
        let user_wallet_guard = self.user_wallet.read().await;
        let user_wallet = user_wallet_guard.clone();
        let environment = self.config.environment;  // Get environment from config
        let api_port = self.config.protocols_config.api_port;  // Get API port from config
        let bootstrap_validators = self.config.network_config.bootstrap_validators.clone();  // Get bootstrap validators from config
        let joined_existing_network = *self.joined_existing_network.read().await;  // Check if we joined existing network
        self.register_component(Arc::new(BlockchainComponent::new_with_full_config(user_wallet, environment, bootstrap_validators, joined_existing_network))).await?;
        self.register_component(Arc::new(ConsensusComponent::new(environment))).await?;
        self.register_component(Arc::new(EconomicsComponent::new())).await?;
        let is_edge_node = *self.is_edge_node.read().await;
        self.register_component(Arc::new(ProtocolsComponent::new_with_node_type(environment, api_port, is_edge_node))).await?;
        self.register_component(Arc::new(ApiComponent::new())).await?;
        
        info!("All components registered successfully");
        Ok(())
    }

    /// Set user wallet data for components that need it (replaces identity-based approach)
    pub async fn set_user_identity(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet);
        Ok(())
    }

    /// Set user wallet data for components that need it
    pub async fn set_user_wallet(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
        // Store wallet in orchestrator for use during component creation
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet.clone());
        info!("User wallet stored in orchestrator for component initialization");
        drop(user_wallet);
        
        // Extract and store genesis identities for IdentityManager registration (PUBLIC DATA ONLY)
        let mut genesis_identities = self.genesis_identities.write().await;
        genesis_identities.push(wallet.user_identity.clone());
        genesis_identities.push(wallet.node_identity.clone());
        info!(
            "Stored {} genesis identities (public data) for IdentityManager registration",
            genesis_identities.len()
        );
        drop(genesis_identities);
        
        // Store PRIVATE KEYS separately in secure memory (NEVER touches blockchain)
        let mut genesis_private_data = self.genesis_private_data.write().await;
        genesis_private_data.push((wallet.user_identity.id.clone(), wallet.user_private_data.clone()));
        genesis_private_data.push((wallet.node_identity.id.clone(), wallet.node_private_data.clone()));
        info!(" Stored {} private keys in secure memory (never stored on blockchain)", genesis_private_data.len());
        info!("    USER Identity ID: {}", hex::encode(&wallet.user_identity.id.0));
        info!("    NODE Identity ID: {}", hex::encode(&wallet.node_identity.id.0));
        info!("    USER Public Key (first 32): {}", hex::encode(&wallet.user_private_data.quantum_keypair.public_key[..32]));
        info!("    NODE Public Key (first 32): {}", hex::encode(&wallet.node_private_data.quantum_keypair.public_key[..32]));
        drop(genesis_private_data);
        
        // Try to store private keys in global IdentityManager if already available
        if let Ok(identity_manager_arc) = crate::runtime::identity_manager_provider::get_global_identity_manager().await {
            let mut manager = identity_manager_arc.write().await;
            manager.add_identity_with_private_data(wallet.user_identity.clone(), wallet.user_private_data.clone());
            manager.add_identity_with_private_data(wallet.node_identity.clone(), wallet.node_private_data.clone());
            info!(" Stored private keys for genesis identities in IdentityManager");
        } else {
            info!("  IdentityManager not yet initialized - private keys will be loaded when IdentityComponent starts");
        }
        
        // Initialize blockchain with genesis funding NOW, before starting BlockchainComponent
        info!(" Creating blockchain with genesis funding for user wallet...");
        let mut blockchain = lib_blockchain::Blockchain::new()?;
        
        // Set development difficulty (easy mining for testing)
        // TODO: In production, keep the default INITIAL_DIFFICULTY (0x1d00ffff)
        if matches!(self.config.environment, crate::config::Environment::Development) {
            blockchain.difficulty = lib_blockchain::types::Difficulty::from_bits(0x1fffffff);
            // Also update genesis block difficulty to match
            if let Some(genesis) = blockchain.blocks.get_mut(0) {
                genesis.header.difficulty = lib_blockchain::types::Difficulty::from_bits(0x1fffffff);
            }
            info!(" Development mode: Set blockchain difficulty to 0x1fffffff (easy mining)");
        }
        
        // Create genesis validator from USER identity (not node identity)
        // NOTE: A person can only be a validator once, regardless of how many nodes they own
        // Nodes are just devices controlled by the user's identity
        // Reduced stake to 1_000 for development so a single welcome bonus (5k) or small pools can start the chain
        let genesis_validator = crate::runtime::components::GenesisValidator {
            identity_id: wallet.user_identity.id.clone(), // Use USER identity, not node identity
            stake: 1_000, // Initial stake for genesis validator (1k ZHTP - accessible for testing)
            storage_provided: 0,
            commission_rate: 500, // 5% commission
            endpoints: vec![],
            consensus_key: None,
            node_device_id: Some(wallet.node_identity_id.clone()), // Track which node is running validator
        };
        
        // Extract primary wallet ID and public key from user identity
        let primary_wallet_info = {
            let primary_wallet = wallet.user_identity.wallet_manager.wallets
                .iter()
                .find(|(_, w)| w.wallet_type == lib_identity::wallets::WalletType::Primary)
                .map(|(id, w)| (id.clone(), w.public_key.clone()));
            
            if primary_wallet.is_none() {
                warn!("  No primary wallet found in user identity - genesis will not fund user wallet");
            }
            
            primary_wallet
        };
        
        // Get genesis private data for wallet registry initialization
        let genesis_private_data = self.genesis_private_data.read().await.clone();
        
        // Fund the blockchain genesis with user wallet
        crate::runtime::components::BlockchainComponent::create_genesis_funding(
            &mut blockchain,
            vec![genesis_validator],
            &self.config.environment,
            primary_wallet_info,
            Some(wallet.user_identity.id.clone()), // Pass user identity ID
            genesis_private_data, // Pass private data for Dilithium2 public key extraction
        ).await?;
        
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        // Set in global provider BEFORE BlockchainComponent starts
        set_global_blockchain(blockchain_arc.clone()).await?;
        info!(" Global blockchain provider initialized with user wallet funding");
        
        // CRITICAL: Also push wallet to BlockchainComponent if already registered
        let components = self.components.read().await;
        if let Some(component) = components.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.set_user_wallet(wallet).await;
                info!(" User wallet propagated to BlockchainComponent");
            }
        }
        
        Ok(())
    }

    /// Set whether we joined an existing network (vs creating genesis)
    pub async fn set_joined_existing_network(&self, joined: bool) -> Result<()> {
        let mut joined_network = self.joined_existing_network.write().await;
        *joined_network = joined;
        if joined {
            info!(" Orchestrator: Joining existing network - genesis will NOT be created");
        } else {
            info!(" Orchestrator: Creating new genesis network");
        }
        Ok(())
    }
    
    /// Get current blockchain height (returns 0 if blockchain not initialized)
    pub async fn get_blockchain_height(&self) -> Result<u64> {
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let blockchain = blockchain_arc.read().await;
                Ok(blockchain.height)
            }
            Err(_) => Ok(0)
        }
    }
    
    /// Wait for initial blockchain sync to reach at least height 1
    pub async fn wait_for_initial_sync(&self, timeout: std::time::Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        info!("⏳ Waiting for initial blockchain sync (timeout: {:?})...", timeout);
        
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!("Initial sync timeout after {:?}", timeout));
            }
            
            let height = self.get_blockchain_height().await?;
            if height > 0 {
                info!("✓ Initial sync complete: height = {}", height);
                return Ok(());
            }
            
            // Check every 500ms
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    
    /// Start blockchain sync from existing network (called before identity setup)
    pub async fn start_blockchain_sync(&mut self, network_info: &crate::cli::commands::node::ExistingNetworkInfo) -> Result<()> {
        info!("📦 Starting blockchain sync from {} peers...", network_info.peer_count);
        
        // Initialize a temporary blockchain to receive sync data
        // This will be populated by the mesh sync before the full BlockchainComponent starts
        let blockchain = lib_blockchain::Blockchain::new()?;
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        // Set in global provider so sync handlers can access it
        crate::runtime::blockchain_provider::set_global_blockchain(blockchain_arc.clone()).await?;
        info!("✓ Temporary blockchain initialized for sync reception");
        
        // Note: The actual sync will be triggered by the UnifiedServer when it processes
        // peer connections. The blockchain is now ready to receive synced blocks.
        
        info!("✓ Blockchain ready to receive sync from network peers");
        Ok(())
    }
    
    /// Check if this node is configured as an edge node
    pub async fn is_edge_node(&self) -> bool {
        *self.is_edge_node.read().await
    }

    /// Set edge node mode (overrides auto-detection)
    pub async fn set_edge_node(&self, is_edge: bool) {
        *self.is_edge_node.write().await = is_edge;
    }

    /// Set edge node max headers configuration
    pub async fn set_edge_max_headers(&self, max_headers: usize) {
        *self.edge_max_headers.write().await = max_headers;
    }

    /// Get edge node max headers configuration
    pub async fn get_edge_max_headers(&self) -> usize {
        *self.edge_max_headers.read().await
    }

    /// Start all components in the correct order
    pub async fn start_all_components(&self) -> Result<()> {
        info!(" Starting all ZHTP components...");
        
        // Register components once if not already registered
        self.register_all_components().await?;
        
        // Initialize blockchain BEFORE starting components
        info!(" Creating blockchain instance...");
        let blockchain = lib_blockchain::Blockchain::new()?;
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        // Set in global provider so BlockchainComponent can access it
        set_global_blockchain(blockchain_arc.clone()).await?;
        info!(" Global blockchain provider initialized");
        
        for component_id in &self.startup_order {
            self.start_component(component_id.clone()).await
                .with_context(|| format!("Failed to start component {}", component_id))?;
            
            // Wait between component starts for proper initialization
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        info!(" All components started successfully");
        Ok(())
    }

    /// Start a specific component
    pub async fn start_component(&self, component_id: ComponentId) -> Result<()> {
        // Check if component is already running to prevent duplicate starts
        {
            let health = self.component_health.read().await;
            if let Some(health_info) = health.get(&component_id) {
                if matches!(health_info.status, ComponentStatus::Running) {
                    info!("Component {} is already running, skipping start", component_id);
                    return Ok(());
                }
            }
        }
        
        info!(" Starting component: {}", component_id);
        
        // Update status to starting
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Starting;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Get component and start it
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            let start_time = Instant::now();
            
            match component.start().await {
                Ok(()) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Running;
                        health_info.last_heartbeat = Instant::now();
                        health_info.uptime = start_time.elapsed();
                    }
                    
                    info!("Component {} started successfully", component_id);
                    
                    // Initialize shared blockchain service after BlockchainComponent starts
                    if component_id == ComponentId::Blockchain {
                        if let Err(e) = self.initialize_shared_blockchain().await {
                            warn!("Failed to initialize shared blockchain service: {}", e);
                        }
                        
                        // NOTE: Reward orchestrator moved to after ProtocolsComponent
                        // (needs mesh server to be initialized)
                    }
                    
                    // Wire blockchain to consensus component after consensus starts
                    if component_id == ComponentId::Consensus {
                        if let Err(e) = self.wire_blockchain_to_consensus().await {
                            warn!("Failed to wire blockchain to consensus: {}", e);
                        } else {
                            info!(" Blockchain successfully wired to consensus component");
                        }
                    }
                    
                    // Start reward orchestrator after ProtocolsComponent (mesh server now ready)
                    if component_id == ComponentId::Protocols {
                        // Give mesh server a moment to fully initialize
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        
                        if let Err(e) = self.start_reward_orchestrator().await {
                            warn!("Failed to start reward orchestrator: {}", e);
                        } else {
                            info!(" Reward orchestrator started (mesh server ready for statistics)");
                        }
                    }
                    
                    // Sync wallet balances from blockchain after BLOCKCHAIN component starts
                    // (Must run after blockchain starts, not after Identity, since we need blockchain data)
                    if component_id == ComponentId::Blockchain {
                        if let Err(e) = self.sync_wallet_balances_from_blockchain().await {
                            warn!("Failed to sync wallet balances from blockchain: {}", e);
                        } else {
                            info!(" Wallet balances synced from blockchain wallet registry");
                        }
                    }
                    
                    // Send start notification to other components
                    self.broadcast_message(ComponentMessage::Custom(
                        format!("component_started:{}", component_id),
                        vec![]
                    )).await?;
                    
                    Ok(())
                }
                Err(e) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }
                    
                    error!("Failed to start component {}: {}", component_id, e);
                    Err(e)
                }
            }
        } else {
            let error_msg = format!("Component {} not found", component_id);
            error!("{}", error_msg);
            Err(anyhow::anyhow!(error_msg))
        }
    }

    /// Stop all components in reverse order with timeout
    pub async fn shutdown_all_components(&self) -> Result<()> {
        info!("Shutting down all ZHTP components...");
        
        // Stop unified reward orchestrator first
        if let Err(e) = self.stop_reward_orchestrator().await {
            warn!("Failed to stop reward orchestrator: {}", e);
        }
        
        // Set overall shutdown timeout
        let shutdown_future = async {
            // Stop components in reverse order
            for component_id in self.startup_order.iter().rev() {
                if let Err(e) = self.stop_component(component_id.clone()).await {
                    error!("Failed to stop component {}: {}", component_id, e);
                    // Continue with other components even if one fails
                }
                
                // Wait between component stops
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };

        // Apply overall timeout for shutdown
        let shutdown_timeout_ms = self.config.integration_settings.cross_package_timeouts
            .get("shutdown").copied().unwrap_or(30000);
        match tokio::time::timeout(Duration::from_millis(shutdown_timeout_ms), shutdown_future).await {
            Ok(()) => {
                info!("All components shut down normally");
            }
            Err(_timeout) => {
                warn!("Shutdown timeout reached - forcing termination");
                
                // Force stop all remaining components
                let components = self.components.read().await;
                for component_id in components.keys() {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(component_id) {
                        if !matches!(health_info.status, ComponentStatus::Stopped) {
                            health_info.status = ComponentStatus::Stopped;
                            health_info.last_heartbeat = Instant::now();
                        }
                    }
                }
                warn!(" Forced shutdown completed");
            }
        }
        
        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_signal.lock().await.take() {
            let _ = shutdown_tx.send(());
        }
        
        info!("All components shut down");
        Ok(())
    }

    /// Stop a specific component with timeout
    pub async fn stop_component(&self, component_id: ComponentId) -> Result<()> {
        info!("Stopping component: {}", component_id);
        
        // Update status to stopping
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Stopping;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Get component and stop it with timeout
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            // Add timeout to prevent hanging on shutdown
            match tokio::time::timeout(Duration::from_secs(10), component.stop()).await {
                Ok(Ok(())) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }
                    
                    info!("Component {} stopped successfully", component_id);
                    Ok(())
                }
                Ok(Err(e)) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }
                    
                    error!("Failed to stop component {}: {}", component_id, e);
                    Err(e)
                }
                Err(_timeout) => {
                    warn!("Timeout stopping component {}, forcing shutdown", component_id);
                    
                    // Try force stop if available
                    match tokio::time::timeout(Duration::from_secs(5), component.force_stop()).await {
                        Ok(Ok(())) => {
                            info!("Component {} force stopped", component_id);
                        }
                        Ok(Err(e)) => {
                            warn!("Force stop failed for {}: {}", component_id, e);
                        }
                        Err(_) => {
                            warn!("Force stop timeout for {}", component_id);
                        }
                    }
                    
                    // Mark as stopped regardless
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }
                    
                    Ok(())
                }
            }
        } else {
            warn!("Component {} not found during shutdown", component_id);
            Ok(()) // Not an error during shutdown
        }
    }

    /// Get status of all components
    pub async fn get_component_status(&self) -> Result<HashMap<String, bool>> {
        let health = self.component_health.read().await;
        let mut status = HashMap::new();
        
        for (id, health_info) in health.iter() {
            let is_running = matches!(health_info.status, ComponentStatus::Running);
            status.insert(id.to_string(), is_running);
        }
        
        Ok(status)
    }

    /// Get detailed health information for all components
    pub async fn get_detailed_health(&self) -> Result<HashMap<ComponentId, ComponentHealth>> {
        let health = self.component_health.read().await;
        Ok(health.clone())
    }

    /// Get the node configuration
    pub fn get_config(&self) -> &NodeConfig {
        &self.config
    }

    /// Send a message to a specific component
    pub async fn send_message(&self, component_id: ComponentId, message: ComponentMessage) -> Result<()> {
        let message_bus = self.message_bus.lock().await;
        message_bus.send((component_id, message))
            .map_err(|e| anyhow::anyhow!("Failed to send message: {}", e))?;
        Ok(())
    }

    /// Broadcast a message to all components
    pub async fn broadcast_message(&self, message: ComponentMessage) -> Result<()> {
        let components = self.components.read().await;
        let message_bus = self.message_bus.lock().await;
        
        for component_id in components.keys() {
            message_bus.send((component_id.clone(), message.clone()))
                .map_err(|e| anyhow::anyhow!("Failed to broadcast message: {}", e))?;
        }
        
        Ok(())
    }

    /// Restart a component
    pub async fn restart_component(&self, component_id: ComponentId) -> Result<()> {
        info!(" Restarting component: {}", component_id);
        
        // Update restart count
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.restart_count += 1;
            }
        }

        self.stop_component(component_id.clone()).await?;
        tokio::time::sleep(Duration::from_millis(1000)).await; // Wait for cleanup
        self.start_component(component_id.clone()).await?;
        
        info!("Component {} restarted successfully", component_id);
        Ok(())
    }

    /// Get aggregated metrics from all components
    pub async fn get_system_metrics(&self) -> Result<HashMap<String, f64>> {
        let components = self.components.read().await;
        let mut aggregated_metrics = HashMap::new();
        
        for (id, component) in components.iter() {
            match component.get_metrics().await {
                Ok(metrics) => {
                    for (key, value) in metrics {
                        let prefixed_key = format!("{}_{}", id, key);
                        aggregated_metrics.insert(prefixed_key, value);
                    }
                }
                Err(e) => {
                    warn!("Failed to get metrics from {}: {}", id, e);
                }
            }
        }
        
        // Add orchestrator metrics
        let health = self.component_health.read().await;
        aggregated_metrics.insert("total_components".to_string(), components.len() as f64);
        aggregated_metrics.insert("running_components".to_string(), 
            health.values().filter(|h| matches!(h.status, ComponentStatus::Running)).count() as f64);
        aggregated_metrics.insert("error_components".to_string(),
            health.values().filter(|h| matches!(h.status, ComponentStatus::Error(_))).count() as f64);
        
        Ok(aggregated_metrics)
    }

    // implementations using lib-network APIs
    
    /// Get connected peers from network component
    pub async fn get_connected_peers(&self) -> Result<Vec<String>> {
        // Get peer information from lib-network
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let mut peers = Vec::new();
                
                // Add peer information from mesh status
                if mesh_status.local_peers > 0 {
                    for i in 1..=mesh_status.local_peers.min(10) {
                        peers.push(format!("local-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.regional_peers > 0 {
                    for i in 1..=mesh_status.regional_peers.min(5) {
                        peers.push(format!("regional-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.global_peers > 0 {
                    for i in 1..=mesh_status.global_peers.min(3) {
                        peers.push(format!("global-mesh-peer-{}", i));
                    }
                }
                
                if mesh_status.relay_peers > 0 {
                    for i in 1..=mesh_status.relay_peers.min(2) {
                        peers.push(format!("relay-peer-{}", i));
                    }
                }
                
                if peers.is_empty() {
                    peers.push("No peers connected".to_string());
                }
                
                Ok(peers)
            }
            Err(e) => {
                warn!("Failed to get mesh status: {}", e);
                Ok(vec!["Network status unavailable".to_string()])
            }
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, addr: &str) -> Result<()> {
        info!("Attempting to connect to peer: {}", addr);
        
        // Send connect message to network component
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("connect_to_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Connect request sent to network component for peer: {}", addr);
        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, addr: &str) -> Result<()> {
        info!(" Attempting to disconnect from peer: {}", addr);
        
        // Send disconnect message to network component
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("disconnect_from_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Disconnect request sent to network component for peer: {}", addr);
        Ok(())
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<String> {
        // Get comprehensive network information from lib-network
        let mut info = String::new();
        
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                info.push_str("ZHTP Mesh Network Status\n");
                info.push_str("===========================\n");
                info.push_str(&format!("Internet Connected: {}\n", 
                    if mesh_status.internet_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Mesh Connected: {}\n", 
                    if mesh_status.mesh_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Connectivity: {:.1}%\n", mesh_status.connectivity_percentage));
                info.push_str(&format!("Active Peers: {}\n", mesh_status.active_peers));
                info.push_str(&format!("  • Local: {}\n", mesh_status.local_peers));
                info.push_str(&format!("  • Regional: {}\n", mesh_status.regional_peers));
                info.push_str(&format!("  • Global: {}\n", mesh_status.global_peers));
                info.push_str(&format!("  • Relays: {}\n", mesh_status.relay_peers));
                info.push_str(&format!("Coverage: {:.1}%\n", mesh_status.coverage));
                info.push_str(&format!("Stability: {:.1}%\n", mesh_status.stability));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get mesh status: {}\n", e));
            }
        }
        
        match lib_network::get_network_statistics().await {
            Ok(net_stats) => {
                info.push_str("\nNetwork Statistics\n");
                info.push_str("=====================\n");
                info.push_str(&format!("Bytes Sent: {} MB\n", net_stats.bytes_sent / 1_000_000));
                info.push_str(&format!("Bytes Received: {} MB\n", net_stats.bytes_received / 1_000_000));
                info.push_str(&format!("Packets Sent: {}\n", net_stats.packets_sent));
                info.push_str(&format!("Packets Received: {}\n", net_stats.packets_received));
                info.push_str(&format!("Connections: {}\n", net_stats.connection_count));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get network statistics: {}\n", e));
            }
        }
        
        Ok(info)
    }

    /// Get mesh status
    pub async fn get_mesh_status(&self) -> Result<String> {
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let status = if mesh_status.connectivity_percentage > 80.0 {
                    "[EXCELLENT]"
                } else if mesh_status.connectivity_percentage > 60.0 {
                    "🟡 Good"
                } else if mesh_status.connectivity_percentage > 30.0 {
                    "🟠 Fair"
                } else {
                    "[POOR]"
                };
                
                Ok(format!(
                    "{} - {:.1}% connectivity, {} peers ({} local, {} regional, {} global, {} relays)",
                    status,
                    mesh_status.connectivity_percentage,
                    mesh_status.active_peers,
                    mesh_status.local_peers,
                    mesh_status.regional_peers,
                    mesh_status.global_peers,
                    mesh_status.relay_peers
                ))
            }
            Err(e) => {
                Ok(format!("Mesh status unavailable: {}", e))
            }
        }
    }

    /// Run the main operational loop
    pub async fn run_main_loop(&self) -> Result<()> {
        info!(" Starting main operational loop...");
        
        // Wait a moment for components to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        info!("ZHTP system fully operational - ready for identity and transaction testing");
        
        // Create a future that never completes to keep the node running
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Perform periodic maintenance
                    if let Err(e) = self.perform_maintenance().await {
                        warn!("Maintenance cycle error: {}", e);
                    }
                }
            }
            
            // Check if shutdown was requested more frequently to improve responsiveness
            {
                let shutdown_signal = self.shutdown_signal.lock().await;
                if shutdown_signal.is_none() {
                    info!("Shutdown signal received, exiting main loop");
                    break;
                }
            }
            
            // Brief pause to allow other tasks to run and improve shutdown responsiveness
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }



    /// Perform periodic maintenance tasks
    async fn perform_maintenance(&self) -> Result<()> {
        // Get system metrics
        let metrics = self.get_system_metrics().await?;
        debug!("System metrics: {} total metrics collected", metrics.len());
        
        // Check component health
        let health = self.get_detailed_health().await?;
        let unhealthy_components: Vec<_> = health.iter()
            .filter(|(_, h)| !matches!(h.status, ComponentStatus::Running))
            .map(|(id, _)| id.to_string())
            .collect();
            
        if !unhealthy_components.is_empty() {
            warn!("Unhealthy components: {:?}", unhealthy_components);
        }
        
        // Log summary
        let running_count = health.values()
            .filter(|h| matches!(h.status, ComponentStatus::Running))
            .count();
        debug!("{}/{} components running normally", running_count, health.len());
        
        Ok(())
    }

    /// Get the shared blockchain service
    pub async fn get_shared_blockchain_service(&self) -> Option<SharedBlockchainService> {
        self.shared_blockchain.read().await.clone()
    }
    
    /// Initialize the shared blockchain service once the blockchain component is started
    pub async fn initialize_shared_blockchain(&self) -> Result<()> {
        // Initialize the global blockchain provider first
        initialize_global_blockchain_provider();
        
        // Get the blockchain component's blockchain instance
        if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            // Try to get the blockchain instance from the blockchain component
            if let Some(blockchain_component) = component.as_any().downcast_ref::<BlockchainComponent>() {
                // Wait for blockchain to be initialized and get the actual instance
                if let Ok(blockchain_arc) = blockchain_component.get_initialized_blockchain().await {
                    // Set up the shared service
                    let shared_service = SharedBlockchainService::new(blockchain_arc.clone());
                    *self.shared_blockchain.write().await = Some(shared_service);
                    
                    // Also set the global blockchain for protocol access
                    if let Err(e) = set_global_blockchain(blockchain_arc).await {
                        warn!("Failed to set global blockchain: {}", e);
                    } else {
                        info!("Global blockchain provider updated");
                    }
                    
                    info!("Shared blockchain service initialized");
                    return Ok(());
                }
            }
        }
        
        warn!("Failed to initialize shared blockchain service - blockchain component not found");
        Ok(())
    }
    
    /// Wire the blockchain to the consensus component for validator synchronization
    /// 
    /// This connects the blockchain's validator registry to the consensus layer's
    /// ValidatorManager, enabling multi-node consensus.
    pub async fn wire_blockchain_to_consensus(&self) -> Result<()> {
        info!("Wiring blockchain to consensus component...");
        
        // Get the blockchain Arc from BlockchainComponent
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };
        
        // Get the ConsensusComponent and set the blockchain reference
        if let Some(component) = self.components.read().await.get(&ComponentId::Consensus) {
            if let Some(consensus_comp) = component.as_any().downcast_ref::<ConsensusComponent>() {
                // Set the blockchain reference in consensus
                consensus_comp.set_blockchain(blockchain_arc).await;
                
                // Sync validators from blockchain to consensus
                consensus_comp.sync_validators_from_blockchain().await?;
                
                // Get the validator manager from consensus
                let validator_manager = consensus_comp.get_validator_manager().await;
                
                // Wire validator manager and node identity back to BlockchainComponent for mining coordination
                if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
                    if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                        // Set validator manager
                        blockchain_comp.set_validator_manager(validator_manager).await;
                        info!(" Validator manager connected to blockchain mining loop");
                        
                        // Set node owner identity from wallet startup (secure node identity)
                        let wallet_guard = self.user_wallet.read().await;
                        if let Some(ref wallet_data) = *wallet_guard {
                            blockchain_comp.set_node_identity(wallet_data.node_identity_id.clone()).await;
                            info!(" Node owner identity connected: {}", hex::encode(&wallet_data.node_identity_id.0[..8]));
                        } else {
                            warn!("  Node owner identity not available yet - mining will use bootstrap mode");
                        }
                    }
                }
                
                info!("Blockchain successfully connected to consensus validator manager");
                return Ok(());
            }
        }
        
        Err(anyhow::anyhow!("Consensus component not found"))
    }

    /// Sync wallet balances from blockchain UTXO set
    /// 
    /// This ensures that in-memory wallet balances reflect the actual
    /// on-chain state, including genesis funding and any transactions.
    pub async fn sync_wallet_balances_from_blockchain(&self) -> Result<()> {
        info!(" Syncing wallet balances from blockchain wallet registry...");
        
        // Get the global IdentityManager
        let identity_manager_arc = match crate::runtime::identity_manager_provider::get_global_identity_manager().await {
            Ok(arc) => arc,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get global IdentityManager: {}", e));
            }
        };
        
        // Get the blockchain Arc from BlockchainComponent
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };
        
        // Extract wallet balance data from blockchain wallet_registry
        let wallet_balances = {
            let blockchain = blockchain_arc.read().await;
            let mut balances = std::collections::HashMap::new();
            
            info!(" Scanning blockchain wallet_registry (total entries: {})...", blockchain.wallet_registry.len());
            
            for (wallet_id_hex, wallet_data) in blockchain.wallet_registry.iter() {
                if wallet_data.initial_balance > 0 {
                    info!("   Found funded wallet: {} → {} ZHTP", 
                        &wallet_id_hex[..16], wallet_data.initial_balance);
                    balances.insert(wallet_id_hex.clone(), wallet_data.initial_balance);
                } else {
                    info!("   Skipping zero-balance wallet: {}", &wallet_id_hex[..16]);
                }
            }
            
            info!(" Extracted {} wallet balance entries from blockchain", balances.len());
            balances
        };
        
        // Lock identity manager and perform sync
        let mut identity_manager = identity_manager_arc.write().await;
        
        // Call the sync method with extracted balance data
        identity_manager.sync_wallet_balances(&wallet_balances)?;
        
        info!(" Wallet balance sync completed successfully");
        Ok(())
    }

    /// Create a blockchain transaction consuming UTXOs for a wallet payment
    /// 
    /// This is the proper UTXO-based payment flow:
    /// 1. Find UTXOs owned by the wallet's public key in blockchain.utxo_set
    /// 2. Select enough UTXOs to cover the payment amount
    /// 3. Ask IdentityManager to create and sign transaction (has access to private key)
    /// 4. Submit signed transaction to blockchain
    /// 5. Blockchain will consume UTXOs and create new outputs
    pub async fn create_wallet_payment_transaction(
        &self,
        identity_id: &lib_identity::IdentityId,
        wallet_pubkey: &[u8],
        recipient_pubkey: &[u8],
        amount: u64,
        purpose: &str,
    ) -> Result<lib_blockchain::Hash> {
        info!(" Creating blockchain transaction for wallet payment: {} ZHTP for '{}'", amount, purpose);
        
        // Step 1: Get blockchain and scan for UTXOs matching wallet_pubkey
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };
        
        let blockchain = blockchain_arc.read().await;
        
        // Scan UTXO set for outputs owned by this wallet
        let mut wallet_utxos: Vec<(lib_blockchain::Hash, u32, u64)> = Vec::new();
        
        info!(" Scanning {} UTXOs for wallet pubkey: {}", 
              blockchain.utxo_set.len(), 
              hex::encode(&wallet_pubkey[..8.min(wallet_pubkey.len())]));
        
        for (utxo_hash, output) in &blockchain.utxo_set {
            // Check if this UTXO belongs to our wallet
            // Compare recipient public key bytes with wallet pubkey
            if output.recipient.as_bytes() == wallet_pubkey {
                // NOTE: Amount is hidden in Pedersen commitment, so we need to get it from wallet_registry
                // For genesis UTXOs, we know the amount from wallet_registry initial_balance
                // In production, we'd need to decrypt the note or track amounts separately
                
                // For now, use a placeholder amount - this would come from wallet's UTXO tracking
                let utxo_amount = 5000u64; // Genesis wallet funding amount
                
                wallet_utxos.push((*utxo_hash, 0, utxo_amount));
                info!("   Found UTXO: {}", hex::encode(utxo_hash.as_bytes()));
            }
        }
        
        if wallet_utxos.is_empty() {
            warn!("  No UTXOs found for wallet");
            return Err(anyhow::anyhow!("No UTXOs found for wallet"));
        }
        
        info!(" Found {} UTXOs for wallet", wallet_utxos.len());
        
        // Step 2: Select UTXOs to cover amount + fee
        let fee = 100u64; // 100 micro-ZHTP fee
        let required_amount = amount + fee;
        
        let mut selected_utxos = Vec::new();
        let mut total_selected = 0u64;
        
        for utxo in wallet_utxos {
            selected_utxos.push(utxo.clone());
            total_selected += utxo.2;
            
            if total_selected >= required_amount {
                break;
            }
        }
        
        if total_selected < required_amount {
            return Err(anyhow::anyhow!(
                "Insufficient UTXO balance: need {}, have {}",
                required_amount,
                total_selected
            ));
        }
        
        info!(" Selected {} UTXOs totaling {} ZHTP", selected_utxos.len(), total_selected);
        
        drop(blockchain); // Release read lock
        
        // Step 3: Get IdentityManager to create signed transaction
        let identity_mgr_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Identity) {
            if let Some(identity_comp) = component.as_any().downcast_ref::<IdentityComponent>() {
                identity_comp.get_identity_manager_arc()
            } else {
                return Err(anyhow::anyhow!("Identity component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Identity component not found"));
        };
        
        let identity_mgr_opt = identity_mgr_arc.read().await;
        let identity_mgr: &lib_identity::IdentityManager = identity_mgr_opt.as_ref()
            .ok_or_else(|| anyhow::anyhow!("IdentityManager not initialized"))?;
        
        // Convert lib_blockchain::Hash to lib_crypto::Hash for IdentityManager
        let selected_utxos_crypto: Vec<(lib_crypto::Hash, u32, u64)> = selected_utxos
            .iter()
            .map(|(hash, idx, amt)| {
                (lib_crypto::Hash::from_bytes(hash.as_bytes()), *idx, *amt)
            })
            .collect();
        
        // Get transaction components (private key, amounts, wallet pubkey)
        let (private_key_bytes, total_input, change_amount, wallet_pubkey) = identity_mgr.create_payment_transaction(
            identity_id,
            selected_utxos_crypto.clone(),
            recipient_pubkey,
            amount,
            fee,
        )?;
        
        drop(identity_mgr_opt);
        
        info!("💳 Building payment transaction: {} ZHTP to recipient, {} ZHTP change", amount, change_amount);
        
        // Step 4: Build Transaction using lib-blockchain TransactionBuilder
        use lib_blockchain::transaction::{TransactionInput, TransactionOutput, TransactionBuilder};
        use lib_blockchain::types::transaction_type::TransactionType;
        use lib_crypto::PrivateKey;
        
        // Create PrivateKey struct
        let private_key = PrivateKey {
            dilithium_sk: private_key_bytes,
            kyber_sk: Vec::new(),
            master_seed: vec![0u8; 32],
        };
        
        // Create transaction inputs from selected UTXOs
        let mut inputs = Vec::new();
        for (utxo_hash, output_index, _amount) in &selected_utxos {
            // Generate nullifier for this UTXO
            let nullifier_data = [utxo_hash.as_bytes(), &output_index.to_le_bytes()].concat();
            let nullifier = lib_blockchain::Hash::from_slice(&lib_crypto::hash_blake3(&nullifier_data)[..32]);
            
            // Create ZK proof - TransactionBuilder will generate proper proofs
            let zk_proof = lib_blockchain::integration::zk_integration::ZkTransactionProof::prove_transaction(
                total_input,     // sender_balance
                0,              // receiver_balance (not needed for input)
                amount,         // amount
                fee,            // fee
                [0u8; 32],     // sender_blinding (placeholder)
                [0u8; 32],     // receiver_blinding
                [0u8; 32],     // nullifier
            ).unwrap_or_else(|_| {
                // Fallback to empty proof if generation fails
                use lib_proofs::types::ZkProof;
                lib_proofs::ZkTransactionProof::new(
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                )
            });
            
            let input = TransactionInput::new(
                *utxo_hash,
                *output_index,
                nullifier,
                zk_proof,
            );
            inputs.push(input);
        }
        
        // Create transaction outputs
        let mut outputs = Vec::new();
        
        // Output 1: Payment to recipient
        let recipient_commitment = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"commitment:"[..], recipient_pubkey, &amount.to_le_bytes()].concat())[..32]
        );
        let recipient_note = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"note:"[..], recipient_pubkey, &amount.to_le_bytes()].concat())[..32]
        );
        let recipient_pk = lib_blockchain::integration::crypto_integration::PublicKey::new(recipient_pubkey.to_vec());
        
        outputs.push(TransactionOutput::new(
            recipient_commitment,
            recipient_note,
            recipient_pk,
        ));
        
        // Output 2: Change back to wallet (if any)
        if change_amount > 0 {
            let change_commitment = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"commitment:"[..], &wallet_pubkey[..], &change_amount.to_le_bytes()].concat())[..32]
            );
            let change_note = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"note:"[..], &wallet_pubkey[..], &change_amount.to_le_bytes()].concat())[..32]
            );
            let change_pk = lib_blockchain::integration::crypto_integration::PublicKey::new(wallet_pubkey.clone());
            
            outputs.push(TransactionOutput::new(
                change_commitment,
                change_note,
                change_pk,
            ));
        }
        
        // Build and sign the transaction
        let transaction = TransactionBuilder::new()
            .transaction_type(TransactionType::Transfer)
            .add_inputs(inputs)
            .add_outputs(outputs)
            .fee(fee)
            .build(&private_key)
            .map_err(|e| anyhow::anyhow!("Failed to build transaction: {:?}", e))?;
        
        let tx_hash = transaction.hash();
        
        info!(" Built signed transaction: {}", hex::encode(tx_hash.as_bytes()));
        
        // Step 5: Submit transaction to blockchain
        let mut blockchain = blockchain_arc.write().await;
        
        blockchain.add_pending_transaction(transaction.clone())
            .map_err(|e| anyhow::anyhow!("Failed to add transaction to blockchain: {:?}", e))?;
        
        info!("📤 Transaction submitted to mempool");
        
        drop(blockchain);
        
        Ok(tx_hash)
    }

    /// Start the unified reward orchestrator
    async fn start_reward_orchestrator(&self) -> Result<()> {
        // Get NetworkComponent
        let network_component = if let Some(component) = self.components.read().await.get(&ComponentId::Network) {
            if let Some(network_comp) = component.as_any().downcast_ref::<NetworkComponent>() {
                Arc::new(network_comp.clone())
            } else {
                warn!("Network component found but type mismatch");
                return Err(anyhow::anyhow!("Network component type mismatch"));
            }
        } else {
            warn!("Network component not found");
            return Err(anyhow::anyhow!("Network component not found"));
        };

        // Get BlockchainComponent's blockchain Arc
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                warn!("Blockchain component found but type mismatch");
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            warn!("Blockchain component not found");
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };

        // Wrap blockchain_arc in Option to match expected type
        let blockchain_with_option = Arc::new(RwLock::new(Some(
            (*blockchain_arc.read().await).clone()
        )));

        // Convert rewards config to orchestrator config
        let orchestrator_config = reward_orchestrator::RewardOrchestratorConfig::from(&self.config.rewards_config);

        // Create the unified reward orchestrator with configuration
        let orchestrator = Arc::new(reward_orchestrator::RewardOrchestrator::with_config(
            network_component,
            blockchain_with_option,
            self.config.environment.clone(),
            orchestrator_config,
        ));

        // Start all enabled reward processors
        orchestrator.start_all().await?;

        // Store the orchestrator instance
        *self.reward_orchestrator.write().await = Some(orchestrator);

        info!("Unified reward orchestrator started successfully");
        Ok(())
    }

    /// Stop the unified reward orchestrator
    async fn stop_reward_orchestrator(&self) -> Result<()> {
        if let Some(orchestrator) = self.reward_orchestrator.write().await.take() {
            info!("Stopping unified reward orchestrator...");
            orchestrator.stop_all().await?;
            info!("Unified reward orchestrator stopped");
        }
        Ok(())
    }

    /// Get the shared blockchain instance from the blockchain component
    pub async fn get_shared_blockchain(&self) -> Result<Option<Arc<RwLock<Option<lib_blockchain::Blockchain>>>>> {
        // Create a channel for the response
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Store response sender for potential cleanup
        let _response_sender = response_tx.clone();
        
        // Send a request to the blockchain component
        let blockchain_request = ComponentMessage::Custom(
            "get_blockchain_instance".to_string(),
            vec![], // Empty data since we can't serialize channels
        );
        
        if let Err(e) = self.send_message(ComponentId::Blockchain, blockchain_request).await {
            warn!("Failed to request blockchain instance: {}", e);
            return Ok(None);
        }
        
        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(5), response_rx.recv()).await {
            Ok(Some(blockchain_arc)) => {
                info!("Received shared blockchain instance from blockchain component");
                Ok(Some(blockchain_arc))
            }
            Ok(None) => {
                warn!("Blockchain component channel closed");
                Ok(None)
            }
            Err(_) => {
                warn!("Timeout waiting for blockchain instance");
                Ok(None)
            }
        }
    }

    /// Send a blockchain operation to the blockchain component
    pub async fn execute_blockchain_operation(&self, operation: &str, data: Vec<u8>) -> Result<()> {
        let message = ComponentMessage::BlockchainOperation(operation.to_string(), data);
        self.send_message(ComponentId::Blockchain, message).await
    }
    
    /// Graceful shutdown of the orchestrator
    pub async fn graceful_shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown...");
        
        // Stop all components
        if let Err(e) = self.shutdown_all_components().await {
            error!("Error during component shutdown: {}", e);
        }
        
        // Signal shutdown completion
        {
            let mut shutdown_signal = self.shutdown_signal.lock().await;
            if let Some(tx) = shutdown_signal.take() {
                let _ = tx.send(());
            }
        }
        
        info!("Graceful shutdown completed");
        Ok(())
    }

    // ========================================================================
    // Public Getter Methods for Private Fields
    // ========================================================================

    /// Get a read-only clone of genesis identities
    pub async fn get_genesis_identities(&self) -> Vec<lib_identity::ZhtpIdentity> {
        self.genesis_identities.read().await.clone()
    }

    /// Get genesis private data for identity initialization
    pub async fn get_genesis_private_data(&self) -> Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)> {
        self.genesis_private_data.read().await.clone()
    }

    /// Get a read-only clone of user wallet
    pub async fn get_user_wallet(&self) -> Option<crate::runtime::did_startup::WalletStartupResult> {
        self.user_wallet.read().await.clone()
    }

    /// Get the environment configuration
    pub fn get_environment(&self) -> crate::config::environment::Environment {
        self.config.environment
    }

    /// Get bootstrap validators from network config
    pub fn get_bootstrap_validators(&self) -> Vec<crate::config::aggregation::BootstrapValidator> {
        self.config.network_config.bootstrap_validators.clone()
    }

    /// Check if node joined an existing network
    pub async fn get_joined_existing_network(&self) -> bool {
        *self.joined_existing_network.read().await
    }
}

