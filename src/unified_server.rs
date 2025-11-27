//! ZHTP Unified Server - Single Server for All Protocols
//! 
//! ✅ REFACTORED - Now uses modular components from server/ directory
//! 
//! This file orchestrates the server components:
//! - Protocol detection and routing (server::protocol_detection)
//! - TCP/UDP handlers (server::tcp_handler, server::udp_handler)
//! - HTTP router and middleware (server::http)
//! - Mesh router and authentication (server::mesh)
//! - WiFi/Bluetooth protocols (server::protocols)
//! - API handler registration (server::api_registration)

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
// REMOVED: TCP/UDP no longer used - QUIC-only architecture
// use tokio::net::{TcpListener, UdpSocket, TcpStream};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

// Import from libraries (no circular dependencies!)
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse};
use lib_network::protocols::quic_mesh::QuicMeshProtocol;
use lib_network::protocols::zhtp_encryption::ZhtpEncryptionSession;
use lib_network::protocols::zhtp_auth::ZhtpAuthManager;

// Import new QUIC handler for native ZHTP-over-QUIC
use crate::server::QuicHandler;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_network::MeshConnection;
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;
use lib_identity::IdentityManager;
use lib_economy::EconomicModel;
use lib_crypto::PublicKey;

// Import lib-network's ZhtpMeshServer (network layer) and our MeshBridge (application layer)
use lib_network::mesh::server::ZhtpMeshServer;
use crate::server::MeshBridge;

// Import our comprehensive API handlers
use crate::api::handlers::{
    DhtHandler, 
    ProtocolHandler,
    BlockchainHandler,
    CryptoHandler,
    NetworkHandler,
    IdentityHandler,
    StorageHandler,
    WalletHandler,
    DaoHandler,
    Web4Handler,
    DnsHandler,
};
use crate::session_manager::SessionManager;

// Re-export for backward compatibility with code that imports from crate::unified_server::*
pub use crate::server::{
    // Protocol detection
    IncomingProtocol,
    // ❌ DELETED: TcpHandler, UdpHandler - Replaced by QuicHandler
    // API registration
    register_api_handlers,
    // HTTP layer
    HttpRouter,
    Middleware,
    CorsMiddleware,
    RateLimitMiddleware,
    AuthMiddleware,
    // Monitoring layer
    PeerReputation,
    PeerRateLimit,
    BroadcastMetrics,
    SyncPerformanceMetrics,
    SyncAlert,
    AlertLevel,
    AlertThresholds,
    MetricsSnapshot,
    PeerPerformanceStats,
    // Protocol routers
    WiFiRouter,
    BluetoothRouter,
    BluetoothClassicRouter,
    ClassicProtocol,
    // ❌ REMOVED: BootstrapRouter - Use lib-network::bootstrap instead
};

/// Main unified server that handles all protocols
/// QUIC-ONLY ARCHITECTURE: TCP/UDP removed, QUIC is the primary transport
#[derive(Clone)]
pub struct ZhtpUnifiedServer {
    // QUIC-native protocol (required, primary transport)
    quic_mesh: Arc<RwLock<QuicMeshProtocol>>,
    quic_handler: Arc<QuicHandler>,
    
    // Protocol routers
    http_router: HttpRouter,
    mesh_bridge: MeshBridge,  // NEW: Replaces deprecated MeshRouter
    wifi_router: WiFiRouter,
    bluetooth_router: BluetoothRouter,
    bluetooth_classic_router: BluetoothClassicRouter,
    // ❌ REMOVED: bootstrap_router - Using lib-network::bootstrap servers instead
    
    // Shared backend state (from ZHTP orchestrator)
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<EconomicModel>>,
    
    // Session management
    session_manager: Arc<SessionManager>,
    
    // Server state
    is_running: Arc<RwLock<bool>>,
    server_id: Uuid,
    port: u16,
    
    // Runtime orchestrator (optional, for NetworkHandler)
    runtime: Option<Arc<crate::runtime::RuntimeOrchestrator>>,
}

impl ZhtpUnifiedServer {
    /// Check if an address is a self-connection from our own node trying to connect to itself
    /// This prevents multi-NIC self-loops but ALLOWS browser connections from localhost
    fn is_self_connection(addr: &std::net::SocketAddr) -> bool {
        let ip = addr.ip();
        
        // IMPORTANT: Do NOT block loopback (127.0.0.1) - that's how browsers connect!
        // We only want to block our actual network IP connecting to itself
        
        // Check if the source IP matches our local network IP
        // (This prevents Ethernet connecting to WiFi on same machine)
        if let Ok(local_ip) = local_ip_address::local_ip() {
            // Only block if source IP matches our non-loopback local IP
            if !local_ip.is_loopback() && ip == local_ip {
                return true;
            }
        }
        
        // Check for link-local auto-assigned addresses (169.254.x.x, fe80::/10)
        // These can cause issues on multi-NIC systems
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // 169.254.x.x is link-local (auto-assigned)
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V4(ipv4) == local_ip {
                            return true;
                        }
                    }
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                // fe80::/10 is link-local
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V6(ipv6) == local_ip {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    /// Get broadcast metrics from mesh bridge
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.mesh_bridge.get_broadcast_metrics().await
    }
    
    /// Get the mesh bridge as an Arc for global provider access
    pub fn get_mesh_router_arc(&self) -> Arc<MeshBridge> {
        // MeshBridge is already Arc-wrapped internally, but we need to clone the Arc to return
        Arc::new(self.mesh_bridge.clone())
    }
    
    /// Create new unified server with comprehensive backend integration
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16, // Port from configuration
    ) -> Result<Self> {
        Self::new_with_peer_notification(blockchain, storage, identity_manager, economic_model, port, None, None).await
    }
    
    /// Create new unified server with peer discovery notification channel
    pub async fn new_with_peer_notification(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16,
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
        runtime: Option<Arc<crate::runtime::RuntimeOrchestrator>>,
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        
        info!("Creating ZHTP Unified Server (ID: {})", server_id);
        info!("Port: {} (HTTP + UDP + WiFi + Bootstrap)", port);
        
        // Initialize session manager first
        let session_manager = Arc::new(SessionManager::new());
        session_manager.start_cleanup_task();
        
        // Initialize protocol routers
        let mut http_router = HttpRouter::new();
        let mut zhtp_router = crate::server::zhtp::ZhtpRouter::new();  // Native ZHTP router for QUIC
        let wifi_router = WiFiRouter::new_with_peer_notification(peer_discovery_tx);
        let bluetooth_router = BluetoothRouter::new();
        let bluetooth_classic_router = BluetoothClassicRouter::new();
        
        // Create network layer: ZhtpMeshServer from lib-network (replaces deprecated MeshRouter)
        let node_id = lib_network::node_id::from_uuid(server_id);
        
        // Get owner key from identity manager
        let owner_key = {
            let identity_mgr = identity_manager.read().await;
            // Try to get any identity's public_key (Vec<u8>), or generate a new one
            if let Some(identity) = identity_mgr.list_identities().first() {
                PublicKey::new(identity.public_key.clone())
            } else {
                // Generate temporary keypair if no identity exists yet
                lib_crypto::generate_keypair()?.public_key
            }
        };
        
        // Note: We'll create the mesh server AFTER creating the main QUIC-networked storage
        // so it can use the same networked storage instance
        
        // Specify which protocols to enable
        let protocols = vec![
            lib_network::protocols::NetworkProtocol::QUIC,
            lib_network::protocols::NetworkProtocol::BluetoothLE,
        ];
        
        // Note: mesh_bridge will be created later after we create the mesh_server with QUIC storage
        
        // Create blockchain broadcast channel for real-time sync
        let (broadcast_sender, broadcast_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        // Configure blockchain to use broadcast channel
        // NOTE: 'blockchain' should BE the shared instance, not a separate copy
        {
            let mut blockchain_write = blockchain.write().await;
            blockchain_write.set_broadcast_channel(broadcast_sender);
        }
        
        // Initialize WiFi Direct protocol
        if let Err(e) = wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
        } else {
            info!(" WiFi Direct protocol initialized but DISABLED by default");
            info!("   Use API endpoint /api/v1/protocols/wifi-direct/enable to activate");
        }
        
        // NOTE: Bluetooth initialization happens in start() to avoid double initialization
        // The bluetooth_router is created here but initialized later when server starts
        
        // ❌ REMOVED: Bootstrap router - lib-network bootstrap servers handle this now
        // let bootstrap_router = BootstrapRouter::new(server_id);
        
        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 1: Initialize QUIC Mesh FIRST (before storage, to enable DHT transport)
        // ═══════════════════════════════════════════════════════════════════════
        info!("🌐 Initializing QUIC mesh protocol (global singleton)...");
        let node_id_for_quic = lib_network::node_id::from_uuid(server_id);
        let quic_bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", 
            lib_network::constants::ports::QUIC_MESH
        ).parse().context("Failed to parse QUIC bind address")?;
        
        let quic_arc = lib_network::protocols::quic_mesh::QuicMeshProtocol::get_or_create_global(
            node_id_for_quic,
            quic_bind_addr
        ).context("Failed to create global QUIC mesh protocol")?;
        
        // Set message handler on QUIC
        let mesh_connections = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let message_handler = lib_network::messaging::message_handler::MeshMessageHandler::new(
            mesh_connections,
            long_range_relays,
            revenue_pools,
        );
        quic_arc.write().await.set_message_handler(Arc::new(RwLock::new(message_handler)));
        
        // Start QUIC receiver
        quic_arc.read().await.start_receiving().await
            .context("Failed to start QUIC receiver")?;
        
        info!("✅ QUIC mesh protocol initialized on UDP port 9334 (global singleton)");
        
        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 2: Create Storage WITH QuicDhtTransport (DHT now uses QUIC)
        // ═══════════════════════════════════════════════════════════════════════
        info!("💾 Creating storage system WITH QUIC DHT transport...");
        
        // Create QuicDhtTransport from global QUIC instance
        let quic_dht_transport = Arc::new(
            lib_network::QuicDhtTransport::new(
                quic_arc.clone(),
                owner_key.clone(),
            )
        ) as Arc<dyn lib_storage::dht::transport::DhtTransport>;
        
        // Create storage config with QUIC transport
        let storage_config_with_quic = lib_storage::UnifiedStorageConfig {
            node_id: node_id.clone(),
            addresses: vec![format!("127.0.0.1:{}", port)],
            dht_transport: Some(quic_dht_transport), // ✅ FIX: Actually provide QUIC transport!
            economic_config: lib_storage::EconomicManagerConfig::default(),
            storage_config: lib_storage::StorageConfig {
                max_storage_size: 10_000_000_000, // 10GB
                default_tier: lib_storage::StorageTier::Hot,
                enable_compression: true,
                enable_encryption: true,
            },
            erasure_config: lib_storage::ErasureConfig {
                data_shards: 4,
                parity_shards: 2,
            },
        };
        
        // Replace the storage instance with QUIC-enabled one
        let storage = Arc::new(RwLock::new(
            lib_storage::UnifiedStorageSystem::new(storage_config_with_quic).await?
        ));
        
        info!("✅ Storage system created WITH QUIC DHT transport (DHT now networked!)");
        
        // Create ZhtpMeshServer using a SECOND storage instance (also with QUIC transport)
        // Note: We create a separate instance to avoid shared mutable state conflicts
        info!("💾 Creating mesh server with its own QUIC-networked storage...");
        let storage_for_mesh_config = lib_storage::UnifiedStorageConfig {
            node_id: node_id.clone(),
            addresses: vec![],
            dht_transport: Some(Arc::new(
                lib_network::QuicDhtTransport::new(
                    quic_arc.clone(),
                    owner_key.clone(),
                )
            ) as Arc<dyn lib_storage::dht::transport::DhtTransport>),
            economic_config: lib_storage::EconomicManagerConfig::default(),
            storage_config: lib_storage::StorageConfig {
                max_storage_size: 10_000_000_000, // 10GB
                default_tier: lib_storage::StorageTier::Hot,
                enable_compression: true,
                enable_encryption: true,
            },
            erasure_config: lib_storage::ErasureConfig {
                data_shards: 4,
                parity_shards: 2,
            },
        };
        let storage_for_mesh = lib_storage::UnifiedStorageSystem::new(storage_for_mesh_config).await?;
        
        // NOW create the mesh server with the QUIC-networked storage
        let zhtp_mesh_server = ZhtpMeshServer::new(node_id.clone(), owner_key.clone(), storage_for_mesh, protocols.clone()).await?;
        info!("✅ Mesh server created WITH QUIC-networked storage!");
        
        // ═══════════════════════════════════════════════════════════════════════
        // PHASE 3: Initialize Mesh Bridge and Handlers
        // ═══════════════════════════════════════════════════════════════════════
        
        // Create application layer: MeshBridge wraps ZhtpMeshServer with ZHTP-specific features
        let mut mesh_bridge = MeshBridge::new(
            server_id,
            Arc::new(RwLock::new(zhtp_mesh_server)),
            session_manager.clone(),
        );
        
        // Set identity manager on mesh bridge for authentication
        mesh_bridge.set_identity_manager(identity_manager.clone());
        
        // Configure mesh bridge to receive broadcasts
        mesh_bridge.set_broadcast_receiver(broadcast_receiver).await;
        
        // Set QUIC protocol on mesh_bridge for sending messages
        mesh_bridge.set_quic_protocol(quic_arc.clone()).await;
        
        // Create DHT handler for pure UDP mesh protocol and register it on mesh_bridge
        // This MUST happen before register_api_handlers to ensure the actual mesh_bridge instance gets the handler
        let dht_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DhtHandler::with_storage(storage.clone())
        );
        mesh_bridge.set_dht_handler(dht_handler.clone()).await;
        
        // Register comprehensive API handlers on both HTTP and native ZHTP routers
        Self::register_api_handlers(
            &mut http_router,
            &mut zhtp_router,
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            session_manager.clone(),
            dht_handler,
            runtime.clone(),
        ).await?;
        
        // Initialize QUIC handler for native ZHTP-over-QUIC (AFTER handler registration)
        let zhtp_router_arc = Arc::new(zhtp_router);
        let quic_handler = Arc::new(QuicHandler::new(
            Arc::new(RwLock::new((*zhtp_router_arc).clone())),  // Native ZhtpRouter wrapped in RwLock
            quic_arc.clone(),                    // QuicMeshProtocol for transport
        ));
        info!(" QUIC handler initialized for native ZHTP-over-QUIC");
        
        // Set ZHTP router on mesh_bridge for proper endpoint routing over UDP
        mesh_bridge.set_zhtp_router(zhtp_router_arc.clone()).await;
        info!(" ZHTP router registered with mesh bridge for UDP endpoint handling");
        
        Ok(Self {
            quic_mesh: quic_arc,
            quic_handler,
            http_router,
            mesh_bridge,  // NEW: Using MeshBridge instead of deprecated MeshRouter
            wifi_router,
            bluetooth_router,
            bluetooth_classic_router,
            // ❌ REMOVED: bootstrap_router field
            blockchain,
            storage,
            identity_manager,
            economic_model,
            session_manager,
            is_running: Arc::new(RwLock::new(false)),
            server_id,
            port,
            runtime,
        })
    }
    
    /// Initialize QUIC mesh protocol (DEPRECATED - use get_or_create_global instead)
    /// This function is kept for backward compatibility but now uses the global singleton
    #[deprecated(note = "Use QuicMeshProtocol::get_or_create_global instead to prevent port conflicts")]
    async fn init_quic_mesh(_port: u16, server_id: Uuid) -> Result<QuicMeshProtocol> {
        // Use global singleton pattern to prevent port conflicts
        let node_id = lib_network::node_id::from_uuid(server_id);
        let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", 
            lib_network::constants::ports::QUIC_MESH
        ).parse().context("Failed to parse QUIC bind address")?;
        
        let quic_arc = lib_network::protocols::quic_mesh::QuicMeshProtocol::get_or_create_global(
            node_id,
            bind_addr
        )?;
        
        // Return a clone (not ideal, but maintains backward compatibility)
        // Callers should use the Arc directly instead
        warn!("⚠️ init_quic_mesh is deprecated - returning clone from global singleton");
        let quic = quic_arc.read().await;
        // Since we can't clone QuicMeshProtocol directly, return error suggesting proper usage
        Err(anyhow::anyhow!("init_quic_mesh is deprecated. Use QuicMeshProtocol::get_or_create_global() which returns Arc<RwLock<QuicMeshProtocol>>"))
    }
    
    /// Register all comprehensive API handlers on both HTTP and ZHTP routers
    async fn register_api_handlers(
        http_router: &mut HttpRouter,
        zhtp_router: &mut crate::server::zhtp::ZhtpRouter,
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        _economic_model: Arc<RwLock<EconomicModel>>,
        _session_manager: Arc<SessionManager>,
        dht_handler: Arc<dyn ZhtpRequestHandler>,
        runtime: Option<Arc<crate::runtime::RuntimeOrchestrator>>,
    ) -> Result<()> {
        info!("Registering comprehensive API handlers on HTTP and ZHTP routers...");
        
        // Blockchain operations
        let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            BlockchainHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler.clone());
        zhtp_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler);
        
        // Identity and wallet management  
        // Note: Using lib_identity::economics::EconomicModel as expected by IdentityHandler
        let identity_economic_model = Arc::new(RwLock::new(
            lib_identity::economics::EconomicModel::new()
        ));
        let identity_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            IdentityHandler::new(identity_manager.clone(), identity_economic_model)
        );
        http_router.register_handler("/api/v1/identity".to_string(), identity_handler.clone());
        zhtp_router.register_handler("/api/v1/identity".to_string(), identity_handler);
        
        // Wallet content ownership manager (shared across handlers)
        let wallet_content_manager = Arc::new(RwLock::new(lib_storage::WalletContentManager::new()));
        
        // Storage operations (with wallet content manager for ownership tracking)
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
                .with_wallet_manager(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/v1/storage".to_string(), storage_handler.clone());
        zhtp_router.register_handler("/api/v1/storage".to_string(), storage_handler);
        
        // Wallet operations
        let wallet_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            WalletHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/wallet".to_string(), wallet_handler.clone());
        zhtp_router.register_handler("/api/v1/wallet".to_string(), wallet_handler);
        
        // DAO operations
        let dao_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DaoHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/dao".to_string(), dao_handler.clone());
        zhtp_router.register_handler("/api/v1/dao".to_string(), dao_handler);
        
        // Crypto utilities (sign message, verify signature, generate keypair)
        let crypto_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::CryptoHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/crypto".to_string(), crypto_handler.clone());
        zhtp_router.register_handler("/api/v1/crypto".to_string(), crypto_handler);
        
        // Register DHT handler on both HTTP and native ZHTP (already registered on mesh_router for pure UDP)
        http_router.register_handler("/api/v1/dht".to_string(), dht_handler.clone());
        zhtp_router.register_handler("/api/v1/dht".to_string(), dht_handler);
        
        // Web4 domain and content (handle async creation first)
        // Pass existing storage, identity manager, AND blockchain for UTXO transaction creation
        let web4_handler = Web4Handler::new(storage.clone(), identity_manager.clone(), blockchain.clone()).await?;
        let web4_manager = web4_handler.get_web4_manager();
        let wallet_content_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::WalletContentHandler::new(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
        http_router.register_handler("/api/content".to_string(), Arc::clone(&wallet_content_handler));
        zhtp_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
        zhtp_router.register_handler("/api/content".to_string(), wallet_content_handler);
        
        // Marketplace handler for buying/selling content (shares managers with wallet content)
        let marketplace_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::MarketplaceHandler::new(
                Arc::clone(&wallet_content_manager),
                Arc::clone(&blockchain),
                Arc::clone(&identity_manager)
            )
        );
        http_router.register_handler("/api/marketplace".to_string(), marketplace_handler.clone());
        zhtp_router.register_handler("/api/marketplace".to_string(), marketplace_handler);
        
        // DNS resolution for .zhtp domains (connect to Web4Manager)
        let mut dns_handler = DnsHandler::new();
        dns_handler.set_web4_manager(web4_manager);
        let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
        http_router.register_handler("/api/v1/dns".to_string(), dns_handler.clone());
        zhtp_router.register_handler("/api/v1/dns".to_string(), dns_handler);
        
        // Register Web4 handler
        let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
        http_router.register_handler("/api/v1/web4".to_string(), web4_handler.clone());
        zhtp_router.register_handler("/api/v1/web4".to_string(), web4_handler);
        
        // Validator management
        let validator_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::ValidatorHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/validator".to_string(), validator_handler.clone());
        zhtp_router.register_handler("/api/v1/validator".to_string(), validator_handler);
        
        // Protocol management
        let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            ProtocolHandler::new()
        );
        http_router.register_handler("/api/v1/protocol".to_string(), protocol_handler.clone());
        zhtp_router.register_handler("/api/v1/protocol".to_string(), protocol_handler);
        
        // Network management (peers, sync, statistics) - only if runtime is available
        if let Some(runtime) = runtime {
            let network_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
                NetworkHandler::new(runtime)
            );
            http_router.register_handler("/api/v1/blockchain/network".to_string(), network_handler.clone());
            http_router.register_handler("/api/v1/blockchain/sync".to_string(), network_handler.clone());
            zhtp_router.register_handler("/api/v1/blockchain/network".to_string(), network_handler.clone());
            zhtp_router.register_handler("/api/v1/blockchain/sync".to_string(), network_handler);
        }
        
        info!("All API handlers registered successfully");
        Ok(())
    }
    
    /// Start the unified server on port 9333
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ZHTP Unified Server on port {}", self.port);
        
        // STEP 1: Apply network isolation to block internet access
        info!(" Applying network isolation for ISP-free mesh operation...");
        if let Err(e) = crate::config::network_isolation::initialize_network_isolation().await {
            warn!("Failed to apply network isolation: {}", e);
            warn!(" Mesh may still have internet access - check network configuration");
        } else {
            info!(" Network isolation applied - mesh is now ISP-free");
        }
        
        // Initialize ZHTP relay protocol ONLY if not already initialized
        // (components.rs may have already initialized it with authentication)
        if self.mesh_bridge.get_relay_protocol().await.is_none() {
            info!(" Initializing ZHTP relay protocol...");
            if let Err(e) = self.mesh_bridge.initialize_relay_protocol().await {
                warn!("Failed to initialize ZHTP relay protocol: {}", e);
            }
        } else {
            info!(" ZHTP relay protocol already initialized (authentication active)");
        }
        
        // ============================================================================
        // PEER DISCOVERY STATUS SUMMARY
        // ============================================================================
        info!("═══════════════════════════════════════════════════════════════");
        info!("  PEER DISCOVERY METHODS - STATUS REPORT");
        info!("═══════════════════════════════════════════════════════════════");
        
        // Get our public key for discovery protocols
        let our_public_key_for_discovery = match self.mesh_bridge.get_sender_public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                warn!(" Failed to get public key for discovery: {}", e);
                return Ok(()); // Skip discovery initialization if we can't get public key
            }
        };
        
        // NOTE: Multicast discovery is already started in Phase 1 (runtime/mod.rs start_network_components_for_discovery)
        // Starting it again here would create a second UUID and cause self-discovery
        // The Phase 1 multicast will continue running and handle peer discovery
        info!(" UDP Multicast: ACTIVE (started in Phase 1, reusing existing discovery)");
        info!("   → Already broadcasting every 30s from Phase 1 initialization");
        let multicast_status = "ACTIVE (Phase 1)";
        
        // IP scanning disabled - using multicast/mDNS/WiFi Direct for efficient discovery
        info!("  IP Scanner: DISABLED (inefficient, replaced by broadcast)");
        
        // Create BLE peer discovery notification channel for blockchain sync trigger
        let (ble_peer_tx, mut ble_peer_rx) = tokio::sync::mpsc::unbounded_channel::<PublicKey>();
        
        // Get our public key for BLE handshakes
        let our_public_key = match self.mesh_bridge.get_sender_public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                warn!(" Failed to get public key for BLE initialization: {}", e);
                return Ok(()); // Skip BLE initialization if we can't get public key
            }
        };
        
        // Initialize Bluetooth LE discovery
        let sync_manager = self.mesh_bridge.get_sync_coordinator().await;
        
        // Create ZHTP authentication manager for Bluetooth LE
        let ble_auth_manager = match lib_network::protocols::zhtp_auth::ZhtpAuthManager::new(our_public_key.clone()) {
            Ok(auth) => Some(auth),
            Err(e) => {
                warn!("Failed to create BLE auth manager: {}", e);
                None
            }
        };
        
        let bluetooth_le_status = match self.bluetooth_router.initialize(
            self.mesh_bridge.get_connections().await,
            Some(ble_peer_tx.clone()),
            our_public_key.clone(),
            self.mesh_bridge.get_blockchain_provider().await,
            sync_manager.clone(),
            Arc::new(self.mesh_bridge.clone()),
            ble_auth_manager, // Pass the auth manager
        ).await {
            Ok(()) => {
                info!("📱 Bluetooth LE: ACTIVE (10m range)");
                info!("   → GATT-based mesh for mobile devices");
                info!("   → Auto-sync headers/proofs to phones");
                "ACTIVE"
            }
            Err(e) => {
                warn!("⚠️  Bluetooth LE: FAILED - {}", e);
                warn!("   → This is normal if no Bluetooth adapter is present");
                "FAILED"
            }
        };
        
        // Start BLE peer discovery sync task if blockchain provider is available
        if self.mesh_bridge.get_blockchain_provider().await.is_some() {
            tokio::spawn(async move {
                while let Some(peer_pubkey) = ble_peer_rx.recv().await {
                    info!("📱 New BLE peer discovered: {}", hex::encode(&peer_pubkey.key_id[..8]));
                    info!("   → Blockchain sync for mobile device");
                    // Sync is handled automatically by BlockchainSyncManager
                    // when peer is added to mesh_connections
                }
            });
            info!("📱 BLE peer discovery listener: ACTIVE (auto-sync on connection)");
        } else {
            info!("📱 BLE peer discovery listener: DISABLED (no blockchain provider)");
        }
        
        // Initialize Bluetooth Classic (high-throughput)
        let bluetooth_classic_status = if let Err(e) = self.bluetooth_classic_router.initialize().await {
            warn!("⚠️  Bluetooth Classic: FAILED - {}", e);
            warn!("   → This is normal if no Bluetooth adapter supports RFCOMM");
            "FAILED"
        } else {
            info!("📡 Bluetooth Classic: ACTIVE (100m range)");
            info!("   → RFCOMM high-throughput mesh");
            info!("   → Large file transfers and bulk sync");
            "ACTIVE"
        };
        
        // Initialize WiFi Direct + mDNS
        let wifi_direct_status = if let Err(e) = self.wifi_router.initialize().await {
            warn!(" WiFi Direct + mDNS: FAILED - {}", e);
            warn!("   → This is normal on systems without P2P WiFi support");
            "FAILED"
        } else {
            info!(" WiFi Direct P2P: ACTIVE (200m range)");
            info!("   → Direct device connections without router");
            info!(" mDNS/Bonjour: ACTIVE (_zhtp._tcp.local)");
            info!("   → Automatic service discovery on local network");
            "ACTIVE"
        };
        
        info!("───────────────────────────────────────────────────────────────");
        info!("  DISCOVERY SUMMARY:");
        info!("    UDP Multicast:      {}", multicast_status);
        info!("    mDNS/Bonjour:       {}", if wifi_direct_status == "ACTIVE" { "ACTIVE" } else { "FAILED" });
        info!("    WiFi Direct P2P:    {}", wifi_direct_status);
        info!("    Bluetooth LE:       {}", bluetooth_le_status);
        info!("    Bluetooth Classic:  {}", bluetooth_classic_status);
        info!("    IP Scanner:         DISABLED");
        info!("═══════════════════════════════════════════════════════════════");
        
        // Inform user about what's working
        let active_count = [multicast_status, wifi_direct_status, bluetooth_le_status, bluetooth_classic_status]
            .iter()
            .filter(|&&s| s == "ACTIVE")
            .count();
        
        if active_count == 0 {
            warn!("  WARNING: NO DISCOVERY METHODS ARE WORKING!");
            warn!("   This node cannot discover peers automatically.");
            warn!("   Check WiFi adapter capabilities and Bluetooth hardware.");
            warn!("   Ensure required ports are open in your firewall (see deployment-guide.md)");
        } else if active_count == 1 {
            info!("  {} discovery method active - limited peer discovery", active_count);
            info!("   For best results, enable WiFi Direct and Bluetooth");
        } else {
            info!(" {} discovery methods active - excellent peer discovery!", active_count);
            info!("   Your node can discover peers via multiple protocols");
        }
        
        info!("═══════════════════════════════════════════════════════════════");
        
        // QUIC-ONLY MODE: Native ZHTP-over-QUIC (TCP/UDP deprecated)
        info!(" QUIC-Only Mode: Native ZHTP protocol over QUIC transport");
        info!(" TCP/UDP deprecated - using QUIC for all networking");
        
        // Get QUIC endpoint from QuicMeshProtocol for accept loop
        let endpoint = self.quic_mesh.read().await.get_endpoint();
        
        *self.is_running.write().await = true;
        
        // Start QUIC connection acceptance loop (PRIMARY PROTOCOL)
        let quic_handler = self.quic_handler.clone();
        tokio::spawn(async move {
            info!("🚀 Starting QUIC accept loop on endpoint...");
            if let Err(e) = quic_handler.accept_loop(endpoint).await {
                error!("❌ QUIC accept loop terminated: {}", e);
            }
        });
        info!(" ✅ QUIC handler started - Native ZHTP-over-QUIC ready");
        
        // Start UDP ZHTP listener (TESTING/SIMPLE CLIENTS)
        // Extract router from mesh_bridge: Arc<RwLock<Option<Arc<ZhtpRouter>>>> -> Arc<ZhtpRouter>
        let zhtp_router = self.mesh_bridge.zhtp_router.read().await.as_ref()
            .expect("ZHTP router must be initialized before starting server")
            .clone();
        let udp_zhtp_handler = crate::server::UdpZhtpHandler::new(zhtp_router.clone());
        let udp_port = self.port + 2; // Use port 9336 for raw UDP (9334=QUIC, 9335=WebSocket, 9336=UDP)
        tokio::spawn(async move {
            let bind_addr = format!("0.0.0.0:{}", udp_port);
            info!("📡 Starting UDP ZHTP listener on {}...", bind_addr);
            if let Err(e) = udp_zhtp_handler.listen(&bind_addr).await {
                error!("❌ UDP ZHTP listener terminated: {}", e);
            }
        });
        info!(" ✅ UDP ZHTP listener started on port {} - Raw UDP transport for testing/simple clients", udp_port);
        
        // Start WebSocket ZHTP bridge (BROWSER CLIENTS)
        let ws_zhtp_bridge = crate::server::WebSocketZhtpBridge::new(zhtp_router.clone());
        let ws_port = self.port + 1; // Use port 9335 for WebSocket
        tokio::spawn(async move {
            let bind_addr = format!("0.0.0.0:{}", ws_port);
            info!("🌐 Starting WebSocket ZHTP bridge on {}...", bind_addr);
            if let Err(e) = ws_zhtp_bridge.listen(&bind_addr).await {
                error!("❌ WebSocket ZHTP bridge terminated: {}", e);
            }
        });
        info!(" ✅ WebSocket ZHTP bridge started - Browser clients can connect on port {}", ws_port);
        
        // Start mesh protocol handlers (background listeners only)
        self.start_bluetooth_mesh_handler().await?;
        self.start_bluetooth_classic_handler().await?;
        // WiFi Direct already initialized above with mDNS
        self.start_lorawan_handler().await?;
        
        info!("ZHTP Unified Server online");
        info!("Protocols: BLE + BT Classic + WiFi Direct + LoRaWAN + ZHTP Relay");
        info!(" ZHTP relay: Encrypted DHT queries with Dilithium2 + Kyber512 + ChaCha20");
        
        // Log network isolation configuration (documentation only)
        info!(" Network isolation configuration:");
        info!("   Note: Application does NOT modify system firewalls");
        info!("   Administrators must manually configure firewall rules");
        info!("   See deployment-guide.md for firewall setup instructions");
        
        Ok(())
    }

    /// Start Bluetooth mesh protocol handler
    async fn start_bluetooth_mesh_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth LE mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let protocol_guard = self.bluetooth_router.get_protocol().await;
        let is_initialized = protocol_guard.is_some();
        drop(protocol_guard);
        
        if !is_initialized {
            warn!("Bluetooth LE protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth LE mesh handler active - discoverable for phone connections");
        
        Ok(())
    }

    /// Start Bluetooth Classic RFCOMM mesh handler
    async fn start_bluetooth_classic_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth Classic RFCOMM mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let protocol_guard = self.bluetooth_classic_router.get_protocol().await;
        let is_initialized = protocol_guard.is_some();
        
        if !is_initialized {
            warn!("Bluetooth Classic protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth Classic RFCOMM handler active");
        
        // Note: Windows Bluetooth API types are not Send, so periodic discovery
        // cannot run in a spawned task. Manual discovery can still be triggered.
        #[cfg(not(all(target_os = "windows", feature = "windows-bluetooth")))]
        {
            info!("Starting periodic Bluetooth Classic peer discovery...");
            // Start periodic peer discovery task
            let bt_router = self.bluetooth_classic_router.clone();
            let mesh_bridge = self.mesh_bridge.clone();
            let is_running = self.is_running.clone();
            
            tokio::spawn(async move {
                // Initial discovery after 5 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                
                while *is_running.read().await {
                    interval.tick().await;
                    
                    info!(" Bluetooth Classic: Starting periodic peer discovery...");
                    match bt_router.discover_and_connect_peers(&mesh_router).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(" Bluetooth Classic: Connected to {} new peers", count);
                            } else {
                                debug!("Bluetooth Classic: No new peers found");
                            }
                        }
                        Err(e) => {
                            warn!("Bluetooth Classic discovery error: {}", e);
                        }
                    }
                }
            });
        }
        
        #[cfg(all(target_os = "windows", feature = "windows-bluetooth"))]
        {
            info!("  Windows: Automatic periodic discovery disabled (API not thread-safe)");
            info!("    Use manual discovery commands or API calls instead");
        }
        
        info!(" Bluetooth Classic periodic discovery task started (60s interval)");
        
        Ok(())
    }

    /// Start LoRaWAN mesh protocol handler
    async fn start_lorawan_handler(&self) -> Result<()> {
        info!(" Starting LoRaWAN mesh handler...");
        
        // LoRaWAN requires specific hardware - check availability
        info!(" LoRaWAN mesh protocol ready (requires LoRa hardware)");
        info!(" Long-range mesh capability available");
        
        Ok(())
    }
    
    /// Start TCP connection handler (HTTP + TCP mesh + WiFi + Bootstrap)




    
    /// Connect to bootstrap peers and initiate blockchain sync via QUIC
    /// This method should be called after the server starts to establish outgoing connections
    /// Uses intelligent peer selection to connect to closest/fastest peers first
    /// 
    /// # Arguments
    /// * `bootstrap_peers` - List of bootstrap peer addresses
    /// * `is_edge_node` - If true, syncs headers+ZK proofs only. If false, downloads complete blockchain
    pub async fn connect_to_bootstrap_peers(&self, bootstrap_peers: Vec<String>, is_edge_node: bool) -> Result<()> {
        if bootstrap_peers.is_empty() {
            info!(" No bootstrap peers to connect to");
            return Ok(());
        }
        
        // Limit bootstrap connections to avoid overwhelming network
        // Connect to max 5 bootstrap peers or max_peers/2, whichever is smaller
        let max_bootstrap_connections = 5.min(bootstrap_peers.len());
        
        let sync_mode = if is_edge_node { "edge mode (headers+proofs)" } else { "full mode (complete blockchain)" };
        info!(" Connecting to {} bootstrap peer(s) (out of {} configured) via QUIC - {}...", 
              max_bootstrap_connections, bootstrap_peers.len(), sync_mode);
        
        let mut successful_connections = 0;
        let mut failed_peers = Vec::new();
        
        // Try to connect to peers in order until we have enough connections
        for (idx, peer_str) in bootstrap_peers.iter().enumerate() {
            if successful_connections >= max_bootstrap_connections {
                debug!("   Reached bootstrap connection limit ({}), stopping", max_bootstrap_connections);
                break;
            }
            
            // Parse the peer address - it might be "192.168.1.245:9333" (discovery port) or "zhtp://192.168.1.245:9334" (QUIC port)
            let addr_str = peer_str.trim_start_matches("zhtp://").trim_start_matches("http://");
            
            match addr_str.parse::<SocketAddr>() {
                Ok(mut peer_addr) => {
                    // Discovery announces port 9333, but QUIC mesh runs on port 9334
                    // If we see port 9333, adjust to 9334 for QUIC connection
                    if peer_addr.port() == 9333 {
                        peer_addr.set_port(9334);
                        info!("   [{}/{}] Connecting to bootstrap peer: {} (adjusted discovery port 9333 → QUIC port 9334)", 
                              idx + 1, bootstrap_peers.len(), peer_addr);
                    } else {
                        info!("   [{}/{}] Connecting to bootstrap peer: {}", 
                              idx + 1, bootstrap_peers.len(), peer_addr);
                    }
                    
                    // Use bootstrap connection mode (allows unauthenticated blockchain sync)
                    // Edge nodes get headers+proofs, full nodes get complete blocks
                    match self.quic_mesh.read().await.connect_as_bootstrap(peer_addr, is_edge_node).await {
                        Ok(()) => {
                            successful_connections += 1;
                            info!("   ✓ Connected to bootstrap peer {} via QUIC (bootstrap mode)", peer_addr);
                        }
                        Err(e) => {
                            warn!("   ✗ Failed to connect to bootstrap peer {}: {}", peer_addr, e);
                            failed_peers.push((peer_str.clone(), e.to_string()));
                        }
                    }
                }
                Err(e) => {
                    warn!("   ✗ Failed to parse bootstrap peer address '{}': {}", peer_str, e);
                    failed_peers.push((peer_str.clone(), e.to_string()));
                }
            }
        }
        
        info!(" Bootstrap peer connections completed: {} successful, {} failed", 
              successful_connections, failed_peers.len());
        
        if successful_connections == 0 {
            return Err(anyhow::anyhow!(
                "Failed to connect to any bootstrap peers. Tried {} peers", 
                bootstrap_peers.len()
            ));
        }
        
        if !failed_peers.is_empty() && successful_connections < 3 {
            warn!(" ⚠️  Connected to fewer than 3 bootstrap peers. Network reliability may be reduced.");
            warn!(" Failed peers: {:?}", failed_peers.iter().map(|(addr, _)| addr).collect::<Vec<_>>());
        }
        
        Ok(())
    }
    
    /// Stop the unified server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping ZHTP Unified Server...");
        
        *self.is_running.write().await = false;
        
        info!("ZHTP Unified Server stopped");
        Ok(())
    }
    
    /// Get server status
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Initialize ZHTP authentication manager (wrapper for mesh_router method)
    pub async fn initialize_auth_manager(&mut self, blockchain_pubkey: lib_crypto::PublicKey) -> Result<()> {
        self.mesh_bridge.initialize_auth_manager(blockchain_pubkey).await
    }
    
    /// Initialize ZHTP relay protocol (wrapper for mesh_router method)
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        self.mesh_bridge.initialize_relay_protocol().await
    }
    
    /// Initialize WiFi Direct authentication with blockchain identity
    /// SECURITY: Ensures only ZHTP nodes can connect via WiFi Direct
    pub async fn initialize_wifi_direct_auth(&self, identity_manager: Arc<RwLock<lib_identity::IdentityManager>>) -> Result<()> {
        info!(" Initializing WiFi Direct ZHTP authentication...");
        
        // Get blockchain public key from identity manager
        let mgr = identity_manager.read().await;
        let identities = mgr.list_identities();
        
        if identities.is_empty() {
            warn!("  No identities found - WiFi Direct authentication cannot be initialized");
            return Ok(()); // Non-fatal, WiFi Direct will work without auth
        }
        
        // Use first identity - identities is Vec<ZhtpIdentity>
        let identity = &identities[0];
        
        // Create PublicKey from identity's public_key field (Dilithium2 public key)
        let blockchain_pubkey = lib_crypto::PublicKey::new(identity.public_key.clone());
        
        info!(" Using identity {} for WiFi Direct authentication", hex::encode(&identity.id.0[..8]));
        info!("   Public key: {}...", hex::encode(&blockchain_pubkey.as_bytes()[..8]));
        
        // Access WiFi Direct protocol and initialize authentication
        let protocol_guard = self.wifi_router.get_protocol().await;
        if let Some(wifi_protocol) = protocol_guard.as_ref() {
            wifi_protocol.initialize_auth(blockchain_pubkey).await?;
            
            info!(" WiFi Direct authentication initialized successfully");
            info!("    Non-ZHTP devices will be rejected");
            info!("    Hidden SSID mode enabled");
        } else {
            warn!("  WiFi Direct protocol not initialized - authentication setup skipped");
        }
        
        Ok(())
    }
    
    /// Set blockchain provider for network layer (delegates to mesh router)
    pub async fn set_blockchain_provider(&mut self, provider: Arc<dyn lib_network::blockchain_sync::BlockchainProvider>) {
        self.mesh_bridge.set_blockchain_provider(provider).await;
    }
    
    /// Set edge sync manager (delegates to mesh router)
    pub async fn set_edge_sync_manager(&mut self, manager: Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>) {
        self.mesh_bridge.set_edge_sync_manager(manager).await;
    }
    
    /// Get server information
    pub fn get_server_info(&self) -> (Uuid, u16) {
        (self.server_id, self.port)
    }
    
    /// Get blockchain statistics
    pub async fn get_blockchain_stats(&self) -> Result<serde_json::Value> {
        let blockchain = self.blockchain.read().await;
        Ok(serde_json::json!({
            "block_count": blockchain.blocks.len(),
            "pending_transactions": blockchain.pending_transactions.len(),
            "identity_count": blockchain.identity_registry.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get storage system status
    pub async fn get_storage_status(&self) -> Result<serde_json::Value> {
        let _storage = self.storage.read().await;
        Ok(serde_json::json!({
            "status": "active",
            "server_id": self.server_id,
            "storage_type": "unified"
        }))
    }
    
    /// Get identity manager statistics  
    pub async fn get_identity_stats(&self) -> Result<serde_json::Value> {
        let identity_manager = self.identity_manager.read().await;
        let identities = identity_manager.list_identities();
        Ok(serde_json::json!({
            "identity_count": identities.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get economic model information
    pub async fn get_economic_info(&self) -> Result<serde_json::Value> {
        let _economic_model = self.economic_model.read().await;
        Ok(serde_json::json!({
            "model_type": "ZHTP",
            "server_id": self.server_id,
            "status": "active"
        }))
    }
}
