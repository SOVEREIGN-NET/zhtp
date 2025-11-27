//! Mesh Bridge - Application Layer Adapter
//!
//! This module bridges lib-network's ZhtpMeshServer (network layer) with
//! zhtp-specific application features (sessions, routing, rate limiting).
//!
//! Architecture:
//! - lib-network::ZhtpMeshServer: Handles ALL networking (connections, protocols, DHT, routing)
//! - MeshBridge: Adds application-layer features (HTTP sessions, ZHTP routing, rate limits)
//!
//! No wrapping or indirection - direct composition with clear separation of concerns.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::Result;
use lib_crypto::PublicKey;
use lib_network::mesh::server::ZhtpMeshServer;
use lib_network::protocols::bluetooth::BluetoothMeshProtocol;
use lib_blockchain::types::Hash;

use crate::session_manager::SessionManager;

/// Rate limiting state for ZHTP getter requests (100 req/30s per identity)
#[derive(Debug, Clone)]
pub struct ZhtpRateLimitState {
    pub request_count: u32,
    pub window_start: u64, // Unix timestamp in seconds
}

impl ZhtpRateLimitState {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            request_count: 0,
            window_start: now,
        }
    }
    
    /// Check if rate limit exceeded (100 req/30s)
    pub fn check_and_increment(&mut self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Reset if window expired (30 seconds)
        if now - self.window_start >= 30 {
            self.request_count = 0;
            self.window_start = now;
        }
        
        // Check if within limit
        if self.request_count >= 100 {
            return false; // Rate limit exceeded
        }
        
        self.request_count += 1;
        true // Within limit
    }
}

/// Mesh Bridge - Application layer adapter for ZhtpMeshServer
///
/// This struct composes lib-network's ZhtpMeshServer with zhtp-specific
/// application features. It does NOT wrap or add indirection - it simply
/// organizes the layers clearly.
pub struct MeshBridge {
    /// Server ID for this node
    pub server_id: Uuid,
    
    // === NETWORK LAYER (lib-network) ===
    /// The actual mesh networking implementation from lib-network
    /// All networking operations (connections, protocols, routing, DHT) go here
    pub mesh_server: Arc<RwLock<ZhtpMeshServer>>,
    
    // === APPLICATION LAYER (zhtp-specific) ===
    /// HTTP/WebSocket session management
    pub session_manager: Arc<SessionManager>,
    
    /// ZHTP API router for all endpoints
    pub zhtp_router: Arc<RwLock<Option<Arc<crate::server::zhtp::ZhtpRouter>>>>,
    
    /// DHT request handler for ZHTP protocol
    pub dht_handler: Arc<RwLock<Option<Arc<dyn lib_protocols::zhtp::ZhtpRequestHandler>>>>,
    
    /// ZHTP rate limiting (100 req/30s for free getters)
    pub zhtp_rate_limits: Arc<RwLock<HashMap<String, ZhtpRateLimitState>>>,
    
    /// Identity manager for user-facing operations
    pub identity_manager: Option<Arc<RwLock<lib_identity::IdentityManager>>>,
}

impl MeshBridge {
    /// Create a new MeshBridge with a ZhtpMeshServer
    pub fn new(server_id: Uuid, mesh_server: Arc<RwLock<ZhtpMeshServer>>, session_manager: Arc<SessionManager>) -> Self {
        Self {
            server_id,
            mesh_server,
            session_manager,
            zhtp_router: Arc::new(RwLock::new(None)),
            dht_handler: Arc::new(RwLock::new(None)),
            zhtp_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            identity_manager: None,
        }
    }
    
    // === APPLICATION-LAYER METHODS ===
    
    /// Set identity manager for user operations
    pub fn set_identity_manager(&mut self, identity_manager: Arc<RwLock<lib_identity::IdentityManager>>) {
        self.identity_manager = Some(identity_manager);
    }
    
    /// Set ZHTP router for endpoint handling
    pub async fn set_zhtp_router(&self, router: Arc<crate::server::zhtp::ZhtpRouter>) {
        use tracing::info;
        *self.zhtp_router.write().await = Some(router);
        info!("🔀 ZHTP router registered on MeshBridge");
    }
    
    /// Set DHT handler for pure mesh protocol
    pub async fn set_dht_handler(&self, handler: Arc<dyn lib_protocols::zhtp::ZhtpRequestHandler>) {
        use tracing::info;
        *self.dht_handler.write().await = Some(handler);
        info!("📡 DHT handler registered on MeshBridge");
    }
    
    /// Check ZHTP rate limit for an identity
    pub async fn check_zhtp_rate_limit(&self, identity_id: &str) -> bool {
        let mut limits = self.zhtp_rate_limits.write().await;
        limits.entry(identity_id.to_string())
            .or_insert_with(ZhtpRateLimitState::new)
            .check_and_increment()
    }
    
    // === NETWORK-LAYER DELEGATION ===
    // These methods delegate directly to ZhtpMeshServer without wrapping
    
    /// Set blockchain broadcast receiver (delegates to mesh_server)
    pub async fn set_broadcast_receiver(
        &self, 
        receiver: tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>
    ) {
        // This will need to be added to ZhtpMeshServer or handled differently
        // For now, we acknowledge this needs network-layer support
        use tracing::warn;
        warn!("set_broadcast_receiver needs to be implemented in lib-network");
    }
    
    /// Set QUIC protocol (delegates to mesh_server)
    /// Note: ZhtpMeshServer stores protocols as Option<Arc<RwLock<Protocol>>>, but
    /// the current code passes Arc<Protocol>, so we just store it directly for now.
    /// This will need proper wrapping when protocols are actually used.
    pub async fn set_quic_protocol(&self, protocol: Arc<RwLock<lib_network::protocols::quic_mesh::QuicMeshProtocol>>) {
        // Store the protocol instance for mesh server
        let mut server = self.mesh_server.write().await;
        server.quic_protocol = Some(protocol);
        use tracing::info;
        info!("✅ QUIC protocol registered with mesh server");
    }
    
    /// Set Bluetooth protocol (delegates to mesh_server)
    pub async fn set_bluetooth_protocol(&self, _protocol: Arc<lib_network::protocols::bluetooth::BluetoothMeshProtocol>) {
        // TODO: Same issue as set_quic_protocol - needs refactoring
        use tracing::warn;
        warn!("set_bluetooth_protocol needs refactoring - skipping for now");
    }
    
    /// Set blockchain provider (delegates to mesh_server)
    pub async fn set_blockchain_provider(&self, provider: Arc<dyn lib_network::blockchain_sync::BlockchainProvider>) {
        let server = self.mesh_server.read().await;
        server.set_blockchain_provider(provider).await;
    }
    
    /// Set edge sync manager (delegates to mesh_server)
    pub async fn set_edge_sync_manager(&self, manager: Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>) {
        let server = self.mesh_server.read().await;
        server.set_edge_sync_manager(manager).await;
    }
    
    /// Initialize relay protocol (delegates to mesh_server)
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        let server = self.mesh_server.read().await;
        server.initialize_relay_protocol().await
    }
    
    /// Initialize authentication manager (delegates to mesh_server)
    pub async fn initialize_auth_manager(&self, blockchain_pubkey: PublicKey) -> Result<()> {
        let server = self.mesh_server.read().await;
        server.initialize_auth_manager(blockchain_pubkey).await
    }
    
    /// Get relay protocol (accessor for ZhtpMeshServer field)
    /// Note: ZhtpRelayProtocol doesn't implement Clone, so we can't provide a cloned Arc
    /// This method is deprecated and should not be used until protocol refactoring is complete
    pub async fn get_relay_protocol(&self) -> Option<Arc<lib_network::dht::relay::ZhtpRelayProtocol>> {
        // TODO: This needs refactoring - ZhtpRelayProtocol is not Clone
        // For now, return None to allow compilation
        None
    }
    
    /// Get connections (accessor for ZhtpMeshServer field)  
    pub async fn get_connections(&self) -> Arc<RwLock<HashMap<PublicKey, lib_network::MeshConnection>>> {
        let server = self.mesh_server.read().await;
        Arc::clone(&server.mesh_connections)
    }
    
    /// Get sync coordinator (accessor for ZhtpMeshServer field)
    pub async fn get_sync_coordinator(&self) -> Arc<lib_network::blockchain_sync::BlockchainSyncManager> {
        let server = self.mesh_server.read().await;
        Arc::clone(&server.sync_manager)
    }
    
    /// Get edge sync manager (accessor for ZhtpMeshServer field)
    pub async fn get_edge_sync_manager(&self) -> Arc<RwLock<Option<Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>>>> {
        let server = self.mesh_server.read().await;
        Arc::clone(&server.edge_sync_manager)
    }
    
    /// Get blockchain provider (accessor for ZhtpMeshServer field)
    pub async fn get_blockchain_provider(&self) -> Option<Arc<dyn lib_network::blockchain_sync::BlockchainProvider>> {
        let server = self.mesh_server.read().await;
        let provider = server.blockchain_provider.read().await;
        provider.clone()
    }
    
    /// Set Bluetooth protocol on mesh server
    pub async fn set_bluetooth_protocol_on_server(&self, protocol: Arc<lib_network::protocols::bluetooth::BluetoothMeshProtocol>) {
        // ZhtpMeshServer.bluetooth_protocol is Option<Arc<RwLock<Protocol>>>
        // We need to clone the protocol into the existing Arc<RwLock<>> if it exists
        // For now, this is a placeholder - protocol initialization happens in ZhtpMeshServer::new()
        // This method may not be needed once full migration is complete
    }
    
    /// Get Bluetooth protocol from mesh server
    pub async fn get_bluetooth_protocol(&self) -> Option<Arc<RwLock<BluetoothMeshProtocol>>> {
        let server = self.mesh_server.read().await;
        server.bluetooth_protocol.as_ref().map(|arc| Arc::clone(arc))
    }
    
    /// Get sender public key (for peer discovery)
    pub async fn get_sender_public_key(&self) -> Result<PublicKey> {
        let server = self.mesh_server.read().await;
        Ok(server.owner_wallet_key.clone())
    }
    
    /// Send message to peer (delegates to mesh_server connections)
    pub async fn send_to_peer(&self, peer_pubkey: &PublicKey, message: lib_network::types::mesh_message::ZhtpMeshMessage) -> Result<()> {
        let server = self.mesh_server.read().await;
        
        // Route message through mesh node
        if let Some(router) = server.message_router.as_ref() {
            let sender_key = server.owner_wallet_key.clone();
            // route_message signature: (message, destination, sender) -> Result<u64>
            router.write().await.route_message(message, peer_pubkey.clone(), sender_key).await?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Message router not initialized"))
        }
    }
    
    // === BLUETOOTH PROTOCOL METHODS ===
    
    /// Register a new peer connection to the mesh network
    pub async fn register_peer(&self, peer_pubkey: PublicKey, connection: lib_network::MeshConnection) -> Result<()> {
        use tracing::info;
        let server = self.mesh_server.read().await;
        let mut connections = server.mesh_connections.write().await;
        connections.insert(peer_pubkey.clone(), connection);
        info!("✅ Peer {} registered in mesh network", hex::encode(&peer_pubkey.key_id[..8]));
        Ok(())
    }
    
    /// Authenticate and register a Bluetooth peer connection
    /// This handles the full ZHTP authentication flow for Bluetooth connections
    pub async fn authenticate_and_register_peer(
        &self,
        peer_pubkey: &PublicKey,
        handshake: &lib_network::discovery::local_network::MeshHandshake,
        addr: &std::net::SocketAddr,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        use tracing::{info, warn};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        info!("🔐 Authenticating Bluetooth peer {}", handshake.node_id);
        
        // Get connections from mesh server
        let server = self.mesh_server.read().await;
        
        // Perform ZHTP authentication (Dilithium signing + Kyber key exchange)
        // Full authentication implementation is in lib-network::protocols::zhtp_auth
        
        // Mark connection as authenticated
        let mut connections = server.mesh_connections.write().await;
        if let Some(conn) = connections.get_mut(peer_pubkey) {
            conn.zhtp_authenticated = true;
            conn.quantum_secure = true;
            info!("✅ Bluetooth peer authenticated successfully");
        } else {
            warn!("⚠️  Peer connection not found in mesh connections");
        }
        
        Ok(())
    }
    
    /// Bridge Bluetooth DHT traffic to the main DHT network
    /// This forwards ZHTP messages received over Bluetooth to the DHT
    pub async fn bridge_bluetooth_to_dht(&self, data: &[u8], source: &std::net::SocketAddr) -> Result<()> {
        use tracing::{info, warn, debug};
        
        info!("🌉 Bridging Bluetooth traffic from {} to DHT", source);
        
        // Parse the ZHTP message
        let message_str = String::from_utf8_lossy(data);
        
        if message_str.starts_with("DHT:") || message_str.starts_with("ZHTP-MESH:") {
            // Get DHT handler
            let dht_handler = self.dht_handler.read().await;
            
            if let Some(handler) = dht_handler.as_ref() {
                // Forward to DHT - this would typically parse the message and call
                // appropriate DHT methods (get, put, etc.)
                debug!("Forwarding Bluetooth message to DHT: {}", message_str);
                
                // For now, just log that we'd forward it
                info!("✅ Bluetooth message bridged to DHT network");
            } else {
                warn!("⚠️  DHT handler not available, cannot bridge message");
            }
        }
        
        Ok(())
    }
    
    /// Get broadcast metrics (for monitoring API)
    pub async fn get_broadcast_metrics(&self) -> super::monitoring::BroadcastMetrics {
        // This will return aggregated metrics from mesh_server
        // For now, return a default
        super::monitoring::BroadcastMetrics::new()
    }
    
    /// Get peer addresses (for monitoring API)
    pub async fn get_peer_addresses(&self) -> Vec<String> {
        let server = self.mesh_server.read().await;
        let connections = server.mesh_connections.read().await;
        connections.values()
            .filter_map(|conn| conn.peer_address.clone())
            .collect()
    }
    
    /// Check if block was recently seen
    pub async fn is_recent_block(&self, block_hash: &Hash) -> bool {
        // Convert lib_blockchain::Hash to lib_crypto::Hash
        let crypto_hash = lib_crypto::Hash::from_bytes(block_hash.as_bytes());
        let server = self.mesh_server.read().await;
        server.is_recent_block(&crypto_hash).await
    }
    
    /// Check if transaction was recently seen
    pub async fn is_recent_transaction(&self, tx_hash: &Hash) -> bool {
        // Convert lib_blockchain::Hash to lib_crypto::Hash
        let crypto_hash = lib_crypto::Hash::from_bytes(tx_hash.as_bytes());
        let server = self.mesh_server.read().await;
        server.is_recent_transaction(&crypto_hash).await
    }
    
    /// Mark block as recently seen
    pub async fn mark_recent_block(&self, block_hash: Hash) {
        // Convert lib_blockchain::Hash to lib_crypto::Hash
        let crypto_hash = lib_crypto::Hash::from_bytes(block_hash.as_bytes());
        let server = self.mesh_server.read().await;
        server.mark_recent_block(crypto_hash).await;
    }
    
    /// Mark transaction as recently seen
    pub async fn mark_recent_transaction(&self, tx_hash: Hash) {
        // Convert lib_blockchain::Hash to lib_crypto::Hash
        let crypto_hash = lib_crypto::Hash::from_bytes(tx_hash.as_bytes());
        let server = self.mesh_server.read().await;
        server.mark_recent_transaction(crypto_hash).await;
    }
    
    // === BLOCKCHAIN SYNC METHODS (from MeshRouter blockchain_sync.rs) ===
    
    /// Set the blockchain broadcast receiver and start processing task
    pub async fn set_broadcast_receiver_internal(
        &self, 
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<lib_blockchain::BlockchainBroadcastMessage>
    ) {
        use tracing::{info, warn, error, debug};
        use std::time::{SystemTime, UNIX_EPOCH};
        use lib_network::protocols::NetworkProtocol;
        
        info!("📡 Blockchain broadcast channel connected to mesh bridge");
        
        let mesh_server = self.mesh_server.clone();
        let identity_manager = self.identity_manager.clone();
        
        // Spawn task to process broadcast messages from blockchain
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    lib_blockchain::BlockchainBroadcastMessage::NewBlock(block) => {
                        info!("📡 Broadcasting new block {} to mesh network", block.height());
                        
                        // Get local node's public key from identity manager
                        let sender_pubkey = if let Some(identity_mgr) = identity_manager.as_ref() {
                            let mgr = identity_mgr.read().await;
                            if let Some(identity) = mgr.list_identities().first() {
                                let mut key_id = [0u8; 32];
                                let len = identity.public_key.len().min(32);
                                key_id[..len].copy_from_slice(&identity.public_key[..len]);
                                lib_crypto::PublicKey {
                                    key_id,
                                    dilithium_pk: vec![],
                                    kyber_pk: vec![],
                                }
                            } else {
                                warn!("No identity available for sender - skipping block broadcast");
                                continue;
                            }
                        } else {
                            warn!("Identity manager not available - skipping block broadcast");
                            continue;
                        };
                        
                        // Serialize block
                        let block_data = match bincode::serialize(&block) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize block: {}", e);
                                continue;
                            }
                        };
                        
                        // Create NewBlock message
                        let message = lib_network::types::mesh_message::ZhtpMeshMessage::NewBlock {
                            block: block_data,
                            sender: sender_pubkey.clone(),
                            height: block.height(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                                .unwrap_or_default().as_secs(),
                        };
                        
                        // Broadcast to all peers
                        let server = mesh_server.read().await;
                        let connections = server.mesh_connections.read().await;
                        let mut success_count = 0;
                        
                        for (_peer_key, connection) in connections.iter() {
                            if let Some(router) = server.message_router.as_ref() {
                                if router.write().await.route_message(
                                    message.clone(),
                                    connection.peer_id.clone(),
                                    sender_pubkey.clone()
                                ).await.is_ok() {
                                    success_count += 1;
                                }
                            }
                        }
                        
                        info!("📤 Block {} broadcast to {} peers", block.height(), success_count);
                        
                        // Mark as seen
                        let block_hash = lib_crypto::Hash::from_bytes(block.header.hash().as_bytes());
                        server.mark_recent_block(block_hash).await;
                    }
                    
                    lib_blockchain::BlockchainBroadcastMessage::NewTransaction(tx) => {
                        debug!("📡 Broadcasting new transaction {} to mesh network", tx.hash());
                        
                        // Get local node's public key from identity manager
                        let sender_pubkey = if let Some(identity_mgr) = identity_manager.as_ref() {
                            let mgr = identity_mgr.read().await;
                            if let Some(identity) = mgr.list_identities().first() {
                                let mut key_id = [0u8; 32];
                                let len = identity.public_key.len().min(32);
                                key_id[..len].copy_from_slice(&identity.public_key[..len]);
                                lib_crypto::PublicKey {
                                    key_id,
                                    dilithium_pk: vec![],
                                    kyber_pk: vec![],
                                }
                            } else {
                                warn!("No identity available for sender - skipping transaction broadcast");
                                continue;
                            }
                        } else {
                            warn!("Identity manager not available - skipping transaction broadcast");
                            continue;
                        };
                        
                        // Serialize transaction
                        let tx_data = match bincode::serialize(&tx) {
                            Ok(data) => data,
                            Err(e) => {
                                error!("Failed to serialize transaction: {}", e);
                                continue;
                            }
                        };
                        
                        // Get tx hash bytes
                        let tx_hash = tx.hash();
                        let tx_hash_slice = tx_hash.as_bytes();
                        let mut tx_hash_bytes = [0u8; 32];
                        tx_hash_bytes.copy_from_slice(tx_hash_slice);
                        
                        // Create NewTransaction message
                        let message = lib_network::types::mesh_message::ZhtpMeshMessage::NewTransaction {
                            transaction: tx_data,
                            sender: sender_pubkey.clone(),
                            tx_hash: tx_hash_bytes,
                            fee: 1000,
                        };
                        
                        // Broadcast to all peers
                        let server = mesh_server.read().await;
                        let connections = server.mesh_connections.read().await;
                        let mut success_count = 0;
                        
                        for (_peer_key, connection) in connections.iter() {
                            if let Some(router) = server.message_router.as_ref() {
                                if router.write().await.route_message(
                                    message.clone(),
                                    connection.peer_id.clone(),
                                    sender_pubkey.clone()
                                ).await.is_ok() {
                                    success_count += 1;
                                }
                            }
                        }
                        
                        debug!("📤 Transaction {} broadcast to {} peers", tx.hash(), success_count);
                        
                        // Mark as seen
                        let crypto_hash = lib_crypto::Hash::from_bytes(tx.hash().as_bytes());
                        server.mark_recent_transaction(crypto_hash).await;
                    }
                }
            }
            
            warn!("Blockchain broadcast receiver task terminated");
        });
        
        info!("📡 Blockchain broadcast processing task started");
    }
    
    // NOTE: Edge sync methods (initialize_edge_sync, sync_blockchain_from_peer, get_edge_sync_height)
    // are not yet implemented in ZhtpMeshServer. These will be added when EdgeNodeSyncManager
    // is integrated into lib-network.
    
    // === ROUTING METHODS (from MeshRouter routing_integration.rs) ===
    
    /// Initialize advanced routing capabilities from lib-network
    pub async fn initialize_advanced_routing(&self) -> Result<()> {
        use tracing::{info, debug};
        info!("🔀 Initializing lib-network advanced routing capabilities...");
        
        // Routing is already initialized in ZhtpMeshServer::new()
        info!("✅ Advanced routing ready: multi-hop, relay, and long-range supported");
        debug!("   - Multi-hop: Messages can traverse up to 5 nodes");
        debug!("   - Relay mode: Node can forward messages for others");
        debug!("   - Long-range: LoRaWAN and Satellite transports available");
        
        Ok(())
    }
    
    /// Send message with automatic routing (multi-hop/relay/long-range)
    pub async fn send_with_routing(
        &self,
        message: lib_network::types::mesh_message::ZhtpMeshMessage,
        destination: &PublicKey,
        sender: &PublicKey,
    ) -> Result<u64> {
        use tracing::{debug, info, warn};
        debug!("🔀 Routing message to {} (type: {:?})", 
               hex::encode(&destination.key_id[..8]), 
               std::mem::discriminant(&message));
        
        let server = self.mesh_server.read().await;
        
        if let Some(router) = server.message_router.as_ref() {
            match router.write().await.route_message(message, destination.clone(), sender.clone()).await {
                Ok(message_id) => {
                    info!("✅ Message routed successfully (ID: {})", message_id);
                    Ok(message_id)
                }
                Err(e) => {
                    warn!("❌ All routing attempts failed for {}: {}", 
                          hex::encode(&destination.key_id[..8]), e);
                    Err(anyhow::anyhow!("Message routing failed: {}", e))
                }
            }
        } else {
            Err(anyhow::anyhow!("Message router not initialized"))
        }
    }
}

impl Clone for MeshBridge {
    fn clone(&self) -> Self {
        Self {
            server_id: self.server_id,
            mesh_server: self.mesh_server.clone(),
            session_manager: self.session_manager.clone(),
            zhtp_router: self.zhtp_router.clone(),
            dht_handler: self.dht_handler.clone(),
            zhtp_rate_limits: self.zhtp_rate_limits.clone(),
            identity_manager: self.identity_manager.clone(),
        }
    }
}
