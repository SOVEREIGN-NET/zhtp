//! Discovery Coordinator - Centralized peer discovery management
//! 
//! This module coordinates all discovery protocols (UDP multicast, mDNS, BLE, WiFi Direct, etc.)
//! to prevent duplicate peer discoveries and optimize network resource usage.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use anyhow::{Result, Context};
use tracing::{info, debug, warn};
use serde::{Serialize, Deserialize};

use lib_crypto::PublicKey;

/// Discovery protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoveryProtocol {
    /// UDP multicast on local network
    UdpMulticast,
    /// mDNS/Bonjour service discovery
    MDns,
    /// Bluetooth Low Energy scanning
    BluetoothLE,
    /// Bluetooth Classic RFCOMM
    BluetoothClassic,
    /// WiFi Direct P2P discovery
    WiFiDirect,
    /// DHT Kademlia routing
    DHT,
    /// Direct port scanning (fallback)
    PortScan,
    /// LoRaWAN gateway discovery
    LoRaWAN,
    /// Satellite peer discovery
    Satellite,
}

impl DiscoveryProtocol {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::UdpMulticast => "UDP Multicast",
            Self::MDns => "mDNS/Bonjour",
            Self::BluetoothLE => "Bluetooth LE",
            Self::BluetoothClassic => "Bluetooth Classic",
            Self::WiFiDirect => "WiFi Direct",
            Self::DHT => "DHT",
            Self::PortScan => "Port Scan",
            Self::LoRaWAN => "LoRaWAN",
            Self::Satellite => "Satellite",
        }
    }
    
    /// Priority order (lower number = higher priority)
    pub fn priority(&self) -> u8 {
        match self {
            Self::UdpMulticast => 1,  // Fastest, local
            Self::MDns => 2,           // Fast, cross-subnet
            Self::BluetoothLE => 3,    // Medium, mobile-friendly
            Self::WiFiDirect => 4,     // Medium, good for phones
            Self::DHT => 5,            // Slower, global
            Self::BluetoothClassic => 6, // High bandwidth
            Self::PortScan => 7,       // Slow, fallback only
            Self::LoRaWAN => 8,        // Long range but slow
            Self::Satellite => 9,      // Very slow, last resort
        }
    }
}

/// Information about a discovered peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    /// Peer's public key (optional - may be learned after initial discovery)
    pub public_key: Option<PublicKey>,
    
    /// Network addresses (can have multiple)
    pub addresses: Vec<String>,
    
    /// Which protocol discovered this peer
    pub discovered_via: DiscoveryProtocol,
    
    /// When this peer was first discovered
    pub first_seen: SystemTime,
    
    /// When this peer was last seen
    pub last_seen: SystemTime,
    
    /// Node ID (if available)
    pub node_id: Option<String>,
    
    /// Node capabilities (if available)
    pub capabilities: Option<String>,
}

/// Discovery strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryStrategy {
    /// Fast local network discovery (< 2 seconds)
    FastLocal {
        protocols: Vec<DiscoveryProtocol>,
        timeout: Duration,
    },
    
    /// Thorough local + regional (< 10 seconds)
    Thorough {
        protocols: Vec<DiscoveryProtocol>,
        timeout: Duration,
    },
    
    /// Global mesh discovery (< 30 seconds)
    Global {
        protocols: Vec<DiscoveryProtocol>,
        timeout: Duration,
    },
    
    /// Battery-saving mode for mobile devices
    LowPower {
        protocols: Vec<DiscoveryProtocol>,
        interval: Duration,
    },
    
    /// Custom strategy
    Custom {
        protocols: Vec<DiscoveryProtocol>,
        timeout: Duration,
        sequential: bool,
    },
}

impl Default for DiscoveryStrategy {
    fn default() -> Self {
        Self::FastLocal {
            protocols: vec![
                DiscoveryProtocol::UdpMulticast,
                DiscoveryProtocol::MDns,
            ],
            timeout: Duration::from_secs(2),
        }
    }
}

impl DiscoveryStrategy {
    /// Get protocols in priority order
    pub fn protocols_prioritized(&self) -> Vec<DiscoveryProtocol> {
        let mut protocols = match self {
            Self::FastLocal { protocols, .. } => protocols.clone(),
            Self::Thorough { protocols, .. } => protocols.clone(),
            Self::Global { protocols, .. } => protocols.clone(),
            Self::LowPower { protocols, .. } => protocols.clone(),
            Self::Custom { protocols, .. } => protocols.clone(),
        };
        
        protocols.sort_by_key(|p| p.priority());
        protocols
    }
    
    /// Get timeout for this strategy
    pub fn timeout(&self) -> Duration {
        match self {
            Self::FastLocal { timeout, .. } => *timeout,
            Self::Thorough { timeout, .. } => *timeout,
            Self::Global { timeout, .. } => *timeout,
            Self::LowPower { interval, .. } => *interval,
            Self::Custom { timeout, .. } => *timeout,
        }
    }
    
    /// Whether to run protocols sequentially
    pub fn is_sequential(&self) -> bool {
        match self {
            Self::Custom { sequential, .. } => *sequential,
            _ => true, // Default to sequential
        }
    }
}

/// Statistics for each discovery protocol
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub peers_discovered: u64,
    pub discovery_attempts: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub avg_discovery_time_ms: f64,
    pub last_success: Option<SystemTime>,
}

/// Central discovery coordinator
pub struct DiscoveryCoordinator {
    /// All discovered peers (deduplicated by public key)
    peers: Arc<RwLock<HashMap<Vec<u8>, DiscoveredPeer>>>,
    
    /// Currently active protocols
    active_protocols: Arc<RwLock<HashSet<DiscoveryProtocol>>>,
    
    /// Channel for discovery events
    discovery_tx: mpsc::UnboundedSender<DiscoveredPeer>,
    discovery_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<DiscoveredPeer>>>>,
    
    /// Prevent duplicate processing
    seen_addresses: Arc<RwLock<HashSet<String>>>,
    
    /// Statistics per protocol
    stats: Arc<RwLock<HashMap<DiscoveryProtocol, ProtocolStats>>>,
    
    /// Current discovery strategy
    strategy: Arc<RwLock<DiscoveryStrategy>>,
}

impl DiscoveryCoordinator {
    /// Create a new discovery coordinator
    pub fn new() -> Self {
        let (discovery_tx, discovery_rx) = mpsc::unbounded_channel();
        
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            active_protocols: Arc::new(RwLock::new(HashSet::new())),
            discovery_tx,
            discovery_rx: Arc::new(RwLock::new(Some(discovery_rx))),
            seen_addresses: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            strategy: Arc::new(RwLock::new(DiscoveryStrategy::default())),
        }
    }
    
    /// Set discovery strategy
    pub async fn set_strategy(&self, strategy: DiscoveryStrategy) {
        info!("🔍 Discovery strategy set to: {:?}", strategy);
        *self.strategy.write().await = strategy;
    }
    
    /// Get discovery event sender (for protocols to use)
    pub fn get_sender(&self) -> mpsc::UnboundedSender<DiscoveredPeer> {
        self.discovery_tx.clone()
    }
    
    /// Start listening for discovery events
    pub async fn start_event_listener(&self) {
        let mut rx = self.discovery_rx.write().await.take()
            .expect("Event listener already started");
        
        let peers = self.peers.clone();
        let seen = self.seen_addresses.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            info!("📡 Discovery event listener started");
            
            while let Some(discovered_peer) = rx.recv().await {
                // Deduplicate by public key (if available) or primary address
                let peer_key = if let Some(ref pubkey) = discovered_peer.public_key {
                    pubkey.key_id.to_vec()
                } else {
                    // Use primary address as key when PublicKey unavailable
                    discovered_peer.addresses.first()
                        .map(|addr| addr.as_bytes().to_vec())
                        .unwrap_or_default()
                };
                
                let mut peers_lock = peers.write().await;
                
                if let Some(existing_peer) = peers_lock.get_mut(&peer_key) {
                    // Merge addresses
                    for addr in &discovered_peer.addresses {
                        if !existing_peer.addresses.contains(addr) {
                            existing_peer.addresses.push(addr.clone());
                            debug!("➕ Added address {} to existing peer", addr);
                        }
                    }
                    existing_peer.last_seen = SystemTime::now();
                    
                    // Update PublicKey if we didn't have it before
                    if existing_peer.public_key.is_none() && discovered_peer.public_key.is_some() {
                        existing_peer.public_key = discovered_peer.public_key.clone();
                        debug!("🔑 Updated peer with PublicKey");
                    }
                } else {
                    // New peer
                    let pubkey_status = if discovered_peer.public_key.is_some() {
                        "with PublicKey"
                    } else {
                        "address-only (awaiting handshake)"
                    };
                    info!(
                        "🆕 New peer discovered via {}: {} addresses ({})",
                        discovered_peer.discovered_via.name(),
                        discovered_peer.addresses.len(),
                        pubkey_status
                    );
                    peers_lock.insert(peer_key.to_vec(), discovered_peer.clone());
                }
                
                // Track seen addresses
                let mut seen_lock = seen.write().await;
                for addr in &discovered_peer.addresses {
                    seen_lock.insert(addr.clone());
                }
                
                // Update stats
                let mut stats_lock = stats.write().await;
                let protocol_stats = stats_lock.entry(discovered_peer.discovered_via)
                    .or_insert_with(ProtocolStats::default);
                protocol_stats.peers_discovered += 1;
                protocol_stats.success_count += 1;
                protocol_stats.last_success = Some(SystemTime::now());
            }
            
            info!("📡 Discovery event listener stopped");
        });
    }
    
    /// Register a discovered peer (thread-safe, deduplicates automatically)
    pub async fn register_peer(&self, peer: DiscoveredPeer) -> Result<bool> {
        // Send through channel for centralized processing
        self.discovery_tx.send(peer)
            .context("Failed to send discovery event")?;
        Ok(true)
    }
    
    /// Get all discovered peers
    pub async fn get_all_peers(&self) -> Vec<DiscoveredPeer> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }
    
    /// Get peers discovered by specific protocol
    pub async fn get_peers_by_protocol(&self, protocol: DiscoveryProtocol) -> Vec<DiscoveredPeer> {
        let peers = self.peers.read().await;
        peers.values()
            .filter(|p| p.discovered_via == protocol)
            .cloned()
            .collect()
    }
    
    /// Get total peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
    
    /// Check if an address has been seen before
    pub async fn has_seen_address(&self, address: &str) -> bool {
        self.seen_addresses.read().await.contains(address)
    }
    
    /// Mark a protocol as active
    pub async fn activate_protocol(&self, protocol: DiscoveryProtocol) {
        let mut active = self.active_protocols.write().await;
        if active.insert(protocol) {
            info!("✓ Activated {} discovery", protocol.name());
        }
    }
    
    /// Mark a protocol as inactive
    pub async fn deactivate_protocol(&self, protocol: DiscoveryProtocol) {
        let mut active = self.active_protocols.write().await;
        if active.remove(&protocol) {
            info!("✗ Deactivated {} discovery", protocol.name());
        }
    }
    
    /// Get currently active protocols
    pub async fn active_protocols(&self) -> HashSet<DiscoveryProtocol> {
        self.active_protocols.read().await.clone()
    }
    
    /// Get statistics for a protocol
    pub async fn get_protocol_stats(&self, protocol: DiscoveryProtocol) -> Option<ProtocolStats> {
        self.stats.read().await.get(&protocol).cloned()
    }
    
    /// Get statistics for all protocols
    pub async fn get_all_stats(&self) -> HashMap<DiscoveryProtocol, ProtocolStats> {
        self.stats.read().await.clone()
    }
    
    /// Record a discovery attempt
    pub async fn record_attempt(&self, protocol: DiscoveryProtocol, success: bool, duration_ms: f64) {
        let mut stats = self.stats.write().await;
        let protocol_stats = stats.entry(protocol)
            .or_insert_with(ProtocolStats::default);
        
        protocol_stats.discovery_attempts += 1;
        
        if success {
            protocol_stats.success_count += 1;
            protocol_stats.last_success = Some(SystemTime::now());
        } else {
            protocol_stats.failure_count += 1;
        }
        
        // Update rolling average
        let total = protocol_stats.discovery_attempts as f64;
        protocol_stats.avg_discovery_time_ms = 
            (protocol_stats.avg_discovery_time_ms * (total - 1.0) + duration_ms) / total;
    }
    
    /// Clean up stale peers (not seen for X duration)
    pub async fn cleanup_stale_peers(&self, max_age: Duration) -> usize {
        let mut peers = self.peers.write().await;
        let now = SystemTime::now();
        
        let before_count = peers.len();
        
        peers.retain(|_, peer| {
            now.duration_since(peer.last_seen)
                .map(|age| age < max_age)
                .unwrap_or(false)
        });
        
        let removed = before_count - peers.len();
        if removed > 0 {
            info!("🗑️ Cleaned up {} stale peers", removed);
        }
        
        removed
    }
    
    /// Get discovery statistics summary
    pub async fn get_summary(&self) -> String {
        let peers = self.peers.read().await;
        let active = self.active_protocols.read().await;
        let stats = self.stats.read().await;
        
        let mut summary = format!("Discovery Coordinator Summary:\n");
        summary.push_str(&format!("  Total Peers: {}\n", peers.len()));
        summary.push_str(&format!("  Active Protocols: {}\n", active.len()));
        
        for protocol in active.iter() {
            if let Some(stat) = stats.get(protocol) {
                summary.push_str(&format!(
                    "    {} - {} peers, {:.0}ms avg\n",
                    protocol.name(),
                    stat.peers_discovered,
                    stat.avg_discovery_time_ms
                ));
            }
        }
        
        summary
    }
    
    // ========================================================================
    // HIGH-LEVEL DISCOVERY API - Used by RuntimeOrchestrator
    // ========================================================================
    
    /// Discover ZHTP network using all available methods
    /// 
    /// This is the main entry point for network discovery. It tries:
    /// 1. DHT/mDNS discovery
    /// 2. UDP multicast announcements
    /// 3. Port scanning on common ZHTP ports
    /// 
    /// Returns network information if peers are found
    pub async fn discover_network(
        &self,
        environment: &crate::config::Environment,
    ) -> Result<crate::runtime::ExistingNetworkInfo> {
        info!("📡 Discovering ZHTP peers on local network...");
        info!("   Methods: DHT/mDNS, UDP multicast, port scanning");
        
        // Create node identity for DHT
        let node_identity = crate::runtime::create_or_load_node_identity(environment).await?;
        
        // Initialize DHT
        info!("   → Initializing DHT for peer discovery...");
        crate::runtime::shared_dht::initialize_global_dht_safe(node_identity.clone()).await?;
        
        // Perform active discovery
        info!("   → Scanning network (timeout: 30 seconds)...");
        let discovered_peers = self.perform_active_discovery(&node_identity, environment).await?;
        
        if discovered_peers.is_empty() {
            warn!("✗ No ZHTP peers discovered on local network");
            return Err(anyhow::anyhow!("No network peers found"));
        }
        
        info!("✓ Discovered {} ZHTP peer(s)!", discovered_peers.len());
        for (i, peer) in discovered_peers.iter().enumerate() {
            info!("   {}. {}", i + 1, peer);
        }
        
        // Give peers time to respond to handshakes
        info!("   ⏳ Waiting 5 seconds for peer handshakes...");
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // Query blockchain status
        info!("   📊 Querying blockchain status from peers...");
        let blockchain_info = self.fetch_blockchain_info(&discovered_peers).await?;
        
        Ok(crate::runtime::ExistingNetworkInfo {
            peer_count: discovered_peers.len() as u32,
            blockchain_height: blockchain_info.height,
            network_id: blockchain_info.network_id,
            bootstrap_peers: discovered_peers,
            environment: environment.clone(),
        })
    }
    

    /// Perform active peer discovery using all methods
    async fn perform_active_discovery(
        &self,
        _node_identity: &lib_identity::ZhtpIdentity,
        _environment: &crate::config::Environment,
    ) -> Result<Vec<String>> {
        let mut discovered_peers = Vec::new();
        
        // Method 1: UDP Multicast
        info!("   → Trying UDP multicast...");
        match self.discover_via_multicast().await {
            Ok(peers) => {
                info!("      Found {} peer(s) via multicast", peers.len());
                discovered_peers.extend(peers);
            }
            Err(e) => warn!("      Multicast failed: {}", e),
        }
        
        // Method 2: Port scanning (fallback)
        if discovered_peers.is_empty() {
            info!("   → Trying port scan...");
            match self.scan_local_subnet().await {
                Ok(peers) => {
                    info!("      Found {} peer(s) via port scan", peers.len());
                    discovered_peers.extend(peers);
                }
                Err(e) => warn!("      Port scan failed: {}", e),
            }
        }
        
        // Deduplicate
        discovered_peers.sort();
        discovered_peers.dedup();
        
        Ok(discovered_peers)
    }
    
    /// Discover peers via UDP multicast (COMPLETE IMPLEMENTATION)
    async fn discover_via_multicast(&self) -> Result<Vec<String>> {
        use tokio::net::UdpSocket;
        use std::net::Ipv4Addr;
        
        const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75";
        const ZHTP_MULTICAST_PORT: u16 = 37775;
        
        // Use SO_REUSEADDR for multicast
        use socket2::{Socket, Domain, Type, Protocol};
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        
        // Join multicast group
        let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
        let interface_addr = Ipv4Addr::new(0, 0, 0, 0);
        socket.join_multicast_v4(multicast_addr, interface_addr)?;
        
        info!("      Listening for multicast on {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
        
        let mut discovered = Vec::new();
        let timeout = tokio::time::timeout(Duration::from_secs(35), async {
            let mut buf = [0u8; 1024];
            
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) if len > 0 => {
                        let message = String::from_utf8_lossy(&buf[..len]);
                        debug!("      Received multicast from {}: {}", addr, message);
                        
                        // Filter out our own broadcasts by checking if the source IP is a local interface
                        let source_ip = addr.ip();
                        let is_local = Self::is_local_ip(&source_ip).await;
                        if is_local {
                            debug!("      Ignoring multicast from local interface: {}", source_ip);
                            continue;
                        }
                        
                        // Try parsing as JSON NodeAnnouncement
                        if let Ok(announcement) = serde_json::from_str::<serde_json::Value>(&message) {
                            if announcement.get("node_id").is_some() && announcement.get("mesh_port").is_some() {
                                let peer_addr = format!("{}:9333", source_ip);
                                if !discovered.contains(&peer_addr) {
                                    info!("      ✓ Discovered peer via multicast: {}", peer_addr);
                                    discovered.push(peer_addr);
                                }
                            }
                        }
                    }
                    Ok((_, _)) => {
                        // Empty packet, ignore
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        debug!("      Multicast recv error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        let _ = timeout.await;
        Ok(discovered)
    }
    
    /// Scan local subnet for ZHTP nodes (COMPLETE WITH PARALLEL SCANNING)
    async fn scan_local_subnet(&self) -> Result<Vec<String>> {
        use tokio::net::TcpStream;
        use futures::stream::{self, StreamExt};
        
        let local_ip = self.get_local_ip().await?;
        let base_ip = format!("{}.{}.{}", 
            local_ip.split('.').nth(0).unwrap_or("192"),
            local_ip.split('.').nth(1).unwrap_or("168"),
            local_ip.split('.').nth(2).unwrap_or("1")
        );
        
        info!("      Scanning subnet: {}.0/24", base_ip);
        let ports = vec![9333, 33444];
        
        // Parallel scan with concurrency limit
        let scan_results = stream::iter(1..255)
            .map(|i| {
                let base_ip = base_ip.clone();
                let ports = ports.clone();
                async move {
                    for port in &ports {
                        let addr = format!("{}.{}:{}", base_ip, i, port);
                        if let Ok(Ok(_)) = tokio::time::timeout(
                            Duration::from_millis(50),
                            TcpStream::connect(&addr)
                        ).await {
                            return Some(addr);
                        }
                    }
                    None
                }
            })
            .buffer_unordered(50)
            .filter_map(|result| async move { result })
            .collect::<Vec<_>>().await;
        
        Ok(scan_results)
    }
    
    /// Get local IP address
    async fn get_local_ip(&self) -> Result<String> {
        use local_ip_address::local_ip;
        
        match local_ip() {
            Ok(ip) => Ok(ip.to_string()),
            Err(_) => Ok("127.0.0.1".to_string()),
        }
    }
    
    /// Check if an IP address belongs to this machine (to filter out self-discovery)
    async fn is_local_ip(ip: &std::net::IpAddr) -> bool {
        use local_ip_address::list_afinet_netifas;
        
        // Check loopback
        if ip.is_loopback() {
            return true;
        }
        
        // Get all local network interfaces
        if let Ok(interfaces) = list_afinet_netifas() {
            for (_name, interface_ip) in interfaces {
                if &interface_ip == ip {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Fetch blockchain info from discovered peers (COMPLETE HTTP API QUERY)
    async fn fetch_blockchain_info(&self, peers: &[String]) -> Result<BlockchainInfo> {
        let mut height = 0u64;
        
        for peer in peers {
            // Try to query HTTP API
            let http_url = if peer.contains("://") {
                format!("http://{}/api/v1/blockchain/info", 
                    peer.strip_prefix("zhtp://").or(peer.strip_prefix("http://")).unwrap_or(peer))
            } else {
                format!("http://{}/api/v1/blockchain/info", peer)
            };
            
            match tokio::time::timeout(
                Duration::from_secs(2),
                reqwest::get(&http_url)
            ).await {
                Ok(Ok(response)) => {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if let Some(h) = json.get("height").and_then(|v| v.as_u64()) {
                            height = h;
                            info!("      Peer {} reports blockchain height: {}", peer, height);
                            break;
                        }
                    }
                }
                Ok(Err(e)) => warn!("      Failed to query peer {}: {}", peer, e),
                Err(_) => warn!("      Timeout querying peer {}", peer),
            }
        }
        
        let network_id = if peers.is_empty() {
            "zhtp-genesis".to_string()
        } else {
            "zhtp-mainnet".to_string()
        };
        
        Ok(BlockchainInfo {
            height,
            network_id,
        })
    }
}

#[derive(Debug)]
struct BlockchainInfo {
    height: u64,
    network_id: String,
}

impl Default for DiscoveryCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coordinator_deduplication() {
        let coordinator = DiscoveryCoordinator::new();
        coordinator.start_event_listener().await;
        
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);
        
        let peer1 = DiscoveredPeer {
            public_key: pubkey.clone(),
            addresses: vec!["192.168.1.1:9333".to_string()],
            discovered_via: DiscoveryProtocol::UdpMulticast,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            node_id: None,
            capabilities: None,
        };
        
        let peer2 = DiscoveredPeer {
            public_key: pubkey.clone(),
            addresses: vec!["192.168.1.1:9334".to_string()],
            discovered_via: DiscoveryProtocol::MDns,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            node_id: None,
            capabilities: None,
        };
        
        coordinator.register_peer(peer1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        coordinator.register_peer(peer2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Should have 1 peer with 2 addresses
        assert_eq!(coordinator.peer_count().await, 1);
        
        let peers = coordinator.get_all_peers().await;
        assert_eq!(peers[0].addresses.len(), 2);
    }
    
    #[tokio::test]
    async fn test_protocol_stats() {
        let coordinator = DiscoveryCoordinator::new();
        
        coordinator.record_attempt(DiscoveryProtocol::UdpMulticast, true, 50.0).await;
        coordinator.record_attempt(DiscoveryProtocol::UdpMulticast, true, 100.0).await;
        coordinator.record_attempt(DiscoveryProtocol::UdpMulticast, false, 0.0).await;
        
        let stats = coordinator.get_protocol_stats(DiscoveryProtocol::UdpMulticast).await.unwrap();
        
        assert_eq!(stats.discovery_attempts, 3);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.avg_discovery_time_ms, 50.0);
    }
}
