//! Protocol Detection Module
//!
//! Extracted from unified_server.rs (lines 53-67, 6938-7080)
//! 
//! Automatic protocol detection for incoming TCP/UDP connections:
//! - HTTP/1.1 REST API (GET, POST, etc.)
//! - ZHTP Mesh TCP (binary handshakes, text protocol)
//! - ZHTP Mesh UDP (bincode messages, JSON)
//! - WiFi Direct P2P
//! - Bluetooth (BLE/Classic)
//! - Bootstrap discovery

use tracing::debug;

/// Protocol detection for incoming connections
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingProtocol {
    /// HTTP/1.1 REST API requests
    HTTP,
    /// ZHTP mesh protocol over TCP
    ZhtpMeshTcp,
    /// ZHTP mesh protocol over UDP
    ZhtpMeshUdp,
    /// WiFi Direct device connections
    WiFiDirect,
    /// Bluetooth device connections
    Bluetooth,
    /// Network bootstrap connections
    Bootstrap,
    /// Unknown protocol
    Unknown,
}

impl IncomingProtocol {
    /// Detect protocol type from TCP stream data
    pub fn detect_tcp(buffer: &[u8]) -> Self {
        let data = String::from_utf8_lossy(buffer);
        
        // HTTP detection
        if data.starts_with("GET ") || data.starts_with("POST ") || 
           data.starts_with("PUT ") || data.starts_with("DELETE ") ||
           data.starts_with("OPTIONS ") || data.starts_with("HEAD ") {
            return IncomingProtocol::HTTP;
        }
        
        // ZHTP mesh detection (text protocol)
        if data.starts_with("ZHTP/1.0 MESH") {
            return IncomingProtocol::ZhtpMeshTcp;
        }
        
        // Binary mesh handshake detection (bincode format from local discovery)
        // Bincode handshakes contain version byte + node_id + public_key + protocols
        // With full cryptographic public keys, they can be 1000-2000 bytes
        if buffer.len() >= 20 && buffer.len() < 4096 {
            // Try to deserialize as MeshHandshake
            if let Ok(_handshake) = bincode::deserialize::<lib_network::discovery::local_network::MeshHandshake>(buffer) {
                return IncomingProtocol::ZhtpMeshTcp;
            }
        }
        
        // WiFi Direct detection
        if data.contains("WIFI-DIRECT") || data.contains("P2P-DEVICE") {
            return IncomingProtocol::WiFiDirect;
        }
        
        // Bluetooth detection (phone connections often include these markers)
        if data.contains("BLUETOOTH") || data.contains("BT-") || 
           data.contains("ZHTP-PHONE") || data.contains("RFCOMM") {
            return IncomingProtocol::Bluetooth;
        }
        
        // Default to bootstrap for unknown TCP connections
        IncomingProtocol::Bootstrap
    }
    
    /// Detect protocol type from UDP packet data
    pub fn detect_udp(data: &[u8]) -> Self {
        use lib_network::types::mesh_message::ZhtpMeshMessage;
        
        // Try to parse as bincode ZhtpMeshMessage first (PeerAnnouncement, NewBlock, etc.)
        if let Ok(_) = bincode::deserialize::<ZhtpMeshMessage>(data) {
            return IncomingProtocol::ZhtpMeshUdp;
        }
        
        // Try to parse as text second (bootstrap, JSON)
        if let Ok(text) = std::str::from_utf8(data) {
            // ZHTP mesh JSON detection
            if text.contains("\"ZhtpRequest\"") || text.contains("\"ZhtpResponse\"") {
                return IncomingProtocol::ZhtpMeshUdp;
            }
            
            // JSON structure indicates mesh protocol
            if text.trim().starts_with('{') && 
               (text.contains("\"requester\"") || text.contains("\"mesh\"")) {
                return IncomingProtocol::ZhtpMeshUdp;
            }
        }
        
        // Default to bootstrap for other UDP packets
        IncomingProtocol::Bootstrap
    }
    
    /// Check if protocol is mesh-related
    pub fn is_mesh(&self) -> bool {
        matches!(self, IncomingProtocol::ZhtpMeshTcp | IncomingProtocol::ZhtpMeshUdp)
    }
    
    /// Check if protocol is wireless
    pub fn is_wireless(&self) -> bool {
        matches!(self, IncomingProtocol::WiFiDirect | IncomingProtocol::Bluetooth)
    }
    
    /// Get protocol name for logging
    pub fn name(&self) -> &'static str {
        match self {
            IncomingProtocol::HTTP => "HTTP/1.1",
            IncomingProtocol::ZhtpMeshTcp => "ZHTP Mesh (TCP)",
            IncomingProtocol::ZhtpMeshUdp => "ZHTP Mesh (UDP)",
            IncomingProtocol::WiFiDirect => "WiFi Direct",
            IncomingProtocol::Bluetooth => "Bluetooth",
            IncomingProtocol::Bootstrap => "Bootstrap",
            IncomingProtocol::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection() {
        let buffer = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(IncomingProtocol::detect_tcp(buffer), IncomingProtocol::HTTP);
        
        let buffer = b"POST /api HTTP/1.1\r\n";
        assert_eq!(IncomingProtocol::detect_tcp(buffer), IncomingProtocol::HTTP);
    }
    
    #[test]
    fn test_mesh_detection() {
        let buffer = b"ZHTP/1.0 MESH ANNOUNCE";
        assert_eq!(IncomingProtocol::detect_tcp(buffer), IncomingProtocol::ZhtpMeshTcp);
    }
    
    #[test]
    fn test_protocol_helpers() {
        assert!(IncomingProtocol::ZhtpMeshTcp.is_mesh());
        assert!(IncomingProtocol::ZhtpMeshUdp.is_mesh());
        assert!(!IncomingProtocol::HTTP.is_mesh());
        
        assert!(IncomingProtocol::WiFiDirect.is_wireless());
        assert!(IncomingProtocol::Bluetooth.is_wireless());
        assert!(!IncomingProtocol::HTTP.is_wireless());
    }
}
