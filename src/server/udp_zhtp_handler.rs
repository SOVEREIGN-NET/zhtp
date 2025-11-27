
//! UDP ZHTP Listener - Simplified ZHTP protocol over UDP for testing
//!
//! This module provides a UDP-based listener for ZHTP requests, useful for
//! testing clients that don't have full QUIC support yet.

use std::sync::Arc;
use anyhow::{Result, Context};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use super::zhtp::ZhtpRouter;
use super::zhtp::serialization::{deserialize_request, serialize_response, ZHTP_MAGIC, ZHTP_VERSION};

/// UDP ZHTP handler
pub struct UdpZhtpHandler {
    /// ZHTP router
    zhtp_router: Arc<ZhtpRouter>,
}

impl UdpZhtpHandler {
    /// Create new UDP ZHTP handler
    pub fn new(zhtp_router: Arc<ZhtpRouter>) -> Self {
        Self {
            zhtp_router,
        }
    }
    
    /// Start listening for UDP ZHTP messages
    pub async fn listen(&self, bind_addr: &str) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await
            .context("Failed to bind UDP socket")?);
        
        info!("📡 UDP ZHTP listener started on {}", bind_addr);
        info!("   Expecting ZHTP protocol: Magic=ZHTP, Version=1, Format=bincode");
        
        let mut buf = vec![0u8; 65536]; // Max UDP packet size
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    info!("📨 Received {} bytes from {}", len, peer_addr);
                    
                    // Log first few bytes for debugging
                    if len >= 9 {
                        let magic = &buf[..4];
                        let version = buf[4];
                        let msg_len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
                        info!("   Magic: {:?} (expected: {:?})", 
                              String::from_utf8_lossy(magic), "ZHTP");
                        info!("   Version: {} (expected: {})", version, ZHTP_VERSION);
                        info!("   Declared message length: {} bytes", msg_len);
                        info!("   Total packet size: {} bytes", len);
                    } else {
                        warn!("   ⚠️ Packet too small: {} bytes (minimum 9 required)", len);
                    }
                    
                    let data = buf[..len].to_vec();
                    let router = self.zhtp_router.clone();
                    let response_socket = Arc::clone(&socket);
                    
                    // Process request in separate task
                    tokio::spawn(async move {
                        match Self::handle_request(&data, router).await {
                            Ok(response_data) => {
                                info!("✅ Successfully processed request from {}", peer_addr);
                                info!("   Response size: {} bytes", response_data.len());
                                if let Err(e) = response_socket.send_to(&response_data, peer_addr).await {
                                    error!("❌ Failed to send UDP response to {}: {}", peer_addr, e);
                                } else {
                                    info!("✅ Response sent to {}", peer_addr);
                                }
                            }
                            Err(e) => {
                                error!("❌ Failed to process UDP ZHTP request from {}: {}", peer_addr, e);
                                error!("   Error details: {:?}", e);
                                
                                // Send error response
                                if let Ok(error_response) = Self::create_error_response(&e) {
                                    if let Err(send_err) = response_socket.send_to(&error_response, peer_addr).await {
                                        error!("❌ Failed to send error response: {}", send_err);
                                    } else {
                                        info!("📤 Sent error response to {}", peer_addr);
                                    }
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("❌ UDP receive error: {}", e);
                }
            }
        }
    }
    
    /// Handle a single ZHTP request
    async fn handle_request(data: &[u8], router: Arc<ZhtpRouter>) -> Result<Vec<u8>> {
        info!("🔍 Starting request validation...");
        
        // Validate minimum size
        if data.len() < 9 {
            let msg = format!("Message too short: {} bytes (minimum 9 required)", data.len());
            error!("❌ Validation failed: {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
        info!("   ✓ Size validation passed: {} bytes", data.len());
        
        // Validate magic bytes
        let magic = &data[0..4];
        if magic != ZHTP_MAGIC {
            let msg = format!("Invalid ZHTP magic bytes. Expected {:?}, got {:?} (hex: {:02x?})", 
                            String::from_utf8_lossy(ZHTP_MAGIC),
                            String::from_utf8_lossy(magic),
                            magic);
            error!("❌ {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
        info!("   ✓ Magic bytes validated: ZHTP");
        
        // Validate version
        let version = data[4];
        if version != ZHTP_VERSION {
            let msg = format!("Unsupported ZHTP version: {} (expected {})", version, ZHTP_VERSION);
            error!("❌ {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
        info!("   ✓ Version validated: {}", version);
        
        // Get declared message length
        let declared_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        info!("   Declared message length: {} bytes", declared_len);
        info!("   Actual payload size: {} bytes", data.len() - 9);
        
        if data.len() < 9 + declared_len {
            let msg = format!("Incomplete message: declared {} bytes, but only {} bytes available",
                            declared_len, data.len() - 9);
            error!("❌ {}", msg);
            return Err(anyhow::anyhow!(msg));
        }
        
        // Deserialize request - try bincode first, fall back to JSON for JavaScript clients
        // Track which format was used to respond in the same format
        info!("🔄 Deserializing request...");
        let (request, use_json) = match deserialize_request(data) {
            Ok(req) => {
                info!("   ✓ Request deserialized successfully (bincode)");
                info!("   Method: {:?}", req.method);
                info!("   URI: {}", req.uri);
                info!("   Body size: {} bytes", req.body.len());
                (req, false)
            }
            Err(bincode_err) => {
                // Try JSON deserialization for JavaScript/testing clients
                info!("   Bincode failed, trying JSON deserialization...");
                let payload = &data[9..9 + declared_len];
                match serde_json::from_slice::<lib_protocols::types::ZhtpRequest>(payload) {
                    Ok(req) => {
                        info!("   ✓ Request deserialized successfully (JSON)");
                        info!("   Method: {:?}", req.method);
                        info!("   URI: {}", req.uri);
                        info!("   Body size: {} bytes", req.body.len());
                        (req, true)
                    }
                    Err(json_err) => {
                        error!("❌ Failed to deserialize ZHTP request with both bincode and JSON");
                        error!("   Bincode error: {}", bincode_err);
                        error!("   JSON error: {}", json_err);
                        error!("   Payload (first 100 bytes): {:02x?}", &data[9..std::cmp::min(109, data.len())]);
                        error!("   Payload (as string): {}", String::from_utf8_lossy(&data[9..std::cmp::min(109, data.len())]));
                        return Err(anyhow::anyhow!("Failed to deserialize request: tried bincode and JSON"));
                    }
                }
            }
        };
        
        // Route request
        info!("🔀 Routing request: {} {}", request.method, request.uri);
        let response = match router.route_request(request).await {
            Ok(resp) => {
                info!("   ✓ Request routed successfully");
                info!("   Response status: {:?}", resp.status);
                info!("   Response body size: {} bytes", resp.body.len());
                resp
            }
            Err(e) => {
                error!("❌ Routing failed: {}", e);
                return Err(e);
            }
        };
        
        // Serialize response using same format as request
        info!("📦 Serializing response...");
        let response_data = if use_json {
            // JSON response for JSON clients
            let payload = serde_json::to_vec(&response)
                .map_err(|e| anyhow::anyhow!("Failed to serialize response as JSON: {}", e))?;
            
            let mut message = Vec::with_capacity(9 + payload.len());
            message.extend_from_slice(b"ZHTP");
            message.push(1);
            message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            message.extend_from_slice(&payload);
            
            info!("   ✓ Response serialized as JSON: {} bytes", message.len());
            message
        } else {
            // Bincode response for Rust clients
            match serialize_response(&response) {
                Ok(data) => {
                    info!("   ✓ Response serialized as bincode: {} bytes", data.len());
                    data
                }
                Err(e) => {
                    error!("❌ Failed to serialize response: {}", e);
                    return Err(e);
                }
            }
        };
        
        Ok(response_data)
    }
    
    /// Create an error response
    fn create_error_response(error: &anyhow::Error) -> Result<Vec<u8>> {
        let error_msg = format!("{{\"error\": \"{}\"}}", error);
        let response = lib_protocols::ZhtpResponse::bad_request(error_msg);
        serialize_response(&response)
    }
}

