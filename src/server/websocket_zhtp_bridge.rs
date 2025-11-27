//! WebSocket ZHTP Bridge - ZHTP protocol over WebSocket for browsers
//!
//! Provides browser connectivity by transporting ZHTP messages over WebSocket.
//! The ZHTP protocol remains unchanged - WebSocket is just the transport layer.

use std::sync::Arc;
use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use futures_util::stream::{StreamExt, SplitSink, SplitStream};
use futures_util::sink::SinkExt;
use tracing::{info, warn, error, debug};

use super::zhtp::ZhtpRouter;
use super::zhtp::serialization::{deserialize_request, serialize_response};

/// WebSocket ZHTP bridge
pub struct WebSocketZhtpBridge {
    /// ZHTP router
    router: Arc<ZhtpRouter>,
}

impl WebSocketZhtpBridge {
    /// Create new WebSocket ZHTP bridge
    pub fn new(router: Arc<ZhtpRouter>) -> Self {
        Self {
            router,
        }
    }
    
    /// Start WebSocket server
    pub async fn listen(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await
            .context(format!("Failed to bind WebSocket server to {}", bind_addr))?;
        
        info!("🌐 WebSocket ZHTP bridge started on {}", bind_addr);
        info!("   → Browser clients can connect via ws://{}", bind_addr);
        
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("📱 WebSocket connection from {}", peer_addr);
                    
                    let router = self.router.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, router).await {
                            warn!("⚠️ WebSocket connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("⚠️ Failed to accept WebSocket connection: {}", e);
                }
            }
        }
    }
    
    /// Handle a single WebSocket connection
    async fn handle_connection(
        stream: TcpStream,
        router: Arc<ZhtpRouter>,
    ) -> Result<()> {
        // Upgrade to WebSocket
        let ws_stream = accept_async(stream).await
            .context("WebSocket handshake failed")?;
        
        debug!("✅ WebSocket connection established");
        
        let (write, read) = ws_stream.split();
        let mut write: SplitSink<WebSocketStream<TcpStream>, Message> = write;
        let mut read: SplitStream<WebSocketStream<TcpStream>> = read;
        
        // Process messages
        while let Some(msg_result) = read.next().await {
            match msg_result {
                Ok(Message::Binary(data)) => {
                    debug!("📨 Received ZHTP message ({} bytes)", data.len());
                    
                    // Deserialize ZHTP request
                    match deserialize_request(&data) {
                        Ok(request) => {
                            debug!("📥 Processing {} {}", request.method, request.uri);
                            
                            // Route request
                            match router.route_request(request).await {
                                Ok(response) => {
                                    debug!("📤 Sending response: {:?}", response.status);
                                    
                                    // Serialize and send response
                                    match serialize_response(&response) {
                                        Ok(response_data) => {
                                            if let Err(e) = write.send(Message::Binary(response_data)).await {
                                                error!("❌ Failed to send response: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ Failed to serialize response: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("❌ Failed to route request: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ Failed to deserialize ZHTP request: {}", e);
                        }
                    }
                }
                Ok(Message::Text(text)) => {
                    warn!("⚠️ Received text message (expected binary ZHTP): {}", 
                        &text[..text.len().min(100)]);
                }
                Ok(Message::Ping(data)) => {
                    if let Err(e) = write.send(Message::Pong(data)).await {
                        error!("❌ Failed to send pong: {}", e);
                        break;
                    }
                }
                Ok(Message::Pong(_)) => {
                    // Ignore pongs
                }
                Ok(Message::Close(_)) => {
                    debug!("🔒 WebSocket closed by client");
                    break;
                }
                Ok(Message::Frame(_)) => {
                    // Ignore raw frames
                }
                Err(e) => {
                    warn!("⚠️ WebSocket read error: {}", e);
                    break;
                }
            }
        }
        
        debug!("👋 WebSocket connection closed");
        Ok(())
    }
}
