//! Edge Node Runtime
//! 
//! Lightweight runtime for edge nodes that only sync headers
//! and route mesh traffic. No consensus, no smart contracts, no hosted storage.
//!
//! Edge nodes MUST discover an existing network - they cannot create genesis.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::config::NodeConfig;
use crate::runtime::RuntimeOrchestrator;

pub struct EdgeRuntime {
    orchestrator: RuntimeOrchestrator,
    max_headers: usize,
}

impl EdgeRuntime {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Enforce edge node constraints at compile-time (via features)
        let mut edge_config = config;
        edge_config.blockchain_config.smart_contracts = false;
        edge_config.consensus_config.validator_enabled = false;
        edge_config.storage_config.hosted_storage_gb = 0;
        
        let orchestrator = RuntimeOrchestrator::new(edge_config).await?;
        
        Ok(Self {
            orchestrator,
            max_headers: 500, // ~100 KB
        })
    }
    
    pub async fn start(&mut self) -> Result<()> {
        info!("🌐 Starting Edge Node runtime");
        info!("   Max headers: {} (~{} KB)", self.max_headers, self.max_headers / 5);
        info!("   Consensus: ❌ disabled");
        info!("   Smart contracts: ❌ disabled");
        info!("   Hosted storage: ❌ disabled");
        info!("   Genesis creation: ❌ disabled (must find existing network)");
        
        // Edge nodes use EdgeNodeState (header-only) instead of full Blockchain
        // This is enforced at the RuntimeOrchestrator level
        
        // Start minimal components for edge nodes:
        // - Crypto (foundation)
        // - Identity (wallet + DID)
        // - Network (mesh routing)
        // - Blockchain (header sync only via EdgeNodeState)
        
        // Edge nodes MUST discover and join existing network
        // This will loop forever until a network is found
        self.discover_and_join_network().await?;
        
        // Once network is found, start all components
        self.orchestrator.start_all_components().await?;
        
        Ok(())
    }
    
    async fn discover_and_join_network(&mut self) -> Result<()> {
        // Edge nodes MUST find existing network - they cannot create genesis
        // Pass is_edge_node=true for infinite retry loop
        match self.orchestrator.discover_network_with_retry(true).await? {
            Some(network_info) => {
                info!("✅ Successfully joined ZHTP network");
                info!("   Network peers: {}", network_info.peer_count);
                info!("   Blockchain height: {}", network_info.blockchain_height);
                Ok(())
            }
            None => {
                // This should never happen for edge nodes (infinite loop)
                Err(anyhow::anyhow!("Edge node discovery unexpectedly returned None"))
            }
        }
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("🛑 Stopping Edge Node runtime");
        self.orchestrator.shutdown_all_components().await?;
        Ok(())
    }
}
