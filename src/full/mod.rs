//! Full Node Runtime
//! 
//! Complete blockchain node with WASM smart contract execution
//! and hosted storage. No consensus participation.
//!
//! Full nodes CAN create genesis networks if no existing network is found.

use anyhow::Result;
use tracing::info;

use crate::config::NodeConfig;
use crate::runtime::RuntimeOrchestrator;

pub struct FullRuntime {
    orchestrator: RuntimeOrchestrator,
}

impl FullRuntime {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Enforce full node constraints at compile-time (via features)
        let mut full_config = config;
        full_config.blockchain_config.smart_contracts = true; // Enable WASM
        full_config.consensus_config.validator_enabled = false; // Not a validator
        
        // Warn about storage configuration
        if full_config.storage_config.hosted_storage_gb < 100 {
            info!("⚠️  Hosted storage < 100 GB - consider increasing to earn more rewards");
        }
        
        let orchestrator = RuntimeOrchestrator::new(full_config).await?;
        
        Ok(Self {
            orchestrator,
        })
    }
    
    pub async fn start(&mut self) -> Result<()> {
        info!("🏛️  Starting Full Node runtime");
        info!("   Full blockchain: ✅ enabled");
        info!("   Smart contracts: ✅ enabled (WASM)");
        info!("   Hosted storage: ✅ enabled");
        info!("   Consensus: ❌ disabled (not a validator)");
        info!("   Genesis creation: ✅ enabled (can bootstrap new networks)");
        
        // Full nodes use complete Blockchain (not EdgeNodeState)
        // This is enforced at the RuntimeOrchestrator level
        
        // Try to discover existing network (30s timeout)
        // If none found, full nodes can create genesis
        match self.orchestrator.discover_network_with_retry(false).await? {
            Some(network_info) => {
                info!("✅ Found existing ZHTP network");
                info!("   Network peers: {}", network_info.peer_count);
                info!("   Blockchain height: {}", network_info.blockchain_height);
            }
            None => {
                info!("ℹ️  No existing network found");
                info!("🌱 Creating genesis network (first node)");
                // Genesis creation handled by RuntimeOrchestrator
            }
        }
        
        // Start all components except consensus validation
        self.orchestrator.start_all_components().await?;
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("🛑 Stopping Full Node runtime");
        self.orchestrator.shutdown_all_components().await?;
        Ok(())
    }
}
