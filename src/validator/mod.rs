//! Validator Node Runtime
//! 
//! Full consensus validator with staking, block production,
//! and DAO governance participation.
//!
//! Validators participate in consensus (PoW + PoS + DAO) and produce blocks.

use anyhow::Result;
use tracing::{info, error};

use crate::config::NodeConfig;
use crate::runtime::RuntimeOrchestrator;

pub struct ValidatorRuntime {
    orchestrator: RuntimeOrchestrator,
    min_stake: u64,
}

impl ValidatorRuntime {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Enforce validator constraints at compile-time (via features)
        let mut validator_config = config;
        validator_config.blockchain_config.smart_contracts = true; // Must validate contracts
        validator_config.consensus_config.validator_enabled = true; // Must be validator
        
        // Check minimum stake requirement
        let min_stake = 1000 * 1_000_000; // 1000 ZHTP with 6 decimals
        if validator_config.consensus_config.min_stake < min_stake {
            error!("❌ Insufficient stake: {} ZHTP required", min_stake / 1_000_000);
            anyhow::bail!("Validator requires minimum stake of 1000 ZHTP");
        }
        
        let orchestrator = RuntimeOrchestrator::new(validator_config).await?;
        
        Ok(Self {
            orchestrator,
            min_stake,
        })
    }
    
    pub async fn start(&mut self) -> Result<()> {
        info!("⚡ Starting Validator Node runtime");
        info!("   Full blockchain: ✅ enabled");
        info!("   Smart contracts: ✅ enabled (WASM)");
        info!("   Consensus: ✅ enabled (PoW + PoS + DAO)");
        info!("   Minimum stake: {} ZHTP", self.min_stake / 1_000_000);
        info!("   Block production: ✅ enabled");
        info!("   DAO voting: ✅ enabled");
        info!("   Genesis creation: ✅ enabled (can bootstrap new networks)");
        
        // Validators use complete Blockchain + Consensus engine
        // This is enforced at the RuntimeOrchestrator level
        
        // Try to discover existing network (30s timeout)
        // If none found, validators can create genesis
        match self.orchestrator.discover_network_with_retry(false).await? {
            Some(network_info) => {
                info!("✅ Found existing ZHTP network");
                info!("   Network peers: {}", network_info.peer_count);
                info!("   Blockchain height: {}", network_info.blockchain_height);
                info!("   Registering as validator in existing network");
            }
            None => {
                info!("ℹ️  No existing network found");
                info!("🌱 Creating genesis network as first validator");
                // Genesis creation handled by RuntimeOrchestrator
            }
        }
        
        // Start ALL components including consensus
        self.orchestrator.start_all_components().await?;
        
        info!("⚡ Validator ready for consensus participation");
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("🛑 Stopping Validator Node runtime");
        self.orchestrator.shutdown_all_components().await?;
        Ok(())
    }
}
