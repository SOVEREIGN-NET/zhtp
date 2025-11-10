use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use lib_blockchain::{BlockHeader, Hash};
use lib_network::blockchain_sync::BlockchainProvider as NetworkBlockchainProvider;
use lib_proofs::ChainRecursiveProof;
use tracing::{debug, warn, error};

use super::blockchain_provider::{get_global_blockchain, is_global_blockchain_available};

/// Implementation of lib-network's BlockchainProvider trait using zhtp's global blockchain
/// This bridges the application layer blockchain access to the network layer's needs
pub struct ZhtpBlockchainProvider;

impl ZhtpBlockchainProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NetworkBlockchainProvider for ZhtpBlockchainProvider {
    async fn get_current_height(&self) -> Result<u64> {
        debug!("Network layer requesting current blockchain height");
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_lock = blockchain.read().await;
        let height = blockchain_lock.get_height();
        
        debug!("Current blockchain height: {}", height);
        Ok(height)
    }

    async fn get_headers(&self, start_height: u64, count: u64) -> Result<Vec<BlockHeader>> {
        debug!("Network layer requesting {} headers starting from height {}", count, start_height);
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_lock = blockchain.read().await;
        let current_height = blockchain_lock.get_height();
        
        // Calculate how many headers we can actually return
        let end_height = (start_height + count - 1).min(current_height);
        let actual_count = if start_height > current_height {
            0
        } else {
            (end_height - start_height + 1) as usize
        };
        
        debug!("Fetching headers: start={}, end={}, count={}", start_height, end_height, actual_count);
        
        let mut headers = Vec::with_capacity(actual_count);
        for height in start_height..=end_height {
            match blockchain_lock.get_block(height) {
                Some(block) => {
                    // Use the block's header directly
                    headers.push(block.header.clone());
                }
                None => {
                    warn!("Block at height {} not found", height);
                    break;
                }
            }
        }
        
        debug!("Successfully retrieved {} headers", headers.len());
        Ok(headers)
    }

    async fn get_chain_proof(&self, up_to_height: u64) -> Result<ChainRecursiveProof> {
        debug!("Network layer requesting chain proof up to height {}", up_to_height);
        
        // TODO: Implement actual chain proof generation
        // This requires:
        // 1. BlockAggregatedProof for each block (generated during consensus)
        // 2. Previous ChainRecursiveProof (from last checkpoint)
        // 3. RecursiveProofAggregator to combine them
        //
        // For now, return a placeholder error since:
        // - Edge nodes never generate proofs (they only verify)
        // - Full nodes/validators should use consensus-generated proofs
        // - This is called by message handlers when responding to BootstrapProofRequest
        
        warn!("Chain proof generation not yet implemented (height {})", up_to_height);
        warn!("Note: Only validators generate proofs; edge nodes only verify");
        
        Err(anyhow::anyhow!(
            "Chain proof generation requires BlockAggregatedProof from consensus. \
             Edge nodes should request proofs from validators, not generate them."
        ))
    }

    async fn is_available(&self) -> bool {
        let available = is_global_blockchain_available().await;
        if !available {
            debug!("Blockchain not available to network layer");
        }
        available
    }
}

impl Default for ZhtpBlockchainProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blockchain_not_available_initially() {
        let provider = ZhtpBlockchainProvider::new();
        
        // Should fail gracefully when blockchain not set
        let result = provider.get_current_height().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_available_returns_false_initially() {
        let provider = ZhtpBlockchainProvider::new();
        assert!(!provider.is_available().await);
    }
}
