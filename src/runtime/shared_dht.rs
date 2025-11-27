//! Shared DHT Instance Manager
//! 
//! Provides a singleton UnifiedStorageSystem that can be shared across all components
//! to prevent multiple initialization and port conflicts.
//! This replaces the old ZkDHTIntegration with the networked UnifiedStorageSystem.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{RwLock, OnceCell};
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig, StorageConfig, ErasureConfig, StorageTier};
use lib_storage::types::economic_types::EconomicManagerConfig;
use lib_identity::ZhtpIdentity;
use lib_crypto::Hash;
use tracing::{info, debug};

/// Global DHT instance manager - wrapped in RwLock for mutable access
static GLOBAL_DHT: OnceCell<Arc<RwLock<Option<Arc<RwLock<UnifiedStorageSystem>>>>>> = OnceCell::const_new();

/// Initialize the global UnifiedStorageSystem with networking (singleton with proper guards)
/// This should be called once at application startup
pub async fn initialize_global_dht(identity: ZhtpIdentity, dht_bind_addr: std::net::SocketAddr) -> Result<()> {
    let dht_container = GLOBAL_DHT.get_or_init(|| async {
        Arc::new(RwLock::new(None))
    }).await;
    
    let mut dht_guard = dht_container.write().await;
    
    // Check if DHT is already initialized
    if dht_guard.is_some() {
        debug!("UnifiedStorageSystem already initialized, skipping duplicate initialization");
        return Ok(());
    }
    
    info!("Initializing global UnifiedStorageSystem with DHT networking (singleton)");
    
    // Extract node ID from identity
    let node_id = Hash::from_bytes(&blake3::hash(&identity.public_key).as_bytes()[..32]);
    
    // Create UnifiedStorageSystem configuration with networking enabled
    let config = UnifiedStorageConfig {
        node_id,
        addresses: vec![dht_bind_addr.to_string()],
        economic_config: EconomicManagerConfig::default(),
        storage_config: StorageConfig {
            max_storage_size: 10_000_000_000, // 10GB default
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
        dht_transport: None, // Will be set by UnifiedStorageSystem using QUIC mesh
    };
    
    // Create the UnifiedStorageSystem with networking enabled
    let storage_system = UnifiedStorageSystem::new(config).await?;
    
    // Store in global container wrapped in Arc<RwLock<_>> for mutable access
    *dht_guard = Some(Arc::new(RwLock::new(storage_system)));
    
    info!("Global UnifiedStorageSystem initialized successfully with DHT networking");
    Ok(())
}

/// Initialize UnifiedStorageSystem if not already initialized (safe wrapper)
pub async fn initialize_global_dht_safe(identity: ZhtpIdentity, dht_bind_addr: std::net::SocketAddr) -> Result<()> {
    if is_dht_initialized().await {
        debug!("UnifiedStorageSystem already initialized, skipping");
        return Ok(());
    }
    
    initialize_global_dht(identity, dht_bind_addr).await
}

/// Get a reference to the global UnifiedStorageSystem instance
/// Returns None if not yet initialized
pub async fn get_global_dht() -> Option<Arc<RwLock<Option<Arc<RwLock<UnifiedStorageSystem>>>>>> {
    GLOBAL_DHT.get().cloned()
}

/// Get a clone of the UnifiedStorageSystem for use in operations
/// Returns Arc<RwLock<UnifiedStorageSystem>> to allow mutable access when needed
pub async fn get_dht_client() -> Result<Arc<RwLock<UnifiedStorageSystem>>> {
    let dht_container = get_global_dht().await
        .ok_or_else(|| anyhow::anyhow!("UnifiedStorageSystem not initialized - call initialize_global_dht() first"))?;
    
    let dht_guard = dht_container.read().await;
    
    match dht_guard.as_ref() {
        Some(storage_system) => {
            debug!("Retrieved shared UnifiedStorageSystem instance");
            Ok(storage_system.clone())
        }
        None => {
            Err(anyhow::anyhow!("Storage container exists but instance is None"))
        }
    }
}

/// Check if the global UnifiedStorageSystem is initialized
pub async fn is_dht_initialized() -> bool {
    if let Some(dht_container) = get_global_dht().await {
        let dht_guard = dht_container.read().await;
        dht_guard.is_some()
    } else {
        false
    }
}

/// Shutdown the global UnifiedStorageSystem instance
pub async fn shutdown_global_dht() -> Result<()> {
    if let Some(dht_container) = get_global_dht().await {
        let mut dht_guard = dht_container.write().await;
        if let Some(storage_system) = dht_guard.take() {
            info!("🔌 Shutting down global UnifiedStorageSystem instance");
            // Storage system will be dropped and cleaned up automatically
            drop(storage_system);
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::ZhtpIdentity;
    use lib_proofs::ZeroKnowledgeProof;
    use lib_crypto::generate_keypair;

    #[tokio::test]
    async fn test_unified_storage_singleton_pattern() {
        // Create test identity
        let keypair = generate_keypair().unwrap();
        let public_key = keypair.public_key.dilithium_pk.clone();
        let ownership_proof = ZeroKnowledgeProof::default();
        
        let identity = ZhtpIdentity::new(
            lib_identity::IdentityType::Device,
            public_key.to_vec(),
            ownership_proof,
        ).unwrap();

        let bind_addr = "127.0.0.1:8000".parse().unwrap();

        // Test initialization
        assert!(!is_dht_initialized().await);
        
        initialize_global_dht(identity.clone(), bind_addr).await.unwrap();
        
        assert!(is_dht_initialized().await);
        
        // Test duplicate initialization (should be ignored)
        initialize_global_dht(identity.clone(), bind_addr).await.unwrap();
        
        // Test getting storage system
        let _storage_system = get_dht_client().await.unwrap();
        
        // Test shutdown
        shutdown_global_dht().await.unwrap();
        
        // Note: We can't easily test if it's uninitialized due to OnceCell behavior
    }
}