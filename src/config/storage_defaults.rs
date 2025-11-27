//! Default Storage Configuration
//! 
//! Provides centralized default configuration for UnifiedStorageSystem
//! to avoid duplication across the codebase.

use anyhow::Result;
use lib_storage::{UnifiedStorageConfig, StorageConfig, ErasureConfig, StorageTier};
use lib_crypto::Hash;
use std::sync::Arc;

/// Create default storage configuration for ZHTP nodes
/// 
/// This provides sensible defaults for most ZHTP node deployments:
/// - 10GB storage limit
/// - Hot tier for frequently accessed content
/// - Compression and encryption enabled
/// - 4 data shards + 2 parity shards for erasure coding
/// - DHT transport uses QUIC mesh (no separate port)
pub fn create_default_storage_config() -> Result<UnifiedStorageConfig> {
    create_storage_config_with_defaults(
        Hash([1u8; 32]),
        vec!["127.0.0.1:8080".to_string()],
        1024 * 1024 * 1024 * 10, // 10GB
    )
}

/// Create storage configuration with custom node ID
pub fn create_storage_config_with_node_id(node_id: Hash) -> Result<UnifiedStorageConfig> {
    create_storage_config_with_defaults(
        node_id,
        vec!["127.0.0.1:8080".to_string()],
        1024 * 1024 * 1024 * 10, // 10GB
    )
}

/// Create storage configuration with custom parameters
pub fn create_storage_config_with_defaults(
    node_id: Hash,
    addresses: Vec<String>,
    max_storage_size: u64,
) -> Result<UnifiedStorageConfig> {
    Ok(UnifiedStorageConfig {
        node_id,
        addresses,
        dht_transport: None,
        economic_config: Default::default(),
        storage_config: StorageConfig {
            max_storage_size,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    })
}

/// Create storage configuration for testing with minimal storage
pub fn create_test_storage_config() -> Result<UnifiedStorageConfig> {
    create_storage_config_with_defaults(
        Hash([1u8; 32]),
        vec![],
        1024 * 1024 * 1024, // 1GB for tests
    )
}

/// Create storage config WITH DHT transport (for production with networking)
pub fn create_storage_config_with_transport(
    node_id: Hash,
    addresses: Vec<String>,
    max_storage_size: u64,
    dht_transport: Arc<dyn lib_storage::dht::transport::DhtTransport>,
) -> Result<UnifiedStorageConfig> {
    Ok(UnifiedStorageConfig {
        node_id,
        addresses,
        dht_transport: Some(dht_transport),
        economic_config: Default::default(),
        storage_config: StorageConfig {
            max_storage_size,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    })
}

/// Create storage config with QUIC transport (recommended for production)
/// Requires global QUIC instance to be initialized first
pub fn create_storage_config_with_quic(
    node_id: Hash,
    addresses: Vec<String>,
    local_identity: lib_crypto::PublicKey,
) -> Result<UnifiedStorageConfig> {
    // Create QuicDhtTransport from global QUIC instance
    let quic_transport = lib_network::QuicDhtTransport::new_from_global(local_identity)?;
    
    create_storage_config_with_transport(
        node_id,
        addresses,
        10 * 1024 * 1024 * 1024, // 10GB
        Arc::new(quic_transport),
    )
}
