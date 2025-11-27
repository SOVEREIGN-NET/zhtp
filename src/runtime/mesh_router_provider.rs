use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn};

use crate::server::mesh_bridge::MeshBridge;
use crate::server::monitoring::BroadcastMetrics;

/// Global mesh router provider for shared access across components
/// This allows API handlers to access mesh router metrics and state
/// without directly coupling to the protocols component or unified server
#[derive(Clone)]
pub struct MeshRouterProvider {
    mesh_bridge: Arc<RwLock<Option<Arc<MeshBridge>>>>,
}

impl MeshRouterProvider {
    /// Create a new empty mesh router provider
    pub fn new() -> Self {
        Self {
            mesh_bridge: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the mesh bridge instance
    pub async fn set_mesh_bridge(&self, mesh_bridge: Arc<MeshBridge>) -> Result<()> {
        *self.mesh_bridge.write().await = Some(mesh_bridge);
        info!("Global mesh bridge instance set");
        Ok(())
    }

    /// Get the mesh bridge instance
    pub async fn get_mesh_bridge(&self) -> Result<Arc<MeshBridge>> {
        self.mesh_bridge.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Mesh bridge not available"))
    }

    /// Check if mesh bridge is available
    pub async fn is_available(&self) -> bool {
        self.mesh_bridge.read().await.is_some()
    }
}

/// Global mesh router provider instance
static GLOBAL_MESH_ROUTER_PROVIDER: OnceLock<MeshRouterProvider> = OnceLock::new();

/// Initialize the global mesh router provider
pub fn initialize_global_mesh_router_provider() -> &'static MeshRouterProvider {
    GLOBAL_MESH_ROUTER_PROVIDER.get_or_init(|| {
        info!("Initializing global mesh router provider");
        MeshRouterProvider::new()
    })
}

/// Get the global mesh router provider
pub fn get_global_mesh_router_provider() -> Option<&'static MeshRouterProvider> {
    GLOBAL_MESH_ROUTER_PROVIDER.get()
}

/// Set the global mesh bridge instance
pub async fn set_global_mesh_bridge(mesh_bridge: Arc<MeshBridge>) -> Result<()> {
    let provider = initialize_global_mesh_router_provider();
    provider.set_mesh_bridge(mesh_bridge).await
}

/// Get the global mesh bridge instance
pub async fn get_global_mesh_bridge() -> Result<Arc<MeshBridge>> {
    let provider = get_global_mesh_router_provider()
        .ok_or_else(|| anyhow::anyhow!("Global mesh router provider not initialized"))?;
    provider.get_mesh_bridge().await
}

/// Check if global mesh router is available
pub async fn is_global_mesh_router_available() -> bool {
    if let Some(provider) = get_global_mesh_router_provider() {
        provider.is_available().await
    } else {
        false
    }
}

/// Get broadcast metrics from the global mesh bridge
pub async fn get_broadcast_metrics() -> Result<BroadcastMetrics> {
    let mesh_bridge = get_global_mesh_bridge().await?;
    Ok(mesh_bridge.get_broadcast_metrics().await)
}

// NOTE: The following monitoring functions are stubs that return errors
// because advanced monitoring is not yet implemented in MeshBridge.
// They will be properly implemented when the monitoring system is fully
// integrated into lib-network's ZhtpMeshServer.

/// Get active alerts (stub - not yet implemented)
pub async fn get_active_alerts() -> Result<Vec<crate::server::monitoring::SyncAlert>> {
    Err(anyhow::anyhow!("Alert monitoring not yet available in MeshBridge"))
}

/// Acknowledge an alert (stub - not yet implemented)
pub async fn acknowledge_alert(_alert_id: &str) -> Result<bool> {
    Err(anyhow::anyhow!("Alert management not yet available in MeshBridge"))
}

/// Clear acknowledged alerts (stub - not yet implemented)
pub async fn clear_acknowledged_alerts() -> Result<usize> {
    Err(anyhow::anyhow!("Alert management not yet available in MeshBridge"))
}

/// Get alert thresholds (stub - not yet implemented)
pub async fn get_alert_thresholds() -> Result<crate::server::monitoring::AlertThresholds> {
    Err(anyhow::anyhow!("Alert threshold configuration not yet available in MeshBridge"))
}

/// Update alert thresholds (stub - not yet implemented)
pub async fn update_alert_thresholds(_thresholds: crate::server::monitoring::AlertThresholds) -> Result<()> {
    Err(anyhow::anyhow!("Alert threshold configuration not yet available in MeshBridge"))
}

/// Get metrics history (stub - not yet implemented)
pub async fn get_metrics_history(_last_n: usize) -> Result<Vec<crate::server::monitoring::MetricsSnapshot>> {
    Err(anyhow::anyhow!("Metrics history not yet available in MeshBridge"))
}

/// List peer performance (stub - not yet implemented)
pub async fn list_peer_performance() -> Result<Vec<crate::server::monitoring::PeerPerformanceStats>> {
    Err(anyhow::anyhow!("Peer performance monitoring not yet available in MeshBridge"))
}

/// Get peer performance (stub - not yet implemented)
pub async fn get_peer_performance(_peer_id: &str) -> Result<Option<crate::server::monitoring::PeerPerformanceStats>> {
    Err(anyhow::anyhow!("Peer performance monitoring not yet available in MeshBridge"))
}
