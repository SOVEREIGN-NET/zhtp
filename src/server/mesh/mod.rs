//! Mesh Networking Module - Legacy Components
//! 
//! ⚠️ MIGRATION IN PROGRESS - Most mesh functionality moved to:
//! - lib-network::mesh::server::ZhtpMeshServer (network layer)
//! - zhtp::server::mesh_bridge::MeshBridge (application layer)
//!
//! Remaining components:
//! - identity_api.rs: Identity API methods for mesh (1,400+ lines)

pub mod identity_api;