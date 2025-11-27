//! Shared components used by all node types
//! 
//! This module contains core functionality that is common across
//! edge, full, and validator nodes:
//! - Network mesh protocols (via lib-network)
//! - Cryptographic primitives (via lib-crypto)
//! - Identity management (via lib-identity)
//! - CLI parsing
//! - Configuration loading

pub mod network;
pub mod crypto;
pub mod identity;

// Re-export commonly used shared types
pub use crate::config::NodeConfig;
