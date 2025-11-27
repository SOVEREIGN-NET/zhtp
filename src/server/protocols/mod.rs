//! Protocol Routers Module
//! 
//! Multi-protocol networking layer - extracted from unified_server.rs
//! 
//! ✅ PHASE 5 COMPLETE - All Protocol Routers Extracted:
//! - wifi.rs: ✅ WiFi Direct P2P router with mDNS discovery (173 lines)
//! - bluetooth_le.rs: ✅ BLE GATT mesh for phone connectivity (438 lines)
//! - bluetooth_classic.rs: ✅ RFCOMM high-throughput mesh (298 lines)
//! - bootstrap.rs: ✅ Service discovery and capability announcement (104 lines)
//!
//! Total: 1,013 lines extracted from 1,250-line protocol layer (81%)
//!
//! ## Protocol Capabilities
//!
//! For protocol specifications and capabilities, see `lib_network::protocols::NetworkProtocol`.
//! All protocol characteristics (bandwidth, latency, range) are defined in the canonical enum.

pub mod wifi;
pub mod bluetooth_le;
pub mod bluetooth_classic;
// ❌ REMOVED: pub mod bootstrap; - Use lib-network::bootstrap instead

pub use wifi::WiFiRouter;
pub use bluetooth_le::BluetoothRouter;
pub use bluetooth_classic::{BluetoothClassicRouter, ClassicProtocol};
// ❌ REMOVED: pub use bootstrap::BootstrapRouter; - Use lib-network::bootstrap instead
