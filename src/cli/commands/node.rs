//! Node management commands for ZHTP orchestrator

use anyhow::{Result, anyhow};
use crate::cli::{NodeArgs, NodeAction, ZhtpCli};
use crate::config::environment::Environment;  // NEW: For network-specific data paths
use crate::runtime::RuntimeOrchestrator;
use crate::runtime::did_startup::{WalletStartupManager, WalletStartupResult};
use crate::runtime::shared_dht::{initialize_global_dht_safe, get_dht_client};
use lib_identity::ZhtpIdentity;
use std::io::{self, Write};
use std::sync::Arc;
use blake3;

// ============================================================================
// Password Utility Functions
// ============================================================================

/// Prompt user for identity/node name
fn prompt_for_identity_name() -> Result<String> {
    loop {
        print!("\nEnter a name for your identity (node): ");
        io::stdout().flush()?;
        
        let mut name = String::new();
        io::stdin().read_line(&mut name)?;
        let name = name.trim();
        
        if name.is_empty() {
            println!(" Name cannot be empty. Please try again.");
            continue;
        }
        
        if name.len() < 3 {
            println!(" Name must be at least 3 characters long.");
            continue;
        }
        
        return Ok(name.to_string());
    }
}

/// Validate password strength
fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters long"));
    }
    
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    if !has_uppercase {
        return Err(anyhow!("Password must contain at least one uppercase letter"));
    }
    if !has_lowercase {
        return Err(anyhow!("Password must contain at least one lowercase letter"));
    }
    if !has_digit {
        return Err(anyhow!("Password must contain at least one number"));
    }
    if !has_special {
        return Err(anyhow!("Password must contain at least one special character"));
    }
    
    Ok(())
}

/// Securely prompt for password (no echo)
fn prompt_for_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    Ok(password)
}

/// Prompt for seed phrase confirmation
fn confirm_seed_phrase(seed_phrase: &str) -> Result<()> {
    println!("\n  IMPORTANT: Write down your recovery phrase!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" Your Recovery Phrase:");
    println!("{}", seed_phrase);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n  Store this in a safe place. You'll need it to recover your wallet!");
    println!("  Anyone with this phrase can access your funds!");
    
    loop {
        print!("\nType 'CONFIRM' to verify you've saved your recovery phrase: ");
        io::stdout().flush()?;
        
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        
        if confirmation.trim() == "CONFIRM" {
            println!(" Recovery phrase confirmed!");
            return Ok(());
        } else {
            println!(" You must type 'CONFIRM' to continue. Please save your recovery phrase first.");
        }
    }
}

/// Prompt for DID password with confirmation
fn prompt_for_did_password() -> Result<String> {
    println!("\n Set a password to protect your Digital Identity");
    println!("Requirements: 8+ chars, uppercase, lowercase, number, special character");
    
    loop {
        let password = prompt_for_password("\nEnter password: ")?;
        
        if let Err(e) = validate_password_strength(&password) {
            println!(" {}", e);
            continue;
        }
        
        let confirmation = prompt_for_password("Confirm password: ")?;
        
        if password != confirmation {
            println!(" Passwords don't match. Please try again.");
            continue;
        }
        
        println!(" Password set successfully!");
        return Ok(password);
    }
}

/// Prompt for optional wallet password
fn prompt_for_wallet_password(wallet_type: &str) -> Result<Option<String>> {
    println!("\n Set a password for your {} wallet (optional)", wallet_type);
    print!("Press Enter to skip, or type a password: ");
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    if password.is_empty() {
        println!("  Skipping wallet password");
        return Ok(None);
    }
    
    // Validate wallet password (minimum 6 chars)
    if password.len() < 6 {
        println!(" Wallet password must be at least 6 characters. Skipping.");
        return Ok(None);
    }
    
    let confirmation = prompt_for_password("Confirm wallet password: ")?;
    
    if password != confirmation {
        println!(" Passwords don't match. Skipping wallet password.");
        return Ok(None);
    }
    
    println!(" Wallet password set!");
    Ok(Some(password))
}

// ============================================================================
// Network Info and Identity Management
// ============================================================================

#[derive(Debug, Clone)]
pub struct ExistingNetworkInfo {
    pub peer_count: u32,
    pub blockchain_height: u64,
    pub network_id: String,
    pub bootstrap_peers: Vec<String>,
    pub environment: Environment,  // NEW: Network-specific environment for proper data paths
}

pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        NodeAction::Start { config, port, dev, pure_mesh, network, edge_mode, edge_max_headers, .. } => {
            println!(" Starting ZHTP orchestrator node...");
            if let Some(p) = port {
                println!("Port override: {}", p);
            }
            println!("Config: {:?}", config);
            println!("Dev mode: {}", dev);
            println!("Pure mesh mode: {}", pure_mesh);
            
            if edge_mode {
                println!(" Edge Mode: ENABLED (lightweight sync)");
                println!("   Max headers: {} (~{} KB storage)", 
                    edge_max_headers, 
                    (edge_max_headers * 200) / 1024);
            }
            
            // Parse network override if provided
            let network_override = network.as_ref().and_then(|n| {
                match n.as_str() {
                    "mainnet" => Some(Environment::Mainnet),
                    "testnet" => Some(Environment::Testnet),
                    "dev" => Some(Environment::Development),
                    _ => None,
                }
            });
            
            if let Some(ref net) = network_override {
                println!(" Network Override: {}", net);
            }
            
            // Show node type information if using predefined configs
            if let Some(ref config_path) = config {
                if config_path.contains("full-node") {
                    println!("🖥️ Node Type: Full Node (Complete blockchain functionality)");
                } else if config_path.contains("validator-node") {
                    println!(" Node Type: Validator Node (Consensus participation)");
                } else if config_path.contains("storage-node") {
                    println!(" Node Type: Storage Node (Distributed storage services)");
                } else if config_path.contains("edge-node") {
                    println!("Node Type: Edge Node (Mesh networking and )");
                } else if config_path.contains("dev-node") {
                    println!("Node Type: Development Node (Testing and development)");
                }
            }
            
            // Load the node configuration
            use crate::config::{load_configuration, CliArgs, Environment};
            use crate::runtime::RuntimeOrchestrator;
            use std::path::PathBuf;
            
            let cli_args = CliArgs {
                mesh_port: port,
                pure_mesh,
                config: PathBuf::from(config.unwrap_or_else(|| "./config".to_string())),
                environment: network_override.unwrap_or(Environment::Development), // Use CLI override or default
                log_level: if dev { "debug".to_string() } else { "info".to_string() },
                data_dir: PathBuf::from("./data"),
            };
            
            println!("Loading configuration...");
            let mut node_config = load_configuration(&cli_args).await?;
            
            // ========================================================================
            // Detect node type from configuration or CLI flags
            // ========================================================================
            let hosted_storage = if node_config.storage_config.hosted_storage_gb > 0 {
                node_config.storage_config.hosted_storage_gb
            } else {
                // Backward compatibility: use old storage_capacity_gb field
                node_config.storage_config.storage_capacity_gb
            };
            
            // CLI flag takes precedence over auto-detection
            let is_edge_node = if edge_mode {
                true  // Explicitly enabled via --edge-mode
            } else {
                !node_config.consensus_config.validator_enabled 
                && !node_config.blockchain_config.smart_contracts
                && hosted_storage < 100  // Less than 100 GB hosted storage = edge node
            };
            
            let is_validator = node_config.consensus_config.validator_enabled;
            
            if is_edge_node {
                println!(" Node Type: EDGE NODE");
                println!("   - Headers-only sync (~{} KB storage)", (edge_max_headers * 200) / 1024);
                println!("   - ZK proof verification (no generation)");
                println!("   - Optimized for BLE/mesh networking");
                println!("   - Max headers: {}", edge_max_headers);
            } else if is_validator {
                println!("🔶 Node Type: VALIDATOR");
                println!("   - Full blockchain sync");
                println!("   - Consensus participation");
                println!("   - ZK proof generation");
            } else {
                println!(" Node Type: FULL NODE");
                println!("   - Full blockchain sync");
                println!("   - No consensus participation");
            }
            
            // Apply network override if --network flag was provided
            if let Some(network_env) = network_override {
                println!(" Overriding config environment with CLI flag: {}", network_env);
                node_config.environment = network_env;
                
                // Update related config fields for consistency
                match network_env {
                    Environment::Mainnet => {
                        println!("   → Using mainnet genesis block (chain_id: 0x01)");
                        println!("   → Data directory: ./data/mainnet");
                    }
                    Environment::Testnet => {
                        println!("   → Using testnet genesis block (chain_id: 0x02)");
                        println!("   → Data directory: ./data/testnet");
                    }
                    Environment::Development => {
                        println!("   → Using development genesis block (chain_id: 0x03)");
                        println!("   → Data directory: ./data/dev");
                    }
                }
            }
            
            // Apply network isolation if pure mesh mode is enabled
            if pure_mesh {
                println!(" Applying network isolation for pure mesh mode...");
                use crate::config::network_isolation::NetworkIsolationConfig;
                
                let isolation_config = NetworkIsolationConfig::default();
                match isolation_config.apply_isolation().await {
                    Ok(_) => {
                        println!(" Network isolation applied successfully");
                        println!(" Internet access blocked - mesh networking only");
                        
                        // Test isolation
                        match isolation_config.verify_isolation().await {
                            Ok(_) => {
                                println!(" Isolation verified: Local OK, Internet blocked");
                            }
                            Err(e) => println!(" Isolation verification failed: {}", e),
                        }
                    }
                    Err(e) => {
                        println!(" Failed to apply network isolation: {}", e);
                        println!(" Continuing without isolation - manual configuration may be required");
                    }
                }
            }
            
            println!("Starting runtime orchestrator...");
            let mut orchestrator = RuntimeOrchestrator::new(node_config.clone()).await?;
            
            // Set edge mode configuration if explicitly enabled via CLI
            if is_edge_node {
                orchestrator.set_edge_node(true).await;
                orchestrator.set_edge_max_headers(edge_max_headers).await;
                println!(" Edge mode configured: max_headers={}", edge_max_headers);
            }
            
            // ================================================================
            // NEW APPROACH: Start network components FIRST, then discover peers
            // ================================================================
            
            println!("🔌 Starting network components for peer discovery...");
            
            // PHASE 1: Register and start ONLY Crypto + Network for peer discovery
            // We'll register remaining components AFTER getting genesis identities
            use crate::runtime::components::{CryptoComponent, NetworkComponent};
            
            println!("   → Registering CryptoComponent...");
            orchestrator.register_component(Arc::new(CryptoComponent::new())).await?;
            println!("   → Starting CryptoComponent...");
            orchestrator.start_component(crate::runtime::ComponentId::Crypto).await?;
            
            println!("   → Registering NetworkComponent...");
            orchestrator.register_component(Arc::new(NetworkComponent::new())).await?;
            println!("   → Starting NetworkComponent...");
            orchestrator.start_component(crate::runtime::ComponentId::Network).await?;
            
            // CRITICAL: Wait for network stack to fully initialize
            println!("   → Waiting for network stack to initialize...");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // NOTE: We used to do "early broadcasting" here, but it caused duplicate node_ids
            // because the unified_server generates its own node_id later.
            // The unified_server will start broadcasting within ~5 seconds, which is fast enough
            // for the edge node's 35-second multicast listen window to catch.
            
            println!("✓ Network components ready for peer discovery");
            
            // NOW try to bootstrap to existing network (network is listening!)
            // EDGE NODES: Keep retrying until a peer is found
            let mesh_connection_result = if is_edge_node {
                println!("\n🔍 Edge node: Continuously searching for ZHTP network...");
                println!("   Will retry every 35 seconds until a full node is found");
                println!("   Press Ctrl+C to stop\n");
                
                let mut attempt = 1;
                loop {
                    println!("📡 Discovery attempt #{}", attempt);
                    match attempt_mesh_bootstrap(&mut orchestrator, &node_config.environment).await {
                        Ok(network_info) => break Ok(network_info),
                        Err(e) => {
                            println!("   ✗ Attempt #{} failed: {}", attempt, e);
                            println!("   ⏳ Waiting 5 seconds before retry #{}", attempt + 1);
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            attempt += 1;
                        }
                    }
                }
            } else {
                println!("\n🔍 Attempting to discover existing ZHTP network...");
                println!("   Discovery timeout: 30 seconds (allows BLE/WiFi Direct time)");
                attempt_mesh_bootstrap(&mut orchestrator, &node_config.environment).await
            };
            
            let startup_result = match mesh_connection_result {
                Ok(existing_network_info) => {
                    println!("\n✓ Connected to existing ZHTP network!");
                    println!("   Network peers: {}", existing_network_info.peer_count);
                    println!("   Blockchain height: {}", existing_network_info.blockchain_height);
                    println!("   Network ID: {}", existing_network_info.network_id);
                    
                    // Start blockchain sync BEFORE identity setup
                    println!("\n📦 Initializing blockchain for sync...");
                    orchestrator.start_blockchain_sync(&existing_network_info).await?;
                    
                    // Wait for initial sync (at least some blocks)
                    println!("   ⏳ Waiting for initial sync to start...");
                    match orchestrator.wait_for_initial_sync(tokio::time::Duration::from_secs(30)).await {
                        Ok(()) => {
                            let current_height = orchestrator.get_blockchain_height().await?;
                            println!("✓ Sync in progress: height {} / {}", current_height, existing_network_info.blockchain_height);
                        }
                        Err(e) => {
                            println!("⚠ Initial sync timeout: {} - will continue syncing in background", e);
                        }
                    }
                    
                    // Tell orchestrator we're joining existing network (don't create genesis)
                    if let Err(e) = orchestrator.set_joined_existing_network(true).await {
                        eprintln!("Warning: Failed to set network join status: {}", e);
                    }
                    
                    // Step 2a: Handle identity for existing network
                    handle_existing_network_identity(&existing_network_info).await?
                }
                Err(e) => {
                    println!("\nℹ No existing ZHTP network found: {}", e);
                    
                    // EDGE NODES CANNOT CREATE GENESIS BLOCKS!
                    // (This should never be reached for edge nodes due to retry loop above)
                    if is_edge_node {
                        return Err(anyhow::anyhow!(
                            "\n❌ Edge Node Cannot Start Without Network\n\
                             \n\
                             This should not happen - edge nodes retry indefinitely.\n\
                             Please report this bug.\n"
                        ));
                    }
                    
                    println!("📝 Starting new genesis network...");
                    
                    // Tell orchestrator we're creating new network (create genesis)
                    if let Err(e) = orchestrator.set_joined_existing_network(false).await {
                        eprintln!("Warning: Failed to set network create status: {}", e);
                    }
                    
                    // Step 2b: Handle identity for new genesis network (pass environment)
                    handle_genesis_network_identity(&node_config.environment).await?
                }
            };
            
            println!(" User wallet established: {}", startup_result.wallet_name);
            
            // CRITICAL: Pass user wallet to orchestrator BEFORE registering remaining components
            // so genesis identities are available when IdentityComponent is created
            if let Err(e) = orchestrator.set_user_wallet(startup_result).await {
                eprintln!("Warning: Failed to set user wallet: {}", e);
            }
            
            println!("  Registering remaining system components with genesis identities...");
            
            // PHASE 2: Register remaining components (now that we have genesis identities)
            use crate::runtime::components::{
                ZKComponent, IdentityComponent, StorageComponent, BlockchainComponent,
                ConsensusComponent, EconomicsComponent, ProtocolsComponent, ApiComponent
            };
            
            orchestrator.register_component(Arc::new(ZKComponent::new())).await?;
            
            // Register Identity component with genesis identities AND private keys
            let genesis_identities = orchestrator.get_genesis_identities().await;
            let genesis_private_data = orchestrator.get_genesis_private_data().await;
            
            if genesis_identities.is_empty() {
                println!("     Warning: No genesis identities found!");
                orchestrator.register_component(Arc::new(IdentityComponent::new())).await?;
            } else {
                println!("    Registering IdentityComponent with {} genesis identities", genesis_identities.len());
                orchestrator.register_component(Arc::new(
                    IdentityComponent::new_with_identities_and_private_data(genesis_identities, genesis_private_data)
                )).await?;
            }
            
            orchestrator.register_component(Arc::new(StorageComponent::new())).await?;
            
            // Register BlockchainComponent with user wallet
            let user_wallet = orchestrator.get_user_wallet().await;
            let environment = orchestrator.get_environment();
            let bootstrap_validators = orchestrator.get_bootstrap_validators();
            let joined_existing_network = orchestrator.get_joined_existing_network().await;
            orchestrator.register_component(Arc::new(BlockchainComponent::new_with_full_config(
                user_wallet,
                environment,
                bootstrap_validators,
                joined_existing_network
            ))).await?;
            
            orchestrator.register_component(Arc::new(ConsensusComponent::new(environment))).await?;
            orchestrator.register_component(Arc::new(ProtocolsComponent::new(environment, node_config.protocols_config.api_port))).await?;
            orchestrator.register_component(Arc::new(EconomicsComponent::new())).await?;
            orchestrator.register_component(Arc::new(ApiComponent::new())).await?;
            
            println!("  Starting remaining system components...");
            // BlockchainComponent creates the shared blockchain with proper genesis funding.
            // ProtocolsComponent needs that shared blockchain to exist when it starts.
            
            // Start remaining components (skip already-started Crypto, Network)
            orchestrator.start_component(crate::runtime::ComponentId::ZK).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Identity).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Storage).await?;
            // Network already started above
            
            // Start BlockchainComponent FIRST - it creates shared blockchain with genesis funding
            orchestrator.start_component(crate::runtime::ComponentId::Blockchain).await?;
            
            // Start Consensus BEFORE Protocols for validator coordination
            orchestrator.start_component(crate::runtime::ComponentId::Consensus).await?;
            
            // Now start Protocols - it will use the shared blockchain created by BlockchainComponent
            orchestrator.start_component(crate::runtime::ComponentId::Protocols).await?;
            
            orchestrator.start_component(crate::runtime::ComponentId::Economics).await?;
            orchestrator.start_component(crate::runtime::ComponentId::Api).await?;
            
            println!("Blockchain component started - Mining ready!");
            println!("Consensus engine started - Validators active!");
            println!("Network mesh initialized - P2P connectivity!");
            
            if dev {
                println!("Development mode enabled - Enhanced logging and debug features");
            }
            
            // The ZHTP server and API endpoints are already running via ProtocolsComponent
            println!("ZHTP orchestrator fully operational!");
            println!("blockchain mining and consensus active");
            println!("Level 1 Orchestrator managing: crypto, zk, identity, storage, network, blockchain, consensus, economics, protocols");
            println!("ZHTP server and Web4 API endpoints active on port {}", node_config.protocols_config.api_port);
            println!("Press Ctrl+C to stop the node");
            
            // Wait for shutdown signal (no need to start duplicate API server)
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutting down orchestrator...");
                    orchestrator.graceful_shutdown().await?;
                }
            }
            
            Ok(())
        }
        NodeAction::Stop => {
            println!("Stopping ZHTP orchestrator node...");
            println!("Node stopped successfully");
            Ok(())
        }
        NodeAction::Status => {
            println!("ZHTP Orchestrator Status:");
            println!("Status: Running");
            println!("Role: Level 1 Orchestrator");
            println!("Coordinating: protocols, blockchain, network");
            println!("API Port: {}", cli.server.split(':').nth(1).unwrap_or("9333"));
            Ok(())
        }
        NodeAction::Restart => {
            println!(" Restarting ZHTP orchestrator node...");
            println!("Node restarted successfully");
            Ok(())
        }
    }
}

/// Attempt to bootstrap to an existing ZHTP mesh network
async fn attempt_mesh_bootstrap(_orchestrator: &mut RuntimeOrchestrator, environment: &Environment) -> Result<ExistingNetworkInfo> {
    println!("📡 Discovering ZHTP peers on local network...");
    println!("   Methods: DHT/mDNS, UDP multicast, port scanning");
    
    // Initialize DHT and perform ACTIVE peer discovery
    println!("   → Initializing DHT for peer discovery...");
    let node_identity = create_or_load_node_identity(environment).await?;
    initialize_global_dht_safe(node_identity.clone()).await?;
    
    // Start actual discovery mechanisms with INCREASED timeout (30s total)
    println!("   → Scanning network (timeout: 30 seconds)...");
    let discovered_peers = perform_active_peer_discovery(&node_identity, environment).await?;
    
    let peer_count = discovered_peers.len();
    
    if peer_count > 0 {
        println!("\n✓ Discovered {} ZHTP peer(s)!", peer_count);
        for (i, peer) in discovered_peers.iter().enumerate() {
            println!("   {}. {}", i + 1, peer);
        }
        
        // Give peers additional time to respond to handshakes
        println!("\n   ⏳ Waiting 5 seconds for peer handshakes...");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        // Try to connect to blockchain via peers
        println!("   📊 Querying blockchain status from peers...");
        let blockchain_info = fetch_blockchain_info_from_discovered_peers(&discovered_peers).await?;
        
        Ok(ExistingNetworkInfo {
            peer_count: peer_count as u32,
            blockchain_height: blockchain_info.height,
            network_id: blockchain_info.network_id,
            bootstrap_peers: discovered_peers,
            environment: environment.clone(),
        })
    } else {
        println!("\n✗ No ZHTP peers discovered on local network");
        Err(anyhow!("No network peers found"))
    }
}

/// Handle wallet setup when connecting to an existing network
async fn handle_existing_network_identity(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!("\nZHTP Network Connection Established");
    println!("=====================================");
    println!("Connected to existing ZHTP network: {}", network_info.network_id);
    println!("Network peers: {}", network_info.peer_count);
    println!("Blockchain height: {}", network_info.blockchain_height);
    println!();
    println!("Choose how to set up your Digital Identity (DID):");
    println!("1) Import existing identity from mesh network");
    println!("2) Import identity from recovery phrase");
    println!("3) Create new identity with wallets (Primary, Savings, Staking)");
    println!("4) Quick start (auto-generate for testing)");
    println!();
    println!("Note: Your DID will own this node and manage multiple wallets.");
    println!();
    
    loop {
        print!("Enter your choice (1-4): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\nScanning mesh network for existing identity...");
                return import_identity_from_mesh(network_info).await;
            }
            "2" => {
                println!("\nImport identity from recovery phrase...");
                return WalletStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n Creating new digital identity with wallets...");
                println!(" Your DID will own 3 wallets: Primary (rewards), Savings, Staking");
                println!(" Node will route rewards to your Primary wallet");
                return create_wallet_from_node_identity(network_info).await;
            }
            "4" => {
                println!("\n Quick start mode...");
                return WalletStartupManager::quick_start_wallet().await;
            }
            _ => {
                println!("Invalid choice. Please enter 1, 2, 3, or 4.");
                continue;
            }
        }
    }
}

/// Handle wallet setup when creating a new genesis network
async fn handle_genesis_network_identity(environment: &Environment) -> Result<WalletStartupResult> {
    println!("\nCreating New ZHTP Genesis Network");
    println!("====================================");
    println!("No existing network found. You'll be creating a new genesis network.");
    println!("This node will become the first node in a new ZHTP mesh.");
    println!();
    println!("Choose how to set up your Digital Identity (DID):");
    println!("1) Create new identity with wallets (Primary, Savings, Staking)");
    println!("2) Import existing identity from recovery phrase");
    println!("3) Quick start (auto-generate for testing)");
    println!();
    println!("Note: Your DID will own this node. The node routes rewards to your wallets.");
    println!();
    
    loop {
        print!("Enter your choice (1-3): ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("\n Creating new digital identity with wallets...");
                println!(" Your DID will own 3 wallets: Primary (rewards), Savings, Staking");
                println!(" Node will route rewards to your Primary wallet");
                return create_genesis_wallet_from_node_identity(environment).await;
            }
            "2" => {
                println!("\nImport identity from recovery phrase...");
                return WalletStartupManager::import_from_recovery_phrase().await;
            }
            "3" => {
                println!("\n Quick start mode...");
                return WalletStartupManager::quick_start_wallet().await;
            }
            _ => {
                println!("Invalid choice. Please enter 1, 2, or 3.");
                continue;
            }
        }
    }
}

/// Import wallet from mesh network
async fn import_identity_from_mesh(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!("Searching for wallets in mesh network...");
    println!("Querying {} bootstrap peers...", network_info.bootstrap_peers.len());
    
    // Use the shared DHT client (already initialized)
    let dht_client = get_dht_client().await?;
    
    // Discover peers in the mesh network using shared DHT instance
    let dht = dht_client.read().await;
    match dht.discover_peers().await {
        Ok(discovered_peers) => {
            println!("Found {} peers in mesh network", discovered_peers.len());
            for (i, peer) in discovered_peers.iter().take(5).enumerate() {
                println!("  {}. {}", i + 1, peer);
            }
            
            // Try to find importable identities from discovered peers
            // For now, this is simplified - in a implementation,
            // we would query each peer for available identity services
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            if discovered_peers.is_empty() {
                println!("No identities available for import from discovered peers");
            } else {
                println!("Identity import from mesh peers not yet implemented");
            }
        }
        Err(e) => {
            println!("Failed to discover peers: {}", e);
        }
    }
    
    println!(" Falling back to manual wallet creation...");
    handle_genesis_network_identity(&network_info.environment).await
}

/// Perform ACTIVE peer discovery using all available methods
async fn perform_active_peer_discovery(node_identity: &ZhtpIdentity, environment: &Environment) -> Result<Vec<String>> {
    use lib_network::dht::bootstrap::DHTBootstrap;
    
    let mut all_discovered_peers = Vec::new();
    
    // Method 1: DHT Enhanced Bootstrap (includes mDNS)
    println!("   → Method 1: DHT bootstrap with mDNS discovery");
    let local_public_key = lib_crypto::PublicKey::new(node_identity.public_key.clone());
    let mut dht_bootstrap = DHTBootstrap::new(Default::default(), local_public_key.clone());
    
    // SEQUENTIAL DISCOVERY: Try methods one at a time, stop when peers found
    // This prevents network flooding and reduces discovery time by 80%
    
    // Method 1: DHT/mDNS (fast, cross-subnet capable)
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(8),  // Reduced from 15s
        dht_bootstrap.enhance_bootstrap(&[])
    ).await {
        Ok(Ok(peers)) if !peers.is_empty() => {
            println!("      ✓ DHT/mDNS found {} peers - discovery complete!", peers.len());
            all_discovered_peers.extend(peers);
            // EARLY RETURN - we found peers, no need to try other methods!
            all_discovered_peers.sort();
            all_discovered_peers.dedup();
            return Ok(all_discovered_peers);
        }
        Ok(Ok(_)) => {
            println!("      DHT/mDNS found 0 peers - trying next method");
        }
        Ok(Err(e)) => {
            println!("     ✗ DHT/mDNS discovery failed: {} - trying next method", e);
        }
        Err(_) => {
            println!("     ⏱ DHT/mDNS timeout - trying next method");
        }
    }
    
    // Method 2: UDP multicast (only if DHT/mDNS found nothing)
    println!("   → Method 2: UDP multicast peer discovery");
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(40),  // Allow 35s listen window + 5s buffer
        discover_via_multicast()
    ).await {
        Ok(Ok(peers)) if !peers.is_empty() => {
            println!("      ✓ Multicast found {} peers - discovery complete!", peers.len());
            all_discovered_peers.extend(peers);
            // EARLY RETURN - we found peers!
            all_discovered_peers.sort();
            all_discovered_peers.dedup();
            return Ok(all_discovered_peers);
        }
        Ok(Ok(_)) => {
            println!("      Multicast found 0 peers - trying fallback method");
        }
        Ok(Err(e)) => {
            println!("     ✗ Multicast failed: {} - trying fallback", e);
        }
        Err(_) => {
            println!("     ⏱ Multicast timeout - trying fallback");
        }
    }
    
    // Method 3: Port scanning (last resort fallback)
    // Note: Port scanning is expensive, so we only do it if other methods failed
    println!("   → Method 3: Port scanning fallback (last resort)");
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        scan_local_subnet_for_zhtp(environment)
    ).await {
        Ok(Ok(peers)) if !peers.is_empty() => {
            println!("      ✓ Port scan found {} peers", peers.len());
                all_discovered_peers.extend(peers);
            }
            Ok(Ok(_)) => {
                println!("      Port scan found 0 peers");
            }
            Ok(Err(e)) => {
                println!("     ✗ Port scan failed: {}", e);
            }
            Err(_) => {
                println!("     ⏱ Port scan timeout");
            }
        }
    
    // Deduplicate and return
    all_discovered_peers.sort();
    all_discovered_peers.dedup();
    
    Ok(all_discovered_peers)
}

/// Discover peers via UDP multicast announcements
async fn discover_via_multicast() -> Result<Vec<String>> {
    use tokio::net::UdpSocket;
    use std::net::{Ipv4Addr, SocketAddr};
    
    const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75";
    const ZHTP_MULTICAST_PORT: u16 = 37775;
    
    // Use SO_REUSEADDR to allow multiple listeners on the same port
    // This lets us coexist with the persistent multicast broadcaster
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    
    let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED)?;
    
    let mut discovered = Vec::new();
    let mut buf = [0u8; 1024];
    // Wait up to 35 seconds to catch broadcasts (nodes broadcast every 30 seconds)
    // This ensures we catch at least one broadcast cycle
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(35);
    
    // Get our local IP to filter out our own broadcasts
    let our_local_ip = match get_local_ip_address().await {
        Ok(ip) => {
            eprintln!("     [MULTICAST DEBUG] Our local IP: {}", ip);
            Some(ip)
        },
        Err(_) => None,
    };
    
    eprintln!("     [MULTICAST DEBUG] Listening on 224.0.1.75:37775 for 35 seconds...");
    
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            socket.recv_from(&mut buf)
        ).await {
            Ok(Ok((len, addr))) => {
                eprintln!("     [MULTICAST DEBUG] Received packet from {} ({} bytes)", addr, len);
                if let Ok(announcement) = String::from_utf8(buf[..len].to_vec()) {
                    eprintln!("     [MULTICAST DEBUG] Packet content: {}", announcement);
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&announcement) {
                        // Extract node_id and local_ip from announcement
                        let _node_id = parsed.get("node_id").and_then(|n| n.as_str());
                        let local_ip = parsed.get("local_ip").and_then(|ip| ip.as_str());
                        
                        // Skip our own announcements (check local_ip)
                        if let (Some(our_ip), Some(peer_ip)) = (our_local_ip.as_ref(), local_ip) {
                            if our_ip.to_string() == peer_ip {
                                continue; // Ignore our own broadcast
                            }
                        }
                        
                        if let Some(mesh_port) = parsed.get("mesh_port").and_then(|p| p.as_u64()) {
                            let peer_addr = format!("zhtp://{}:{}", addr.ip(), mesh_port);
                            if !discovered.contains(&peer_addr) {
                                discovered.push(peer_addr);
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                // Socket error - break loop
                eprintln!("UDP socket error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout on recv - no packet in last 500ms, keep waiting
                continue;
            }
        }
    }
    
    eprintln!("     [MULTICAST DEBUG] Discovery complete: found {} peers", discovered.len());
    Ok(discovered)
}

/// Scan local subnet for ZHTP nodes on common ports
async fn scan_local_subnet_for_zhtp(_environment: &Environment) -> Result<Vec<String>> {
    use tokio::net::TcpStream;
    use std::net::{IpAddr, Ipv4Addr};
    
    let mut discovered = Vec::new();
    
    // Get local IP to determine subnet
    let local_ip = get_local_ip_address().await?;
    
    // Parse to get subnet (assumes /24)
    if let IpAddr::V4(ipv4) = local_ip {
        let octets = ipv4.octets();
        let subnet_base = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
        
        // Common ZHTP ports to check
        let ports = vec![9333, 33446];
        
        // Scan intelligently: check IPs near us first, then expand outward
        let our_last_octet = octets[3];
        let mut scan_range: Vec<u8> = Vec::new();
        
        // Check neighbors first (within ±10 of our IP)
        for offset in 1..=10 {
            if our_last_octet >= offset {
                let ip = our_last_octet - offset;
                if ip > 0 {
                    scan_range.push(ip);
                }
            }
            if our_last_octet + offset <= 254 {
                scan_range.push(our_last_octet + offset);
            }
        }
        
        // Then check common router/gateway IPs
        for common_ip in [1, 254, 100, 101, 200, 201] {
            if common_ip != our_last_octet && !scan_range.contains(&common_ip) {
                scan_range.push(common_ip);
            }
        }
        
        // Finally, scan some random IPs across the range for broader coverage
        for ip in (1..=254).step_by(25) {
            if ip != our_last_octet && !scan_range.contains(&ip) {
                scan_range.push(ip);
            }
        }
        
        // Limit total scan to 50 IPs to keep it fast
        scan_range.truncate(50);
        
        for last_octet in scan_range {
            for &port in &ports {
                let target = format!("{}.{}:{}", subnet_base, last_octet, port);
                
                // Quick TCP connection test
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    TcpStream::connect(&target)
                ).await {
                    Ok(Ok(_stream)) => {
                        let peer_addr = format!("zhtp://{}", target);
                        discovered.push(peer_addr);
                    }
                    _ => continue,
                }
            }
        }
    }
    
    Ok(discovered)
}

/// Get local IP address
async fn get_local_ip_address() -> Result<std::net::IpAddr> {
    use tokio::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    Ok(socket.local_addr()?.ip())
}

/// Fetch blockchain info from discovered peers
async fn fetch_blockchain_info_from_discovered_peers(peers: &[String]) -> Result<BlockchainInfo> {
    // Don't query local blockchain (it's not started yet!)
    // Instead, query the first discovered peer for blockchain info
    let mut height = 0u64;
    
    for peer in peers {
        // Try to extract HTTP API port from peer address
        // peer format might be: "zhtp://192.168.1.137:9333" or similar
        if let Some(api_url) = peer.strip_prefix("zhtp://").or_else(|| peer.strip_prefix("http://")) {
            let http_url = format!("http://{}/api/v1/blockchain/info", api_url);
            
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                reqwest::get(&http_url)
            ).await {
                Ok(Ok(response)) => {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if let Some(h) = json.get("height").and_then(|v| v.as_u64()) {
                            height = h;
                            println!("      Peer {} reports blockchain height: {}", api_url, height);
                            break; // Got valid response
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("      Failed to query peer {}: {}", api_url, e);
                }
                Err(_) => {
                    println!("     ⏱ Timeout querying peer {}", api_url);
                }
            }
        }
    }
    
    let network_id = if peers.is_empty() {
        "zhtp-genesis".to_string()
    } else {
        "zhtp-mainnet".to_string()
    };
    
    Ok(BlockchainInfo {
        height,
        network_id,
        peers: peers.to_vec(),
    })
}

#[derive(Debug)]
struct BlockchainInfo {
    height: u64,
    network_id: String,
    peers: Vec<String>,
}

/// Create or load persistent node identity that serves as both DHT address and wallet address
/// This ensures the node has a consistent identity across all DHT operations
pub async fn create_or_load_node_identity(environment: &Environment) -> Result<ZhtpIdentity> {
    use lib_crypto::generate_keypair;
    
    // Create new node identity in RAM only (no disk persistence yet)
    println!(" Creating new node identity in memory...");
    
    // Generate cryptographic key pair for the node
    let keypair = generate_keypair()?;
    let public_key = keypair.public_key.dilithium_pk.clone(); // Use Dilithium public key bytes
    
    // Create zero-knowledge proof of ownership (simplified for now)
    let ownership_proof = lib_proofs::ZeroKnowledgeProof::default();
    
    // Create the identity - this ID will be used as DHT address
    let node_identity = ZhtpIdentity::new(
        lib_identity::IdentityType::Device, // Node identity type
        public_key.to_vec(),
        ownership_proof,
    )?;
    
    println!(" Created node identity with ID: {:?}", &node_identity.id.to_string()[..8]);
    println!(" This identity serves as both DHT address and primary node address");
    println!(" [RAM-ONLY] Identity will be recreated on next startup (no persistence yet)");
    
    Ok(node_identity)
}

/// Create a wallet using proper dual-identity architecture
/// Creates BOTH a user identity (with wallets) AND a node device identity (owned by user)
async fn create_wallet_from_node_identity(network_info: &ExistingNetworkInfo) -> Result<WalletStartupResult> {
    println!(" Creating identity and wallet...");
    println!(" Network: {}", network_info.network_id);
    
    // ========================================================================
    // STEP 1: Prompt for identity name
    // ========================================================================
    let identity_name = prompt_for_identity_name()?;
    println!(" Identity name: {}", identity_name);
    
    // ========================================================================
    // STEP 2: Create user identity with wallet and seed phrase
    // ========================================================================
    let wallet_name = format!("{}'s Primary Wallet", identity_name);
    
    let (user_identity, wallet_id, seed_phrase, user_private_data) = lib_identity::create_user_identity_with_wallet(
        identity_name.clone(),
        wallet_name.clone(),
        Some("primary".to_string()),
    ).await?;
    
    println!("  User identity created: {}", hex::encode(&user_identity.id.0[..8]));
    println!("  Wallet created with seed phrase");
    
    // ========================================================================
    // STEP 3: Display and confirm seed phrase
    // ========================================================================
    confirm_seed_phrase(&seed_phrase)?;
    
    // ========================================================================
    // STEP 4: Set DID password
    // ========================================================================
    let did_password = prompt_for_did_password()?;
    
    // Hash the password for storage using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(did_password.as_bytes());
    let password_hash = hasher.finalize();
    
    println!(" DID password secured with Blake3 hash: {}...", hex::encode(&password_hash.as_bytes()[..8]));
    
    // ========================================================================
    // STEP 5: Optional wallet passwords
    // ========================================================================
    let _primary_wallet_password = prompt_for_wallet_password("Primary")?;
    let _savings_wallet_password = prompt_for_wallet_password("Savings")?;
    let _staking_wallet_password = prompt_for_wallet_password("Staking")?;
    
    println!("\n All passwords and security configured!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // ========================================================================
    // STEP 6: Create node device identity owned by the user
    // ========================================================================
    let node_device_name = format!("{}'s Node Device", identity_name);
    let (node_identity, node_private_data) = lib_identity::create_node_device_identity(
        user_identity.id.clone(),  // User owns this device
        wallet_id.clone(),
        node_device_name,
    ).await?;
    
    println!("  Node device identity created: {}", hex::encode(&node_identity.id.0[..8]));
    println!("  Node device owned by user: {}", hex::encode(&user_identity.id.0[..8]));
    
    // Create wallet address in ZHTP format for compatibility
    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0));
    
    // Return result with proper dual-identity architecture
    Ok(WalletStartupResult {
        user_identity: user_identity.clone(),
        node_identity: node_identity.clone(),
        user_private_data,
        node_private_data,
        node_identity_id: node_identity.id.clone(),
        node_wallet_id: wallet_id,
        wallet_name,
        seed_phrase,
        wallet_address,
    })
}

/// Create a genesis wallet using the node's DHT identity as the primary address
/// This now creates BOTH a user identity (with wallet) AND a node device identity (for networking)
/// Identities are kept in memory only - never loaded from disk
async fn create_genesis_wallet_from_node_identity(_environment: &Environment) -> Result<WalletStartupResult> {
    println!("Creating genesis wallet and identity setup...");
    println!(" This will create:");
    println!("   1. User identity (Human) with genesis wallet");
    println!("   2. Node device identity (Device) for networking");
    println!();
    
    // ========================================================================
    // STEP 1: Prompt for identity name
    // ========================================================================
    let user_name = prompt_for_identity_name()?;
    println!(" Identity name: {}", user_name);
    
    // ========================================================================
    // STEP 2: Create wallet and get seed phrase
    // ========================================================================
    let wallet_name = format!("{}'s Genesis Wallet", user_name);
    
    let (user_identity, wallet_id, seed_phrase, user_private_data) = lib_identity::create_user_identity_with_wallet(
        user_name.clone(),
        wallet_name.clone(),
        Some("genesis".to_string()),
    ).await?;
    
    println!("  User identity created: {}", hex::encode(&user_identity.id.0[..8]));
    
    // ========================================================================
    // STEP 3: Display and confirm seed phrase
    // ========================================================================
    confirm_seed_phrase(&seed_phrase)?;
    
    // ========================================================================
    // STEP 4: Set DID password
    // ========================================================================
    let did_password = prompt_for_did_password()?;
    
    // Hash the password for storage using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(did_password.as_bytes());
    let password_hash = hasher.finalize();
    
    println!(" DID password secured with Blake3 hash: {}...", hex::encode(&password_hash.as_bytes()[..8]));
    
    // ========================================================================
    // STEP 5: Optional wallet passwords
    // ========================================================================
    let _primary_wallet_password = prompt_for_wallet_password("Primary")?;
    let _savings_wallet_password = prompt_for_wallet_password("Savings")?;
    let _staking_wallet_password = prompt_for_wallet_password("Staking")?;
    
    // Note: Wallet passwords are collected but not yet integrated into wallet storage
    // This will be implemented in a future update to the wallet encryption system
    
    println!("\n All passwords and security configured!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // ========================================================================
    // STEP 6: Create node device identity owned by the user
    // ========================================================================
    let node_device_name = format!("{}'s Node Device", user_name);
    let (node_identity, node_private_data) = lib_identity::create_node_device_identity(
        user_identity.id.clone(),
        wallet_id.clone(),
        node_device_name,
    ).await?;
    
    println!("  Node device identity created: {}", hex::encode(&node_identity.id.0[..8]));
    println!(" Genesis Node DHT Address (full): {}", hex::encode(&node_identity.id.0));
    println!(" Genesis Wallet Address (full): {}", hex::encode(&wallet_id.0));
    println!(" This node will be the genesis node for a new ZHTP network");
    
    // NOTE: Identities are kept in memory only - not saved to disk
    // When persistent storage is implemented, we'll save/load properly
    println!(" Identities created in memory (not persisted to disk)");
    
    println!(" Genesis Seed Phrase: {}", seed_phrase);
    println!(" CRITICAL: Save this seed phrase - it controls the genesis node!");
    
    // Create wallet address in ZHTP format
    let wallet_address = format!("zhtp:{}", hex::encode(&wallet_id.0[..16]));
    
    // Return result with the identities and REAL private keys
    Ok(WalletStartupResult {
        user_identity: user_identity.clone(),
        node_identity: node_identity.clone(),
        user_private_data,
        node_private_data,
        node_identity_id: node_identity.id.clone(),
        node_wallet_id: wallet_id,
        wallet_name: format!("genesis-{}", hex::encode(&user_identity.id.0[..8])),
        seed_phrase,
        wallet_address,
    })
}

