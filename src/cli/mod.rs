//! ZHTP Orchestrator CLI
//! 
//! Command-line interface for the ZHTP orchestrator that provides
//! high-level user commands and coordinates Level 2 components

pub mod commands;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;

/// ZHTP Orchestrator CLI
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[command(name = "zhtp")]
pub struct ZhtpCli {
    /// API server address
    #[arg(short, long, default_value = "127.0.0.1:9333")]
    pub server: String,
    
    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Output format (json, yaml, table)
    #[arg(short, long, default_value = "table")]
    pub format: String,
    
    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<String>,
    
    /// API key for authentication
    #[arg(long)]
    pub api_key: Option<String>,
    
    /// User ID for authenticated requests
    #[arg(long)]
    pub user_id: Option<String>,
    
    #[command(subcommand)]
    pub command: ZhtpCommand,
}

/// ZHTP Orchestrator commands
#[derive(Subcommand, Debug, Clone)]
pub enum ZhtpCommand {
    /// Start the ZHTP orchestrator node
    Node(NodeArgs),
    
    /// Wallet operations (orchestrated)
    Wallet(WalletArgs),
    
    /// DAO operations (orchestrated)
    Dao(DaoArgs),
    
    /// Identity operations (orchestrated)
    Identity(IdentityArgs),

    /// Backup operations (encrypted backup files)
    Backup(BackupArgs),

    /// Guardian management for social recovery
    Guardian(GuardianArgs),

    /// Network operations (orchestrated)
    Network(NetworkArgs),
    
    /// Blockchain operations (orchestrated)
    Blockchain(BlockchainArgs),
    
    /// System monitoring and status
    Monitor(MonitorArgs),
    
    /// Component management
    Component(ComponentArgs),
    
    /// Interactive shell
    Interactive(InteractiveArgs),
    
    /// Server management
    Server(ServerArgs),
    
    /// Network isolation management
    Isolation(IsolationArgs),
}

/// Node management commands
#[derive(Args, Debug, Clone)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub action: NodeAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NodeAction {
    /// Start the ZHTP orchestrator node
    Start {
        /// Configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Port to bind to (overrides config file mesh_port if specified)
        #[arg(short, long)]
        port: Option<u16>,
        /// Enable development mode
        #[arg(long)]
        dev: bool,
        /// Enable pure mesh mode (ISP-free networking)
        #[arg(long)]
        pure_mesh: bool,
        /// Network environment (overrides config file)
        #[arg(short, long, value_parser = ["mainnet", "testnet", "dev"])]
        network: Option<String>,
    },
    /// Stop the orchestrator node
    Stop,
    /// Get node status
    Status,
    /// Restart the node
    Restart,
}

/// Wallet operation commands
#[derive(Args, Debug, Clone)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub action: WalletAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum WalletAction {
    /// Create new wallet (orchestrated)
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: String,
        /// Wallet type
        #[arg(short, long, default_value = "citizen")]
        wallet_type: String,
    },
    /// Get wallet balance (orchestrated)
    Balance {
        /// Wallet address
        address: String,
    },
    /// Transfer funds (orchestrated)
    Transfer {
        /// From wallet
        #[arg(short, long)]
        from: String,
        /// To wallet
        #[arg(short, long)]
        to: String,
        /// Amount to transfer
        #[arg(short, long)]
        amount: u64,
    },
    /// Get transaction history (orchestrated)
    History {
        /// Wallet address
        address: String,
    },
    /// List all wallets
    List,
}

/// DAO operation commands
#[derive(Args, Debug, Clone)]
pub struct DaoArgs {
    #[command(subcommand)]
    pub action: DaoAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DaoAction {
    /// Get DAO information (orchestrated)
    Info,
    /// Create new proposal (orchestrated)
    Propose {
        /// Proposal title
        #[arg(short, long)]
        title: String,
        /// Proposal description
        #[arg(short, long)]
        description: String,
    },
    /// Vote on proposal (orchestrated)
    Vote {
        /// Proposal ID
        #[arg(short, long)]
        proposal_id: String,
        /// Vote choice (yes/no/abstain)
        #[arg(short, long)]
        choice: String,
    },
    /// Claim UBI (orchestrated)
    ClaimUbi,
}

/// Identity operation commands
#[derive(Args, Debug, Clone)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub action: IdentityAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityAction {
    /// Create new identity (orchestrated)
    Create {
        /// Identity name
        name: String,
    },
    /// Create zero-knowledge DID identity
    CreateDid {
        /// Identity name
        name: String,
        /// Identity type (human, organization, device, service)
        #[arg(short, long, default_value = "human")]
        identity_type: String,
        /// Recovery options
        #[arg(short, long)]
        recovery_options: Vec<String>,
    },
    /// Verify identity (orchestrated)
    Verify {
        /// Identity ID
        identity_id: String,
    },
    /// List identities
    List,
    /// Restore identity from seed phrases
    RestoreFromSeeds {
        /// Primary wallet seed phrase (20 words, space-separated)
        #[arg(long)]
        primary_seed: String,
        /// UBI wallet seed phrase (20 words, space-separated)
        #[arg(long)]
        ubi_seed: String,
        /// Savings wallet seed phrase (20 words, space-separated)
        #[arg(long)]
        savings_seed: String,
        /// Display name for the restored identity
        #[arg(long)]
        display_name: String,
        /// Optional password to set
        #[arg(long)]
        password: Option<String>,
    },
    /// Verify a seed phrase without importing
    VerifySeed {
        /// Seed phrase to verify (20 words, space-separated)
        #[arg(long)]
        seed_phrase: String,
        /// Wallet type (primary, ubi, savings)
        #[arg(long)]
        wallet_type: Option<String>,
    },
    /// Export seed phrases for an identity (DANGEROUS - requires password)
    ExportSeeds {
        /// Identity ID to export seeds for
        #[arg(long)]
        identity_id: String,
        /// Password for authentication
        #[arg(long)]
        password: String,
        /// Optional output file path
        #[arg(long)]
        output: Option<String>,
    },
}

/// Backup operation commands
#[derive(Args, Debug, Clone)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub action: BackupAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BackupAction {
    /// Export identity to encrypted backup file
    Export {
        /// Identity ID to export
        #[arg(long)]
        identity_id: String,
        /// Password to encrypt backup
        #[arg(long)]
        password: String,
        /// Output file path
        #[arg(long)]
        output: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Import identity from encrypted backup file
    Import {
        /// Backup file path
        #[arg(long)]
        input: String,
        /// Password to decrypt backup
        #[arg(long)]
        password: String,
    },
    /// Verify backup file integrity
    Verify {
        /// Backup file path
        #[arg(long)]
        input: String,
    },
}

/// Guardian operation commands
#[derive(Args, Debug, Clone)]
pub struct GuardianArgs {
    #[command(subcommand)]
    pub action: GuardianAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GuardianAction {
    /// Add a new guardian
    Add {
        /// Identity ID to add guardian for
        #[arg(long)]
        identity_id: String,
        /// Guardian display name
        #[arg(long)]
        name: String,
        /// Guardian email
        #[arg(long)]
        email: Option<String>,
        /// Guardian phone
        #[arg(long)]
        phone: Option<String>,
        /// Guardian's identity ID (if they're a user)
        #[arg(long)]
        guardian_identity_id: Option<String>,
    },
    /// List guardians for an identity
    List {
        /// Identity ID
        #[arg(long)]
        identity_id: String,
    },
    /// Remove a guardian
    Remove {
        /// Identity ID
        #[arg(long)]
        identity_id: String,
        /// Guardian ID to remove
        #[arg(long)]
        guardian_id: String,
    },
    /// Accept guardian invitation
    Accept {
        /// Guardian ID
        #[arg(long)]
        guardian_id: String,
        /// Verification code
        #[arg(long)]
        code: String,
    },
    /// Decline guardian invitation
    Decline {
        /// Guardian ID
        #[arg(long)]
        guardian_id: String,
    },
    /// Initiate recovery request
    InitiateRecovery {
        /// Identity ID to recover
        #[arg(long)]
        identity_id: String,
        /// New password
        #[arg(long)]
        new_password: String,
    },
    /// Approve recovery request (as a guardian)
    ApproveRecovery {
        /// Recovery request ID
        #[arg(long)]
        request_id: String,
        /// Guardian ID
        #[arg(long)]
        guardian_id: String,
        /// Verification code
        #[arg(long)]
        code: String,
    },
    /// Check recovery request status
    RecoveryStatus {
        /// Recovery request ID
        #[arg(long)]
        request_id: String,
    },
    /// Cancel a recovery request
    CancelRecovery {
        /// Recovery request ID
        #[arg(long)]
        request_id: String,
    },
}

/// Network operation commands
#[derive(Args, Debug, Clone)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub action: NetworkAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NetworkAction {
    /// Get network status (orchestrated)
    Status,
    /// Get connected peers (orchestrated)
    Peers,
    /// Test network connectivity
    Test,
}

/// Blockchain operation commands
#[derive(Args, Debug, Clone)]
pub struct BlockchainArgs {
    #[command(subcommand)]
    pub action: BlockchainAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BlockchainAction {
    /// Get blockchain status (orchestrated)
    Status,
    /// Get transaction info (orchestrated)
    Transaction {
        /// Transaction hash
        tx_hash: String,
    },
    /// Get blockchain stats
    Stats,
}

/// Monitoring commands
#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    #[command(subcommand)]
    pub action: MonitorAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MonitorAction {
    /// Show system monitoring
    System,
    /// Show component health
    Health,
    /// Show performance metrics
    Performance,
    /// Show system logs
    Logs,
}

/// Component management commands
#[derive(Args, Debug, Clone)]
pub struct ComponentArgs {
    #[command(subcommand)]
    pub action: ComponentAction,
}

/// Interactive shell commands
#[derive(Args, Debug, Clone)]
pub struct InteractiveArgs {
    /// Initial command to run
    #[arg(short, long)]
    pub command: Option<String>,
}

/// Server management commands
#[derive(Args, Debug, Clone)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub action: ServerAction,
}

/// Network isolation commands
#[derive(Args, Debug, Clone)]
pub struct IsolationArgs {
    #[command(subcommand)]
    pub action: IsolationAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ComponentAction {
    /// List all Level 2 components
    List,
    /// Start a component
    Start {
        /// Component name
        name: String,
    },
    /// Stop a component
    Stop {
        /// Component name
        name: String,
    },
    /// Restart a component
    Restart {
        /// Component name
        name: String,
    },
    /// Get component status
    Status {
        /// Component name
        name: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServerAction {
    /// Start the orchestrator server
    Start,
    /// Stop the orchestrator server
    Stop,
    /// Restart the orchestrator server
    Restart,
    /// Get server status
    Status,
    /// Get server configuration
    Config,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IsolationAction {
    /// Apply network isolation for pure mesh mode
    Apply,
    /// Check current isolation status
    Check,
    /// Remove network isolation
    Remove,
    /// Test network connectivity
    Test,
}

/// Main CLI runner
pub async fn run_cli() -> Result<()> {
    let cli = ZhtpCli::parse();
    
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    
    match &cli.command {
        ZhtpCommand::Node(args) => commands::node::handle_node_command(args.clone(), &cli).await,
        ZhtpCommand::Wallet(args) => commands::wallet::handle_wallet_command(args.clone(), &cli).await,
        ZhtpCommand::Dao(args) => commands::dao::handle_dao_command(args.clone(), &cli).await,
        ZhtpCommand::Identity(args) => commands::identity::handle_identity_command(args.clone(), &cli).await,
        ZhtpCommand::Backup(args) => commands::backup::handle_backup_command(args.clone(), &cli).await,
        ZhtpCommand::Guardian(args) => commands::guardian::handle_guardian_command(args.clone(), &cli).await,
        ZhtpCommand::Network(args) => commands::network::handle_network_command(args.clone(), &cli).await,
        ZhtpCommand::Blockchain(args) => commands::blockchain::handle_blockchain_command(args.clone(), &cli).await,
        ZhtpCommand::Monitor(args) => commands::monitor::handle_monitor_command(args.clone(), &cli).await,
        ZhtpCommand::Component(args) => commands::component::handle_component_command(args.clone(), &cli).await,
        ZhtpCommand::Interactive(args) => commands::interactive::handle_interactive_command(args.clone(), &cli).await,
        ZhtpCommand::Server(args) => commands::server::handle_server_command(args.clone(), &cli).await,
        ZhtpCommand::Isolation(args) => commands::isolation::handle_isolation_command(args.clone(), &cli).await,
    }
}

/// Format output based on CLI format preference
pub fn format_output(data: &Value, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(data)?),
        "yaml" => {
            #[cfg(feature = "yaml")]
            {
                Ok(serde_yaml::to_string(data)?)
            }
            #[cfg(not(feature = "yaml"))]
            {
                Ok(serde_json::to_string_pretty(data)?)
            }
        }
        "table" => {
            if let Some(obj) = data.as_object() {
                let mut result = String::new();
                for (key, value) in obj {
                    result.push_str(&format!("{:<20} {}\n", key, value));
                }
                Ok(result)
            } else if let Some(array) = data.as_array() {
                let mut result = String::new();
                for (i, item) in array.iter().enumerate() {
                    result.push_str(&format!("[{}] {}\n", i, item));
                }
                Ok(result)
            } else {
                Ok(data.to_string())
            }
        }
        _ => Err(anyhow::anyhow!("Unsupported output format: {}", format)),
    }
}

/// Parse command line arguments
pub fn parse_arguments() -> ZhtpCli {
    ZhtpCli::parse()
}

/// Display startup banner
pub fn display_startup_banner() {
    println!("
    ███████╗██╗  ██╗████████╗██████╗ 
    ╚══███╔╝██║  ██║╚══██╔══╝██╔══██╗
      ███╔╝ ███████║   ██║   ██████╔╝
     ███╔╝  ██╔══██║   ██║   ██╔═══╝ 
    ███████╗██║  ██║   ██║   ██║     
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     
    
    Zero-Knowledge Hypertext Transfer Protocol
    Orchestrator - Level 2 Components Manager
    ");
}

/// Interactive shell structure
pub struct InteractiveShell {
    // Shell state
}

impl InteractiveShell {
    pub async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

/// Start interactive shell
pub async fn start_interactive_shell() -> Result<InteractiveShell> {
    InteractiveShell::new().await
}
