//! Zentinel GraphQL Security Agent binary (Protocol v2).
//!
//! Run with: `zentinel-agent-graphql-security --config config.yaml`
//!
//! Supports gRPC transport for v2 protocol:
//! - gRPC: `--grpc-address 0.0.0.0:50051` (recommended for v2 features)
//! - UDS: `--socket /tmp/graphql-security.sock`

use anyhow::{Context, Result};
use clap::Parser;
use zentinel_agent_graphql_security::{GraphQLSecurityAgent, GraphQLSecurityConfig};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use std::path::PathBuf;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// GraphQL Security Agent for Zentinel proxy (Protocol v2).
///
/// This agent analyzes GraphQL queries for security concerns including:
/// - Query depth limiting
/// - Complexity/cost analysis
/// - Alias limiting
/// - Batch query limiting
/// - Introspection control
/// - Field-level authorization
/// - Persisted queries / allowlist mode
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (YAML)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Unix socket path for agent communication (UDS transport)
    #[arg(short, long, default_value = "/tmp/zentinel-graphql-security.sock")]
    socket: PathBuf,

    /// gRPC address for agent communication (e.g., 0.0.0.0:50051)
    ///
    /// When specified, the agent runs as a gRPC server with full v2 protocol support
    /// including capability negotiation, health reporting, and metrics export.
    #[arg(long)]
    grpc_address: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse().unwrap_or(Level::INFO);
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    info!(
        "Starting Zentinel GraphQL Security Agent v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Protocol version: v2");
    info!("Config file: {}", args.config.display());

    // Load configuration
    let config = if args.config.exists() {
        let content = tokio::fs::read_to_string(&args.config)
            .await
            .context("Failed to read config file")?;
        serde_yaml::from_str(&content).context("Failed to parse config file")?
    } else {
        info!("Config file not found, using defaults");
        GraphQLSecurityConfig::default()
    };

    // Create the agent with async initialization
    let agent = GraphQLSecurityAgent::with_async_init(config)
        .await
        .context("Failed to create agent")?;

    info!("Agent initialized successfully");

    // Run the agent with the appropriate transport
    if let Some(grpc_addr) = args.grpc_address {
        // gRPC transport - full v2 protocol support
        info!("Starting gRPC server on {}", grpc_addr);
        let addr = grpc_addr.parse().context("Invalid gRPC address format")?;

        let server = GrpcAgentServerV2::new("graphql-security", Box::new(agent));

        // Set up graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal");
        };

        tokio::select! {
            result = server.run(addr) => {
                result.context("gRPC server error")?;
            }
            _ = shutdown => {
                info!("Shutting down gRPC server");
            }
        }
    } else {
        // UDS transport (v2 protocol)
        info!("Socket path: {}", args.socket.display());

        let server = UdsAgentServerV2::new(
            "graphql-security",
            &args.socket,
            Box::new(agent),
        );

        // Set up graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal");
        };

        tokio::select! {
            result = server.run() => {
                result.context("UDS server error")?;
            }
            _ = shutdown => {
                info!("Shutting down UDS server");
            }
        }
    }

    info!("Agent stopped");
    Ok(())
}
