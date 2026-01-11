//! GraphQL Security Agent for Sentinel
//!
//! Provides GraphQL-specific security controls including query depth limiting,
//! complexity analysis, introspection control, and field-level authorization.
//!
//! # Features
//!
//! - Query depth limiting (prevent deeply nested queries)
//! - Complexity/cost analysis (prevent expensive queries)
//! - Alias limiting (prevent alias-based attacks)
//! - Batch query limiting (limit operations per request)
//! - Introspection control (block in production)
//! - Field-level authorization (role/scope-based)
//! - Persisted queries / allowlist mode
//!
//! # Example
//!
//! ```ignore
//! use sentinel_agent_graphql_security::GraphQLSecurityAgent;
//! use sentinel_agent_sdk::AgentRunner;
//!
//! let agent = GraphQLSecurityAgent::new(config)?;
//! AgentRunner::new(agent)
//!     .with_socket("/tmp/graphql-security.sock")
//!     .run()
//!     .await?;
//! ```

pub mod agent;
pub mod analyzer;
pub mod config;
pub mod error;
pub mod parser;

pub use agent::GraphQLSecurityAgent;
pub use config::GraphQLSecurityConfig;
pub use error::{GraphQLError, ViolationCode};
