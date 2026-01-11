//! Configuration types for the GraphQL Security agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for the GraphQL Security agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphQLSecurityConfig {
    /// Config version
    pub version: String,

    /// General settings
    pub settings: SettingsConfig,

    /// Depth limiting configuration
    pub depth: DepthConfig,

    /// Complexity/cost analysis configuration
    pub complexity: ComplexityConfig,

    /// Alias limiting configuration
    pub aliases: AliasConfig,

    /// Batch query limiting configuration
    pub batch: BatchConfig,

    /// Introspection control configuration
    pub introspection: IntrospectionConfig,

    /// Field-level authorization configuration
    pub field_auth: FieldAuthConfig,

    /// Persisted queries / allowlist configuration
    pub persisted_queries: PersistedQueriesConfig,
}

impl Default for GraphQLSecurityConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            settings: SettingsConfig::default(),
            depth: DepthConfig::default(),
            complexity: ComplexityConfig::default(),
            aliases: AliasConfig::default(),
            batch: BatchConfig::default(),
            introspection: IntrospectionConfig::default(),
            field_auth: FieldAuthConfig::default(),
            persisted_queries: PersistedQueriesConfig::default(),
        }
    }
}

/// General settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SettingsConfig {
    /// Maximum body size to process (bytes)
    pub max_body_size: usize,

    /// Add debug headers (X-GraphQL-*) to responses
    pub debug_headers: bool,

    /// Action on failure: "block" or "allow"
    pub fail_action: FailAction,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            max_body_size: 1_048_576, // 1MB
            debug_headers: false,
            fail_action: FailAction::Block,
        }
    }
}

/// Failure action when violations are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailAction {
    /// Block the request
    Block,
    /// Allow the request (log only)
    Allow,
}

impl Default for FailAction {
    fn default() -> Self {
        Self::Block
    }
}

/// Depth limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DepthConfig {
    /// Enable depth limiting
    pub enabled: bool,

    /// Maximum nesting depth allowed
    pub max_depth: u32,

    /// Don't count introspection queries in depth calculation
    pub ignore_introspection: bool,
}

impl Default for DepthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 10,
            ignore_introspection: true,
        }
    }
}

/// Complexity/cost analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplexityConfig {
    /// Enable complexity analysis
    pub enabled: bool,

    /// Maximum calculated complexity allowed
    pub max_complexity: u64,

    /// Default cost per field
    pub default_field_cost: u64,

    /// Default multiplier for list fields
    pub default_list_multiplier: u64,

    /// Per-type costs (e.g., "User" -> 2)
    pub type_costs: HashMap<String, u64>,

    /// Per-field costs (e.g., "Query.users" -> 10)
    pub field_costs: HashMap<String, u64>,

    /// Arguments that indicate list size (e.g., "first", "limit")
    pub list_size_arguments: Vec<String>,
}

impl Default for ComplexityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_complexity: 1000,
            default_field_cost: 1,
            default_list_multiplier: 10,
            type_costs: HashMap::new(),
            field_costs: HashMap::new(),
            list_size_arguments: vec![
                "first".to_string(),
                "last".to_string(),
                "limit".to_string(),
                "pageSize".to_string(),
            ],
        }
    }
}

/// Alias limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AliasConfig {
    /// Enable alias limiting
    pub enabled: bool,

    /// Maximum aliases per query
    pub max_aliases: u32,

    /// Maximum times the same field can be aliased
    pub max_duplicate_aliases: u32,
}

impl Default for AliasConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_aliases: 10,
            max_duplicate_aliases: 3,
        }
    }
}

/// Batch query limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BatchConfig {
    /// Enable batch query limiting
    pub enabled: bool,

    /// Maximum queries in a batch
    pub max_queries: u32,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_queries: 5,
        }
    }
}

/// Introspection control configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntrospectionConfig {
    /// Enable introspection control
    pub enabled: bool,

    /// Allow introspection queries
    pub allow: bool,

    /// Client IPs or header values that can introspect
    pub allowed_clients: Vec<String>,

    /// Header to check for allowed clients (e.g., "X-Introspection-Key")
    pub allowed_clients_header: Option<String>,

    /// Allow __typename (needed for Apollo Client)
    pub allow_typename: bool,
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: false,
            allowed_clients: Vec::new(),
            allowed_clients_header: None,
            allow_typename: true,
        }
    }
}

/// Field-level authorization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FieldAuthConfig {
    /// Enable field-level authorization
    pub enabled: bool,

    /// Authorization rules
    pub rules: Vec<FieldAuthRule>,
}

impl Default for FieldAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: Vec::new(),
        }
    }
}

/// Single field authorization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAuthRule {
    /// Fields this rule applies to (supports glob patterns like "User.*")
    pub fields: Vec<String>,

    /// Required roles (any of these roles grants access)
    #[serde(default)]
    pub require_roles: Vec<String>,

    /// Header containing comma-separated roles
    #[serde(default)]
    pub roles_header: Option<String>,

    /// Required scopes (any of these scopes grants access)
    #[serde(default)]
    pub require_scopes: Vec<String>,

    /// Header containing comma-separated scopes
    #[serde(default)]
    pub scopes_header: Option<String>,
}

/// Persisted queries / allowlist configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedQueriesConfig {
    /// Enable persisted queries
    pub enabled: bool,

    /// Mode: "allowlist" (only allowed hashes) or "cache" (any query, cached)
    pub mode: PersistedQueryMode,

    /// Path to allowlist JSON file (for allowlist mode)
    pub allowlist_file: Option<String>,

    /// Require APQ hash extension
    pub require_hash: bool,
}

impl Default for PersistedQueriesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: PersistedQueryMode::Allowlist,
            allowlist_file: None,
            require_hash: false,
        }
    }
}

/// Persisted query mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PersistedQueryMode {
    /// Only queries in the allowlist are permitted
    Allowlist,
    /// Any query is allowed, cached for performance
    Cache,
}

impl Default for PersistedQueryMode {
    fn default() -> Self {
        Self::Allowlist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GraphQLSecurityConfig::default();
        assert!(config.depth.enabled);
        assert_eq!(config.depth.max_depth, 10);
        assert!(config.complexity.enabled);
        assert_eq!(config.complexity.max_complexity, 1000);
        assert!(config.introspection.enabled);
        assert!(!config.introspection.allow);
    }

    #[test]
    fn test_config_serialization() {
        let config = GraphQLSecurityConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: GraphQLSecurityConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.depth.max_depth, config.depth.max_depth);
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
version: "1"
settings:
  debug_headers: true
  max_body_size: 2097152
depth:
  max_depth: 15
complexity:
  max_complexity: 2000
  field_costs:
    Query.users: 10
    Query.orders: 15
"#;
        let config: GraphQLSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.settings.debug_headers);
        assert_eq!(config.settings.max_body_size, 2_097_152);
        assert_eq!(config.depth.max_depth, 15);
        assert_eq!(config.complexity.max_complexity, 2000);
        assert_eq!(config.complexity.field_costs.get("Query.users"), Some(&10));
    }
}
