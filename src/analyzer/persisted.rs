//! Persisted query analyzer.
//!
//! Enforces query allowlists or persisted query requirements.

use super::{AnalysisContext, AnalysisResult, Analyzer};
use crate::config::{PersistedQueriesConfig, PersistedQueryMode};
use crate::error::{GraphQLError, Violation};
use crate::parser::{get_apq_hash, ParsedDocument};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Analyzer that enforces persisted queries / allowlists.
pub struct PersistedQueryAnalyzer {
    config: PersistedQueriesConfig,
    /// Set of allowed query hashes
    allowlist: Arc<RwLock<HashSet<String>>>,
}

/// Format for allowlist JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllowlistFile {
    /// Version for future compatibility
    #[serde(default)]
    version: u32,
    /// List of allowed query hashes
    queries: Vec<AllowlistEntry>,
}

/// Entry in the allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllowlistEntry {
    /// SHA-256 hash of the query
    hash: String,
    /// Optional name/description for the query
    #[serde(default)]
    name: Option<String>,
}

impl PersistedQueryAnalyzer {
    /// Create a new persisted query analyzer.
    pub fn new(config: PersistedQueriesConfig) -> Self {
        Self {
            config,
            allowlist: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create analyzer and load allowlist from file.
    pub async fn with_allowlist(config: PersistedQueriesConfig) -> Result<Self, GraphQLError> {
        let analyzer = Self::new(config);
        analyzer.load_allowlist().await?;
        Ok(analyzer)
    }

    /// Load allowlist from configured file.
    pub async fn load_allowlist(&self) -> Result<(), GraphQLError> {
        let file_path = match &self.config.allowlist_file {
            Some(path) => path,
            None => return Ok(()), // No file configured
        };

        if !Path::new(file_path).exists() {
            warn!(path = %file_path, "Allowlist file not found, using empty allowlist");
            return Ok(());
        }

        let content = tokio::fs::read_to_string(file_path).await?;
        let allowlist_file: AllowlistFile = serde_json::from_str(&content)?;

        let mut allowlist = self.allowlist.write().await;
        allowlist.clear();
        for entry in allowlist_file.queries {
            allowlist.insert(entry.hash.to_lowercase());
        }

        debug!(
            path = %file_path,
            count = allowlist.len(),
            "Loaded query allowlist"
        );

        Ok(())
    }

    /// Check if a query hash is in the allowlist.
    async fn is_allowed(&self, hash: &str) -> bool {
        let allowlist = self.allowlist.read().await;
        allowlist.contains(&hash.to_lowercase())
    }

    /// Add a query hash to the allowlist (for cache mode).
    pub async fn add_to_cache(&self, hash: &str) {
        let mut allowlist = self.allowlist.write().await;
        allowlist.insert(hash.to_lowercase());
    }
}

#[async_trait(?Send)]
impl Analyzer for PersistedQueryAnalyzer {
    fn name(&self) -> &'static str {
        "persisted_queries"
    }

    async fn analyze(
        &self,
        document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult {
        // Get query hash - either from APQ extension or calculated
        let apq_hash = get_apq_hash(&ctx.extensions);
        let query_hash = apq_hash.as_ref().unwrap_or(&document.query_hash);

        // Check if hash is required
        if self.config.require_hash && apq_hash.is_none() {
            debug!(
                correlation_id = %ctx.correlation_id,
                "Query rejected: APQ hash required but not provided"
            );
            return AnalysisResult::violation(Violation::new(
                crate::error::ViolationCode::QueryNotAllowed,
                "Persisted query hash is required",
            ));
        }

        match self.config.mode {
            PersistedQueryMode::Allowlist => {
                // In allowlist mode, query must be in the allowlist
                if !self.is_allowed(query_hash).await {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        hash = %query_hash,
                        "Query not in allowlist"
                    );
                    return AnalysisResult::violation(Violation::query_not_allowed());
                }

                debug!(
                    correlation_id = %ctx.correlation_id,
                    hash = %query_hash,
                    "Query found in allowlist"
                );
            }
            PersistedQueryMode::Cache => {
                // In cache mode, we allow all queries but track them
                // The caching itself is handled at a higher level
                debug!(
                    correlation_id = %ctx.correlation_id,
                    hash = %query_hash,
                    "Query processed in cache mode"
                );
            }
        }

        AnalysisResult::ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{calculate_query_hash, parse_query};
    use serde_json::json;
    use std::collections::HashMap;

    fn test_config_allowlist() -> PersistedQueriesConfig {
        PersistedQueriesConfig {
            enabled: true,
            mode: PersistedQueryMode::Allowlist,
            allowlist_file: None,
            require_hash: false,
        }
    }

    fn test_config_cache() -> PersistedQueriesConfig {
        PersistedQueriesConfig {
            enabled: true,
            mode: PersistedQueryMode::Cache,
            allowlist_file: None,
            require_hash: false,
        }
    }

    fn test_context() -> AnalysisContext {
        AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers: HashMap::new(),
            operation_name: None,
            variables: None,
            extensions: None,
            is_batch: false,
            batch_count: 1,
            query: String::new(),
        }
    }

    #[tokio::test]
    async fn test_allowlist_query_not_found() {
        let analyzer = PersistedQueryAnalyzer::new(test_config_allowlist());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::QueryNotAllowed
        );
    }

    #[tokio::test]
    async fn test_allowlist_query_found() {
        let analyzer = PersistedQueryAnalyzer::new(test_config_allowlist());

        // Add the query hash to allowlist
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);
        analyzer.add_to_cache(&hash).await;

        let doc = parse_query(query).unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_cache_mode_allows_all() {
        let analyzer = PersistedQueryAnalyzer::new(test_config_cache());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_apq_hash_used() {
        let analyzer = PersistedQueryAnalyzer::new(test_config_allowlist());

        // Add a specific hash to allowlist
        let apq_hash = "abc123def456";
        analyzer.add_to_cache(apq_hash).await;

        let doc = parse_query("{ users { id } }").unwrap();
        let mut ctx = test_context();
        ctx.extensions = Some(json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": apq_hash
            }
        }));

        let result = analyzer.analyze(&doc, &ctx).await;

        // Should pass because APQ hash is in allowlist
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_require_hash() {
        let mut config = test_config_allowlist();
        config.require_hash = true;
        let analyzer = PersistedQueryAnalyzer::new(config);

        // Add the query hash to allowlist
        let query = "{ users { id } }";
        let hash = calculate_query_hash(query);
        analyzer.add_to_cache(&hash).await;

        let doc = parse_query(query).unwrap();
        let ctx = test_context(); // No APQ extension

        let result = analyzer.analyze(&doc, &ctx).await;

        // Should fail because APQ hash is required but not provided
        assert!(result.has_violations());
    }

    #[tokio::test]
    async fn test_require_hash_with_apq() {
        let mut config = test_config_allowlist();
        config.require_hash = true;
        let analyzer = PersistedQueryAnalyzer::new(config);

        let apq_hash = "abc123";
        analyzer.add_to_cache(apq_hash).await;

        let doc = parse_query("{ users { id } }").unwrap();
        let mut ctx = test_context();
        ctx.extensions = Some(json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": apq_hash
            }
        }));

        let result = analyzer.analyze(&doc, &ctx).await;

        // Should pass - APQ hash is provided and in allowlist
        assert!(!result.has_violations());
    }

    #[tokio::test]
    async fn test_case_insensitive_hash() {
        let analyzer = PersistedQueryAnalyzer::new(test_config_allowlist());

        // Add uppercase hash
        analyzer.add_to_cache("ABC123DEF456").await;

        let doc = parse_query("{ users { id } }").unwrap();
        let mut ctx = test_context();
        ctx.extensions = Some(json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "abc123def456"  // lowercase
            }
        }));

        let result = analyzer.analyze(&doc, &ctx).await;

        // Should match case-insensitively
        assert!(!result.has_violations());
    }
}
