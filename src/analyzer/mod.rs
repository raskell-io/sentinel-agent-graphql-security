//! GraphQL security analyzers.
//!
//! Each analyzer checks for a specific security concern in GraphQL queries.

pub mod aliases;
pub mod batch;
pub mod complexity;
pub mod depth;
pub mod fields;
pub mod introspection;
pub mod persisted;

use crate::error::Violation;
use crate::parser::ParsedDocument;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use aliases::AliasAnalyzer;
pub use batch::BatchAnalyzer;
pub use complexity::ComplexityAnalyzer;
pub use depth::DepthAnalyzer;
pub use fields::FieldAuthAnalyzer;
pub use introspection::IntrospectionAnalyzer;
pub use persisted::PersistedQueryAnalyzer;

/// Context for analysis containing request information.
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Request correlation ID
    pub correlation_id: String,
    /// Client IP address
    pub client_ip: String,
    /// Request headers
    pub headers: HashMap<String, Vec<String>>,
    /// Operation name (if provided)
    pub operation_name: Option<String>,
    /// Variables (if provided)
    pub variables: Option<serde_json::Value>,
    /// Extensions (e.g., APQ hash)
    pub extensions: Option<serde_json::Value>,
    /// Whether this is a batch request
    pub is_batch: bool,
    /// Number of queries in batch
    pub batch_count: usize,
    /// The raw query string
    pub query: String,
}

impl AnalysisContext {
    /// Get a header value (first value if multiple).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Get all values for a header.
    pub fn header_values(&self, name: &str) -> Option<&Vec<String>> {
        self.headers.get(&name.to_lowercase())
    }

    /// Parse comma-separated values from a header.
    pub fn header_csv(&self, name: &str) -> Vec<String> {
        self.header(name)
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Result of running an analyzer.
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// Violations found
    pub violations: Vec<Violation>,
    /// Metrics collected
    pub metrics: AnalysisMetrics,
}

impl AnalysisResult {
    /// Create an empty result (no violations).
    pub fn ok() -> Self {
        Self::default()
    }

    /// Create a result with a single violation.
    pub fn violation(violation: Violation) -> Self {
        Self {
            violations: vec![violation],
            metrics: AnalysisMetrics::default(),
        }
    }

    /// Create a result with metrics only.
    pub fn with_metrics(metrics: AnalysisMetrics) -> Self {
        Self {
            violations: Vec::new(),
            metrics,
        }
    }

    /// Add a violation to the result.
    pub fn add_violation(mut self, violation: Violation) -> Self {
        self.violations.push(violation);
        self
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: AnalysisResult) {
        self.violations.extend(other.violations);
        self.metrics.merge(other.metrics);
    }

    /// Check if there are any violations.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }
}

/// Metrics collected during analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    /// Query depth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// Query complexity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<u64>,
    /// Number of aliases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<u32>,
    /// Number of operations (batch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations: Option<u32>,
    /// Number of fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<u32>,
}

impl AnalysisMetrics {
    /// Merge another metrics into this one.
    pub fn merge(&mut self, other: AnalysisMetrics) {
        if other.depth.is_some() {
            self.depth = other.depth;
        }
        if other.complexity.is_some() {
            self.complexity = other.complexity;
        }
        if other.aliases.is_some() {
            self.aliases = other.aliases;
        }
        if other.operations.is_some() {
            self.operations = other.operations;
        }
        if other.fields.is_some() {
            self.fields = other.fields;
        }
    }
}

/// Trait for GraphQL security analyzers.
///
/// Note: Using `?Send` because `ParsedDocument` contains a rowan `SyntaxNode`
/// which is not `Sync`, so we can't hold references to it across await points
/// in Send futures.
#[async_trait(?Send)]
pub trait Analyzer: Send + Sync {
    /// Analyzer name for logging.
    fn name(&self) -> &'static str;

    /// Analyze a parsed GraphQL document.
    async fn analyze(
        &self,
        document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_context_header() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-user-roles".to_string(),
            vec!["admin, user".to_string()],
        );
        headers.insert("authorization".to_string(), vec!["Bearer xyz".to_string()]);

        let ctx = AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers,
            operation_name: None,
            variables: None,
            extensions: None,
            is_batch: false,
            batch_count: 1,
            query: "{ test }".to_string(),
        };

        assert_eq!(ctx.header("X-User-Roles"), Some("admin, user"));
        assert_eq!(ctx.header("Authorization"), Some("Bearer xyz"));
        assert_eq!(ctx.header("Missing"), None);
    }

    #[test]
    fn test_analysis_context_header_csv() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-user-roles".to_string(),
            vec!["admin, user, guest".to_string()],
        );

        let ctx = AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers,
            operation_name: None,
            variables: None,
            extensions: None,
            is_batch: false,
            batch_count: 1,
            query: "{ test }".to_string(),
        };

        let roles = ctx.header_csv("X-User-Roles");
        assert_eq!(roles, vec!["admin", "user", "guest"]);
    }

    #[test]
    fn test_analysis_result_merge() {
        let mut result1 = AnalysisResult::with_metrics(AnalysisMetrics {
            depth: Some(5),
            ..Default::default()
        });

        let result2 = AnalysisResult {
            violations: vec![Violation::depth_exceeded(15, 10)],
            metrics: AnalysisMetrics {
                complexity: Some(100),
                ..Default::default()
            },
        };

        result1.merge(result2);

        assert_eq!(result1.violations.len(), 1);
        assert_eq!(result1.metrics.depth, Some(5));
        assert_eq!(result1.metrics.complexity, Some(100));
    }
}
