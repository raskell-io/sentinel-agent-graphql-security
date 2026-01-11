//! Batch query analyzer.
//!
//! Limits the number of operations in a batch GraphQL request.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::BatchConfig;
use crate::error::Violation;
use crate::parser::ParsedDocument;
use async_trait::async_trait;
use tracing::debug;

/// Analyzer that limits batch query count.
pub struct BatchAnalyzer {
    config: BatchConfig,
}

impl BatchAnalyzer {
    /// Create a new batch analyzer.
    pub fn new(config: BatchConfig) -> Self {
        Self { config }
    }
}

#[async_trait(?Send)]
impl Analyzer for BatchAnalyzer {
    fn name(&self) -> &'static str {
        "batch"
    }

    async fn analyze(
        &self,
        _document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult {
        let batch_count = ctx.batch_count as u32;

        debug!(
            correlation_id = %ctx.correlation_id,
            is_batch = ctx.is_batch,
            batch_count = batch_count,
            max_queries = self.config.max_queries,
            "Batch analysis complete"
        );

        let metrics = AnalysisMetrics {
            operations: Some(batch_count),
            ..Default::default()
        };

        if ctx.is_batch && batch_count > self.config.max_queries {
            AnalysisResult {
                violations: vec![Violation::too_many_batch_queries(
                    batch_count,
                    self.config.max_queries,
                )],
                metrics,
            }
        } else {
            AnalysisResult::with_metrics(metrics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;
    use std::collections::HashMap;

    fn test_config() -> BatchConfig {
        BatchConfig {
            enabled: true,
            max_queries: 5,
        }
    }

    fn test_context_single() -> AnalysisContext {
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

    fn test_context_batch(count: usize) -> AnalysisContext {
        AnalysisContext {
            correlation_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            headers: HashMap::new(),
            operation_name: None,
            variables: None,
            extensions: None,
            is_batch: true,
            batch_count: count,
            query: String::new(),
        }
    }

    #[tokio::test]
    async fn test_single_query() {
        let analyzer = BatchAnalyzer::new(test_config());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context_single();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.operations, Some(1));
    }

    #[tokio::test]
    async fn test_batch_within_limit() {
        let analyzer = BatchAnalyzer::new(test_config());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context_batch(3);

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.operations, Some(3));
    }

    #[tokio::test]
    async fn test_batch_at_limit() {
        let analyzer = BatchAnalyzer::new(test_config());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context_batch(5);

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.operations, Some(5));
    }

    #[tokio::test]
    async fn test_batch_exceeds_limit() {
        let analyzer = BatchAnalyzer::new(test_config());
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context_batch(10);

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::TooManyBatchQueries
        );
        assert_eq!(result.metrics.operations, Some(10));
    }

    #[tokio::test]
    async fn test_non_batch_large_count_ignored() {
        // If is_batch is false, we don't enforce the limit
        let analyzer = BatchAnalyzer::new(test_config());
        let doc = parse_query("{ users { id } }").unwrap();
        let mut ctx = test_context_single();
        ctx.batch_count = 100; // High count but not a batch

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
    }
}
