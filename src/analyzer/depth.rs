//! Query depth analyzer.
//!
//! Calculates the maximum nesting depth of a GraphQL query and enforces limits.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::DepthConfig;
use crate::error::Violation;
use crate::parser::{FragmentInfo, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Analyzer that limits query depth.
pub struct DepthAnalyzer {
    config: DepthConfig,
}

impl DepthAnalyzer {
    /// Create a new depth analyzer.
    pub fn new(config: DepthConfig) -> Self {
        Self { config }
    }

    /// Calculate the maximum depth of a selection set.
    fn calculate_depth(
        &self,
        selection_set: &cst::SelectionSet,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
    ) -> u32 {
        let mut max_depth = 0;

        for selection in selection_set.selections() {
            let depth = match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Skip introspection fields if configured
                    if self.config.ignore_introspection && is_introspection_field(&field_name) {
                        0
                    } else {
                        let nested_depth = field
                            .selection_set()
                            .map(|ss| {
                                self.calculate_depth(&ss, fragments, visited_fragments)
                            })
                            .unwrap_or(0);
                        1 + nested_depth
                    }
                }
                cst::Selection::FragmentSpread(spread) => {
                    if let Some(name) = spread.fragment_name() {
                        if let Some(name_token) = name.name() {
                            let frag_name = name_token.text().to_string();

                            // Prevent infinite recursion from circular fragments
                            if visited_fragments.contains(&frag_name) {
                                0
                            } else {
                                visited_fragments.insert(frag_name.clone());
                                let depth = self.calculate_fragment_depth(
                                    &frag_name,
                                    fragments,
                                    visited_fragments,
                                );
                                visited_fragments.remove(&frag_name);
                                depth
                            }
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                }
                cst::Selection::InlineFragment(inline) => {
                    inline
                        .selection_set()
                        .map(|ss| {
                            self.calculate_depth(&ss, fragments, visited_fragments)
                        })
                        .unwrap_or(0)
                }
            };

            max_depth = max_depth.max(depth);
        }

        max_depth
    }

    /// Calculate depth through a fragment.
    fn calculate_fragment_depth(
        &self,
        fragment_name: &str,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
    ) -> u32 {
        if let Some(frag_info) = fragments.get(fragment_name) {
            // Re-parse the fragment's selection set to calculate depth
            if !frag_info.selection_set_text.is_empty() {
                // Wrap in a query to make it parseable
                let query = format!("{{ {} }}", frag_info.selection_set_text);
                let parser = apollo_parser::Parser::new(&query);
                let cst = parser.parse();

                if cst.errors().len() == 0 {
                    for def in cst.document().definitions() {
                        if let cst::Definition::OperationDefinition(op) = def {
                            if let Some(ss) = op.selection_set() {
                                return self.calculate_depth(&ss, fragments, visited_fragments);
                            }
                        }
                    }
                }
            }
        }
        0
    }
}

/// Check if a field name is an introspection field.
fn is_introspection_field(name: &str) -> bool {
    name.starts_with("__")
}

#[async_trait(?Send)]
impl Analyzer for DepthAnalyzer {
    fn name(&self) -> &'static str {
        "depth"
    }

    async fn analyze(
        &self,
        document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult {
        let mut max_depth: u32 = 0;

        // Analyze each operation in the document
        for definition in document.document.definitions() {
            match definition {
                cst::Definition::OperationDefinition(op) => {
                    if let Some(selection_set) = op.selection_set() {
                        let mut visited = HashSet::new();
                        let depth = self.calculate_depth(
                            &selection_set,
                            &document.fragments,
                            &mut visited,
                        );
                        max_depth = max_depth.max(depth);
                    }
                }
                _ => {}
            }
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            depth = max_depth,
            max_depth = self.config.max_depth,
            "Depth analysis complete"
        );

        let metrics = AnalysisMetrics {
            depth: Some(max_depth),
            ..Default::default()
        };

        if max_depth > self.config.max_depth {
            AnalysisResult {
                violations: vec![Violation::depth_exceeded(max_depth, self.config.max_depth)],
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

    fn test_config() -> DepthConfig {
        DepthConfig {
            enabled: true,
            max_depth: 5,
            ignore_introspection: true,
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
    async fn test_simple_query_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(2));
    }

    #[tokio::test]
    async fn test_nested_query_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query(
            "{ users { posts { comments { author { name } } } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(5));
    }

    #[tokio::test]
    async fn test_exceeds_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query(
            "{ a { b { c { d { e { f { g } } } } } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, crate::error::ViolationCode::DepthExceeded);
        assert_eq!(result.metrics.depth, Some(7));
    }

    #[tokio::test]
    async fn test_introspection_ignored() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query(
            "{ __schema { types { name fields { name } } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // Introspection should be ignored, depth = 0
        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(0));
    }

    #[tokio::test]
    async fn test_introspection_counted_when_disabled() {
        let config = DepthConfig {
            enabled: true,
            max_depth: 5,
            ignore_introspection: false,
        };
        let analyzer = DepthAnalyzer::new(config);
        let doc = parse_query(
            "{ __schema { types { name fields { name } } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // Introspection counted, depth = 4
        assert!(!result.has_violations());
        assert_eq!(result.metrics.depth, Some(4));
    }

    #[tokio::test]
    async fn test_inline_fragment_depth() {
        let analyzer = DepthAnalyzer::new(test_config());
        let doc = parse_query(
            "{ users { ... on User { posts { title } } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) -> inline fragment(0) -> posts(1) -> title(1) = 3
        // The inline fragment doesn't add depth, but the nested fields do
        assert_eq!(result.metrics.depth, Some(3));
    }
}
