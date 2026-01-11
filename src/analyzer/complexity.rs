//! Query complexity analyzer.
//!
//! Calculates the cost of a GraphQL query based on field costs and list multipliers.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::ComplexityConfig;
use crate::error::Violation;
use crate::parser::{FragmentInfo, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Analyzer that limits query complexity.
pub struct ComplexityAnalyzer {
    config: ComplexityConfig,
}

impl ComplexityAnalyzer {
    /// Create a new complexity analyzer.
    pub fn new(config: ComplexityConfig) -> Self {
        Self { config }
    }

    /// Calculate the complexity of a selection set.
    fn calculate_complexity(
        &self,
        selection_set: &cst::SelectionSet,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
        parent_type: Option<&str>,
        parent_multiplier: u64,
    ) -> u64 {
        let mut total_complexity: u64 = 0;

        for selection in selection_set.selections() {
            let complexity = match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Get field cost
                    let field_cost = self.get_field_cost(&field_name, parent_type);

                    // Get list multiplier from arguments
                    let multiplier = self.get_list_multiplier(&field);

                    // Calculate nested complexity
                    let nested_complexity = field
                        .selection_set()
                        .map(|ss| {
                            self.calculate_complexity(
                                &ss,
                                fragments,
                                visited_fragments,
                                None, // We don't know the nested type without schema
                                multiplier,
                            )
                        })
                        .unwrap_or(0);

                    // Total: base cost + (nested cost * multiplier)
                    // Apply parent multiplier to field cost
                    (field_cost * parent_multiplier) + nested_complexity
                }
                cst::Selection::FragmentSpread(spread) => {
                    if let Some(name) = spread.fragment_name() {
                        if let Some(name_token) = name.name() {
                            let frag_name = name_token.text().to_string();

                            // Prevent infinite recursion
                            if visited_fragments.contains(&frag_name) {
                                0
                            } else {
                                visited_fragments.insert(frag_name.clone());
                                let complexity = self.calculate_fragment_complexity(
                                    &frag_name,
                                    fragments,
                                    visited_fragments,
                                    parent_multiplier,
                                );
                                visited_fragments.remove(&frag_name);
                                complexity
                            }
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                }
                cst::Selection::InlineFragment(inline) => {
                    let type_cond = inline
                        .type_condition()
                        .and_then(|tc| tc.named_type())
                        .and_then(|nt| nt.name())
                        .map(|n| n.text().to_string());

                    inline
                        .selection_set()
                        .map(|ss| {
                            self.calculate_complexity(
                                &ss,
                                fragments,
                                visited_fragments,
                                type_cond.as_deref(),
                                parent_multiplier,
                            )
                        })
                        .unwrap_or(0)
                }
            };

            total_complexity += complexity;
        }

        total_complexity
    }

    /// Get the cost for a field.
    fn get_field_cost(&self, field_name: &str, parent_type: Option<&str>) -> u64 {
        // Check for specific field cost first
        if let Some(parent) = parent_type {
            let full_name = format!("{}.{}", parent, field_name);
            if let Some(cost) = self.config.field_costs.get(&full_name) {
                return *cost;
            }
        }

        // Check for Query.field or Mutation.field
        let query_field = format!("Query.{}", field_name);
        if let Some(cost) = self.config.field_costs.get(&query_field) {
            return *cost;
        }

        let mutation_field = format!("Mutation.{}", field_name);
        if let Some(cost) = self.config.field_costs.get(&mutation_field) {
            return *cost;
        }

        // Check for type cost
        if let Some(parent) = parent_type {
            if let Some(cost) = self.config.type_costs.get(parent) {
                return *cost;
            }
        }

        // Default cost
        self.config.default_field_cost
    }

    /// Get the list multiplier from field arguments.
    fn get_list_multiplier(&self, field: &cst::Field) -> u64 {
        if let Some(args) = field.arguments() {
            for arg in args.arguments() {
                if let Some(arg_name) = arg.name() {
                    let name = arg_name.text();
                    if self.config.list_size_arguments.iter().any(|s| s.as_str() == name.as_str()) {
                        // Try to extract the value
                        if let Some(value) = arg.value() {
                            if let Some(num) = extract_int_value(&value) {
                                return num.max(1) as u64;
                            }
                        }
                    }
                }
            }
        }

        // Default multiplier if no list size argument found
        self.config.default_list_multiplier
    }

    /// Calculate complexity through a fragment.
    fn calculate_fragment_complexity(
        &self,
        fragment_name: &str,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
        parent_multiplier: u64,
    ) -> u64 {
        if let Some(frag_info) = fragments.get(fragment_name) {
            if !frag_info.selection_set_text.is_empty() {
                let query = format!("{{ {} }}", frag_info.selection_set_text);
                let parser = apollo_parser::Parser::new(&query);
                let cst = parser.parse();

                if cst.errors().len() == 0 {
                    for def in cst.document().definitions() {
                        if let cst::Definition::OperationDefinition(op) = def {
                            if let Some(ss) = op.selection_set() {
                                return self.calculate_complexity(
                                    &ss,
                                    fragments,
                                    visited_fragments,
                                    Some(&frag_info.type_condition),
                                    parent_multiplier,
                                );
                            }
                        }
                    }
                }
            }
        }
        0
    }
}

/// Extract integer value from a CST value.
fn extract_int_value(value: &cst::Value) -> Option<i64> {
    match value {
        cst::Value::IntValue(v) => {
            v.int_token().and_then(|t| t.text().parse().ok())
        }
        cst::Value::Variable(_) => {
            // Can't evaluate variables without runtime context
            // Use default multiplier
            None
        }
        _ => None,
    }
}

#[async_trait(?Send)]
impl Analyzer for ComplexityAnalyzer {
    fn name(&self) -> &'static str {
        "complexity"
    }

    async fn analyze(
        &self,
        document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult {
        let mut total_complexity: u64 = 0;

        for definition in document.document.definitions() {
            match definition {
                cst::Definition::OperationDefinition(op) => {
                    if let Some(selection_set) = op.selection_set() {
                        let mut visited = HashSet::new();
                        let complexity = self.calculate_complexity(
                            &selection_set,
                            &document.fragments,
                            &mut visited,
                            None,
                            1, // Base multiplier
                        );
                        total_complexity += complexity;
                    }
                }
                _ => {}
            }
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            complexity = total_complexity,
            max_complexity = self.config.max_complexity,
            "Complexity analysis complete"
        );

        let metrics = AnalysisMetrics {
            complexity: Some(total_complexity),
            ..Default::default()
        };

        if total_complexity > self.config.max_complexity {
            AnalysisResult {
                violations: vec![Violation::complexity_exceeded(
                    total_complexity,
                    self.config.max_complexity,
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

    fn test_config() -> ComplexityConfig {
        ComplexityConfig {
            enabled: true,
            max_complexity: 100,
            default_field_cost: 1,
            default_list_multiplier: 10,
            type_costs: HashMap::new(),
            field_costs: HashMap::new(),
            list_size_arguments: vec![
                "first".to_string(),
                "last".to_string(),
                "limit".to_string(),
            ],
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
    async fn test_simple_complexity() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) + id(1*10) + name(1*10) = 21
        assert_eq!(result.metrics.complexity, Some(21));
    }

    #[tokio::test]
    async fn test_complexity_with_limit() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query("{ users(first: 5) { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        // users(1) + id(1*5) + name(1*5) = 11
        assert_eq!(result.metrics.complexity, Some(11));
    }

    #[tokio::test]
    async fn test_exceeds_complexity() {
        let mut config = test_config();
        config.max_complexity = 10;
        let analyzer = ComplexityAnalyzer::new(config);
        let doc = parse_query("{ users { id name email } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(
            result.violations[0].code,
            crate::error::ViolationCode::ComplexityExceeded
        );
    }

    #[tokio::test]
    async fn test_custom_field_cost() {
        let mut config = test_config();
        config.field_costs.insert("Query.users".to_string(), 10);
        let analyzer = ComplexityAnalyzer::new(config);
        let doc = parse_query("{ users { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // users(10) + id(1*10) = 20
        assert_eq!(result.metrics.complexity, Some(20));
    }

    #[tokio::test]
    async fn test_nested_list_multipliers() {
        let analyzer = ComplexityAnalyzer::new(test_config());
        let doc = parse_query(
            "{ users(first: 10) { posts(first: 5) { title } } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        // users(1) + posts(1*10) + title(1*5) = 16
        // Note: In this simple model, nested multipliers don't compound
        assert_eq!(result.metrics.complexity, Some(16));
    }
}
