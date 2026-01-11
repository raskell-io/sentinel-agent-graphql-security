//! Alias analyzer.
//!
//! Counts aliases in a GraphQL query and enforces limits to prevent alias-based attacks.

use super::{AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer};
use crate::config::AliasConfig;
use crate::error::Violation;
use crate::parser::{FragmentInfo, ParsedDocument};
use apollo_parser::cst;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Analyzer that limits aliases in queries.
pub struct AliasAnalyzer {
    config: AliasConfig,
}

impl AliasAnalyzer {
    /// Create a new alias analyzer.
    pub fn new(config: AliasConfig) -> Self {
        Self { config }
    }

    /// Count aliases in a selection set.
    fn count_aliases(
        &self,
        selection_set: &cst::SelectionSet,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
        alias_counts: &mut AliasCounters,
    ) {
        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    let field_name = field
                        .name()
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    // Check for alias
                    if let Some(alias) = field.alias() {
                        if alias.name().is_some() {
                            alias_counts.total_aliases += 1;
                            *alias_counts
                                .field_alias_counts
                                .entry(field_name.clone())
                                .or_insert(0) += 1;
                        }
                    }

                    // Recurse into nested selection set
                    if let Some(ss) = field.selection_set() {
                        self.count_aliases(&ss, fragments, visited_fragments, alias_counts);
                    }
                }
                cst::Selection::FragmentSpread(spread) => {
                    if let Some(name) = spread.fragment_name() {
                        if let Some(name_token) = name.name() {
                            let frag_name = name_token.text().to_string();

                            // Prevent infinite recursion
                            if visited_fragments.contains(&frag_name) {
                                continue;
                            }

                            visited_fragments.insert(frag_name.clone());
                            self.count_fragment_aliases(
                                &frag_name,
                                fragments,
                                visited_fragments,
                                alias_counts,
                            );
                            visited_fragments.remove(&frag_name);
                        }
                    }
                }
                cst::Selection::InlineFragment(inline) => {
                    if let Some(ss) = inline.selection_set() {
                        self.count_aliases(&ss, fragments, visited_fragments, alias_counts);
                    }
                }
            }
        }
    }

    /// Count aliases in a fragment.
    fn count_fragment_aliases(
        &self,
        fragment_name: &str,
        fragments: &HashMap<String, FragmentInfo>,
        visited_fragments: &mut HashSet<String>,
        alias_counts: &mut AliasCounters,
    ) {
        if let Some(frag_info) = fragments.get(fragment_name) {
            if !frag_info.selection_set_text.is_empty() {
                let query = format!("{{ {} }}", frag_info.selection_set_text);
                let parser = apollo_parser::Parser::new(&query);
                let cst = parser.parse();

                if cst.errors().len() == 0 {
                    for def in cst.document().definitions() {
                        if let cst::Definition::OperationDefinition(op) = def {
                            if let Some(ss) = op.selection_set() {
                                self.count_aliases(
                                    &ss,
                                    fragments,
                                    visited_fragments,
                                    alias_counts,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Counters for alias tracking.
#[derive(Debug, Default)]
struct AliasCounters {
    /// Total number of aliases
    total_aliases: u32,
    /// Number of times each field is aliased
    field_alias_counts: HashMap<String, u32>,
}

#[async_trait(?Send)]
impl Analyzer for AliasAnalyzer {
    fn name(&self) -> &'static str {
        "aliases"
    }

    async fn analyze(
        &self,
        document: &ParsedDocument,
        ctx: &AnalysisContext,
    ) -> AnalysisResult {
        let mut alias_counts = AliasCounters::default();

        // Analyze each operation in the document
        for definition in document.document.definitions() {
            match definition {
                cst::Definition::OperationDefinition(op) => {
                    if let Some(selection_set) = op.selection_set() {
                        let mut visited = HashSet::new();
                        self.count_aliases(
                            &selection_set,
                            &document.fragments,
                            &mut visited,
                            &mut alias_counts,
                        );
                    }
                }
                _ => {}
            }
        }

        // Find max duplicate alias count
        let max_duplicate = alias_counts
            .field_alias_counts
            .values()
            .copied()
            .max()
            .unwrap_or(0);

        debug!(
            correlation_id = %ctx.correlation_id,
            total_aliases = alias_counts.total_aliases,
            max_duplicate = max_duplicate,
            max_aliases = self.config.max_aliases,
            max_duplicate_aliases = self.config.max_duplicate_aliases,
            "Alias analysis complete"
        );

        let metrics = AnalysisMetrics {
            aliases: Some(alias_counts.total_aliases),
            ..Default::default()
        };

        let mut violations = Vec::new();

        // Check total aliases
        if alias_counts.total_aliases > self.config.max_aliases {
            violations.push(Violation::too_many_aliases(
                alias_counts.total_aliases,
                self.config.max_aliases,
            ));
        }

        // Check duplicate aliases
        if max_duplicate > self.config.max_duplicate_aliases {
            violations.push(Violation::new(
                crate::error::ViolationCode::TooManyAliases,
                format!(
                    "Field aliased {} times, maximum allowed is {}",
                    max_duplicate, self.config.max_duplicate_aliases
                ),
            ));
        }

        AnalysisResult { violations, metrics }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn test_config() -> AliasConfig {
        AliasConfig {
            enabled: true,
            max_aliases: 5,
            max_duplicate_aliases: 2,
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
    async fn test_no_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ users { id name } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(0));
    }

    #[tokio::test]
    async fn test_within_alias_limit() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ a: user(id: 1) { id } b: user(id: 2) { id } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(2));
    }

    #[tokio::test]
    async fn test_exceeds_total_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query(
            "{ a: user(id: 1) { id } b: user(id: 2) { id } c: user(id: 3) { id } d: user(id: 4) { id } e: user(id: 5) { id } f: user(id: 6) { id } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, crate::error::ViolationCode::TooManyAliases);
        assert_eq!(result.metrics.aliases, Some(6));
    }

    #[tokio::test]
    async fn test_exceeds_duplicate_aliases() {
        let mut config = test_config();
        config.max_aliases = 10;
        config.max_duplicate_aliases = 2;
        let analyzer = AliasAnalyzer::new(config);
        let doc = parse_query(
            "{ a: user(id: 1) { id } b: user(id: 2) { id } c: user(id: 3) { id } }",
        )
        .unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(result.has_violations());
        // 3 aliases of "user" exceeds max_duplicate_aliases of 2
        assert_eq!(result.violations[0].code, crate::error::ViolationCode::TooManyAliases);
    }

    #[tokio::test]
    async fn test_nested_aliases() {
        let analyzer = AliasAnalyzer::new(test_config());
        let doc = parse_query("{ users { a: posts { id } b: posts { id } } }").unwrap();
        let ctx = test_context();

        let result = analyzer.analyze(&doc, &ctx).await;

        assert!(!result.has_violations());
        assert_eq!(result.metrics.aliases, Some(2));
    }
}
