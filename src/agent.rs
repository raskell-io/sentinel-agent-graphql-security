//! Main GraphQL Security Agent implementation.
//!
//! Coordinates all analyzers and integrates with the Sentinel Agent SDK.

use crate::analyzer::{
    AliasAnalyzer, AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer, BatchAnalyzer,
    ComplexityAnalyzer, DepthAnalyzer, FieldAuthAnalyzer, IntrospectionAnalyzer,
    PersistedQueryAnalyzer,
};
use crate::config::{FailAction, GraphQLSecurityConfig};
use crate::error::{graphql_error_response, GraphQLError, Violation};
use crate::parser::{parse_query, parse_request};
use async_trait::async_trait;
use sentinel_agent_sdk::{Agent, Decision, Request};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// GraphQL Security Agent for Sentinel.
///
/// Analyzes GraphQL queries for security concerns including depth, complexity,
/// aliases, batch limits, introspection, field authorization, and persisted queries.
pub struct GraphQLSecurityAgent {
    config: GraphQLSecurityConfig,
    /// Active analyzers
    analyzers: Vec<Arc<dyn Analyzer>>,
}

impl GraphQLSecurityAgent {
    /// Create a new GraphQL security agent with the given configuration.
    pub fn new(config: GraphQLSecurityConfig) -> Result<Self, GraphQLError> {
        let analyzers = Self::build_analyzers(&config);
        Ok(Self { config, analyzers })
    }

    /// Create agent with async initialization (for loading allowlist files).
    pub async fn with_async_init(config: GraphQLSecurityConfig) -> Result<Self, GraphQLError> {
        let mut analyzers: Vec<Arc<dyn Analyzer>> = Vec::new();

        // Add enabled analyzers
        if config.depth.enabled {
            analyzers.push(Arc::new(DepthAnalyzer::new(config.depth.clone())));
        }

        if config.complexity.enabled {
            analyzers.push(Arc::new(ComplexityAnalyzer::new(config.complexity.clone())));
        }

        if config.aliases.enabled {
            analyzers.push(Arc::new(AliasAnalyzer::new(config.aliases.clone())));
        }

        if config.batch.enabled {
            analyzers.push(Arc::new(BatchAnalyzer::new(config.batch.clone())));
        }

        if config.introspection.enabled {
            analyzers.push(Arc::new(IntrospectionAnalyzer::new(
                config.introspection.clone(),
            )));
        }

        if config.field_auth.enabled {
            analyzers.push(Arc::new(FieldAuthAnalyzer::new(config.field_auth.clone())));
        }

        if config.persisted_queries.enabled {
            let persisted_analyzer =
                PersistedQueryAnalyzer::with_allowlist(config.persisted_queries.clone()).await?;
            analyzers.push(Arc::new(persisted_analyzer));
        }

        Ok(Self { config, analyzers })
    }

    /// Build analyzers from configuration (sync version).
    fn build_analyzers(config: &GraphQLSecurityConfig) -> Vec<Arc<dyn Analyzer>> {
        let mut analyzers: Vec<Arc<dyn Analyzer>> = Vec::new();

        if config.depth.enabled {
            analyzers.push(Arc::new(DepthAnalyzer::new(config.depth.clone())));
        }

        if config.complexity.enabled {
            analyzers.push(Arc::new(ComplexityAnalyzer::new(config.complexity.clone())));
        }

        if config.aliases.enabled {
            analyzers.push(Arc::new(AliasAnalyzer::new(config.aliases.clone())));
        }

        if config.batch.enabled {
            analyzers.push(Arc::new(BatchAnalyzer::new(config.batch.clone())));
        }

        if config.introspection.enabled {
            analyzers.push(Arc::new(IntrospectionAnalyzer::new(
                config.introspection.clone(),
            )));
        }

        if config.field_auth.enabled {
            analyzers.push(Arc::new(FieldAuthAnalyzer::new(config.field_auth.clone())));
        }

        if config.persisted_queries.enabled {
            analyzers.push(Arc::new(PersistedQueryAnalyzer::new(
                config.persisted_queries.clone(),
            )));
        }

        analyzers
    }

    /// Analyze a GraphQL request.
    fn analyze_request_sync(
        &self,
        body: &[u8],
        headers: &std::collections::HashMap<String, Vec<String>>,
        correlation_id: &str,
        client_ip: &str,
    ) -> Result<AnalysisResult, Violation> {
        // Check body size
        if body.len() > self.config.settings.max_body_size {
            return Err(Violation::invalid_request(&format!(
                "Request body too large: {} bytes (max: {})",
                body.len(),
                self.config.settings.max_body_size
            )));
        }

        // Parse the request(s)
        let requests = parse_request(body)?;

        let mut combined_result = AnalysisResult::ok();

        // Analyze each request in the batch
        for (idx, request) in requests.iter().enumerate() {
            // Parse the query
            let document = parse_query(&request.query)?;

            // Build analysis context
            let ctx = AnalysisContext {
                correlation_id: if requests.len() > 1 {
                    format!("{}-{}", correlation_id, idx)
                } else {
                    correlation_id.to_string()
                },
                client_ip: client_ip.to_string(),
                headers: headers.clone(),
                operation_name: request.operation_name.clone(),
                variables: request.variables.clone(),
                extensions: request.extensions.clone(),
                is_batch: request.is_batch,
                batch_count: request.batch_count,
                query: request.query.clone(),
            };

            // Run all analyzers synchronously using block_on
            // This is necessary because the Analyzer trait is async but we want
            // to avoid Send/Sync issues with the ParsedDocument
            for analyzer in &self.analyzers {
                let result = futures::executor::block_on(analyzer.analyze(&document, &ctx));
                combined_result.merge(result);
            }
        }

        Ok(combined_result)
    }

    /// Build decision with debug headers if enabled.
    fn build_block_decision(&self, violations: &[Violation], metrics: &AnalysisMetrics) -> Decision {
        let error_body = graphql_error_response(violations);
        let body_str = serde_json::to_string(&error_body).unwrap_or_default();

        let mut decision = Decision::block(200)
            .with_body(&body_str)
            .add_response_header("Content-Type", "application/json");

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            decision = self.add_debug_headers(decision, metrics);
        }

        decision
    }

    /// Add debug headers to a decision.
    fn add_debug_headers(&self, mut decision: Decision, metrics: &AnalysisMetrics) -> Decision {
        if let Some(depth) = metrics.depth {
            decision = decision.add_response_header("X-GraphQL-Depth", &depth.to_string());
        }
        if let Some(complexity) = metrics.complexity {
            decision = decision.add_response_header("X-GraphQL-Complexity", &complexity.to_string());
        }
        if let Some(aliases) = metrics.aliases {
            decision = decision.add_response_header("X-GraphQL-Aliases", &aliases.to_string());
        }
        if let Some(operations) = metrics.operations {
            decision = decision.add_response_header("X-GraphQL-Operations", &operations.to_string());
        }
        if let Some(fields) = metrics.fields {
            decision = decision.add_response_header("X-GraphQL-Fields", &fields.to_string());
        }
        decision
    }
}

#[async_trait]
impl Agent for GraphQLSecurityAgent {
    fn name(&self) -> &str {
        "graphql-security"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let correlation_id = request
            .header("x-correlation-id")
            .or_else(|| request.header("x-request-id"))
            .unwrap_or("unknown")
            .to_string();

        let client_ip = request.client_ip().to_string();

        debug!(
            correlation_id = %correlation_id,
            client_ip = %client_ip,
            method = %request.method(),
            path = %request.path(),
            "Processing GraphQL request"
        );

        // Get body - if not available yet, allow through
        let body = match request.body() {
            Some(b) => b,
            None => {
                debug!(
                    correlation_id = %correlation_id,
                    "No body available, passing through"
                );
                return Decision::allow();
            }
        };

        // Convert headers
        let headers = request.headers().clone();

        // Analyze the request
        let result = self.analyze_request_sync(body, &headers, &correlation_id, &client_ip);

        match result {
            Ok(analysis_result) => {
                if analysis_result.has_violations() {
                    warn!(
                        correlation_id = %correlation_id,
                        violation_count = analysis_result.violations.len(),
                        "GraphQL security violations detected"
                    );

                    match self.config.settings.fail_action {
                        FailAction::Block => {
                            self.build_block_decision(
                                &analysis_result.violations,
                                &analysis_result.metrics,
                            )
                        }
                        FailAction::Allow => {
                            info!(
                                correlation_id = %correlation_id,
                                "Violations detected but allowing request (fail_action=allow)"
                            );
                            let mut decision = Decision::allow();
                            if self.config.settings.debug_headers {
                                decision = self.add_debug_headers(decision, &analysis_result.metrics);
                            }
                            decision
                        }
                    }
                } else {
                    debug!(
                        correlation_id = %correlation_id,
                        "GraphQL request passed security checks"
                    );
                    let mut decision = Decision::allow();
                    if self.config.settings.debug_headers {
                        decision = self.add_debug_headers(decision, &analysis_result.metrics);
                    }
                    decision
                }
            }
            Err(violation) => {
                warn!(
                    correlation_id = %correlation_id,
                    code = %violation.code,
                    message = %violation.message,
                    "GraphQL request error"
                );

                match self.config.settings.fail_action {
                    FailAction::Block => {
                        self.build_block_decision(&[violation], &AnalysisMetrics::default())
                    }
                    FailAction::Allow => {
                        info!(
                            correlation_id = %correlation_id,
                            "Error occurred but allowing request (fail_action=allow)"
                        );
                        Decision::allow()
                    }
                }
            }
        }
    }

    async fn on_request_body(&self, request: &Request) -> Decision {
        // Process in on_request_body since we need the body
        self.on_request(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> GraphQLSecurityConfig {
        GraphQLSecurityConfig {
            settings: crate::config::SettingsConfig {
                max_body_size: 1_048_576,
                debug_headers: true,
                fail_action: FailAction::Block,
            },
            depth: crate::config::DepthConfig {
                enabled: true,
                max_depth: 5,
                ignore_introspection: true,
            },
            complexity: crate::config::ComplexityConfig {
                enabled: true,
                max_complexity: 100,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_agent_creation() {
        let agent = GraphQLSecurityAgent::new(test_config());
        assert!(agent.is_ok());
    }

    #[test]
    fn test_analyze_valid_query() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = br#"{"query": "{ users { id name } }"}"#;
        let headers = HashMap::new();

        let result = agent.analyze_request_sync(body, &headers, "test", "127.0.0.1");

        assert!(result.is_ok());
        assert!(!result.unwrap().has_violations());
    }

    #[test]
    fn test_analyze_depth_exceeded() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = br#"{"query": "{ a { b { c { d { e { f { g } } } } } } }"}"#;
        let headers = HashMap::new();

        let result = agent.analyze_request_sync(body, &headers, "test", "127.0.0.1");

        assert!(result.is_ok());
        assert!(result.unwrap().has_violations());
    }

    #[test]
    fn test_analyze_invalid_json() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = b"not json";
        let headers = HashMap::new();

        let result = agent.analyze_request_sync(body, &headers, "test", "127.0.0.1");

        assert!(result.is_err());
    }

    #[test]
    fn test_body_size_limit() {
        let mut config = test_config();
        config.settings.max_body_size = 10;
        let agent = GraphQLSecurityAgent::new(config).unwrap();
        let body = br#"{"query": "{ users { id name email } }"}"#;
        let headers = HashMap::new();

        let result = agent.analyze_request_sync(body, &headers, "test", "127.0.0.1");

        assert!(result.is_err());
    }
}
