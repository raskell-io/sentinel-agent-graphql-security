//! Main GraphQL Security Agent implementation.
//!
//! Coordinates all analyzers and integrates with the Zentinel Agent Protocol v2.

use crate::analyzer::{
    AliasAnalyzer, AnalysisContext, AnalysisMetrics, AnalysisResult, Analyzer, BatchAnalyzer,
    ComplexityAnalyzer, DepthAnalyzer, FieldAuthAnalyzer, IntrospectionAnalyzer,
    PersistedQueryAnalyzer,
};
use crate::config::{FailAction, GraphQLSecurityConfig};
use crate::error::{graphql_error_response, GraphQLError, Violation};
use crate::parser::{parse_query, parse_request};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthConfig,
    HealthStatus, MetricsReport, ShutdownReason, PROTOCOL_VERSION_2,
};
use zentinel_agent_protocol::{AgentResponse, Decision, EventType, HeaderOp, RequestHeadersEvent};

/// GraphQL Security Agent for Zentinel.
///
/// Analyzes GraphQL queries for security concerns including depth, complexity,
/// aliases, batch limits, introspection, field authorization, and persisted queries.
///
/// Implements Protocol v2 with capability negotiation, health reporting, and metrics.
pub struct GraphQLSecurityAgent {
    /// Agent configuration
    config: RwLock<GraphQLSecurityConfig>,
    /// Active analyzers
    analyzers: RwLock<Vec<Arc<dyn Analyzer>>>,
    /// Request counters for metrics
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    /// Configuration version
    config_version: RwLock<Option<String>>,
}

impl GraphQLSecurityAgent {
    /// Create a new GraphQL security agent with the given configuration.
    pub fn new(config: GraphQLSecurityConfig) -> Result<Self, GraphQLError> {
        let analyzers = Self::build_analyzers(&config);
        Ok(Self {
            config: RwLock::new(config),
            analyzers: RwLock::new(analyzers),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            config_version: RwLock::new(None),
        })
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

        Ok(Self {
            config: RwLock::new(config),
            analyzers: RwLock::new(analyzers),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            config_version: RwLock::new(None),
        })
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
    ///
    /// Reads config and analyzers, then parses and analyzes each query in the
    /// request. The `ParsedDocument` (which contains a non-Send rowan `SyntaxNode`)
    /// is scoped so it does not live across `.await` points, satisfying the Send
    /// requirement of the outer future.
    async fn analyze_request(
        &self,
        body: &[u8],
        headers: &HashMap<String, Vec<String>>,
        correlation_id: &str,
        client_ip: &str,
    ) -> Result<AnalysisResult, Violation> {
        // Read config and analyzers before analysis
        let max_body_size = {
            let config = self.config.read().await;
            config.settings.max_body_size
        };

        // Get a snapshot of analyzers
        let analyzers: Vec<Arc<dyn Analyzer>> = {
            let analyzers_guard = self.analyzers.read().await;
            analyzers_guard.clone()
        };

        // Check body size
        if body.len() > max_body_size {
            return Err(Violation::invalid_request(&format!(
                "Request body too large: {} bytes (max: {})",
                body.len(),
                max_body_size
            )));
        }

        // Parse the request(s) — this produces only Send types
        let requests = parse_request(body)?;

        let mut combined_result = AnalysisResult::ok();

        // Analyze each request in the batch
        for (idx, request) in requests.iter().enumerate() {
            // Build analysis context (Send + 'static-friendly)
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

            // Parse the query and run all analyzers within a block_in_place
            // scope. ParsedDocument contains a non-Send rowan SyntaxNode, and
            // the Analyzer trait uses #[async_trait(?Send)], producing !Send
            // futures. block_in_place moves the current task off the tokio
            // worker thread so we can safely call Handle::block_on without
            // deadlocking, while still having access to the tokio runtime
            // (which analyzers like PersistedQueryAnalyzer need for
            // tokio::sync::RwLock).
            let request_result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();

                let document = parse_query(&request.query)?;

                let mut result = AnalysisResult::ok();
                for analyzer in analyzers.iter() {
                    let analyzer_result = handle.block_on(analyzer.analyze(&document, &ctx));
                    result.merge(analyzer_result);
                }

                Ok::<AnalysisResult, Violation>(result)
            })?;

            combined_result.merge(request_result);
        }

        Ok(combined_result)
    }

    /// Build block response with GraphQL error body.
    fn build_block_response(
        &self,
        violations: &[Violation],
        metrics: &AnalysisMetrics,
        debug_headers: bool,
    ) -> AgentResponse {
        let error_body = graphql_error_response(violations);
        let body_str = serde_json::to_string(&error_body).unwrap_or_default();

        let mut response_headers = vec![HeaderOp::Set {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }];

        // Add debug headers if enabled
        if debug_headers {
            self.add_debug_headers(&mut response_headers, metrics);
        }

        AgentResponse {
            version: PROTOCOL_VERSION_2,
            decision: Decision::Block {
                status: 200, // GraphQL errors use HTTP 200 with errors in body
                body: Some(body_str),
                headers: None,
            },
            request_headers: vec![],
            response_headers,
            routing_metadata: HashMap::new(),
            audit: Default::default(),
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    /// Build allow response with optional debug headers.
    fn build_allow_response(
        &self,
        metrics: &AnalysisMetrics,
        debug_headers: bool,
    ) -> AgentResponse {
        let mut response_headers = vec![];

        if debug_headers {
            self.add_debug_headers(&mut response_headers, metrics);
        }

        AgentResponse {
            version: PROTOCOL_VERSION_2,
            decision: Decision::Allow,
            request_headers: vec![],
            response_headers,
            routing_metadata: HashMap::new(),
            audit: Default::default(),
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    /// Add debug headers to response.
    fn add_debug_headers(&self, headers: &mut Vec<HeaderOp>, metrics: &AnalysisMetrics) {
        if let Some(depth) = metrics.depth {
            headers.push(HeaderOp::Set {
                name: "X-GraphQL-Depth".to_string(),
                value: depth.to_string(),
            });
        }
        if let Some(complexity) = metrics.complexity {
            headers.push(HeaderOp::Set {
                name: "X-GraphQL-Complexity".to_string(),
                value: complexity.to_string(),
            });
        }
        if let Some(aliases) = metrics.aliases {
            headers.push(HeaderOp::Set {
                name: "X-GraphQL-Aliases".to_string(),
                value: aliases.to_string(),
            });
        }
        if let Some(operations) = metrics.operations {
            headers.push(HeaderOp::Set {
                name: "X-GraphQL-Operations".to_string(),
                value: operations.to_string(),
            });
        }
        if let Some(fields) = metrics.fields {
            headers.push(HeaderOp::Set {
                name: "X-GraphQL-Fields".to_string(),
                value: fields.to_string(),
            });
        }
    }
}

/// Protocol v2 implementation
#[async_trait]
impl AgentHandlerV2 for GraphQLSecurityAgent {
    /// Return agent capabilities for protocol negotiation.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "graphql-security".to_string(),
            name: "GraphQL Security Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![
                EventType::RequestHeaders,
                EventType::RequestBodyChunk,
                EventType::Configure,
            ],
            features: AgentFeatures {
                streaming_body: false, // We need full body for GraphQL parsing
                websocket: false,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: 10 * 1024 * 1024, // 10MB
                max_concurrency: 100,
                preferred_chunk_size: 64 * 1024,
                max_memory: None,
                max_processing_time_ms: Some(5000),
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle request headers event - this is where GraphQL requests are analyzed.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        let correlation_id = event.metadata.correlation_id.clone();
        let client_ip = event.metadata.client_ip.clone();

        debug!(
            correlation_id = %correlation_id,
            client_ip = %client_ip,
            method = %event.method,
            uri = %event.uri,
            "Processing GraphQL request"
        );

        // For GraphQL, we need the body. Signal that we need more data.
        // The actual analysis will happen in on_request_body_chunk with is_last=true
        AgentResponse {
            version: PROTOCOL_VERSION_2,
            decision: Decision::Allow,
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: Default::default(),
            needs_more: true, // Signal we need the body
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    /// Handle request body chunk - analyze the GraphQL query when body is complete.
    async fn on_request_body_chunk(
        &self,
        event: zentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        // Only process when we have the complete body
        if !event.is_last {
            return AgentResponse {
                version: PROTOCOL_VERSION_2,
                decision: Decision::Allow,
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: HashMap::new(),
                audit: Default::default(),
                needs_more: true,
                request_body_mutation: None,
                response_body_mutation: None,
                websocket_decision: None,
            };
        }

        let correlation_id = event.correlation_id.clone();

        // Decode the base64 body
        let body = match base64_decode(&event.data) {
            Some(b) => b,
            None => {
                warn!(correlation_id = %correlation_id, "Failed to decode request body");
                return AgentResponse::default_allow();
            }
        };

        // Get config for this request
        let config = self.config.read().await;
        let debug_headers = config.settings.debug_headers;
        let fail_action = config.settings.fail_action;
        drop(config);

        // Analyze the request
        let headers = HashMap::new(); // Headers were in the previous event
        let result = self
            .analyze_request(&body, &headers, &correlation_id, "unknown")
            .await;

        match result {
            Ok(analysis_result) => {
                if analysis_result.has_violations() {
                    self.requests_blocked.fetch_add(1, Ordering::Relaxed);

                    warn!(
                        correlation_id = %correlation_id,
                        violation_count = analysis_result.violations.len(),
                        "GraphQL security violations detected"
                    );

                    match fail_action {
                        FailAction::Block => self.build_block_response(
                            &analysis_result.violations,
                            &analysis_result.metrics,
                            debug_headers,
                        ),
                        FailAction::Allow => {
                            info!(
                                correlation_id = %correlation_id,
                                "Violations detected but allowing request (fail_action=allow)"
                            );
                            self.build_allow_response(&analysis_result.metrics, debug_headers)
                        }
                    }
                } else {
                    debug!(
                        correlation_id = %correlation_id,
                        "GraphQL request passed security checks"
                    );
                    self.build_allow_response(&analysis_result.metrics, debug_headers)
                }
            }
            Err(violation) => {
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);

                warn!(
                    correlation_id = %correlation_id,
                    code = %violation.code,
                    message = %violation.message,
                    "GraphQL request error"
                );

                match fail_action {
                    FailAction::Block => self.build_block_response(
                        &[violation],
                        &AnalysisMetrics::default(),
                        debug_headers,
                    ),
                    FailAction::Allow => {
                        info!(
                            correlation_id = %correlation_id,
                            "Error occurred but allowing request (fail_action=allow)"
                        );
                        AgentResponse::default_allow()
                    }
                }
            }
        }
    }

    /// Handle configuration updates from the proxy.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!("Received configuration update, version: {:?}", version);

        // Try to parse the new configuration
        match serde_json::from_value::<GraphQLSecurityConfig>(config) {
            Ok(new_config) => {
                // Rebuild analyzers with new config
                let new_analyzers = Self::build_analyzers(&new_config);

                // Update config and analyzers atomically
                *self.config.write().await = new_config;
                *self.analyzers.write().await = new_analyzers;
                *self.config_version.write().await = version;

                info!("Configuration updated successfully");
                true
            }
            Err(e) => {
                warn!("Failed to parse configuration: {}", e);
                false
            }
        }
    }

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("graphql-security")
    }

    /// Return metrics report for the proxy.
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let requests = self.requests_total.load(Ordering::Relaxed);
        let blocked = self.requests_blocked.load(Ordering::Relaxed);

        let mut report = MetricsReport::new("graphql-security", 10_000);

        report.counters.push(CounterMetric::new(
            "graphql_security_requests_total",
            requests,
        ));
        report.counters.push(CounterMetric::new(
            "graphql_security_requests_blocked_total",
            blocked,
        ));

        // Calculate block rate
        let block_rate = if requests > 0 {
            (blocked as f64 / requests as f64) * 100.0
        } else {
            0.0
        };
        report.gauges.push(GaugeMetric::new(
            "graphql_security_block_rate_percent",
            block_rate,
        ));

        Some(report)
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            "Shutdown requested: {:?}, grace period: {}ms",
            reason, grace_period_ms
        );
        // Agent will be stopped by the runner
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!("Drain requested: {:?}, duration: {}ms", reason, duration_ms);
        // Stop accepting new requests
    }
}

/// Decode base64 string to bytes
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let bytes = s.as_bytes();
    let mut decoder =
        base64::read::DecoderReader::new(bytes, &base64::engine::general_purpose::STANDARD);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            },
            aliases: crate::config::AliasConfig {
                enabled: true,
                max_aliases: 10,
                max_duplicate_aliases: 3,
            },
            batch: crate::config::BatchConfig {
                enabled: true,
                max_queries: 5,
            },
            introspection: crate::config::IntrospectionConfig {
                enabled: true,
                allow: false,
                allowed_clients: Vec::new(),
                allowed_clients_header: None,
                allow_typename: true,
            },
            field_auth: crate::config::FieldAuthConfig {
                enabled: false,
                rules: Vec::new(),
            },
            persisted_queries: crate::config::PersistedQueriesConfig {
                enabled: false,
                mode: crate::config::PersistedQueryMode::Allowlist,
                allowlist_file: None,
                require_hash: false,
            },
            version: "1".to_string(),
        }
    }

    #[test]
    fn test_agent_creation() {
        let agent = GraphQLSecurityAgent::new(test_config());
        assert!(agent.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_analyze_valid_query() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = br#"{"query": "{ users { id name } }"}"#;
        let headers = HashMap::new();

        let result = agent
            .analyze_request(body, &headers, "test", "127.0.0.1")
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap().has_violations());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_analyze_depth_exceeded() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = br#"{"query": "{ a { b { c { d { e { f { g } } } } } } }"}"#;
        let headers = HashMap::new();

        let result = agent
            .analyze_request(body, &headers, "test", "127.0.0.1")
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().has_violations());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_analyze_invalid_json() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let body = b"not json";
        let headers = HashMap::new();

        let result = agent
            .analyze_request(body, &headers, "test", "127.0.0.1")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_body_size_limit() {
        let mut config = test_config();
        config.settings.max_body_size = 10;
        let agent = GraphQLSecurityAgent::new(config).unwrap();
        let body = br#"{"query": "{ users { id name email } }"}"#;
        let headers = HashMap::new();

        let result = agent
            .analyze_request(body, &headers, "test", "127.0.0.1")
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_capabilities() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let caps = agent.capabilities();

        assert_eq!(caps.agent_id, "graphql-security");
        assert_eq!(caps.protocol_version, 2);
        assert!(caps.features.config_push);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let health = agent.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "graphql-security");
    }

    #[test]
    fn test_metrics_report() {
        let agent = GraphQLSecurityAgent::new(test_config()).unwrap();
        let report = agent.metrics_report();

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "graphql-security");
        assert!(!report.counters.is_empty());
    }
}
