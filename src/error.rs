//! Error types and GraphQL-compliant error responses.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

/// GraphQL security violation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ViolationCode {
    /// Query depth exceeds limit
    DepthExceeded,
    /// Query complexity exceeds limit
    ComplexityExceeded,
    /// Too many aliases in query
    TooManyAliases,
    /// Too many operations in batch
    TooManyBatchQueries,
    /// Introspection is blocked
    IntrospectionBlocked,
    /// Field access unauthorized
    FieldUnauthorized,
    /// Query not in allowlist
    QueryNotAllowed,
    /// GraphQL parse error
    ParseError,
    /// Invalid request format
    InvalidRequest,
}

impl ViolationCode {
    /// Get the code as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DepthExceeded => "DEPTH_EXCEEDED",
            Self::ComplexityExceeded => "COMPLEXITY_EXCEEDED",
            Self::TooManyAliases => "TOO_MANY_ALIASES",
            Self::TooManyBatchQueries => "TOO_MANY_BATCH_QUERIES",
            Self::IntrospectionBlocked => "INTROSPECTION_BLOCKED",
            Self::FieldUnauthorized => "FIELD_UNAUTHORIZED",
            Self::QueryNotAllowed => "QUERY_NOT_ALLOWED",
            Self::ParseError => "PARSE_ERROR",
            Self::InvalidRequest => "INVALID_REQUEST",
        }
    }
}

impl fmt::Display for ViolationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A source location in the GraphQL document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
}

/// A security violation detected in the GraphQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Violation code
    pub code: ViolationCode,
    /// Human-readable message
    pub message: String,
    /// Source locations (if applicable)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    /// Additional metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ViolationExtensions>,
}

/// Additional violation metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViolationExtensions {
    /// Actual value that violated the limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<u64>,
    /// Maximum allowed value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// Field that caused the violation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl Violation {
    /// Create a new violation.
    pub fn new(code: ViolationCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            locations: Vec::new(),
            extensions: None,
        }
    }

    /// Add source location.
    pub fn with_location(mut self, line: usize, column: usize) -> Self {
        self.locations.push(Location { line, column });
        self
    }

    /// Add extension data.
    pub fn with_extensions(mut self, extensions: ViolationExtensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Create a depth exceeded violation.
    pub fn depth_exceeded(actual: u32, max: u32) -> Self {
        Self::new(
            ViolationCode::DepthExceeded,
            format!(
                "Query depth of {} exceeds maximum allowed depth of {}",
                actual, max
            ),
        )
        .with_extensions(ViolationExtensions {
            actual: Some(actual as u64),
            max: Some(max as u64),
            field: None,
        })
    }

    /// Create a complexity exceeded violation.
    pub fn complexity_exceeded(actual: u64, max: u64) -> Self {
        Self::new(
            ViolationCode::ComplexityExceeded,
            format!(
                "Query complexity of {} exceeds maximum allowed complexity of {}",
                actual, max
            ),
        )
        .with_extensions(ViolationExtensions {
            actual: Some(actual),
            max: Some(max),
            field: None,
        })
    }

    /// Create a too many aliases violation.
    pub fn too_many_aliases(actual: u32, max: u32) -> Self {
        Self::new(
            ViolationCode::TooManyAliases,
            format!(
                "Query contains {} aliases, maximum allowed is {}",
                actual, max
            ),
        )
        .with_extensions(ViolationExtensions {
            actual: Some(actual as u64),
            max: Some(max as u64),
            field: None,
        })
    }

    /// Create a too many batch queries violation.
    pub fn too_many_batch_queries(actual: u32, max: u32) -> Self {
        Self::new(
            ViolationCode::TooManyBatchQueries,
            format!(
                "Batch contains {} queries, maximum allowed is {}",
                actual, max
            ),
        )
        .with_extensions(ViolationExtensions {
            actual: Some(actual as u64),
            max: Some(max as u64),
            field: None,
        })
    }

    /// Create an introspection blocked violation.
    pub fn introspection_blocked() -> Self {
        Self::new(
            ViolationCode::IntrospectionBlocked,
            "Introspection queries are not allowed",
        )
    }

    /// Create a field unauthorized violation.
    pub fn field_unauthorized(field: &str) -> Self {
        Self::new(
            ViolationCode::FieldUnauthorized,
            format!("Access to field '{}' is not authorized", field),
        )
        .with_extensions(ViolationExtensions {
            actual: None,
            max: None,
            field: Some(field.to_string()),
        })
    }

    /// Create a query not allowed violation.
    pub fn query_not_allowed() -> Self {
        Self::new(
            ViolationCode::QueryNotAllowed,
            "Query is not in the allowlist",
        )
    }

    /// Create a parse error violation.
    pub fn parse_error(message: &str) -> Self {
        Self::new(ViolationCode::ParseError, message)
    }

    /// Create an invalid request violation.
    pub fn invalid_request(message: &str) -> Self {
        Self::new(ViolationCode::InvalidRequest, message)
    }
}

/// GraphQL agent errors.
#[derive(Debug, thiserror::Error)]
pub enum GraphQLError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Build a GraphQL-compliant error response.
///
/// Returns a JSON value in the standard GraphQL error format.
/// Note: GraphQL errors are returned with HTTP 200 status.
pub fn graphql_error_response(violations: &[Violation]) -> Value {
    json!({
        "errors": violations.iter().map(|v| {
            let mut error = json!({
                "message": v.message,
                "extensions": {
                    "code": v.code.as_str(),
                    "sentinel": true
                }
            });

            // Add locations if present
            if !v.locations.is_empty() {
                error["locations"] = json!(v.locations);
            }

            // Add additional extensions
            if let Some(ext) = &v.extensions {
                if let Some(actual) = ext.actual {
                    error["extensions"]["actual"] = json!(actual);
                }
                if let Some(max) = ext.max {
                    error["extensions"]["max"] = json!(max);
                }
                if let Some(field) = &ext.field {
                    error["extensions"]["field"] = json!(field);
                }
            }

            error
        }).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_violation_code_display() {
        assert_eq!(ViolationCode::DepthExceeded.to_string(), "DEPTH_EXCEEDED");
        assert_eq!(
            ViolationCode::ComplexityExceeded.to_string(),
            "COMPLEXITY_EXCEEDED"
        );
    }

    #[test]
    fn test_depth_exceeded_violation() {
        let violation = Violation::depth_exceeded(15, 10);
        assert_eq!(violation.code, ViolationCode::DepthExceeded);
        assert!(violation.message.contains("15"));
        assert!(violation.message.contains("10"));
        assert_eq!(violation.extensions.as_ref().unwrap().actual, Some(15));
        assert_eq!(violation.extensions.as_ref().unwrap().max, Some(10));
    }

    #[test]
    fn test_graphql_error_response() {
        let violations = vec![Violation::depth_exceeded(15, 10)];
        let response = graphql_error_response(&violations);

        let errors = response["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);

        let error = &errors[0];
        assert!(error["message"].as_str().unwrap().contains("depth"));
        assert_eq!(error["extensions"]["code"], "DEPTH_EXCEEDED");
        assert_eq!(error["extensions"]["sentinel"], true);
        assert_eq!(error["extensions"]["actual"], 15);
        assert_eq!(error["extensions"]["max"], 10);
    }

    #[test]
    fn test_multiple_violations() {
        let violations = vec![
            Violation::depth_exceeded(15, 10),
            Violation::complexity_exceeded(2000, 1000),
        ];
        let response = graphql_error_response(&violations);

        let errors = response["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0]["extensions"]["code"], "DEPTH_EXCEEDED");
        assert_eq!(errors[1]["extensions"]["code"], "COMPLEXITY_EXCEEDED");
    }
}
