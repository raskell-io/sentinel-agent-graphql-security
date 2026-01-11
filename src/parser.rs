//! GraphQL parsing utilities.

use crate::error::Violation;
use apollo_parser::cst::{self, CstNode};
use apollo_parser::Parser;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A parsed GraphQL request.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// The GraphQL query string
    pub query: String,
    /// Operation name (if provided)
    pub operation_name: Option<String>,
    /// Variables (if provided)
    pub variables: Option<Value>,
    /// Extensions (e.g., APQ hash)
    pub extensions: Option<Value>,
    /// Whether this is a batch request
    pub is_batch: bool,
    /// Number of queries in batch
    pub batch_count: usize,
}

/// A parsed GraphQL document with CST.
#[derive(Debug)]
pub struct ParsedDocument {
    /// The parsed CST document
    pub document: cst::Document,
    /// Fragment definitions for resolving spreads
    pub fragments: HashMap<String, FragmentInfo>,
    /// SHA-256 hash of the normalized query
    pub query_hash: String,
}

/// Information about a fragment definition.
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    /// Fragment name
    pub name: String,
    /// Type condition
    pub type_condition: String,
    /// Selection set (stored as text offset for re-parsing)
    pub selection_set_text: String,
}

/// GraphQL request body format.
#[derive(Debug, Clone, Deserialize)]
struct GraphQLRequestBody {
    query: Option<String>,
    #[serde(rename = "operationName")]
    operation_name: Option<String>,
    variables: Option<Value>,
    extensions: Option<Value>,
}

/// Parse a GraphQL request from raw body bytes.
///
/// Handles both single requests and batch requests (JSON array).
pub fn parse_request(body: &[u8]) -> Result<Vec<ParsedRequest>, Violation> {
    // Try to parse as JSON
    let json: Value = serde_json::from_slice(body).map_err(|e| {
        Violation::invalid_request(&format!("Invalid JSON: {}", e))
    })?;

    // Check if it's a batch request (array)
    if let Some(array) = json.as_array() {
        let mut requests = Vec::with_capacity(array.len());
        for (i, item) in array.iter().enumerate() {
            let req = parse_single_request(item).map_err(|mut v| {
                v.message = format!("Batch item {}: {}", i, v.message);
                v
            })?;
            requests.push(ParsedRequest {
                is_batch: true,
                batch_count: array.len(),
                ..req
            });
        }
        Ok(requests)
    } else {
        // Single request
        let req = parse_single_request(&json)?;
        Ok(vec![req])
    }
}

/// Parse a single GraphQL request from a JSON value.
fn parse_single_request(json: &Value) -> Result<ParsedRequest, Violation> {
    let body: GraphQLRequestBody = serde_json::from_value(json.clone()).map_err(|e| {
        Violation::invalid_request(&format!("Invalid GraphQL request format: {}", e))
    })?;

    let query = body.query.ok_or_else(|| {
        Violation::invalid_request("Missing 'query' field in GraphQL request")
    })?;

    Ok(ParsedRequest {
        query,
        operation_name: body.operation_name,
        variables: body.variables,
        extensions: body.extensions,
        is_batch: false,
        batch_count: 1,
    })
}

/// Parse a GraphQL query string into a document.
pub fn parse_query(query: &str) -> Result<ParsedDocument, Violation> {
    let parser = Parser::new(query);
    let cst = parser.parse();

    // Check for parse errors
    if cst.errors().len() > 0 {
        let errors: Vec<String> = cst
            .errors()
            .map(|e| e.message().to_string())
            .collect();
        return Err(Violation::parse_error(&errors.join("; ")));
    }

    let document = cst.document();

    // Extract fragments
    let fragments = extract_fragments(&document);

    // Calculate query hash
    let query_hash = calculate_query_hash(query);

    Ok(ParsedDocument {
        document,
        fragments,
        query_hash,
    })
}

/// Extract fragment definitions from a document.
fn extract_fragments(document: &cst::Document) -> HashMap<String, FragmentInfo> {
    let mut fragments = HashMap::new();

    for definition in document.definitions() {
        if let cst::Definition::FragmentDefinition(fragment) = definition {
            if let Some(name) = fragment.fragment_name() {
                if let Some(name_token) = name.name() {
                    let frag_name = name_token.text().to_string();
                    let type_condition = fragment
                        .type_condition()
                        .and_then(|tc| tc.named_type())
                        .and_then(|nt| nt.name())
                        .map(|n| n.text().to_string())
                        .unwrap_or_default();

                    let selection_set_text = fragment
                        .selection_set()
                        .map(|ss| ss.syntax().text().to_string())
                        .unwrap_or_default();

                    fragments.insert(
                        frag_name.clone(),
                        FragmentInfo {
                            name: frag_name,
                            type_condition,
                            selection_set_text,
                        },
                    );
                }
            }
        }
    }

    fragments
}

/// Calculate SHA-256 hash of a query string.
pub fn calculate_query_hash(query: &str) -> String {
    // Normalize by trimming whitespace
    let normalized = query.trim();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get the APQ (Automatic Persisted Queries) hash from extensions.
pub fn get_apq_hash(extensions: &Option<Value>) -> Option<String> {
    extensions
        .as_ref()?
        .get("persistedQuery")?
        .get("sha256Hash")?
        .as_str()
        .map(String::from)
}

/// Information about a field in the query.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name (without alias)
    pub name: String,
    /// Alias (if any)
    pub alias: Option<String>,
    /// Parent type (if known)
    pub parent_type: Option<String>,
    /// Arguments
    pub arguments: HashMap<String, Value>,
}

/// Extract all fields from a selection set recursively.
pub fn extract_fields(
    selection_set: &cst::SelectionSet,
    fragments: &HashMap<String, FragmentInfo>,
    parent_type: Option<&str>,
) -> Vec<FieldInfo> {
    let mut fields = Vec::new();

    for selection in selection_set.selections() {
        match selection {
            cst::Selection::Field(field) => {
                let name = field
                    .name()
                    .map(|n| n.text().to_string())
                    .unwrap_or_default();
                let alias = field.alias().and_then(|a| a.name()).map(|n| n.text().to_string());

                // Extract arguments
                let mut arguments = HashMap::new();
                if let Some(args) = field.arguments() {
                    for arg in args.arguments() {
                        if let Some(arg_name) = arg.name() {
                            let arg_value = arg
                                .value()
                                .map(|v| value_to_json(&v))
                                .unwrap_or(Value::Null);
                            arguments.insert(arg_name.text().to_string(), arg_value);
                        }
                    }
                }

                fields.push(FieldInfo {
                    name: name.clone(),
                    alias,
                    parent_type: parent_type.map(String::from),
                    arguments,
                });

                // Recurse into nested selection set
                if let Some(nested_ss) = field.selection_set() {
                    // For nested fields, we don't know the type without schema
                    fields.extend(extract_fields(&nested_ss, fragments, None));
                }
            }
            cst::Selection::FragmentSpread(spread) => {
                if let Some(name) = spread.fragment_name() {
                    if let Some(name_token) = name.name() {
                        let frag_name = name_token.text().to_string();
                        if let Some(frag_info) = fragments.get(&frag_name) {
                            // Parse the fragment's selection set and extract fields
                            if !frag_info.selection_set_text.is_empty() {
                                // Re-parse fragment selection set
                                let parser = Parser::new(&frag_info.selection_set_text);
                                let cst = parser.parse();
                                if cst.errors().len() == 0 {
                                    // Try to get selection set from first definition
                                    for def in cst.document().definitions() {
                                        if let cst::Definition::OperationDefinition(op) = def {
                                            if let Some(ss) = op.selection_set() {
                                                fields.extend(extract_fields(
                                                    &ss,
                                                    fragments,
                                                    Some(&frag_info.type_condition),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            cst::Selection::InlineFragment(inline) => {
                let type_cond = inline
                    .type_condition()
                    .and_then(|tc| tc.named_type())
                    .and_then(|nt| nt.name())
                    .map(|n| n.text().to_string());

                if let Some(ss) = inline.selection_set() {
                    fields.extend(extract_fields(&ss, fragments, type_cond.as_deref()));
                }
            }
        }
    }

    fields
}

/// Convert a CST value to JSON.
fn value_to_json(value: &cst::Value) -> Value {
    match value {
        cst::Value::IntValue(v) => {
            v.int_token()
                .and_then(|t| t.text().parse::<i64>().ok())
                .map(Value::from)
                .unwrap_or(Value::Null)
        }
        cst::Value::FloatValue(v) => {
            v.float_token()
                .and_then(|t| t.text().parse::<f64>().ok())
                .map(Value::from)
                .unwrap_or(Value::Null)
        }
        cst::Value::StringValue(v) => {
            let text = v.syntax().text().to_string();
            // Remove quotes
            let stripped = text.trim_matches('"').trim_matches('\'');
            Value::String(stripped.to_string())
        }
        cst::Value::BooleanValue(v) => {
            v.true_token()
                .map(|_| Value::Bool(true))
                .or_else(|| v.false_token().map(|_| Value::Bool(false)))
                .unwrap_or(Value::Null)
        }
        cst::Value::NullValue(_) => Value::Null,
        cst::Value::EnumValue(v) => {
            v.name()
                .map(|n| Value::String(n.text().to_string()))
                .unwrap_or(Value::Null)
        }
        cst::Value::ListValue(v) => {
            let items: Vec<Value> = v.values().map(|val| value_to_json(&val)).collect();
            Value::Array(items)
        }
        cst::Value::ObjectValue(v) => {
            let mut map = serde_json::Map::new();
            for field in v.object_fields() {
                if let Some(name) = field.name() {
                    let key = name.text().to_string();
                    let val = field
                        .value()
                        .map(|v| value_to_json(&v))
                        .unwrap_or(Value::Null);
                    map.insert(key, val);
                }
            }
            Value::Object(map)
        }
        cst::Value::Variable(v) => {
            v.name()
                .map(|n| Value::String(format!("${}", n.text())))
                .unwrap_or(Value::Null)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let query = "{ users { id name } }";
        let result = parse_query(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_query_with_variables() {
        let query = r#"
            query GetUser($id: ID!) {
                user(id: $id) {
                    id
                    name
                    email
                }
            }
        "#;
        let result = parse_query(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_query() {
        let query = "{ users { id name ";
        let result = parse_query(query);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, crate::error::ViolationCode::ParseError);
    }

    #[test]
    fn test_parse_request() {
        let body = br#"{"query": "{ users { id } }"}"#;
        let result = parse_request(body);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].is_batch);
    }

    #[test]
    fn test_parse_batch_request() {
        let body = br#"[
            {"query": "{ users { id } }"},
            {"query": "{ posts { id } }"}
        ]"#;
        let result = parse_request(body);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].is_batch);
        assert_eq!(requests[0].batch_count, 2);
    }

    #[test]
    fn test_query_hash() {
        let query1 = "{ users { id } }";
        let query2 = "  { users { id } }  ";
        // Hashes should be the same after normalization
        assert_eq!(calculate_query_hash(query1), calculate_query_hash(query2));
    }

    #[test]
    fn test_get_apq_hash() {
        let extensions = Some(serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "abc123"
            }
        }));
        assert_eq!(get_apq_hash(&extensions), Some("abc123".to_string()));
    }

    #[test]
    fn test_get_apq_hash_missing() {
        let extensions: Option<Value> = None;
        assert_eq!(get_apq_hash(&extensions), None);
    }
}
