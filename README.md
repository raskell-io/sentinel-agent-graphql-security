# Zentinel GraphQL Security Agent

A dedicated GraphQL security agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Built in **pure Rust** using the [apollo-parser](https://crates.io/crates/apollo-parser) CST, it inspects every GraphQL request in real time and enforces configurable limits on query depth, complexity, aliases, batch size, introspection, field-level authorization, and persisted query allowlists.

## Features

### Query Depth Limiting
- Calculates the maximum nesting depth of each operation
- Configurable `max_depth` threshold (default: 10)
- Follows fragment spreads and inline fragments with cycle detection
- Option to ignore introspection fields (`__schema`, `__type`) in depth calculation

### Complexity / Cost Analysis
- Estimates query cost using field costs and list-size multipliers
- Configurable per-type and per-field cost overrides (e.g., `Query.users: 10`)
- Automatically detects pagination arguments (`first`, `last`, `limit`, `pageSize`) to derive list multipliers
- Default multiplier applied when no pagination argument is present
- Configurable `max_complexity` threshold (default: 1000)

### Alias Limiting
- Counts total aliases across the entire query
- Tracks per-field duplicate alias counts
- Configurable `max_aliases` (default: 10) and `max_duplicate_aliases` (default: 3)
- Prevents alias-based resource exhaustion attacks (e.g., aliasing the same expensive field hundreds of times)

### Batch Query Limiting
- Detects JSON array batch requests and counts operations
- Configurable `max_queries` per batch (default: 5)
- Single (non-batch) requests are never limited by this analyzer

### Introspection Control
- Blocks `__schema` and `__type` queries in production
- Allows `__typename` by default (required by Apollo Client for union/interface resolution)
- IP-based and header-based allowlists for developer access
- Global toggle to enable or disable introspection entirely

### Field-Level Authorization
- Role-based and scope-based access control on individual fields
- Glob pattern matching for field selectors (e.g., `Query.admin*`, `Mutation.delete*`, `User.*`)
- Reads roles/scopes from configurable request headers (defaults: `X-User-Roles`, `X-User-Scopes`)
- Supports both `require_roles` (any-of) and `require_scopes` (any-of) semantics

### Persisted Queries / Allowlist
- **Allowlist mode** -- only queries whose SHA-256 hash appears in a pre-loaded JSON file are permitted
- **Cache mode** -- any query is allowed; hashes are tracked for observability
- Compatible with Apollo Automatic Persisted Queries (APQ) via the `persistedQuery` extension
- Optional `require_hash` flag to reject requests that do not include an APQ hash

### Protocol v2 Support
- Full gRPC transport with capability negotiation, health reporting, and metrics export
- Backwards-compatible UDS (Unix Domain Socket) mode via a v1 adapter
- Live configuration push -- update settings without restarting the agent
- Prometheus-style counter and gauge metrics (`graphql_security_requests_total`, `graphql_security_requests_blocked_total`, `graphql_security_block_rate_percent`)

## Installation

### From Source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-graphql-security
cd zentinel-agent-graphql-security
cargo build --release
```

### Binary

```bash
./target/release/zentinel-graphql-security-agent --config config.yaml
```

## Quick Start

```bash
# gRPC transport (recommended -- full v2 protocol)
zentinel-graphql-security-agent \
  --config config.yaml \
  --grpc-address 0.0.0.0:50051

# UDS transport (v1 compatibility)
zentinel-graphql-security-agent \
  --config config.yaml \
  --socket /var/run/zentinel/graphql-security.sock

# With debug logging
RUST_LOG=debug zentinel-graphql-security-agent --config config.yaml --grpc-address 0.0.0.0:50051
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `config.yaml` | Path to YAML configuration file |
| `--socket`, `-s` | `/tmp/zentinel-graphql-security.sock` | Unix socket path (v1 mode) |
| `--grpc-address` | *(none)* | gRPC listen address, e.g. `0.0.0.0:50051` (v2 mode) |
| `--log-level`, `-l` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

## Configuration

The agent is configured with a YAML file. Every section is optional; sensible defaults are applied when a key is omitted.

```yaml
version: "1"

settings:
  # Maximum request body size in bytes (default: 1048576 = 1 MB)
  max_body_size: 1048576
  # Add X-GraphQL-Depth, X-GraphQL-Complexity, etc. headers to responses
  debug_headers: false
  # Action when a violation is detected: "block" or "allow" (log-only)
  fail_action: block

depth:
  enabled: true
  # Maximum nesting depth (default: 10)
  max_depth: 10
  # Exclude __schema / __type from depth calculation
  ignore_introspection: true

complexity:
  enabled: true
  # Maximum allowed complexity score (default: 1000)
  max_complexity: 1000
  # Base cost per field (default: 1)
  default_field_cost: 1
  # Multiplier when no pagination argument is found (default: 10)
  default_list_multiplier: 10
  # Override cost for specific fields
  field_costs:
    Query.users: 10
    Query.orders: 15
    Mutation.createOrder: 20
  # Override cost for all fields of a type
  type_costs:
    AuditLog: 5
  # Arguments whose value is used as the list multiplier
  list_size_arguments:
    - first
    - last
    - limit
    - pageSize

aliases:
  enabled: true
  # Maximum total aliases in one query (default: 10)
  max_aliases: 10
  # Maximum times the same field may be aliased (default: 3)
  max_duplicate_aliases: 3

batch:
  enabled: true
  # Maximum operations in a JSON-array batch request (default: 5)
  max_queries: 5

introspection:
  enabled: true
  # Globally allow introspection (default: false)
  allow: false
  # Allow __typename (needed by Apollo Client; default: true)
  allow_typename: true
  # IPs or header values that are always allowed to introspect
  allowed_clients:
    - "10.0.0.0/8"
    - "dev-introspection-key"
  # Header to check for allowed clients
  allowed_clients_header: "X-Introspection-Key"

field_auth:
  enabled: true
  rules:
    - fields:
        - "Query.admin*"
        - "Mutation.delete*"
      require_roles:
        - admin
      # Header containing comma-separated roles (default: X-User-Roles)
      roles_header: "X-User-Roles"
    - fields:
        - "User.email"
        - "User.phone"
      require_scopes:
        - "read:pii"
      scopes_header: "X-User-Scopes"

persisted_queries:
  enabled: false
  # "allowlist" (only pre-approved hashes) or "cache" (any query, tracked)
  mode: allowlist
  # Path to a JSON file containing allowed query hashes
  allowlist_file: "/etc/zentinel/graphql-allowlist.json"
  # Require the APQ hash extension on every request
  require_hash: false
```

### Allowlist File Format

When using `persisted_queries.mode: allowlist`, provide a JSON file:

```json
{
  "version": 1,
  "queries": [
    {
      "hash": "a1b2c3d4e5f6...",
      "name": "GetCurrentUser"
    },
    {
      "hash": "f6e5d4c3b2a1...",
      "name": "ListProducts"
    }
  ]
}
```

Hashes are compared case-insensitively. You can generate a hash for any query with:

```bash
echo -n '{ users { id name } }' | shasum -a 256
```

## Zentinel Proxy Integration

Register the agent in your Zentinel proxy configuration:

### gRPC Transport (v2)

```kdl
agents {
    agent "graphql-security" {
        type "custom"
        grpc "127.0.0.1:50051"
        events "request_headers" "request_body"
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "graphql" {
        matches { path-prefix "/graphql" }
        upstream "graphql-backend"
        agents "graphql-security"
    }
}
```

### Unix Socket (v1 compatibility)

```kdl
agents {
    agent "graphql-security" {
        type "custom"
        unix-socket "/var/run/zentinel/graphql-security.sock"
        events "request_headers" "request_body"
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "graphql" {
        matches { path-prefix "/graphql" }
        upstream "graphql-backend"
        agents "graphql-security"
    }
}
```

The agent subscribes to `request_headers` and `request_body_chunk` events. It signals `needs_more` on the headers event and performs the full analysis once the complete request body arrives.

## Response Format

When a violation is detected and `fail_action` is `block`, the agent returns an **HTTP 200** response with a standard GraphQL error body:

```json
{
  "errors": [
    {
      "message": "Query depth of 15 exceeds maximum allowed depth of 10",
      "extensions": {
        "code": "DEPTH_EXCEEDED",
        "zentinel": true,
        "actual": 15,
        "max": 10
      }
    }
  ]
}
```

### Violation Codes

| Code | Description |
|------|-------------|
| `DEPTH_EXCEEDED` | Query nesting depth exceeds `max_depth` |
| `COMPLEXITY_EXCEEDED` | Calculated cost exceeds `max_complexity` |
| `TOO_MANY_ALIASES` | Alias count or duplicate alias count exceeds limit |
| `TOO_MANY_BATCH_QUERIES` | Batch request contains more operations than `max_queries` |
| `INTROSPECTION_BLOCKED` | Introspection query sent by a non-allowed client |
| `FIELD_UNAUTHORIZED` | Client lacks the required role or scope for a field |
| `QUERY_NOT_ALLOWED` | Query hash not found in the persisted query allowlist |
| `PARSE_ERROR` | GraphQL query could not be parsed |
| `INVALID_REQUEST` | Request body is not valid JSON or is too large |

### Debug Headers

When `settings.debug_headers` is enabled, every response includes analysis metrics:

```
X-GraphQL-Depth: 4
X-GraphQL-Complexity: 87
X-GraphQL-Aliases: 2
X-GraphQL-Operations: 1
X-GraphQL-Fields: 12
```

## Example Scenarios

### Blocking a Deeply Nested Query

A query like the following (depth 7) would be rejected with the default `max_depth: 10` raised to a stricter limit of 5:

```graphql
# depth.max_depth: 5
{
  users {
    posts {
      comments {
        author {
          followers {
            posts {    # depth = 7 -- blocked
              title
            }
          }
        }
      }
    }
  }
}
```

Response:

```json
{
  "errors": [{
    "message": "Query depth of 7 exceeds maximum allowed depth of 5",
    "extensions": { "code": "DEPTH_EXCEEDED", "zentinel": true, "actual": 7, "max": 5 }
  }]
}
```

### Preventing Alias-Based DoS

An attacker duplicates an expensive field with aliases to multiply server-side work:

```graphql
{
  a1: expensiveReport(year: 2024) { data }
  a2: expensiveReport(year: 2024) { data }
  a3: expensiveReport(year: 2024) { data }
  a4: expensiveReport(year: 2024) { data }
  # ... repeated many more times
}
```

With `aliases.max_aliases: 10` and `aliases.max_duplicate_aliases: 3`, the request is blocked as soon as the fourth alias of the same field is detected.

### Blocking Introspection in Production

With the default configuration (`introspection.allow: false`), any `__schema` or `__type` query from an unknown client is rejected:

```graphql
{
  __schema {
    types { name }
  }
}
```

Developers can still introspect by setting a header:

```bash
curl -H "X-Introspection-Key: dev-introspection-key" \
     -d '{"query": "{ __schema { types { name } } }"}' \
     https://api.example.com/graphql
```

### Enforcing Field-Level Authorization

Restrict admin-only mutations:

```yaml
field_auth:
  enabled: true
  rules:
    - fields: ["Mutation.delete*"]
      require_roles: ["admin"]
```

A request from a user without the `admin` role:

```graphql
mutation {
  deleteUser(id: "42") { success }
}
```

Response:

```json
{
  "errors": [{
    "message": "Access to field 'Mutation.deleteUser' is not authorized",
    "extensions": { "code": "FIELD_UNAUTHORIZED", "zentinel": true, "field": "Mutation.deleteUser" }
  }]
}
```

### Limiting Batch Queries

A batch of 10 operations with `batch.max_queries: 5`:

```json
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"},
  {"query": "{ user(id: 4) { name } }"},
  {"query": "{ user(id: 5) { name } }"},
  {"query": "{ user(id: 6) { name } }"},
  {"query": "{ user(id: 7) { name } }"},
  {"query": "{ user(id: 8) { name } }"},
  {"query": "{ user(id: 9) { name } }"},
  {"query": "{ user(id: 10) { name } }"}
]
```

Response:

```json
{
  "errors": [{
    "message": "Batch contains 10 queries, maximum allowed is 5",
    "extensions": { "code": "TOO_MANY_BATCH_QUERIES", "zentinel": true, "actual": 10, "max": 5 }
  }]
}
```

## Metrics

The agent exports Prometheus-compatible metrics via the v2 protocol:

| Metric | Type | Description |
|--------|------|-------------|
| `graphql_security_requests_total` | Counter | Total requests processed |
| `graphql_security_requests_blocked_total` | Counter | Total requests blocked |
| `graphql_security_block_rate_percent` | Gauge | Percentage of requests blocked |

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                       Zentinel Proxy                              │
└──────────────────────────┬────────────────────────────────────────┘
                           │ gRPC / Unix Socket
                           ▼
┌───────────────────────────────────────────────────────────────────┐
│               GraphQL Security Agent                              │
│                                                                   │
│   ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────────┐  │
│   │  Depth   │  │ Complexity  │  │  Alias   │  │   Batch     │  │
│   │ Analyzer │  │  Analyzer   │  │ Analyzer │  │  Analyzer   │  │
│   └────┬─────┘  └──────┬──────┘  └────┬─────┘  └──────┬──────┘  │
│        │               │              │               │          │
│   ┌────┴─────┐  ┌──────┴──────┐  ┌────┴─────────────┐│          │
│   │Introspec.│  │ Field Auth  │  │Persisted Queries ││          │
│   │ Analyzer │  │  Analyzer   │  │    Analyzer      ││          │
│   └────┬─────┘  └──────┬──────┘  └────┬─────────────┘│          │
│        │               │              │               │          │
│        └───────────────┼──────────────┼───────────────┘          │
│                        ▼              ▼                           │
│              ┌─────────────────────────────────┐                 │
│              │       Analysis Result           │                 │
│              │  violations[] + metrics{}       │                 │
│              └────────────┬────────────────────┘                 │
│                           ▼                                      │
│              ┌─────────────────────────────────┐                 │
│              │   Decision: Allow / Block       │                 │
│              │   (GraphQL-compliant response)  │                 │
│              └─────────────────────────────────┘                 │
└───────────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Unit tests
cargo test --lib

# All tests
cargo test

# With logging output
RUST_LOG=debug cargo test -- --nocapture
```

## Development

```bash
# Debug build with logging
RUST_LOG=debug cargo run -- --config config.yaml --grpc-address 0.0.0.0:50051

# Release build
cargo build --release

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## License

Apache-2.0

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Report security vulnerabilities to security@raskell.io.
