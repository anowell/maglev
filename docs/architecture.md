# Maglev Architecture

## Overview

Maglev is a focused library providing patterns and utilities for building JSON APIs with Axum and SQLx.

## Design Philosophy

**Library, Not Framework**: Maglev extends Axum rather than abstracting it. Users write normal Axum code and opt-in to Maglev utilities as needed. No custom routing DSL, no opaque magic.

**Trait-Based Extensibility**: Key abstractions use traits (`Job<S>`, `ValidateClaims<S>`, `QueueProvider<S>`) allowing users to customize without forking.

**State-Centric**: Everything generic over state type `S`. Leverages Axum's `FromRef<S>` for component extraction. Makes testing easy - pass your test state.

## Repository Structure

### framework/
Core library with modules for JWT auth, background jobs, error handling, config loading, encryption, routing helpers, and server lifecycle.

### maglev-macros/
Procedural macros - primarily `#[derive(HttpError)]` for generating HTTP status codes and user-facing error messages from error enums.

### cli/
Code generator for scaffolding jobs, models, and other boilerplate.

## Key Patterns

### 1. Wrapper Types with FromRequestParts

Extractors wrap inner types for ergonomic access:

```rust
pub struct Jwt<J>(pub J);

impl<J> Deref for Jwt<J> {
    type Target = J;
    fn deref(&self) -> &J { &self.0 }
}

impl<S, J> FromRequestParts<S> for Jwt<J> { ... }
```

Pattern allows: `async fn handler(user: Jwt<AuthUser>)` with auto-dereference to `AuthUser`.

### 2. Blocking Ops on Tokio Threads

Expensive crypto runs on blocking threads to avoid blocking async runtime:

```rust
pub async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        // Argon2 hashing
    }).await?
}
```

Used for: password hashing, password verification, encryption, decryption.

### 3. Builder Pattern for Config

```rust
JwtConfig::builder()
    .secret(secret)
    .expiration(Duration::weeks(2))
    .cookie(CookieConfig::default())
    .build()
```

Provides discoverability and type-safe construction with defaults.

### 4. Proc Macros for Boilerplate

`#[derive(HttpError)]` generates status codes and user-facing messages from error enums:

```rust
#[derive(thiserror::Error, HttpError)]
enum Error {
    #[error("auth required")]
    #[http_error(UNAUTHORIZED)]
    Unauthorized,

    #[error("db error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "internal error")]
    Database(sqlx::Error),
}
```

Separates internal error logging from user responses.

### 5. Generic State with FromRef

Components extract from state via `FromRef<S>`:

```rust
#[derive(Clone, FromRef)]
struct AppState {
    db: PgPool,
    jwt: JwtContext,
}

async fn handler(
    user: Jwt<AuthUser>,  // Extracts JwtContext from state
    State(db): State<PgPool>,
) { ... }
```

Reduces boilerplate and couples components loosely.

## Dependency Choices

| Crate | Why |
|-------|-----|
| **axum 0.8** | Ergonomic, Tower-based, active ecosystem |
| **sqlx 0.8** | Compile-time SQL checking, async, no ORM |
| **tokio 1.49** | De-facto async runtime |
| **tower 0.5** | Middleware and service abstractions |
| **orion 0.17** | AEAD encryption, security-focused |
| **argon2 0.5** | Memory-hard password hashing |
| **jwt 0.16** | Simple JWT signing/verification |
| **tokio-cron-scheduler** | Background job scheduling |
| **async-trait 0.1** | Object-safe async traits (only for `Job<S>` / `QueueProvider<S>`) |

## Tradeoffs & Decisions

### Why No ORM?

**Decision**: Use SQLx for direct SQL queries.

**Rationale**:
- ORMs hide query performance (N+1, lazy loading)
- Compile-time SQL checking provides similar safety
- Direct SQL is more transparent and debuggable
- Easier to optimize when needed

**Tradeoff**: More boilerplate than ORM, but explicit and controllable.

### Why HMAC-SHA384 over SHA256?

**Decision**: Use SHA384 for JWT signing.

**Rationale**: Stronger collision resistance, minimal size increase.

**Tradeoff**: Slightly larger tokens (~50 bytes), but negligible for HTTP headers.

### Why In-Memory Job Queue?

**Decision**: Default `MemoryQueue<S>` for jobs.

**Rationale**: Simple, fast, no external dependencies. Sufficient for many use cases.

**Tradeoff**: Not durable across restarts. Provide `QueueProvider` trait for Redis/Postgres backends.

### Why No Automatic Migration System?

**Decision**: Don't include database migrations.

**Rationale**:
- Migrations are deployment-specific
- SQLx already has `sqlx-cli` for migrations
- Keeps Maglev focused and lightweight

**Tradeoff**: Users must set up migrations themselves, but avoids coupling to deployment specifics.

## Extension Points

Where users can customize:

1. **Job<S> trait** - Implement custom background jobs
2. **ValidateClaims<S>** - Custom JWT validation logic
3. **QueueProvider<S>** - Pluggable job storage (Redis, Postgres, etc.)
4. **ClaimsExtractor<S>** - Custom auth extractors
5. **EnvConfig** - Auto-implemented for any deserializable config

## Future Considerations

### OpenAPI Generation

**Options evaluated**:
- `utoipa` - Most popular, code-first, macro-based
- `oasgen` - Framework-agnostic, uses docstrings
- `poem-openapi` - Integrated into Poem framework

**Recommendation**: `utoipa` for Axum integration, or keep framework-agnostic with `oasgen`.

### Transactional Outbox Pattern

For durable job enqueuing and event publishing:
- Store jobs in same transaction as domain entities
- Background worker polls outbox table
- Guarantees jobs aren't lost on crash

**Implementation**: Requires `QueueProvider` backed by SQLx transactions.

### CRUD Route Patterns

Current `CrudRouter` is basic. Could enhance with:
- Pagination helpers
- Filtering/sorting from query params
- Soft deletes
- Automatic OpenAPI annotations

## Non-Goals

- **Frontend framework** - JSON APIs only, frontend-agnostic
- **Admin UI** - Out of scope (future consideration)
- **Batteries-included auth** - Provide primitives, not complete solutions
- **Message queue integration** - Use external crates (lapin, rdkafka, etc.)
- **Caching layer** - Use tower-http or external crates

## Architectural Constraints

1. **No breaking Axum patterns** - If it works in Axum, it should work with Maglev
2. **State type must be Clone** - Required by Axum and job system
3. **No runtime reflection** - Everything compile-time checked
4. **Minimal proc macro magic** - Only where significant value (HttpError)
5. **No hidden I/O** - All async operations explicit

## Testing Strategy

- **Integration tests** over unit tests (test public APIs)
- **Real SQLx** in tests (use sqlx::test for transactions)
- **Minimize mocking** - Use test state instead
- **Example code** as living documentation

## Performance Characteristics

Not optimized for extreme performance, but reasonable defaults:

- **JWT validation**: ~5-10μs (HMAC-SHA384)
- **Job queue**: In-memory VecDeque, minimal overhead
- **Encryption**: Orion AEAD, ~1-2μs for small payloads

For high-throughput needs, consider:
- Redis-backed job queue
- Connection pooling (SQLx provides this)
- Tower middleware for caching

## Migration Guide (Future)

When we hit 1.0, document:
- Breaking changes from experimental
- Deprecated APIs and replacements
- Upgrade path from pre-1.0 code
