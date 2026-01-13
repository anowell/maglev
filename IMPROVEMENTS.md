# Maglev Improvement Recommendations

## Overview

This document outlines concrete improvements to make Maglev the most ergonomic way to build durable JSON APIs in Rust. Organized by priority and aligned with the goal: **make it trivially easy to build production-ready JSON APIs without reinventing Axum**.

---

## Priority 1: OpenAPI Integration

### Problem
API documentation is manual and out-of-sync with code. No automatic schema generation.

### Solution: Integrate utoipa

**Why utoipa**:
- Most popular (2.6k stars), actively maintained
- Code-first with derive macros (matches Maglev philosophy)
- Framework-agnostic but excellent Axum integration
- Compile-time generation (no runtime overhead)

**Implementation**:
```rust
// In Cargo.toml
utoipa = { version = "5", features = ["axum_extras"] }
utoipa-swagger-ui = { version = "8", features = ["axum"] }

// Usage
#[derive(Serialize, Deserialize, ToSchema)]
struct User {
    id: Uuid,
    email: String,
}

#[utoipa::path(
    get,
    path = "/users/{id}",
    responses(
        (status = 200, description = "User found", body = User),
        (status = 404, description = "User not found")
    )
)]
async fn get_user(Path(id): Path<Uuid>) -> Result<Json<User>, AppError> { ... }
```

**Maglev additions**:
1. Re-export utoipa macros as `maglev::openapi::*`
2. Add `OpenApiRouter` wrapper with built-in Swagger UI
3. Auto-derive `ToSchema` for Maglev types (JwtClaims, error formats, etc.)
4. Provide `#[derive(ToSchema)]` integration with `HttpError`

**Estimated effort**: 2-3 days
**References**:
- [utoipa](https://github.com/juhaku/utoipa)
- [utoipa integration guide](https://identeco.de/en/blog/generating_and_validating_openapi_docs_in_rust/)

---

## Priority 2: Transactional Outbox Pattern

### Problem
Jobs can be lost if enqueue fails after database commit (dual-write problem). No durability guarantees.

### Solution: SQLx-based Outbox Queue

**Pattern**: Store jobs in same transaction as domain entities.

**Implementation**:
```rust
// New module: maglev::jobs::outbox

pub struct OutboxQueue<S> {
    pool: PgPool,
    _marker: PhantomData<S>,
}

#[derive(Serialize, Deserialize)]
struct OutboxEvent {
    id: Uuid,
    job_type: String,
    payload: JsonValue,
    status: EventStatus,
    retry_count: i32,
    max_retries: i32,
    scheduled_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl<S> OutboxQueue<S> {
    pub async fn enqueue_tx<J: Serialize>(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        job: &J,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO outbox_events (job_type, payload) VALUES ($1, $2)",
            type_name::<J>(),
            serde_json::to_value(job)?
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

// Background worker polls outbox table
async fn process_outbox(pool: PgPool, registry: JobRegistry<S>) {
    loop {
        let events = sqlx::query_as!(
            OutboxEvent,
            "SELECT * FROM outbox_events
             WHERE status = 'pending' AND scheduled_at <= NOW()
             ORDER BY created_at
             FOR UPDATE SKIP LOCKED LIMIT 10"
        )
        .fetch_all(&pool)
        .await?;

        for event in events {
            if let Some(job) = registry.deserialize(&event.job_type, &event.payload) {
                job.perform(state.clone()).await;
                mark_completed(&pool, event.id).await;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
```

**Migration**:
```sql
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 3,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error TEXT
);

CREATE INDEX idx_outbox_pending ON outbox_events(status, scheduled_at)
WHERE status = 'pending';
```

**Key decisions**:
- Require jobs to be Serialize/Deserialize (breaking change from closure-based)
- Provide `JobRegistry` for type-safe deserialization
- Support delayed jobs via `scheduled_at`
- Exponential backoff on retries

**Estimated effort**: 1 week
**References**:
- [Transactional Outbox Pattern](https://microservices.io/patterns/data/transactional-outbox.html)
- [Rust outbox implementation](https://berektassuly.com/solana-postgresql-dual-write-rust-case-study)

---

## Priority 3: Request Validation

### Problem
Manual validation scattered across handlers. Repetitive and error-prone.

### Solution: validator crate integration

**Why validator**:
- Most popular validation crate
- Derive-based (ergonomic)
- Custom validators supported
- i18n for error messages

**Implementation**:
```rust
use validator::Validate;

#[derive(Deserialize, Validate, ToSchema)]
struct CreateUser {
    #[validate(email)]
    email: String,

    #[validate(length(min = 8, max = 100))]
    password: String,

    #[validate(range(min = 18, max = 120))]
    age: u8,
}

// Maglev provides extractor
use maglev::extract::ValidatedJson;

async fn create_user(
    ValidatedJson(input): ValidatedJson<CreateUser>
) -> Result<Json<User>, AppError> {
    // input is pre-validated
}
```

**Maglev additions**:
1. `ValidatedJson<T>` extractor that validates before deserializing
2. Convert validation errors to structured JSON responses
3. Integrate with OpenAPI schema generation

**Estimated effort**: 2 days

---

## Priority 4: Pagination Helpers

### Problem
Pagination logic repeated in every list endpoint. No standard format.

### Solution: Pagination extractors and response types

**Implementation**:
```rust
// New module: maglev::pagination

#[derive(Deserialize, ToSchema)]
pub struct PageParams {
    #[serde(default = "default_page")]
    pub page: u32,

    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

impl PageParams {
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.per_page
    }

    pub fn limit(&self) -> u32 {
        self.per_page.min(100) // Max 100 per page
    }
}

#[derive(Serialize, ToSchema)]
pub struct Page<T> {
    pub data: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total_count: u64,
    pub total_pages: u32,
}

impl<T> Page<T> {
    pub fn new(data: Vec<T>, page: u32, per_page: u32, total_count: u64) -> Self {
        Self {
            data,
            page,
            per_page,
            total_count,
            total_pages: ((total_count + per_page as u64 - 1) / per_page as u64) as u32,
        }
    }
}

// Usage
async fn list_users(
    Query(params): Query<PageParams>,
    State(db): State<PgPool>,
) -> Result<Json<Page<User>>, AppError> {
    let users = sqlx::query_as!(
        User,
        "SELECT * FROM users LIMIT $1 OFFSET $2",
        params.limit(),
        params.offset()
    )
    .fetch_all(&db)
    .await?;

    let total = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(&db)
        .await?;

    Ok(Json(Page::new(users, params.page, params.per_page, total)))
}
```

**Enhancements**:
- Cursor-based pagination option (for real-time data)
- Sorting via query params
- Filtering helpers

**Estimated effort**: 1 day

---

## Priority 5: Enhanced CRUD Patterns

### Problem
Current `CrudRouter` is basic. No filtering, sorting, soft deletes, or field selection.

### Solution: Richer CRUD builder

**Implementation**:
```rust
// Enhanced CrudRouter
CrudRouter::new("/users")
    .list(list_users)
    .create(create_user)
    .read(get_user)
    .update(update_user)
    .delete(delete_user)
    .soft_delete(true)  // Adds deleted_at column support
    .filterable(&["email", "role", "created_at"])  // Query params
    .sortable(&["created_at", "email"])
    .searchable(&["email", "name"])  // Full-text search
    .fields_selectable(true)  // ?fields=id,email
    .paginated(PageParams::default())
    .into_router()
```

**Generated endpoints**:
- `GET /users?page=1&per_page=20&sort=-created_at&filter[role]=admin&search=john`
- `GET /users/:id?fields=id,email,created_at`
- Soft delete: `DELETE /users/:id` sets `deleted_at` instead of removing

**Key decisions**:
- Use traits for filterable/sortable field definitions
- Compile-time checks on field names
- SQLx query builder integration

**Estimated effort**: 1 week

---

## Priority 6: Observability Enhancements

### Problem
Minimal tracing integration. No metrics, no request IDs, no structured logging patterns.

### Solution: Built-in observability middleware

**Implementation**:
```rust
// New module: maglev::observability

pub fn observability_layer() -> ServiceBuilder<
    Stack<
        Stack<TraceLayer, RequestIdLayer>,
        MetricsLayer
    >
> {
    ServiceBuilder::new()
        .layer(RequestIdLayer::new())  // X-Request-ID
        .layer(TraceLayer::new()
            .on_request(|req: &Request, _span: &Span| {
                tracing::info!(
                    method = %req.method(),
                    uri = %req.uri(),
                    request_id = ?req.headers().get("x-request-id"),
                    "request started"
                );
            })
            .on_response(|res: &Response, latency: Duration, _span: &Span| {
                tracing::info!(
                    status = %res.status(),
                    latency_ms = latency.as_millis(),
                    "request completed"
                );
            })
        )
        .layer(MetricsLayer::new())  // Prometheus metrics
}

// Usage
let app = Router::new()
    .route("/users", get(list_users))
    .layer(maglev::observability_layer())
    .with_state(state);
```

**Metrics collected**:
- HTTP request duration histogram (by method, path, status)
- Request count counter (by method, path, status)
- Active request gauge
- Job queue length gauge
- Job processing duration histogram

**Estimated effort**: 3 days

---

## Priority 7: Health Check Endpoints

### Problem
No standardized health checks for load balancers and monitoring.

### Solution: Built-in health check system

**Implementation**:
```rust
// New module: maglev::health

pub struct HealthCheck<S> {
    checks: Vec<Box<dyn Check<S>>>,
}

#[async_trait]
pub trait Check<S>: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self, state: &S) -> Result<(), String>;
}

// Built-in checks
pub struct DatabaseCheck;

#[async_trait]
impl Check<PgPool> for DatabaseCheck {
    fn name(&self) -> &str { "database" }

    async fn check(&self, pool: &PgPool) -> Result<(), String> {
        sqlx::query("SELECT 1")
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|e| format!("database unavailable: {}", e))
    }
}

// Usage
let health = HealthCheck::new()
    .add(DatabaseCheck)
    .add(RedisCheck::new(redis_url))
    .add(CustomCheck::new(|| async { Ok(()) }));

let app = Router::new()
    .route("/health", get(health.liveness()))  // Simple OK
    .route("/health/ready", get(health.readiness()))  // All checks
    .route("/health/details", get(health.details()))  // Verbose
```

**Response format**:
```json
{
    "status": "healthy",
    "timestamp": "2026-01-13T10:30:00Z",
    "uptime_seconds": 3600,
    "checks": {
        "database": { "status": "ok", "latency_ms": 2 },
        "redis": { "status": "ok", "latency_ms": 1 }
    }
}
```

**Estimated effort**: 2 days

---

## Priority 8: Connection Pooling Patterns

### Problem
No guidance on SQLx pool configuration. Users may use suboptimal settings.

### Solution: Documented patterns and config helpers

**Implementation**:
```rust
// New module: maglev::db

pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl PoolConfig {
    pub fn production() -> Self {
        Self {
            max_connections: num_cpus::get() as u32 * 4,
            min_connections: 2,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }

    pub fn development() -> Self {
        Self {
            max_connections: 5,
            min_connections: 1,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(600),
        }
    }

    pub async fn connect_postgres(&self, url: &str) -> Result<PgPool> {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect(url)
            .await
    }
}
```

**Documentation**: Add `docs/database.md` with:
- Connection pool sizing guidance
- Query timeout patterns
- Transaction management best practices
- Common pitfalls (holding transactions too long, etc.)

**Estimated effort**: 1 day

---

## Priority 9: Rate Limiting

### Problem
No built-in rate limiting. Users implement ad-hoc solutions.

### Solution: Tower-based rate limiting middleware

**Implementation**:
```rust
// Integration with tower-governor or tower-limit

use maglev::ratelimit::{RateLimitLayer, RateLimitConfig};

let config = RateLimitConfig::new()
    .per_second(10)  // 10 requests per second
    .burst_size(20)  // Allow bursts up to 20
    .key_fn(|req: &Request| {
        // Extract key from IP, user ID, API key, etc.
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string()
    });

let app = Router::new()
    .route("/api/users", get(list_users))
    .layer(RateLimitLayer::new(config))
```

**Response on limit exceeded**:
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 5
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1673612400

{"code": 429, "message": "rate limit exceeded"}
```

**Estimated effort**: 2 days

---

## Priority 10: Testing Utilities

### Problem
No test helpers. Users reinvent test fixtures and mocks.

### Solution: Test utilities module

**Implementation**:
```rust
// New module: maglev::test (feature-gated)

pub fn test_jwt_context() -> JwtContext {
    JwtContext::builder()
        .secret(b"test-secret-key-32-bytes-long!!")
        .expiration(Duration::hours(1))
        .build()
        .unwrap()
}

pub async fn test_db_pool() -> PgPool {
    let url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL not set");
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("failed to connect to test database")
}

pub struct TestApp {
    pub addr: SocketAddr,
    pub client: reqwest::Client,
    pub db: PgPool,
    pub jwt: JwtContext,
}

impl TestApp {
    pub async fn spawn(state: impl Clone + Send + Sync + 'static) -> Self {
        // Spawn server on random port
        // Return test app with client
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("http://{}{}", self.addr, path))
            .send()
            .await
            .unwrap()
    }

    pub fn with_auth(&self, token: &str) -> RequestBuilder {
        self.client
            .get(format!("http://{}", self.addr))
            .header("Authorization", format!("Bearer {}", token))
    }
}
```

**Estimated effort**: 2 days

---

## Quick Wins (< 1 day each)

### 1. Request Logging Middleware
Add structured request/response logging out of box.

### 2. CORS Helpers
Re-export tower-http CORS with sensible defaults.

### 3. Compression Middleware
Enable gzip/brotli compression by default.

### 4. Static File Serving
Helper for serving static assets (for documentation, admin UIs).

### 5. WebSocket Support
Simple WebSocket handler patterns for Axum.

### 6. Server-Sent Events (SSE)
Helpers for streaming responses.

### 7. Conditional Request Support
ETag and Last-Modified header helpers.

### 8. Content Negotiation
Accept header parsing for multiple response formats.

---

## Future Considerations

### After 1.0

1. **GraphQL Integration** - utoipa-graphql or async-graphql integration
2. **gRPC Support** - tonic integration patterns
3. **Event Sourcing** - Event store patterns with SQLx
4. **Saga Pattern** - Distributed transaction coordinator
5. **Multi-tenancy** - Row-level security patterns
6. **Audit Logging** - Automatic change tracking
7. **Feature Flags** - Dynamic feature toggling
8. **Admin UI** - Optional web UI for jobs, users, etc.

---

## Implementation Strategy

### Phase 1: Foundation (2 weeks)
- ✅ Dependency updates (completed)
- ✅ Documentation (completed)
- OpenAPI integration (Priority 1)
- Validation (Priority 3)
- Pagination (Priority 4)

### Phase 2: Durability (2 weeks)
- Outbox pattern (Priority 2)
- Health checks (Priority 7)
- Connection pooling docs (Priority 8)

### Phase 3: Production-Ready (2 weeks)
- Observability (Priority 6)
- Rate limiting (Priority 9)
- Testing utilities (Priority 10)
- Enhanced CRUD (Priority 5)

### Phase 4: Polish (1 week)
- All quick wins
- Examples and tutorials
- Migration guides
- Performance benchmarks

---

## Success Metrics

Measure improvements by:
1. **Time to first API**: How quickly can someone build their first endpoint?
2. **Production readiness**: What % of production concerns are handled OOTB?
3. **Code reduction**: How much boilerplate eliminated vs raw Axum?
4. **Error frequency**: How many common mistakes prevented at compile time?

Target: **3x faster to production-ready API than raw Axum, with same control.**

---

## References

### Research Sources

**Framework Comparisons**:
- [Rust Web Frameworks 2024](https://www.rustfinity.com/blog/best-rust-web-frameworks)
- [Actix vs Axum vs Rocket](https://dev.to/leapcell/rust-web-frameworks-compared-actix-vs-axum-vs-rocket-4bad)
- [Rust Web Framework Comparison](https://github.com/flosse/rust-web-framework-comparison)

**OpenAPI Tools**:
- [utoipa Documentation](https://github.com/juhaku/utoipa)
- [Auto-Generating OpenAPI in Rust](https://identeco.de/en/blog/generating_and_validating_openapi_docs_in_rust/)
- [Working with OpenAPI in Rust](https://www.shuttle.dev/blog/2024/04/04/using-openapi-rust)

**Patterns**:
- [Transactional Outbox Pattern](https://microservices.io/patterns/data/transactional-outbox.html)
- [Saga Pattern Guide](https://temporal.io/blog/mastering-saga-patterns-for-distributed-transactions-in-microservices)
- [Rust Dual-Write Solution](https://berektassuly.com/solana-postgresql-dual-write-rust-case-study)

**Axum Ecosystem**:
- [Axum 0.8 Announcement](https://tokio.rs/blog/2025-01-01-announcing-axum-0-8-0)
- [Axum Documentation](https://docs.rs/axum/latest/axum/)
- [Custom Extractors in Axum](https://leapcell.io/blog/crafting-custom-extractors-in-axum-and-actix-web)
