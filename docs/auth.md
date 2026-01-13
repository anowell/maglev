# Authentication Architecture

## What Maglev Provides

**JWT-based authentication** with secure defaults, flexible validation, and ergonomic Axum extractors.

**Three extractor types**:
- `Jwt<T>` - Required auth, returns 401 if missing
- `JwtOption<T>` - Optional auth, validates if present
- `JwtClaims<C>` - Raw JWT claims access

**Password utilities**: `hash_password()` and `verify_password()` using Argon2id on blocking threads.

**Optional `basic` feature**: Reference implementations of `Claims`, `Role`, `AuthUser`/`AuthAdmin` extractors, and `LoginResponse`.

## Key Design Decisions

### HMAC-SHA384 over SHA256
Stronger collision resistance with minimal token size increase. 32+ byte secret required (enforced at build).

### Dual Token Transport
Accepts tokens from `Authorization` header OR `jwt` session cookie. Cookie config provides secure defaults (HttpOnly, Secure, SameSite=Strict). Path support enables scoped/multi-tenant auth.

### Trait-Based Customization
Three traits decouple JWT mechanics from app logic:

**ToClaims<C>** - Convert domain types to JWT claims
**ValidateClaims<S>** - Async validation with state access (check revocation, DB, permissions)
**ClaimsExtractor<S>** - Bridge claims to app auth types

This separation keeps JWT payloads small while allowing rich domain models.

Auth traits use native async fn in traits (no `async_trait` dependency).

### In-Memory Revocation
`RevocationList` is a HashMap of revoked token IDs. Fast (O(1)), no dependencies, but lost on restart and not shared across instances. Designed for `QueueProvider`-style abstraction - implement persistent backend (Redis/Postgres) as needed.

### Argon2id Password Hashing
Memory-hard, GPU-resistant algorithm. Runs on `spawn_blocking` since intentionally slow (~100ms). PHC string format enables algorithm upgrades without migration.

### No Refresh Tokens
Not included - adds complexity many APIs don't need. Implement separately if required.

### 2-Week Default Expiration
Balances security and UX. Configurable per-context.

## Security Patterns

**Token IDs (jti)**: Random UUIDs prevent reuse even if secret compromised. Required for revocation.

**Secret storage**: Load from environment, never hardcode. Key rotation not implemented (requires dual-verification).

**Cookie security**: HttpOnly prevents XSS, SameSite=Strict prevents CSRF, Secure enforces HTTPS.

## Extensibility

Implement `ValidateClaims` for DB-backed checks (user active, permissions, etc).

Implement `ClaimsExtractor` for multiple auth strategies (API keys, sessions, etc).

Custom extractors compose naturally with Axum's `FromRequest`.

## Current Limitations

No refresh tokens, no key rotation, no multi-tenant domain scoping, revocation not persistent.

Future additions driven by real-world needs.
