# Maglev Architecture

## Overview

Maglev is a library for building JSON APIs with Axum and SQLx. See [principles.md](principles.md) for design principles and scope.

## Design Philosophy

**Library, not framework.** Extends Axum rather than abstracting it. Users write normal Axum code and opt-in to maglev utilities.

**Trait-based extensibility.** Key abstractions use traits (`Job`, `ValidateClaims`, `QueueProvider`, `ClaimsExtractor`) so apps customize without forking.

**SQL lives in the app.** Maglev never executes SQL queries. Apps own their schema and get SQLx compile-time verification.

**Generate, don't abstract.** Persistence implementations are scaffolded by the CLI into the app's source tree. Apps own and modify the generated code.

## Repository Structure

- `framework/` — Core library: auth, jobs, mail, errors, config, crypto, routing, server lifecycle
- `maglev-macros/` — Proc macros (`#[derive(HttpError)]`)
- `cli/` — Code generator (`maglev generate`)
- `examples/` — Reference implementations
- `docs/` — Architecture and design docs

## Key Patterns

### Wrapper Types with FromRequestParts
```rust
pub struct Jwt<J>(pub J);
// Usage: async fn handler(user: Jwt<AuthUser>) { ... }
```

### Blocking Ops on Tokio Threads
CPU-intensive crypto (password hashing, encryption) runs on `spawn_blocking`.

### Builder Pattern for Config
```rust
JwtConfig::new(secret).duration(Duration::weeks(2)).build()
```

### Generic State with FromRef
Components extract from state via Axum's `FromRef<S>`, keeping coupling loose.

### Proc Macros for Boilerplate
`#[derive(HttpError)]` generates `http_code()` and `http_message()` from error enums. Separates internal error logging from user-facing responses.

## Dependency Choices

| Crate | Role |
|-------|------|
| axum 0.8 | HTTP framework |
| sqlx 0.8 | Async Postgres driver, compile-time SQL |
| tokio | Async runtime |
| tower | Middleware |
| argon2 | Password hashing |
| orion | AEAD encryption |
| jwt | JWT signing/verification |
| lettre | SMTP email |
| tokio-cron-scheduler | Job scheduling |

## Architectural Constraints

1. No breaking Axum patterns — if it works in Axum, it works with maglev
2. No runtime reflection — everything compile-time checked
3. No hidden I/O — all async operations explicit
4. Minimal proc macro magic — only where significant value (HttpError)
