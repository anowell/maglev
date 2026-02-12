# Authentication

## Overview

JWT-based authentication with Axum extractors, trait-based validation, OAuth2 clients, and password hashing utilities.

## JWT

**Extractors:**
- `Jwt<T>` — Required auth, 401 if missing
- `JwtOption<T>` — Optional auth, validates if present
- `JwtClaims<C>` — Raw claims access

**Traits** (apps implement these):
- `ValidateClaims<S>` — Async validation with state access (check revocation, DB, permissions)
- `ClaimsExtractor<S>` — Bridge JWT claims to app-specific auth types
- `ToClaims<C>` — Convert domain types to JWT claims

**Config:** `JwtConfig::new(secret).duration(...).build()` returns a `JwtContext` for state.

**Transport:** Authorization header or `jwt` session cookie. Cookie defaults: HttpOnly, Secure, SameSite=Strict.

**Signing:** HMAC-SHA384. 32+ byte secret required.

### Optional `basic` feature

Reference implementations for common cases: `Claims`, `Role` enum, `AuthUser`/`AuthAdmin` extractors, `RevocationList` (in-memory). Use directly or as patterns for custom implementations.

## OAuth2

Client implementations for Google, GitHub, Microsoft. Each provides:
- `authorize_url()` — Generate OAuth redirect
- `exchange_code()` — Exchange auth code for tokens
- `fetch_profile()` — Fetch user profile from provider

No database interaction. Returns typed profile structs; apps handle storage.

## Password Hashing

`hash_password()` and `verify_password()` using Argon2id on `spawn_blocking` threads. Stateless utilities — no database interaction.

## Sessions

Maglev provides crypto utilities for session management: secure token generation and token hashing. Apps implement session storage with their own schema. Use `maglev generate session` to scaffold a full Postgres-backed session implementation with refresh token rotation.

See [principles.md](principles.md) — SQL lives in the app.
