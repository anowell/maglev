//! Password authentication with session management
//!
//! Demonstrates:
//! - User registration with password hashing
//! - Login with JWT access token (1hr) + refresh token (30 days)
//! - Automatic refresh token rotation
//! - Protected endpoints
//! - Session listing and revocation
//!
//! ## Setup
//!
//! 1. Create database:
//! ```sql
//! CREATE TABLE users (
//!     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//!     email TEXT UNIQUE NOT NULL,
//!     password_hash TEXT NOT NULL,
//!     name TEXT NOT NULL,
//!     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
//! );
//!
//! CREATE TABLE auth_sessions (
//!     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//!     user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//!     refresh_token_hash TEXT NOT NULL,
//!     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//!     last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//!     expires_at TIMESTAMPTZ NOT NULL,
//!     device_name TEXT,
//!     ip_address TEXT,
//!     user_agent TEXT,
//!     revoked_at TIMESTAMPTZ
//! );
//!
//! CREATE INDEX idx_sessions_user_active ON auth_sessions(user_id, last_active_at) WHERE revoked_at IS NULL;
//! CREATE INDEX idx_sessions_refresh_token ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
//! ```
//!
//! 2. Set environment variables:
//! ```
//! DATABASE_URL=postgresql://localhost/mydb
//! HMAC_KEY=your-secret-key-at-least-32-bytes-long
//! PORT=3030
//! ```
//!
//! 3. Run:
//! ```
//! just example auth-password
//! ```
//!
//! ## Usage
//!
//! ```bash
//! # Register
//! curl -X POST http://localhost:3030/register \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"user@example.com","password":"secret123","name":"John Doe"}'
//!
//! # Login
//! curl -X POST http://localhost:3030/login \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"user@example.com","password":"secret123"}'
//! # Returns: {"access_token":"...", "refresh_token":"...", "expires_in":3600}
//!
//! # Access protected endpoint
//! curl http://localhost:3030/me \
//!   -H 'Authorization: Bearer <access_token>'
//!
//! # Refresh access token
//! curl -X POST http://localhost:3030/refresh \
//!   -H 'Content-Type: application/json' \
//!   -d '{"refresh_token":"..."}'
//!
//! # List active sessions
//! curl http://localhost:3030/sessions \
//!   -H 'Authorization: Bearer <access_token>'
//!
//! # Revoke a session
//! curl -X DELETE http://localhost:3030/sessions/<session_id> \
//!   -H 'Authorization: Bearer <access_token>'
//!
//! # Logout (revoke current session)
//! curl -X POST http://localhost:3030/logout \
//!   -H 'Authorization: Bearer <access_token>'
//! ```

use std::net::Ipv4Addr;

use axum::extract::{FromRef, Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use maglev::auth::session::{DeviceInfo, Session};
use maglev::auth::{
    hash_password, verify_password, AuthError, ClaimsExtractor, Jwt, JwtConfig, JwtContext,
    ToClaims, ValidateClaims,
};
use maglev::EnvConfig;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

// ===== Configuration =====

#[derive(Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_database_url")]
    database_url: String,
    #[serde(default = "default_hmac_key")]
    hmac_key: String,
    #[serde(default = "default_port")]
    port: u16,
}

fn default_database_url() -> String {
    "postgresql://localhost/maglev_example".to_string()
}

fn default_hmac_key() -> String {
    "example-hmac-key-not-for-production-use-min-32-bytes".to_string()
}

fn default_port() -> u16 {
    3030
}

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub jwt: JwtContext,
}

// ===== Error Handling =====

#[derive(Debug, thiserror::Error, maglev::HttpError)]
enum Error {
    #[error("Unauthorized")]
    #[http_error(UNAUTHORIZED)]
    Unauthorized,

    #[error("Email already exists")]
    #[http_error(CONFLICT, "email already exists")]
    EmailExists,

    #[error("Invalid credentials")]
    #[http_error(UNAUTHORIZED, "invalid credentials")]
    InvalidCredentials,

    #[error("Session not found")]
    #[http_error(NOT_FOUND, "session not found")]
    SessionNotFound,

    #[error("Database error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "internal error")]
    Database(#[from] sqlx::Error),

    #[error("Auth error: {0}")]
    #[http_error(UNAUTHORIZED, "authentication failed")]
    Auth(#[from] maglev::auth::AuthError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if self.http_code().is_server_error() {
            tracing::error!("Error: {}", self);
        }

        let body = Json(json!({
            "error": self.http_message(),
            "code": self.http_code().as_u16(),
        }));

        (self.http_code(), body).into_response()
    }
}

type Result<T> = std::result::Result<T, Error>;

// ===== Domain Types =====

#[derive(Debug, Clone, Serialize)]
struct User {
    id: Uuid,
    email: String,
    name: String,
    created_at: OffsetDateTime,
}

// Claims stored in JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,        // user_id
    session_id: String, // links to session record
    exp: i64,           // expiration
}

// Validate JWT claims (expiration check)
impl<S> ValidateClaims<S> for AccessTokenClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn validate(&self, _state: &S) -> std::result::Result<(), Self::Rejection> {
        // Check expiration
        if self.exp < OffsetDateTime::now_utc().unix_timestamp() {
            return Err(AuthError::Unauthorized);
        }

        // Note: We don't check session revocation here because:
        // 1. Access tokens are short-lived (1hr)
        // 2. Revocation is checked when using refresh tokens
        // 3. This keeps JWT validation fast (no DB query)

        Ok(())
    }
}

impl<S> ClaimsExtractor<S> for AccessTokenClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;
    type Claims = Self;

    async fn try_extract(claims: Self::Claims, _state: &S) -> std::result::Result<Self, Self::Rejection> {
        Ok(claims)
    }
}

impl ToClaims<AccessTokenClaims> for AccessTokenClaims {
    fn to_claims(&self, exp: i64) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: self.sub.clone(),
            session_id: self.session_id.clone(),
            exp,
        }
    }
}

// Helper type for creating tokens
struct AuthUser {
    user_id: Uuid,
    session_id: Uuid,
}

impl ToClaims<AccessTokenClaims> for AuthUser {
    fn to_claims(&self, exp: i64) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: self.user_id.to_string(),
            session_id: self.session_id.to_string(),
            exp,
        }
    }
}

// ===== Database Operations =====

async fn create_user(pool: &PgPool, email: &str, password: &str, name: &str) -> Result<User> {
    let password_hash = hash_password(password.to_string()).await?;

    let row = sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4) RETURNING id, email, name, created_at"
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(password_hash)
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.constraint() == Some("users_email_key") {
                return Error::EmailExists;
            }
        }
        Error::Database(e)
    })?;

    Ok(User {
        id: row.get("id"),
        email: row.get("email"),
        name: row.get("name"),
        created_at: row.get("created_at"),
    })
}

async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<(User, String)>> {
    let row = sqlx::query(
        "SELECT id, email, name, created_at, password_hash FROM users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        (
            User {
                id: row.get("id"),
                email: row.get("email"),
                name: row.get("name"),
                created_at: row.get("created_at"),
            },
            row.get("password_hash"),
        )
    }))
}

async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    let row = sqlx::query("SELECT id, email, name, created_at FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|row| User {
        id: row.get("id"),
        email: row.get("email"),
        name: row.get("name"),
        created_at: row.get("created_at"),
    }))
}

// ===== Request/Response Types =====

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    name: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct SessionInfo {
    id: Uuid,
    created_at: OffsetDateTime,
    last_active_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    device_name: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

// ===== Handlers =====

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<User>)> {
    let user = create_user(&state.db, &req.email, &req.password, &req.name).await?;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Find user and verify password
    let (user, password_hash) = find_user_by_email(&state.db, &req.email)
        .await?
        .ok_or(Error::InvalidCredentials)?;

    verify_password(req.password, password_hash).await?;

    // Create session
    let (session, refresh_token) =
        Session::create(&state.db, user.id, DeviceInfo::default()).await?;

    // Generate access JWT
    let auth_user = AuthUser {
        user_id: user.id,
        session_id: session.id,
    };
    let access_token = state.jwt.generate_jwt(auth_user);

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in: 3600,
    }))
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>> {
    // Find session by refresh token
    let mut session = Session::find_by_refresh_token(&state.db, &req.refresh_token)
        .await?
        .ok_or(Error::Unauthorized)?;

    // Rotate refresh token (security best practice)
    let new_refresh_token = session.rotate_refresh_token(&state.db).await?;

    // Generate new access JWT
    let auth_user = AuthUser {
        user_id: session.user_id,
        session_id: session.id,
    };
    let access_token = state.jwt.generate_jwt(auth_user);

    Ok(Json(RefreshResponse {
        access_token,
        refresh_token: new_refresh_token,
        expires_in: 3600,
    }))
}

async fn me(Jwt(claims): Jwt<AccessTokenClaims>, State(state): State<AppState>) -> Result<Json<User>> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| Error::Unauthorized)?;
    let user = find_user_by_id(&state.db, user_id)
        .await?
        .ok_or(Error::Unauthorized)?;

    Ok(Json(user))
}

async fn list_sessions(
    Jwt(claims): Jwt<AccessTokenClaims>,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionInfo>>> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| Error::Unauthorized)?;
    let sessions = Session::list_for_user(&state.db, user_id).await?;

    let session_infos = sessions
        .into_iter()
        .map(|s| SessionInfo {
            id: s.id,
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            expires_at: s.expires_at,
            device_name: s.device_name,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
        })
        .collect();

    Ok(Json(session_infos))
}

async fn revoke_session(
    Jwt(claims): Jwt<AccessTokenClaims>,
    Path(session_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| Error::Unauthorized)?;

    // Find session and verify ownership
    let session = Session::find_by_id(&state.db, session_id)
        .await?
        .ok_or(Error::SessionNotFound)?;

    if session.user_id != user_id {
        return Err(Error::Unauthorized);
    }

    // Revoke session
    session.revoke(&state.db).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn logout(Jwt(claims): Jwt<AccessTokenClaims>, State(state): State<AppState>) -> Result<StatusCode> {
    let session_id = Uuid::parse_str(&claims.session_id).map_err(|_| Error::Unauthorized)?;

    // Revoke current session
    let session = Session::find_by_id(&state.db, session_id)
        .await?
        .ok_or(Error::SessionNotFound)?;

    session.revoke(&state.db).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ===== Main =====

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let port = config.port;

    // Connect to database
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    // Initialize JWT
    let jwt = JwtConfig::new(&config.hmac_key).build();

    let state = AppState { db, jwt };

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:id", delete(revoke_session))
        .with_state(state);

    maglev::serve((Ipv4Addr::UNSPECIFIED, port), app).await?;

    Ok(())
}
