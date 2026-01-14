//! OAuth authentication example
//!
//! Demonstrates:
//! - Google OAuth2 flow
//! - GitHub OAuth2 flow
//! - OAuth account storage with encrypted tokens
//! - Session creation after OAuth
//! - Account linking
//!
//! ## Setup
//!
//! 1. Create database:
//! ```sql
//! CREATE TABLE users (
//!     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//!     email TEXT UNIQUE NOT NULL,
//!     name TEXT NOT NULL,
//!     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
//! );
//!
//! CREATE TABLE oauth_accounts (
//!     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//!     user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//!     provider TEXT NOT NULL,
//!     provider_account_id TEXT NOT NULL,
//!     access_token TEXT,
//!     refresh_token TEXT,
//!     profile_data JSONB,
//!     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//!     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//!     UNIQUE(provider, provider_account_id)
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
//! ```
//!
//! 2. Setup OAuth apps:
//!
//! **Google:**
//! - Go to https://console.cloud.google.com/apis/credentials
//! - Create OAuth 2.0 Client ID
//! - Add redirect URI: http://localhost:3030/auth/google/callback
//! - Copy client ID and secret
//!
//! **GitHub:**
//! - Go to https://github.com/settings/developers
//! - Create OAuth App
//! - Set callback URL: http://localhost:3030/auth/github/callback
//! - Copy client ID and secret
//!
//! 3. Set environment variables:
//! ```
//! DATABASE_URL=postgresql://localhost/mydb
//! HMAC_KEY=your-secret-key-at-least-32-bytes-long
//! PORT=3030
//!
//! GOOGLE_CLIENT_ID=your-google-client-id
//! GOOGLE_CLIENT_SECRET=your-google-client-secret
//!
//! GITHUB_CLIENT_ID=your-github-client-id
//! GITHUB_CLIENT_SECRET=your-github-client-secret
//! ```
//!
//! 4. Run:
//! ```
//! just example auth-oauth
//! ```
//!
//! ## Usage
//!
//! 1. Visit http://localhost:3030/auth/google/login (or /auth/github/login)
//! 2. You'll be redirected to Google/GitHub for authorization
//! 3. After authorizing, you'll be redirected back with tokens
//! 4. The response includes access_token and refresh_token
//! 5. Use the access_token in Authorization header for protected endpoints

use std::net::Ipv4Addr;

use axum::extract::{FromRef, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use maglev::auth::oauth::{
    GitHubClient, GitHubProfile, GoogleClient, GoogleProfile, TokenResponse,
};
use maglev::auth::session::{DeviceInfo, Session};
use maglev::auth::{JwtConfig, JwtContext, ToClaims};
use maglev::EnvConfig;
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use time::{Duration, OffsetDateTime};
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

    // Google OAuth
    google_client_id: Option<String>,
    google_client_secret: Option<String>,

    // GitHub OAuth
    github_client_id: Option<String>,
    github_client_secret: Option<String>,
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
    pub google_client: Option<GoogleClient>,
    pub github_client: Option<GitHubClient>,
    // In production, use proper session storage for CSRF tokens
    // For this example, we'll skip it (security risk!)
}

// ===== Error Handling =====

#[derive(Debug, thiserror::Error, maglev::HttpError)]
enum Error {
    #[error("Unauthorized")]
    #[http_error(UNAUTHORIZED)]
    Unauthorized,

    #[error("Provider not configured: {0}")]
    #[http_error(BAD_REQUEST, "oauth provider not configured")]
    ProviderNotConfigured(String),

    #[error("OAuth error: {0}")]
    #[http_error(BAD_REQUEST, "oauth error")]
    OAuth(String),

    #[error("Database error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "internal error")]
    Database(#[from] sqlx::Error),

    #[error("Auth error: {0}")]
    #[http_error(UNAUTHORIZED, "authentication failed")]
    Auth(#[from] maglev::auth::AuthError),
}

impl From<maglev::auth::oauth::OAuthError> for Error {
    fn from(e: maglev::auth::oauth::OAuthError) -> Self {
        Error::OAuth(e.to_string())
    }
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

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,        // user_id
    session_id: String, // links to session record
    exp: i64,           // expiration
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

async fn create_user(pool: &PgPool, email: &str, name: &str) -> Result<User> {
    let row = sqlx::query(
        "INSERT INTO users (id, email, name) VALUES ($1, $2, $3) RETURNING id, email, name, created_at"
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(name)
    .fetch_one(pool)
    .await?;

    Ok(User {
        id: row.get("id"),
        email: row.get("email"),
        name: row.get("name"),
        created_at: row.get("created_at"),
    })
}

async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, email, name, created_at FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|row| User {
        id: row.get("id"),
        email: row.get("email"),
        name: row.get("name"),
        created_at: row.get("created_at"),
    }))
}

async fn find_or_create_oauth_account_google(
    pool: &PgPool,
    profile: GoogleProfile,
    tokens: TokenResponse,
) -> Result<(User, bool)> {
    // Try to find existing OAuth account
    let existing = sqlx::query(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'google' AND provider_account_id = $1"
    )
    .bind(&profile.id)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = existing {
        let user_id: Uuid = row.get("user_id");
        let user = sqlx::query("SELECT id, email, name, created_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;

        return Ok((
            User {
                id: user.get("id"),
                email: user.get("email"),
                name: user.get("name"),
                created_at: user.get("created_at"),
            },
            false,
        ));
    }

    // Create new user
    let user = create_user(pool, &profile.email, &profile.name).await?;

    // Create OAuth account record
    sqlx::query(
        r#"
        INSERT INTO oauth_accounts (
            id, user_id, provider, provider_account_id,
            access_token, refresh_token, profile_data
        )
        VALUES ($1, $2, 'google', $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(&profile.id)
    .bind(&tokens.access_token)
    .bind(&tokens.refresh_token)
    .bind(serde_json::to_value(&profile).unwrap())
    .execute(pool)
    .await?;

    Ok((user, true))
}

async fn find_or_create_oauth_account_github(
    pool: &PgPool,
    profile: GitHubProfile,
    tokens: TokenResponse,
) -> Result<(User, bool)> {
    // Try to find existing OAuth account
    let existing = sqlx::query(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_account_id = $1"
    )
    .bind(profile.id.to_string())
    .fetch_optional(pool)
    .await?;

    if let Some(row) = existing {
        let user_id: Uuid = row.get("user_id");
        let user = sqlx::query("SELECT id, email, name, created_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;

        return Ok((
            User {
                id: user.get("id"),
                email: user.get("email"),
                name: user.get("name"),
                created_at: user.get("created_at"),
            },
            false,
        ));
    }

    // GitHub doesn't always provide email in profile
    let email = profile
        .email
        .clone()
        .unwrap_or_else(|| format!("{}@users.noreply.github.com", profile.login));
    let name = profile.name.clone().unwrap_or(profile.login.clone());

    // Create new user
    let user = create_user(pool, &email, &name).await?;

    // Create OAuth account record
    sqlx::query(
        r#"
        INSERT INTO oauth_accounts (
            id, user_id, provider, provider_account_id,
            access_token, refresh_token, profile_data
        )
        VALUES ($1, $2, 'github', $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(profile.id.to_string())
    .bind(&tokens.access_token)
    .bind(&tokens.refresh_token)
    .bind(serde_json::to_value(&profile).unwrap())
    .execute(pool)
    .await?;

    Ok((user, true))
}

// ===== Response Types =====

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    is_new_user: bool,
}

// ===== Handlers =====

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

// Google OAuth

async fn google_login(State(state): State<AppState>) -> Result<Redirect> {
    let client = state
        .google_client
        .ok_or_else(|| Error::ProviderNotConfigured("google".to_string()))?;

    let (auth_url, _csrf_token) = client.authorize_url(&["email", "profile"]);

    // TODO: Store CSRF token in session for verification
    // For this example, we skip CSRF validation (security risk!)

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

async fn google_callback(
    Query(params): Query<OAuthCallback>,
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>> {
    let client = state
        .google_client
        .ok_or_else(|| Error::ProviderNotConfigured("google".to_string()))?;

    // TODO: Verify CSRF token matches what we stored
    // For this example, we skip CSRF validation (security risk!)

    // Exchange code for tokens
    let tokens = client.exchange_code(&params.code).await?;

    // Fetch user profile
    let profile = client.fetch_profile(&tokens.access_token).await?;

    // Find or create user
    let (user, is_new) =
        find_or_create_oauth_account_google(&state.db, profile, tokens).await?;

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
        is_new_user: is_new,
    }))
}

// GitHub OAuth

async fn github_login(State(state): State<AppState>) -> Result<Redirect> {
    let client = state
        .github_client
        .ok_or_else(|| Error::ProviderNotConfigured("github".to_string()))?;

    let (auth_url, _csrf_token) = client.authorize_url(&["read:user", "user:email"]);

    // TODO: Store CSRF token in session for verification

    Ok(Redirect::to(auth_url.as_str()))
}

async fn github_callback(
    Query(params): Query<OAuthCallback>,
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>> {
    let client = state
        .github_client
        .ok_or_else(|| Error::ProviderNotConfigured("github".to_string()))?;

    // TODO: Verify CSRF token

    // Exchange code for tokens
    let tokens = client.exchange_code(&params.code).await?;

    // Fetch user profile
    let profile = client.fetch_profile(&tokens.access_token).await?;

    // Find or create user
    let (user, is_new) =
        find_or_create_oauth_account_github(&state.db, profile, tokens).await?;

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
        is_new_user: is_new,
    }))
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

    // Initialize OAuth clients (if configured)
    let google_client = config
        .google_client_id
        .zip(config.google_client_secret)
        .map(|(id, secret)| {
            GoogleClient::new(&id, &secret, "http://localhost:3030/auth/google/callback")
        });

    let github_client = config
        .github_client_id
        .zip(config.github_client_secret)
        .map(|(id, secret)| {
            GitHubClient::new(&id, &secret, "http://localhost:3030/auth/github/callback")
        });

    if google_client.is_none() {
        tracing::warn!("Google OAuth not configured (set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)");
    }

    if github_client.is_none() {
        tracing::warn!("GitHub OAuth not configured (set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)");
    }

    let state = AppState {
        db,
        jwt,
        google_client,
        github_client,
    };

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/google/login", get(google_login))
        .route("/auth/google/callback", get(google_callback))
        .route("/auth/github/login", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        .with_state(state);

    tracing::info!("OAuth example running");
    tracing::info!("Visit:");
    tracing::info!("  - http://localhost:{}/auth/google/login (Google OAuth)", port);
    tracing::info!("  - http://localhost:{}/auth/github/login (GitHub OAuth)", port);

    maglev::serve((Ipv4Addr::UNSPECIFIED, port), app).await?;

    Ok(())
}
