use std::net::Ipv4Addr;

use axum::extract::{FromRef, Json, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::CookieJar;
use maglev::auth::basic::{AuthAdmin, AuthUser, LoginResponse, RevocationList, Role};
use maglev::auth::{hash_password, verify_password, Jwt, JwtConfig, JwtContext};
use maglev::EnvConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_hmac_key")]
    hmac_key: String,
    #[serde(default = "default_port")]
    port: u16,
}

fn default_hmac_key() -> String {
    "example-hmac-key-not-for-production-use-min-32-bytes".to_string()
}

fn default_port() -> u16 {
    3030
}

#[derive(Clone, FromRef)]
pub struct Context {
    pub jwt: JwtContext,
    pub revoked_tokens: RevocationList,
}

#[derive(Debug, thiserror::Error, maglev::HttpError)]
enum Error {
    #[error("Unauthorized")]
    #[http_error(UNAUTHORIZED)]
    #[allow(dead_code)]
    Unauthorized,

    #[error("Invalid credentials")]
    #[http_error(UNAUTHORIZED, "invalid credentials")]
    InvalidCredentials,

    #[error("Internal Server Error: {0}")]
    #[http_error(INTERNAL_SERVER_ERROR, "an internal server error occurred")]
    #[allow(dead_code)]
    Internal(String),
}

impl From<maglev::auth::AuthError> for Error {
    fn from(_: maglev::auth::AuthError) -> Self {
        Error::InvalidCredentials
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        // Trace server errors since we don't return the detailed error in the response body
        if self.http_code().is_server_error() {
            tracing::error!("Error Status {}: {}", self.http_code(), self);
        }

        // Construct a response
        let body = Json(json!({
            "code": self.http_code().as_u16(),
            "message": self.http_message(),
        }));
        (self.http_code(), body).into_response()
    }
}

type Result<T> = std::result::Result<T, Error>;
type JsonResult<T> = Result<Json<T>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    let config = Config::from_env()?;
    let port = config.port;

    let jwt = JwtConfig::new(&config.hmac_key).build();
    let revoked_tokens = RevocationList::default();
    let ctx = Context {
        jwt,
        revoked_tokens,
    };

    let routes = api_router(ctx);
    maglev::serve((Ipv4Addr::UNSPECIFIED, port), routes).await?;
    Ok(())
}

fn api_router(ctx: Context) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/admin", get(admin_only))
        .with_state(ctx)
}

async fn health() -> JsonResult<Value> {
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    username: String,
    role: Option<Role>,
}

async fn login(ctx: State<Context>, jar: CookieJar, Json(data): Json<LoginReq>) -> Result<Response> {
    // Hardcoded demo credentials (in real app, query database)
    let (user_id, role, password_hash) = match data.username.as_str() {
        "user" => ("1".to_string(), Some(Role::User), hash_password("password".to_string()).await.unwrap()),
        "admin" => ("2".to_string(), Some(Role::Admin), hash_password("admin".to_string()).await.unwrap()),
        _ => return Err(Error::InvalidCredentials),
    };

    verify_password(data.password, password_hash).await?;

    let auth_user = AuthUser { id: user_id, role };

    let (token, cookie) = ctx.jwt.generate_jwt_and_cookie(auth_user);
    Ok(LoginResponse::new(jar, cookie, token).into_response())
}

async fn logout(jar: CookieJar, _ctx: State<Context>) -> Result<Response> {
    // In a real app, you'd extract the JWT claims and add the token ID to the revocation list
    // For this demo, we'll just clear the cookie
    let cookie = axum_extra::extract::cookie::Cookie::build(("jwt", ""))
        .path("/")
        .build();
    Ok((jar.remove(cookie), Json(json!({"message": "logged out"}))).into_response())
}

async fn me(auth_user: Jwt<AuthUser>) -> JsonResult<UserResponse> {
    Ok(Json(UserResponse {
        id: auth_user.id.clone(),
        username: format!("user{}", auth_user.id),
        role: auth_user.role,
    }))
}

async fn admin_only(auth_admin: Jwt<AuthAdmin>) -> JsonResult<Value> {
    Ok(Json(json!({
        "message": "Welcome, admin!",
        "admin_id": auth_admin.id
    })))
}
