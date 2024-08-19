use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Context as _;
use axum::extract::FromRef;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, http, routing::get, Json, Router};
use maglev::auth::{Jwt, JwtConfig, JwtManager};
use maglev::auth::basic::{AuthUser, Claims, RevocationList}
use maglev::EnvConfig;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};

#[derive(Clone, Deserialize)]
pub struct Config {
    database_url: String,
    hmac_key: String,
    port: u16,
}

#[derive(Clone, FromRef)]
pub struct Context {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub jwt: JwtManager,
    pub revoked_tokens: RevocationList,
}

#[derive(Debug, thiserror::Error, maglev::HttpError)]
enum Error {
    #[error("Unauthorized")]
    #[http_error(UNAUTHORIZED)]
    Unauthorized,

    #[error("Internal Server Error: {0:?}")]
    #[http_error(INTERNAL_SERVER_ERROR, "an internal server error occurred")]
    Anyhow(#[from] anyhow::Error),
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
    let config = Arc::new(Config::from_env()?);
    let port = config.port;

    let db = PgPoolOptions::new()
        .max_connections(50)
        .connect(&config.database_url)
        .await
        .context("Could not connect to database_url")?;

    let jwt = JwtConfig::new(&config.hmac_key).build();
    // TODO: persist and sync. This is currently an in-memory revocation list
    let revoked_tokens = RevocationList::default();
    let ctx = Context { db, config, jwt, revoked_tokens };

    let routes = api_router(ctx);
    maglev::serve((Ipv4Addr::UNSPECIFIED, port), routes)
        .await
        .context("error running HTTP server")?;
    Ok(())
}

fn api_router(ctx: Context) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/login", get(login))
        .route("/login", get(logout))
        .route("/me", get(me))
}

async fn health() -> JsonResult<Value> {
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}

async fn login(ctx: State<Context>, data: Json<LoginReq>) -> Result<Response> {
    let user = models::user::get_user_with_password_hash(&ctx.db, &data.email).await?;
    maglev::auth::verify_password(data.password, user.password_hash).await?;

    let auth_user = AuthUser {
        id: user.id,
        role: user.role,
    };

    Ok(ctx.jwt.generate_reponse(auth_user))
}

async fn logout(claims: Claims, ctx: State<Context>) -> Result<Response> {
    // TODO: persist revoked tokens
    ctx.revoked_tokens.insert(claims.sub, claims.exp);
    // TODO: implement logout_response / generate_logout_cookie
    Ok(ctx.jwt.logout_response())
}

async fn me(auth_user: Jwt<AuthUser>, ctx: State<Context>) -> JsonResult<User> {
    let user = models::user::get_user(&ctx.db, auth_user.id).await?;
    Ok(user)
}

