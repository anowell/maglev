use std::ops::Deref;
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie;

use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::Json;
use axum_extra::extract::cookie::SameSite;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Cookie, HeaderMapExt};
use hmac::{Hmac, Mac};
use jwt::{FromBase64, VerifyWithKey};
use serde_json::json;
use sha2::Sha384;
use time::OffsetDateTime;

const DEFAULT_SESSION_LENGTH: time::Duration = time::Duration::weeks(2);

pub use jwt::RegisteredClaims;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Password hashing error {0}")]
    PasswordHash(argon2::password_hash::errors::Error),
    #[error("Pashword hashing panic")]
    PasswordHashPanic,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        status.into_response()
    }
}

pub struct CookieConfig {
    name: &'static str,
    http_only: bool,
    secure: bool,
    same_site: SameSite,
}

impl CookieConfig {
    /// Uses strict, secure, http_only settings by default
    pub fn new(name: &'static str) -> CookieConfig {
        CookieConfig {
            name,
            http_only: true,
            secure: true,
            same_site: SameSite::Strict,
        }
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }
}

impl Default for CookieConfig {
    /// Uses strict, secure, http_only settings by default
    fn default() -> Self {
        CookieConfig {
            name: "jwt",
            http_only: true,
            secure: true,
            same_site: SameSite::Strict,
        }
    }
}

#[derive(Clone)]
pub struct JwtManager(Arc<JwtConfig>);

pub struct JwtConfig {
    key: Hmac<Sha384>,
    // algorithm: jwt::AlgorithmType,
    duration: time::Duration,
    cookie_config: CookieConfig,
    // validation_state: STATE,
}

impl JwtConfig {
    pub fn new(secret: &str) -> JwtConfig {
        assert!(
            secret.len() >= 32,
            "Provide a longer JWT secret (len={}). Ex: 'openssl rand -base64 48'",
            secret.len()
        );
        // SHA-384 (HS-384) as the HMAC is more difficult to brute-force
        // than SHA-256 (recommended by the JWT spec) at the cost of a slightly larger token.
        let key = Hmac::<Sha384>::new_from_slice(secret.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");
        JwtConfig {
            key,
            duration: DEFAULT_SESSION_LENGTH,
            cookie_config: CookieConfig::default(),
            // validation_state: (),
        }
    }

    pub fn duration(mut self, duration: time::Duration) -> Self {
        self.duration = duration;
        self
    }

    pub fn cookie_config(mut self, cookie_config: CookieConfig) -> Self {
        self.cookie_config = cookie_config;
        self
    }

    pub fn build(self) -> JwtManager {
        JwtManager(Arc::new(self))
    }
}

impl JwtManager {
    pub fn generate_token<C>(&self, claims: C) -> String
    where
        C: jwt::SignWithKey<String>,
    {
        claims
            .sign_with_key(&self.0.key)
            .expect("HMAC signing should be infallible")
    }

    pub fn generate_session_cookie(&self, token: &str) -> cookie::Cookie<'static> {
        let cookie_config = &self.0.cookie_config;
        let cookie = cookie::Cookie::build((cookie_config.name, token.to_owned()))
            .http_only(cookie_config.http_only)
            .secure(cookie_config.secure)
            .same_site(cookie_config.same_site)
            .build();

        cookie
    }

    pub fn generate_reponse<T, C>(&self, claims: T) -> Response<Body>
    where
        T: ToClaims<C>,
        C: jwt::SignWithKey<String>,
    {
        let exp = (OffsetDateTime::now_utc() + self.0.duration).unix_timestamp();
        let token = self.generate_token(claims.to_claims(exp));
        let cookie = self.generate_session_cookie(&token);

        let body = Json(json!({"token": token}));
        let jar = cookie::CookieJar::new().add(cookie);

        (jar, body).into_response()
    }

    pub async fn extract<J, C, E, S>(&self, parts: &mut Parts, state: &S) -> Result<J, E>
    where
        S: Send + Sync,
        C: FromBase64 + ValidateClaims<S> + Send,
        J: ClaimsExtractor<S, Claims = C, Rejection = E>,
        E: From<AuthError> + From<<C as ValidateClaims<S>>::Rejection>,
    {
        self.extract_opt::<J, C, E, S>(parts, state)
            .await?
            .ok_or(AuthError::Unauthorized)
            .map_err(E::from)
    }

    pub async fn extract_opt<J, C, E, S>(
        &self,
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<J>, E>
    where
        S: Send + Sync,
        J: ClaimsExtractor<S, Claims = C, Rejection = E>,
        C: FromBase64 + ValidateClaims<S> + Send,
        E: From<AuthError> + From<<C as ValidateClaims<S>>::Rejection>,
    {
        match self.extract_claims::<C, E>(parts)? {
            None => Ok(None),
            Some(claims) => Ok(Some(J::try_extract(claims, state).await?)),
        }
    }

    /// Returns Ok(None) if the request did not contain auth info
    pub fn extract_claims<C, E>(&self, parts: &mut Parts) -> Result<Option<C>, E>
    where
        C: FromBase64,
        E: From<AuthError>,
    {
        // Get the value of the `Authorization` header, if it was sent at all.
        if let Some(auth_header) = parts.headers.typed_get::<Authorization<Bearer>>() {
            let claims = self.verify_token::<C, E>(auth_header.token())?;
            return Ok(Some(claims));
        }

        // Check session cookie
        if let Some(cookie) = parts.headers.typed_get::<Cookie>() {
            if let Some(token) = cookie.get("jwt") {
                let claims = self.verify_token::<C, E>(token)?;
                return Ok(Some(claims));
            }
        }

        Ok(None)
    }

    /// Parse & verify JWT as Claims
    pub async fn validate_token<C, E, S>(&self, token: &str, state: &S) -> Result<C, E>
    where
        S: Send + Sync,
        C: FromBase64 + ValidateClaims<S>,
        E: From<AuthError> + From<<C as ValidateClaims<S>>::Rejection>,
    {
        let claims = self.verify_token::<C, E>(token)?;
        claims.validate(state).await?;

        Ok(claims)
    }

    /// Parse & verify JWT as Claims
    pub fn verify_token<C, E>(&self, token: &str) -> Result<C, E>
    where
        C: FromBase64,
        E: From<AuthError>,
    {
        let jwt: jwt::Token<jwt::Header, C, _> =
            token.verify_with_key(&self.0.key).map_err(|e| {
                tracing::debug!("JWT failed to verify: {}", e);
                AuthError::Unauthorized
            })?;

        let (_header, claims) = jwt.into();

        Ok(claims)
    }
}

/// Generate claims from a type.
///
/// Typically, you only need to generate this for a single type
/// that is created during the login request
pub trait ToClaims<C>: Sized {
    fn to_claims(&self, exp: i64) -> C;
}

/// Implementation to validate JWT claims.
///
/// Typically, you'll only have a single type of claims.
/// This implementation should validation of the claims
/// such as ensuring not expired or revoked.
#[async_trait]
pub trait ValidateClaims<S>: Sized + Sync
where
    S: Sync,
{
    type Rejection: From<AuthError>;

    async fn validate(&self, state: &S) -> Result<(), Self::Rejection>;
}

/// Extracts claims into a an extractor.
///
/// Implementations should do any validation that claims are valid for target extractor
/// and then convert the claims into that target.
///
/// For example, a basic `AuthUser` merely needs to convert claims,
/// but an `AuthAdmin` would need to validate that the claims are valid for an admin.
#[async_trait]
pub trait ClaimsExtractor<S: Send + Sync>: Sized {
    type Rejection;
    type Claims: FromBase64 + ValidateClaims<S> + Send;

    async fn try_extract(claims: Self::Claims, state: &S) -> Result<Self, Self::Rejection>;
}

/// Extractor for routes that MUST be authenticated.
///
/// Allows patterns like: `Jwt(auth_user): Jwt<AuthUser>` in your axum handlers
/// that will parse and validate claims for the `AuthUser` type.
///
/// Derive with the `axum::FromRequest` macro.
///
/// ```no_compile,ignore
/// #[derive(FromRequest)]
/// #[from_request(via(Jwt))]
/// struct AuthUser { ... }
/// ```
///
/// Also requires: `FromRef<S>` implementation for you axum state. (see `axum::FromRef` macro)
pub struct Jwt<J>(pub J);

impl<J> Deref for Jwt<J> {
    type Target = J;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S, J> FromRequestParts<S> for Jwt<J>
where
    S: Send + Sync,
    JwtManager: FromRef<S>,
    J: ClaimsExtractor<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let maybe = JwtOption::<J>::from_request_parts(parts, state).await?;
        let auth = maybe.0.ok_or(AuthError::Unauthorized)?;
        Ok(Jwt(auth))
    }
}

/// Extractor for routes that MAY optionally be authenticated.
///
/// If the `Authorization` header and `jwt` cookie are absent then this will be `Self(None)`,
/// otherwise it will validate the token.
///
/// This is in contrast to using `Jwt<Option<AuthUser>>`, which will be `None` if there
/// is *any* auth error, which isn't what we want.
///
/// See notes on `Jwt` extractor for usage.
pub struct JwtOption<J>(pub Option<J>);

impl<J> Deref for JwtOption<J> {
    type Target = Option<J>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S, J> FromRequestParts<S> for JwtOption<J>
where
    S: Send + Sync,
    JwtManager: FromRef<S>,
    J: ClaimsExtractor<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt: JwtManager = JwtManager::from_ref(state);
        let claims = jwt.extract_claims::<J::Claims, AuthError>(parts)?;

        match claims {
            None => Ok(JwtOption(None)),
            Some(claims) => {
                claims
                    .validate(state)
                    .await
                    .map_err(|_| AuthError::Unauthorized)?;
                let auth = J::try_extract(claims, state)
                    .await
                    .map_err(|_| AuthError::Unauthorized)?;
                Ok(JwtOption(Some(auth)))
            }
        }
    }
}

/// Extractor that parses and validates claims.
///
/// This extractor exposes the raw JWT claims.
/// It does not try to convert them into any other type.
///
/// Using `Jwt` or `JwtOption` is more common.
pub struct JwtClaims<C>(pub C);

#[async_trait]
impl<S, C> FromRequestParts<S> for JwtClaims<C>
where
    S: Send + Sync,
    JwtManager: FromRef<S>,
    C: FromBase64 + ValidateClaims<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt: JwtManager = JwtManager::from_ref(state);
        let claims = jwt
            .extract_claims::<C, AuthError>(parts)?
            .ok_or(AuthError::Unauthorized)?;

        Ok(JwtClaims(claims))
    }
}

/// A basic set of JWT implementations aimed at quickly scaffolding new apps
#[cfg(feature = "basic")]
pub mod basic {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use axum::{
        async_trait,
        extract::{FromRef, FromRequest},
    };
    use parse_display::{Display, FromStr};
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;

    use super::{AuthError, ClaimsExtractor, Jwt, JwtClaims, ToClaims, ValidateClaims};

    #[derive(Debug, Clone, Copy, FromStr, Display, Serialize, Deserialize)]
    #[display(style = "lowercase")]
    pub enum Role {
        User,
        Admin,
    }

    /// Basic AuthUser extractor
    #[derive(Debug, Clone, Serialize, Deserialize, FromRequest)]
    #[from_request(via(Jwt))]
    pub struct AuthUser {
        pub id: String,
        pub role: Option<Role>,
    }

    #[async_trait]
    impl<S> ClaimsExtractor<S> for AuthUser
    where
        S: Send + Sync,
        RevocationList: FromRef<S>,
    {
        type Rejection = AuthError;
        type Claims = Claims;
        async fn try_extract(claims: Self::Claims, _state: &S) -> Result<Self, Self::Rejection> {
            let role = claims
                .role
                .map(|r| r.parse())
                .transpose()
                .map_err(|_| AuthError::Unauthorized)?;
            Ok(Self {
                id: claims.sub,
                role,
            })
        }
    }

    #[derive(Clone)]
    pub struct RevocationList(Arc<RwLock<HashMap<String, i64>>>);

    impl RevocationList {
        pub fn insert(&self, id: &str, exp: i64) {
            let mut list = self.0.write().unwrap();
            list.insert(id.to_string(), exp);
        }

        pub fn cleanup_expired(&self) {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let mut list = self.0.write().unwrap();
            list.retain(|_, &mut exp| exp > now);
        }

        pub fn contains(&self, id: &str) -> bool {
            let list = self.0.read().unwrap();
            list.contains_key(id)
        }

        pub fn replace<I>(&self, iter: I)
        where
            I: IntoIterator<Item = (String, i64)>,
        {
            let mut list = self.0.write().unwrap();
            list.clear();
            for (id, exp) in iter {
                list.insert(id, exp);
            }
        }
    }

    impl Default for RevocationList {
        fn default() -> Self {
            RevocationList(Arc::new(RwLock::new(HashMap::new())))
        }
    }

    // This impl is stateless; a good impl should check revocation
    #[async_trait]
    impl<S> ValidateClaims<S> for Claims
    where
        S: Send + Sync,
        RevocationList: FromRef<S>,
    {
        type Rejection = AuthError;

        async fn validate(&self, state: &S) -> Result<(), Self::Rejection> {
            let revocation_list = RevocationList::from_ref(state);
            if revocation_list.contains(&self.sub) {
                tracing::debug!("revoked token {}", self.sub);
                return Err(AuthError::Unauthorized);
            }

            if self.exp < OffsetDateTime::now_utc().unix_timestamp() {
                tracing::debug!("token expired");
                return Err(AuthError::Unauthorized);
            }

            Ok(())
        }
    }

    /// Extractor for Admin-only routes
    ///
    /// JWT claim must include the admin role
    pub struct AuthAdmin {
        pub id: String,
    }

    #[async_trait]
    impl<S> ClaimsExtractor<S> for AuthAdmin
    where
        S: Send + Sync,
        RevocationList: FromRef<S>,
    {
        type Rejection = AuthError;
        type Claims = Claims;
        async fn try_extract(claims: Self::Claims, _state: &S) -> Result<Self, Self::Rejection> {
            let role = claims
                .role
                .map(|r| r.parse())
                .transpose()
                .map_err(|_| AuthError::Unauthorized)?;
            match role {
                Some(Role::Admin) => Ok(Self { id: claims.sub }),
                _ => Err(AuthError::Unauthorized),
            }
        }
    }

    #[derive(Clone, serde::Serialize, serde::Deserialize, FromRequest)]
    #[from_request(via(JwtClaims))]
    pub struct Claims {
        sub: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,

        /// Standard JWT `exp` claim.
        exp: i64,
    }

    impl ToClaims<Claims> for AuthUser {
        fn to_claims(&self, exp: i64) -> Claims {
            Claims {
                sub: self.id.clone(),
                role: self.role.map(|r| r.to_string()),
                exp,
            }
        }
    }
}

// pub struct MaybeAuthUser(pub Option<AuthUser>);

/// Hashes a password. Produced hash is a "PHC String" that includes a random salt
///
/// The underlying Argon2 hashing is computationally intensive,
/// therfore performed on a thread where blocking is acceptable
pub async fn hash_password(password: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || -> Result<String, AuthError> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            PasswordHash::generate(Argon2::default(), password, salt.as_salt())
                .inspect_err(|e| tracing::warn!("failed to generate password hash: {}", e))
                .map_err(AuthError::PasswordHash)?
                .to_string(),
        )
    })
    .await
    .map_err(|_| AuthError::PasswordHashPanic)?
}

/// Verifies a hashed password. Assumes the password hash is a "PHC String"
///
/// The underlying Argon2 hashing is computationally intensive,
/// therfore performed on a thread where blocking is acceptable
pub async fn verify_password(password: String, password_hash: String) -> Result<(), AuthError> {
    tokio::task::spawn_blocking(move || -> Result<(), AuthError> {
        let hash = PasswordHash::new(&password_hash)
            .inspect_err(|err| tracing::warn!("invalid password hash: {}", err))
            .map_err(AuthError::PasswordHash)?;

        match hash.verify_password(&[&Argon2::default()], password) {
            Ok(_) => Ok(()),
            Err(argon2::password_hash::Error::Password) => Err(AuthError::Unauthorized),
            Err(err) => {
                tracing::trace!("failed to verify password hash: {}", err);
                Err(AuthError::PasswordHash(err))
            }
        }
    })
    .await
    .map_err(|_| AuthError::PasswordHashPanic)?
}
