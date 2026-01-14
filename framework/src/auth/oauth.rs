//! OAuth2 client implementations for common providers
//!
//! Provides ready-to-use OAuth2 clients for:
//! - Google
//! - GitHub
//! - Microsoft
//!
//! Built on the [`oauth2`](https://docs.rs/oauth2) crate.
//!
//! ## Example
//!
//! ```rust,no_run
//! use maglev::auth::oauth::{GoogleClient, GoogleProfile};
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = GoogleClient::new(
//!         "client_id",
//!         "client_secret",
//!         "http://localhost:3000/auth/google/callback"
//!     );
//!
//!     // Generate authorization URL
//!     let (auth_url, csrf_token) = client.authorize_url(&["email", "profile"]);
//!     // Redirect user to auth_url...
//!
//!     // After callback with code:
//!     let tokens = client.exchange_code("authorization_code").await?;
//!     let profile = client.fetch_profile(&tokens.access_token).await?;
//!
//!     println!("User: {} ({})", profile.name, profile.email);
//!
//!     Ok(())
//! }
//! ```

use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse as OAuth2TokenResponse, TokenUrl,
};
use oauth2::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use url::Url;

/// OAuth2 token response (standardized across providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

/// OAuth2 error
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("OAuth2 error: {0}")]
    OAuth2(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

//
// Google OAuth
//

/// Google OAuth2 client
#[derive(Clone)]
pub struct GoogleClient {
    client: BasicClient,
    http_client: reqwest::Client,
}

impl GoogleClient {
    pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap());

        Self {
            client,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL with CSRF protection
    pub fn authorize_url(&self, scopes: &[&str]) -> (Url, CsrfToken) {
        let mut auth_request = self.client.authorize_url(CsrfToken::new_random);

        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        auth_request.url()
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code(&self, code: &str) -> Result<TokenResponse, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::OAuth2(e.to_string()))?;

        Ok(TokenResponse {
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result
                .refresh_token()
                .map(|t| t.secret().clone()),
            expires_in: token_result.expires_in().map(|d| d.as_secs()),
            scope: token_result
                .scopes()
                .map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
        })
    }

    /// Fetch user profile from Google
    pub async fn fetch_profile(&self, access_token: &str) -> Result<GoogleProfile, OAuthError> {
        let profile = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await?
            .json::<GoogleProfile>()
            .await?;

        Ok(profile)
    }
}

/// Google user profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleProfile {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: String,
    pub locale: Option<String>,
}

//
// GitHub OAuth
//

/// GitHub OAuth2 client
#[derive(Clone)]
pub struct GitHubClient {
    client: BasicClient,
    http_client: reqwest::Client,
}

impl GitHubClient {
    pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap());

        Self {
            client,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL with CSRF protection
    pub fn authorize_url(&self, scopes: &[&str]) -> (Url, CsrfToken) {
        let mut auth_request = self.client.authorize_url(CsrfToken::new_random);

        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        auth_request.url()
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code(&self, code: &str) -> Result<TokenResponse, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::OAuth2(e.to_string()))?;

        Ok(TokenResponse {
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result
                .refresh_token()
                .map(|t| t.secret().clone()),
            expires_in: token_result.expires_in().map(|d| d.as_secs()),
            scope: token_result
                .scopes()
                .map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
        })
    }

    /// Fetch user profile from GitHub
    pub async fn fetch_profile(&self, access_token: &str) -> Result<GitHubProfile, OAuthError> {
        let profile = self
            .http_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "maglev-oauth")
            .send()
            .await?
            .json::<GitHubProfile>()
            .await?;

        Ok(profile)
    }

    /// Fetch user's primary email from GitHub
    /// Note: Requires 'user:email' scope
    pub async fn fetch_emails(&self, access_token: &str) -> Result<Vec<GitHubEmail>, OAuthError> {
        let emails = self
            .http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "maglev-oauth")
            .send()
            .await?
            .json::<Vec<GitHubEmail>>()
            .await?;

        Ok(emails)
    }
}

/// GitHub user profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubProfile {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: String,
    pub bio: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
}

/// GitHub email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
    pub visibility: Option<String>,
}

//
// Microsoft OAuth
//

/// Microsoft OAuth2 client
#[derive(Clone)]
pub struct MicrosoftClient {
    client: BasicClient,
    http_client: reqwest::Client,
}

impl MicrosoftClient {
    pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new(
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            )
            .unwrap(),
            Some(
                TokenUrl::new(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                )
                .unwrap(),
            ),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap());

        Self {
            client,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL with CSRF protection
    pub fn authorize_url(&self, scopes: &[&str]) -> (Url, CsrfToken) {
        let mut auth_request = self.client.authorize_url(CsrfToken::new_random);

        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        auth_request.url()
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code(&self, code: &str) -> Result<TokenResponse, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::OAuth2(e.to_string()))?;

        Ok(TokenResponse {
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result
                .refresh_token()
                .map(|t| t.secret().clone()),
            expires_in: token_result.expires_in().map(|d| d.as_secs()),
            scope: token_result
                .scopes()
                .map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
        })
    }

    /// Fetch user profile from Microsoft Graph
    pub async fn fetch_profile(
        &self,
        access_token: &str,
    ) -> Result<MicrosoftProfile, OAuthError> {
        let profile = self
            .http_client
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(access_token)
            .send()
            .await?
            .json::<MicrosoftProfile>()
            .await?;

        Ok(profile)
    }
}

/// Microsoft user profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftProfile {
    pub id: String,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub mail: Option<String>,
    #[serde(rename = "jobTitle")]
    pub job_title: Option<String>,
}
