//! Reference session management implementation
//!
//! Provides a complete session management system with:
//! - Session creation with refresh tokens
//! - Automatic refresh token rotation
//! - Session revocation
//! - Device tracking
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE auth_sessions (
//!     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//!     user_id UUID NOT NULL,
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
//! ## Example
//!
//! ```rust,no_run
//! use maglev::auth::session::{Session, DeviceInfo};
//! use sqlx::PgPool;
//! use uuid::Uuid;
//!
//! async fn example(pool: PgPool, user_id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
//!     // Create new session
//!     let (session, refresh_token) = Session::create(
//!         &pool,
//!         user_id,
//!         DeviceInfo::default()
//!     ).await?;
//!
//!     // Later: refresh the session
//!     let mut session = Session::find_by_refresh_token(&pool, &refresh_token)
//!         .await?
//!         .ok_or("session not found")?;
//!
//!     let new_refresh_token = session.rotate_refresh_token(&pool).await?;
//!
//!     // Revoke when done
//!     session.revoke(&pool).await?;
//!
//!     Ok(())
//! }
//! ```

use sqlx::{PgPool, Row};
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;
use rand::Rng;
use sha2::{Sha256, Digest};

/// Session record stored in database
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub created_at: OffsetDateTime,
    pub last_active_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub device_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Device information for session tracking
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub device_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl Session {
    /// Create a new session with refresh token
    ///
    /// Returns the session record and the refresh token (plaintext).
    /// Store the refresh token securely on the client.
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        device_info: DeviceInfo,
    ) -> Result<(Self, String), sqlx::Error> {
        let id = Uuid::new_v4();
        let refresh_token = generate_secure_token();
        let refresh_hash = hash_refresh_token(&refresh_token);

        let row = sqlx::query(
            r#"
            INSERT INTO auth_sessions (
                id, user_id, refresh_token_hash, expires_at,
                device_name, ip_address, user_agent
            )
            VALUES ($1, $2, $3, NOW() + INTERVAL '30 days', $4, $5, $6)
            RETURNING
                id, user_id, refresh_token_hash,
                created_at, last_active_at, expires_at,
                device_name, ip_address, user_agent, revoked_at
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(&refresh_hash)
        .bind(&device_info.device_name)
        .bind(&device_info.ip_address)
        .bind(&device_info.user_agent)
        .fetch_one(pool)
        .await?;

        let session = Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            refresh_token_hash: row.get("refresh_token_hash"),
            created_at: row.get("created_at"),
            last_active_at: row.get("last_active_at"),
            expires_at: row.get("expires_at"),
            device_name: row.get("device_name"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            revoked_at: row.get("revoked_at"),
        };

        Ok((session, refresh_token))
    }

    /// Find an active session by refresh token
    pub async fn find_by_refresh_token(
        pool: &PgPool,
        refresh_token: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let hash = hash_refresh_token(refresh_token);

        let row = sqlx::query(
            r#"
            SELECT
                id, user_id, refresh_token_hash,
                created_at, last_active_at, expires_at,
                device_name, ip_address, user_agent, revoked_at
            FROM auth_sessions
            WHERE refresh_token_hash = $1
              AND expires_at > NOW()
              AND revoked_at IS NULL
            "#,
        )
        .bind(&hash)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|row| Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            refresh_token_hash: row.get("refresh_token_hash"),
            created_at: row.get("created_at"),
            last_active_at: row.get("last_active_at"),
            expires_at: row.get("expires_at"),
            device_name: row.get("device_name"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            revoked_at: row.get("revoked_at"),
        }))
    }

    /// Find session by ID
    pub async fn find_by_id(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT
                id, user_id, refresh_token_hash,
                created_at, last_active_at, expires_at,
                device_name, ip_address, user_agent, revoked_at
            FROM auth_sessions
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|row| Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            refresh_token_hash: row.get("refresh_token_hash"),
            created_at: row.get("created_at"),
            last_active_at: row.get("last_active_at"),
            expires_at: row.get("expires_at"),
            device_name: row.get("device_name"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            revoked_at: row.get("revoked_at"),
        }))
    }

    /// Rotate refresh token (security best practice)
    ///
    /// Returns new refresh token. The old token is invalidated.
    pub async fn rotate_refresh_token(
        &mut self,
        pool: &PgPool,
    ) -> Result<String, sqlx::Error> {
        let new_token = generate_secure_token();
        let new_hash = hash_refresh_token(&new_token);

        sqlx::query(
            r#"
            UPDATE auth_sessions
            SET refresh_token_hash = $1, last_active_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(&new_hash)
        .bind(self.id)
        .execute(pool)
        .await?;

        self.refresh_token_hash = new_hash;
        self.last_active_at = OffsetDateTime::now_utc();

        Ok(new_token)
    }

    /// Revoke this session
    pub async fn revoke(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1")
            .bind(self.id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// List all active sessions for a user
    pub async fn list_for_user(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, user_id, refresh_token_hash,
                created_at, last_active_at, expires_at,
                device_name, ip_address, user_agent, revoked_at
            FROM auth_sessions
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY last_active_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| Self {
                id: row.get("id"),
                user_id: row.get("user_id"),
                refresh_token_hash: row.get("refresh_token_hash"),
                created_at: row.get("created_at"),
                last_active_at: row.get("last_active_at"),
                expires_at: row.get("expires_at"),
                device_name: row.get("device_name"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                revoked_at: row.get("revoked_at"),
            })
            .collect())
    }

    /// Cleanup expired sessions (call from background job)
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE expires_at < NOW()")
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }
}

/// Generate cryptographically secure random token
fn generate_secure_token() -> String {
    use base64::Engine;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash refresh token for storage
fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let token1 = generate_secure_token();
        let token2 = generate_secure_token();

        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 43); // base64 of 32 bytes
    }

    #[test]
    fn test_token_hashing() {
        let token = "test_token";
        let hash1 = hash_refresh_token(token);
        let hash2 = hash_refresh_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // sha256 hex
    }
}
