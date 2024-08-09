use core::fmt;
use std::sync::Arc;

use base64::prelude::*;
use orion::aead;
use serde::{
    de::{self, Visitor},
    Deserializer,
};

/// Encryption key suitable for including in request state
///
/// Exposes helpers to encrypt/decrypt, but opaque
/// to prevent leaking the key through logs or responses
#[derive(Clone)]
pub struct EncryptionKey(Arc<aead::SecretKey>);

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Base64 error {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Utf8 error {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Unknown crypto error")]
    Unknown,
}

impl From<orion::errors::UnknownCryptoError> for CryptoError {
    fn from(_err: orion::errors::UnknownCryptoError) -> Self {
        CryptoError::Unknown
    }
}

impl EncryptionKey {
    pub fn try_from_base64(val: &str) -> Result<EncryptionKey, CryptoError> {
        let bytes = BASE64_STANDARD.decode(val.as_bytes())?;
        EncryptionKey::try_from(&*bytes)
    }
}

impl TryFrom<&[u8]> for EncryptionKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let key = aead::SecretKey::from_slice(bytes)?;
        Ok(EncryptionKey(Arc::new(key)))
    }
}

/// Helper to deserialize EncryptionKey from base64
///
/// Use with serde's `deserialize_with` attribute
///
/// ```rust
/// # use serde::Deserialize;
/// #[derive(Deserialize)]
/// struct Config {
///     #[serde(deserialize_with = "deserialize_base64_key")]
///     encryption_key: EncryptionKey,
/// }
/// ````
pub fn deserialize_base64_key<'de, D>(deserializer: D) -> Result<EncryptionKey, D::Error>
where
    D: Deserializer<'de>,
{
    struct EncryptionKeyVisitor;

    impl<'de> Visitor<'de> for EncryptionKeyVisitor {
        type Value = EncryptionKey;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a base64 encoded string representing a secret key")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            EncryptionKey::try_from_base64(value).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_str(EncryptionKeyVisitor)
}

/// Encrypts the message using provided key on a blocking thread
///
/// A unique nonce is generated and included in the returned cyphertext
pub async fn encrypt(key: EncryptionKey, msg: String) -> Result<Vec<u8>, CryptoError> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>, CryptoError> {
        let ciphertext = aead::seal(&key.0, msg.as_bytes())?;
        Ok(ciphertext)
    })
    .await
    .map_err(|_| CryptoError::Unknown)?
}

// Decrypts the message using provided key on a blocking thread
//
// A unique nonce is generated and included in the returned cyphertext
pub async fn decrypt(key: EncryptionKey, ciphertext: Vec<u8>) -> Result<String, CryptoError> {
    tokio::task::spawn_blocking(move || -> Result<String, CryptoError> {
        let decrypted_data = aead::open(&key.0, &ciphertext)?;
        let msg = String::from_utf8(decrypted_data)?;
        Ok(msg)
    })
    .await
    .map_err(|_| CryptoError::Unknown)?
}

// Helper to call `decrypt` with an optional ciphertext.
pub async fn encrypt_opt(
    key: EncryptionKey,
    msg: Option<String>,
) -> Result<Option<Vec<u8>>, CryptoError> {
    match msg {
        None => Ok(None),
        Some(msg) => Ok(Some(encrypt(key, msg).await?)),
    }
}

// Helper to call `decrypt` with an optional ciphertext.
pub async fn decrypt_opt(
    key: EncryptionKey,
    ciphertext: Option<Vec<u8>>,
) -> Result<Option<String>, CryptoError> {
    match ciphertext {
        None => Ok(None),
        Some(ciphertext) => Ok(Some(decrypt(key, ciphertext).await?)),
    }
}
