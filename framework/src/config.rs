use serde::de::DeserializeOwned;

pub use serde_env::error::Error as ConfigError;

pub trait EnvConfig: Sized {
    fn from_env() -> Result<Self, ConfigError>;
    fn from_env_with_prefix(prefix: &str) -> Result<Self, ConfigError>;
}

impl<D> EnvConfig for D
where
    D: DeserializeOwned,
{
    fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        let c = serde_env::from_env()?;
        Ok(c)
    }

    fn from_env_with_prefix(prefix: &str) -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        let c = serde_env::from_env_with_prefix(prefix)?;
        Ok(c)
    }
}
