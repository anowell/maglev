use std::{ops::Deref, sync::Arc};

use serde::de::DeserializeOwned;

pub use config::ConfigError;

pub trait EnvConfig: Sized {
    fn from_env() -> Result<Self, ConfigError>;
    fn from_env_with_prefix(prefix: &str) -> Result<Self, ConfigError>;
}

impl<D> EnvConfig for D
where
    D: DeserializeOwned,
{
    fn from_env() -> Result<Self, ConfigError> {
        let c = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .expect("basic config builder");
        c.try_deserialize()
    }

    fn from_env_with_prefix(prefix: &str) -> Result<Self, ConfigError> {
        let c = config::Config::builder()
            .add_source(config::Environment::with_prefix(prefix))
            .build()
            .expect("basic config builder");
        c.try_deserialize()
    }
}
