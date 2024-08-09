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
        // This returns an error if the `.env` file doesn't exist, but that's not what we want
        // since we're not going to use a `.env` file if we deploy this application.
        dotenvy::dotenv().ok();

        let c = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .expect("basic config builder");
        c.try_deserialize()
    }

    fn from_env_with_prefix(prefix: &str) -> Result<Self, ConfigError> {
        // This returns an error if the `.env` file doesn't exist, but that's not what we want
        // since we're not going to use a `.env` file if we deploy this application.
        dotenvy::dotenv().ok();

        let c = config::Config::builder()
            .add_source(config::Environment::with_prefix(prefix))
            .build()
            .expect("basic config builder");
        c.try_deserialize()
    }
}
