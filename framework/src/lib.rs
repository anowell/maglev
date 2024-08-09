pub use maglev_macros::HttpError;

pub use axum::debug_handler as handler;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;

pub use config::EnvConfig;

#[macro_export]
macro_rules! anyhow_from {
    ($error_type:path) => {
        impl From<$error_type> for Error {
            fn from(err: $error_type) -> Self {
                Error::from(anyhow::Error::new(err))
            }
        }
    };
}
