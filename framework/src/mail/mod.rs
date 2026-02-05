//! Email sending with optional background job support.
//!
//! This module provides a thin abstraction over [lettre](https://lettre.rs) with
//! environment-based configuration and integration with the maglev job system.
//!
//! # Quick Start
//!
//! ```ignore
//! // 1. Initialize mailer from environment
//! let mailer = SmtpMailer::from_env()?;
//!
//! // 2. Send directly
//! let email = Email::builder()
//!     .to("user@example.com")
//!     .subject("Welcome!")
//!     .text("Thanks for signing up.")
//!     .build()?;
//! mailer.send(&email).await?;
//!
//! // 3. Or queue for background delivery
//! let job = SendEmailJob { email };
//! enqueue(&queue, job).await?;
//! ```
//!
//! # Environment Variables
//!
//! The [`SmtpMailer::from_env`] method reads:
//!
//! | Variable | Required | Description |
//! |----------|----------|-------------|
//! | `SMTP_HOST` | Yes | SMTP server hostname |
//! | `SMTP_PORT` | No | Port (default: 587) |
//! | `SMTP_USER` | No | Username for authentication |
//! | `SMTP_PASSWORD` | No | Password for authentication |
//! | `SMTP_FROM` | Yes | Default sender address |
//! | `SMTP_TLS` | No | `starttls` (default), `tls`, or `none` |

mod job;
mod mailer;
mod message;

pub use job::{HasMailer, SendEmailJob};
pub use mailer::{Mailer, MailerConfig, SmtpMailer};
pub use message::{Email, EmailBody, EmailBuilder};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailError {
    #[error("missing required config: {0}")]
    MissingConfig(String),

    #[error("invalid email address: {0}")]
    InvalidAddress(String),

    #[error("failed to build message: {0}")]
    Build(String),

    #[error("SMTP error: {0}")]
    Smtp(String),
}
