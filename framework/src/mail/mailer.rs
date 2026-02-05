//! Mailer trait and SMTP implementation.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;

use super::{Email, EmailBody, MailError};

/// Async email sending trait.
///
/// Implement this trait to provide alternative email backends (e.g., SES, Mailgun).
#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    /// Send an email.
    async fn send(&self, email: &Email) -> Result<(), MailError>;
}

/// Configuration for SMTP mailer.
#[derive(Debug, Clone, Deserialize)]
pub struct MailerConfig {
    /// SMTP server hostname.
    #[serde(rename = "smtp_host")]
    pub host: String,

    /// SMTP server port (default: 587).
    #[serde(rename = "smtp_port", default = "default_port")]
    pub port: u16,

    /// SMTP username for authentication.
    #[serde(rename = "smtp_username")]
    pub username: Option<String>,

    /// SMTP password for authentication.
    #[serde(rename = "smtp_password")]
    pub password: Option<String>,

    /// Default sender address.
    #[serde(rename = "smtp_from")]
    pub from: String,

    /// TLS mode: "starttls" (default), "tls", or "none".
    #[serde(rename = "smtp_tls", default = "default_tls")]
    pub tls: String,

    /// Connection timeout in seconds (default: 10).
    #[serde(rename = "smtp_timeout", default = "default_timeout")]
    pub timeout: u64,
}

fn default_port() -> u16 {
    587
}

fn default_tls() -> String {
    "starttls".to_string()
}

fn default_timeout() -> u64 {
    10
}

/// SMTP-based mailer using lettre.
#[derive(Clone)]
pub struct SmtpMailer {
    transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
}

impl SmtpMailer {
    /// Create a mailer from environment variables.
    ///
    /// Reads `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`.
    pub fn from_env() -> Result<Self, MailError> {
        dotenvy::dotenv().ok();

        let config: MailerConfig =
            serde_env::from_env().map_err(|e| MailError::MissingConfig(e.to_string()))?;

        Self::from_config(config)
    }

    /// Create a mailer from explicit configuration.
    pub fn from_config(config: MailerConfig) -> Result<Self, MailError> {
        let from: Mailbox = config
            .from
            .parse()
            .map_err(|_| MailError::InvalidAddress(config.from.clone()))?;

        let mut builder = match config.tls.as_str() {
            "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host),
            "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| MailError::Smtp(e.to_string()))?,
            _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| MailError::Smtp(e.to_string()))?,
        };

        builder = builder
            .port(config.port)
            .timeout(Some(Duration::from_secs(config.timeout)));

        if let (Some(username), Some(password)) = (config.username, config.password) {
            builder = builder.credentials(Credentials::new(username, password));
        }

        let transport = builder.build();

        Ok(Self {
            transport: Arc::new(transport),
            from,
        })
    }

    /// Build a lettre Message from our Email type.
    fn build_message(&self, email: &Email) -> Result<Message, MailError> {
        let from_mailbox = email
            .from
            .as_ref()
            .map(|f| f.parse())
            .transpose()
            .map_err(|_| {
                MailError::InvalidAddress(email.from.clone().unwrap_or_default())
            })?
            .unwrap_or_else(|| self.from.clone());

        let mut builder = Message::builder().from(from_mailbox);

        for to in &email.to {
            let mailbox: Mailbox = to
                .parse()
                .map_err(|_| MailError::InvalidAddress(to.clone()))?;
            builder = builder.to(mailbox);
        }

        for cc in &email.cc {
            let mailbox: Mailbox = cc
                .parse()
                .map_err(|_| MailError::InvalidAddress(cc.clone()))?;
            builder = builder.cc(mailbox);
        }

        for bcc in &email.bcc {
            let mailbox: Mailbox = bcc
                .parse()
                .map_err(|_| MailError::InvalidAddress(bcc.clone()))?;
            builder = builder.bcc(mailbox);
        }

        if let Some(reply_to) = &email.reply_to {
            let mailbox: Mailbox = reply_to
                .parse()
                .map_err(|_| MailError::InvalidAddress(reply_to.clone()))?;
            builder = builder.reply_to(mailbox);
        }

        builder = builder.subject(&email.subject);

        let message = match &email.body {
            EmailBody::Text(text) => builder
                .body(text.clone())
                .map_err(|e| MailError::Build(e.to_string()))?,
            EmailBody::Html(html) => builder
                .singlepart(SinglePart::html(html.clone()))
                .map_err(|e| MailError::Build(e.to_string()))?,
            EmailBody::Multipart { text, html } => builder
                .multipart(MultiPart::alternative_plain_html(text.clone(), html.clone()))
                .map_err(|e| MailError::Build(e.to_string()))?,
        };

        Ok(message)
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, email: &Email) -> Result<(), MailError> {
        let message = self.build_message(email)?;

        self.transport
            .send(message)
            .await
            .map_err(|e| MailError::Smtp(e.to_string()))?;

        Ok(())
    }
}
