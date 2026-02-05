//! Background email job for async delivery.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{Email, Mailer};
use crate::jobs::{Job, JobOpts, JobResult};

/// Trait for application state that provides mailer access.
///
/// Implement this on your app state to use [`SendEmailJob`]:
///
/// ```ignore
/// #[derive(Clone, FromRef)]
/// pub struct AppState {
///     pub mailer: SmtpMailer,
///     // ...
/// }
///
/// impl HasMailer for AppState {
///     type Mailer = SmtpMailer;
///     fn mailer(&self) -> &SmtpMailer {
///         &self.mailer
///     }
/// }
/// ```
pub trait HasMailer: Send + Sync + 'static {
    type Mailer: Mailer;
    fn mailer(&self) -> &Self::Mailer;
}

/// Background job for sending emails.
///
/// Enqueue this job to send emails asynchronously with automatic retries:
///
/// ```ignore
/// let job = SendEmailJob {
///     email: Email::builder()
///         .to("user@example.com")
///         .subject("Welcome!")
///         .text("Thanks for joining.")
///         .build()?,
/// };
/// enqueue(&queue, job).await?;
/// ```
///
/// The job will retry up to 3 times with exponential backoff on failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEmailJob<S = ()> {
    /// The email to send.
    pub email: Email,
    #[serde(skip)]
    _marker: std::marker::PhantomData<S>,
}

impl<S> SendEmailJob<S> {
    /// Create a new send email job.
    pub fn new(email: Email) -> Self {
        Self {
            email,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S: HasMailer> Job for SendEmailJob<S> {
    const JOB_TYPE: &'static str = "maglev::send_email";
    type Context = S;

    fn default_opts() -> JobOpts {
        JobOpts {
            max_attempts: 3,
            ..Default::default()
        }
    }

    async fn perform(self, ctx: &Self::Context) -> JobResult {
        ctx.mailer()
            .send(&self.email)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(None)
    }
}
