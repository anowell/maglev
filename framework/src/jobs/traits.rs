use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use super::entry::{JobEntry, JobOpts};
use super::JobError;

/// A serializable job with typed execution logic.
///
/// Implement this trait for each job type in your application. The job's fields
/// become the serialized payload, and `perform` defines the execution logic.
///
/// ```ignore
/// #[derive(Serialize, Deserialize)]
/// struct SendEmail { to: String, subject: String, body: String }
///
/// #[async_trait]
/// impl Job for SendEmail {
///     const JOB_TYPE: &'static str = "send_email";
///     type Context = AppState;
///
///     async fn perform(self, ctx: &AppState) -> JobResult {
///         ctx.mailer.send(&self.to, &self.subject, &self.body).await?;
///         Ok(None)
///     }
/// }
/// ```
#[async_trait]
pub trait Job: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Unique identifier for this job type (e.g. `"send_email"`).
    const JOB_TYPE: &'static str;

    /// Application state provided at execution time.
    type Context: Send + Sync + 'static;

    /// Default options for this job type. Override to customise.
    fn default_opts() -> JobOpts {
        JobOpts::default()
    }

    /// Execute the job. Return `Ok(Some(value))` to store a result for
    /// observability, or `Ok(None)` when there is nothing to record.
    async fn perform(
        self,
        ctx: &Self::Context,
    ) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Convenience alias for the return type of [`Job::perform`].
pub type JobResult = Result<Option<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>>;

/// Backend-agnostic queue storage.
///
/// Implement this trait to plug in any persistence layer (in-memory, Postgres,
/// Redis, SQS, etc.). The [`Worker`](super::Worker) polls a `QueueProvider`,
/// handles all state transitions (retry, expiry, completion), and calls
/// `update` with the modified entry.
///
/// Each method maps to a single storage operation, making implementations
/// straightforward — especially for SQL backends where each method is one query.
#[async_trait]
pub trait QueueProvider: Send + Sync + Clone + 'static {
    /// Insert a new job entry into the queue.
    async fn insert(&self, entry: &JobEntry) -> Result<(), JobError>;

    /// Atomically claim the next eligible job (status=pending, run_at <= now).
    ///
    /// The implementation must:
    /// - Select a pending job with `run_at <= now`
    /// - Set `status` to `Running`, `locked_at` to now, `locked_by` to the
    ///   worker id, and increment `attempts`
    /// - Return `None` when no eligible jobs exist
    ///
    /// For Postgres, this is the `SELECT ... FOR UPDATE SKIP LOCKED` pattern.
    async fn claim_next(&self, worker_id: &str) -> Result<Option<JobEntry>, JobError>;

    /// Persist an updated job entry. The [`Worker`](super::Worker) sets all
    /// fields (status, result, timestamps, etc.) before calling this — the
    /// implementation only needs to write the entry back by id.
    async fn update(&self, entry: &JobEntry) -> Result<(), JobError>;
}
