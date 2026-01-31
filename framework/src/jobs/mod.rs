//! Background job queue with pluggable backends, retry, and expiry.
//!
//! # Architecture
//!
//! - [`Job`] — Serializable job trait combining data (payload) with behaviour (`perform`).
//! - [`JobEntry`] — The serialized representation of a queued job. Maps directly to a
//!   database row when using a persistent backend.
//! - [`QueueProvider`] — Backend-agnostic storage trait. Implement for Postgres, Redis, etc.
//! - [`MemoryQueue`] — In-memory provider for development and testing.
//! - [`JobRegistry`] — Maps job type strings to deserialization + execution logic.
//! - [`Worker`] — Generic processor that polls any `QueueProvider` and dispatches jobs.
//! - [`Scheduler`] — Cron and interval scheduling that enqueues jobs on a timer.
//!
//! # Quick Start
//!
//! ```ignore
//! // 1. Define a job
//! #[derive(Serialize, Deserialize)]
//! struct SendEmail { to: String, body: String }
//!
//! #[async_trait]
//! impl Job for SendEmail {
//!     const JOB_TYPE: &'static str = "send_email";
//!     type Context = AppState;
//!
//!     async fn perform(self, ctx: &AppState) -> JobResult {
//!         ctx.mailer.send(&self.to, &self.body).await?;
//!         Ok(None)
//!     }
//! }
//!
//! // 2. Enqueue
//! enqueue(&queue, SendEmail { to: "a@b.com".into(), body: "hi".into() }).await?;
//!
//! // 3. Process
//! let registry = JobRegistry::new().register::<SendEmail>();
//! Worker::new(queue, registry, app_state).start();
//! ```

mod entry;
mod memory;
mod registry;
mod scheduler;
mod traits;
mod worker;

pub use entry::{JobEntry, JobOpts, JobStatus};
pub use memory::MemoryQueue;
pub use registry::JobRegistry;
pub use scheduler::{Schedule, Scheduler};
pub use traits::{Job, JobResult, QueueProvider};
pub use worker::Worker;

use time::OffsetDateTime;
use tokio_cron_scheduler::JobSchedulerError;
use uuid::Uuid;

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("invalid cron schedule")]
    InvalidCron,
    #[error("invalid duration")]
    InvalidDuration,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("scheduler error: {0}")]
    Schedule(#[from] JobSchedulerError),
    #[error("{0}")]
    Other(String),
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Serialize a [`Job`] into a [`JobEntry`] using its default options.
pub fn into_entry<J: Job>(job: &J) -> Result<JobEntry, JobError> {
    into_entry_with(job, J::default_opts())
}

/// Serialize a [`Job`] into a [`JobEntry`] with explicit options.
pub fn into_entry_with<J: Job>(job: &J, opts: JobOpts) -> Result<JobEntry, JobError> {
    let now = OffsetDateTime::now_utc();
    Ok(JobEntry {
        id: Uuid::new_v4(),
        job_type: J::JOB_TYPE.to_string(),
        payload: serde_json::to_value(job)?,
        status: JobStatus::Pending,
        attempts: 0,
        max_attempts: opts.max_attempts,
        run_at: opts.delay.map(|d| now + d).unwrap_or(now),
        expires_at: opts.expires_in.map(|d| now + d),
        locked_at: None,
        locked_by: None,
        last_error: None,
        result: None,
        created_at: now,
        completed_at: None,
    })
}

/// Convenience: serialize a job and insert it into the queue in one call.
pub async fn enqueue<J: Job>(queue: &impl QueueProvider, job: J) -> Result<Uuid, JobError> {
    let entry = into_entry(&job)?;
    let id = entry.id;
    queue.insert(&entry).await?;
    Ok(id)
}

/// Convenience: serialize a job with options and insert it into the queue.
pub async fn enqueue_with<J: Job>(
    queue: &impl QueueProvider,
    job: J,
    opts: JobOpts,
) -> Result<Uuid, JobError> {
    let entry = into_entry_with(&job, opts)?;
    let id = entry.id;
    queue.insert(&entry).await?;
    Ok(id)
}

/// Build a JobEntry from pre-serialized payload (used internally by Scheduler).
pub(crate) fn build_entry(
    job_type: &str,
    payload: serde_json::Value,
    opts: &JobOpts,
) -> JobEntry {
    let now = OffsetDateTime::now_utc();
    JobEntry {
        id: Uuid::new_v4(),
        job_type: job_type.to_string(),
        payload,
        status: JobStatus::Pending,
        attempts: 0,
        max_attempts: opts.max_attempts,
        run_at: opts.delay.map(|d| now + d).unwrap_or(now),
        expires_at: opts.expires_in.map(|d| now + d),
        locked_at: None,
        locked_by: None,
        last_error: None,
        result: None,
        created_at: now,
        completed_at: None,
    }
}
