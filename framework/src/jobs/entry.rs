use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Status of a job in the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Expired,
}

impl JobStatus {
    /// Returns the status as a static string slice.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown job status: {other}")),
        }
    }
}

/// Options controlling retry, expiry, and scheduling for a job.
#[derive(Debug, Clone)]
pub struct JobOpts {
    /// Maximum number of attempts (including the first).
    pub max_attempts: i32,
    /// If set, the job is skipped when dequeued after this duration from creation.
    pub expires_in: Option<std::time::Duration>,
    /// Delay before the job becomes eligible for processing.
    pub delay: Option<std::time::Duration>,
}

impl Default for JobOpts {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            expires_in: None,
            delay: None,
        }
    }
}

/// Serialized representation of a queued job.
///
/// This is the unit of work stored in any queue backend. All fields map
/// directly to database columns when using a persistent backend like Postgres.
///
/// Fields map directly to database columns when using a persistent backend.
/// Applications can derive `sqlx::FromRow` on their own row type or map
/// to/from `JobEntry` for compile-time checked queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEntry {
    pub id: Uuid,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub status: JobStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub run_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub locked_at: Option<OffsetDateTime>,
    pub locked_by: Option<String>,
    pub last_error: Option<String>,
    pub result: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

// For sqlx: JobStatus <-> String conversion
impl TryFrom<String> for JobStatus {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}
