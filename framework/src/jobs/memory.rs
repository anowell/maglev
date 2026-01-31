use async_trait::async_trait;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::entry::{JobEntry, JobStatus};
use super::traits::QueueProvider;
use super::JobError;

/// In-memory [`QueueProvider`] for development and testing.
///
/// Jobs are stored in a `Vec` behind a mutex. Not durable — all jobs are lost
/// on restart.
#[derive(Clone, Default)]
pub struct MemoryQueue {
    entries: Arc<Mutex<Vec<JobEntry>>>,
}

impl MemoryQueue {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl QueueProvider for MemoryQueue {
    async fn insert(&self, entry: &JobEntry) -> Result<(), JobError> {
        let mut entries = self.entries.lock().await;
        entries.push(entry.clone());
        Ok(())
    }

    async fn claim_next(&self, worker_id: &str) -> Result<Option<JobEntry>, JobError> {
        let mut entries = self.entries.lock().await;
        let now = OffsetDateTime::now_utc();

        let pos = entries
            .iter()
            .position(|e| e.status == JobStatus::Pending && e.run_at <= now);

        if let Some(idx) = pos {
            let entry = &mut entries[idx];
            entry.status = JobStatus::Running;
            entry.locked_at = Some(now);
            entry.locked_by = Some(worker_id.to_string());
            entry.attempts += 1;
            Ok(Some(entry.clone()))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &JobEntry) -> Result<(), JobError> {
        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.iter_mut().find(|e| e.id == entry.id) {
            *existing = entry.clone();
        }
        Ok(())
    }
}
