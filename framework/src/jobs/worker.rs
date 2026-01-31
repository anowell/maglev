use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tracing::Instrument;

use super::entry::JobStatus;
use super::registry::JobRegistry;
use super::traits::QueueProvider;

/// Generic job processor that polls any [`QueueProvider`] and dispatches
/// to handlers registered in a [`JobRegistry`].
///
/// The worker owns all state-transition logic: on success it marks the entry
/// completed, on failure it decides whether to retry (with backoff) or mark
/// permanently failed, and it checks expiry before dispatching.
///
/// ```ignore
/// let registry = JobRegistry::new()
///     .register::<SendEmail>()
///     .register::<ProcessPayment>();
///
/// Worker::new(queue, registry, app_state)
///     .concurrency(8)
///     .poll_interval(Duration::from_millis(500))
///     .start();
/// ```
pub struct Worker<Q: QueueProvider, S: Send + Sync + 'static> {
    queue: Q,
    registry: Arc<JobRegistry<S>>,
    ctx: Arc<S>,
    concurrency: usize,
    poll_interval: Duration,
    worker_id: String,
}

impl<Q: QueueProvider, S: Send + Sync + 'static> Worker<Q, S> {
    pub fn new(queue: Q, registry: JobRegistry<S>, ctx: S) -> Self {
        Self {
            queue,
            registry: Arc::new(registry),
            ctx: Arc::new(ctx),
            concurrency: 4,
            poll_interval: Duration::from_secs(1),
            worker_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Maximum number of jobs processed in parallel (default: 4).
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }

    /// How often to poll when idle (default: 1s). Backs off slightly during
    /// idle streaks.
    pub fn poll_interval(mut self, d: Duration) -> Self {
        self.poll_interval = d;
        self
    }

    /// Start the worker loop. Spawns a background tokio task and returns
    /// immediately.
    pub fn start(self) {
        let queue = self.queue;
        let registry = self.registry;
        let ctx = self.ctx;
        let concurrency = self.concurrency;
        let poll_interval = self.poll_interval;
        let worker_id = self.worker_id;

        tokio::spawn(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
            let mut idle_streak: u32 = 0;

            loop {
                let permit = semaphore.clone().acquire_owned().await.unwrap();

                let row = queue.claim_next(&worker_id).await;

                let mut entry = match row {
                    Ok(Some(e)) => e,
                    Ok(None) => {
                        drop(permit);
                        idle_streak = idle_streak.saturating_add(1);
                        let backoff = poll_interval
                            .mul_f64((1.5_f64).min(1.0 + idle_streak as f64 * 0.1));
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(e) => {
                        drop(permit);
                        tracing::error!(error = %e, "failed to poll queue");
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };

                idle_streak = 0;

                let job_id = entry.id;
                let job_type = entry.job_type.clone();

                // Check expiry
                if let Some(exp) = entry.expires_at {
                    if exp < OffsetDateTime::now_utc() {
                        tracing::info!(%job_id, %job_type, "job expired, skipping");
                        entry.status = JobStatus::Expired;
                        entry.completed_at = Some(OffsetDateTime::now_utc());
                        let _ = queue.update(&entry).await;
                        drop(permit);
                        continue;
                    }
                }

                let handler = registry.get(&job_type).cloned();
                let queue2 = queue.clone();
                let ctx2 = ctx.clone();

                tokio::spawn(async move {
                    let _permit = permit;

                    let Some(handler) = handler else {
                        tracing::error!(%job_id, %job_type, "no handler registered");
                        entry.status = JobStatus::Failed;
                        entry.last_error = Some("unknown job type".to_string());
                        entry.completed_at = Some(OffsetDateTime::now_utc());
                        let _ = queue2.update(&entry).await;
                        return;
                    };

                    let span = tracing::info_span!("job", %job_id, %job_type);
                    let result = handler(entry.payload.clone(), ctx2).instrument(span).await;

                    match result {
                        Ok(job_result) => {
                            tracing::info!(%job_id, %job_type, "job completed");
                            entry.status = JobStatus::Completed;
                            entry.result = job_result;
                            entry.completed_at = Some(OffsetDateTime::now_utc());
                            let _ = queue2.update(&entry).await;
                        }
                        Err(e) => {
                            let error_msg = e.to_string();
                            entry.last_error = Some(error_msg.clone());
                            entry.locked_at = None;
                            entry.locked_by = None;

                            if entry.attempts < entry.max_attempts {
                                let backoff_secs =
                                    (2_u64.saturating_pow(entry.attempts as u32)).min(300);
                                entry.status = JobStatus::Pending;
                                entry.run_at = OffsetDateTime::now_utc()
                                    + Duration::from_secs(backoff_secs);
                                tracing::warn!(
                                    %job_id, %job_type,
                                    attempt = entry.attempts,
                                    %error_msg,
                                    backoff_secs,
                                    "job failed, scheduling retry"
                                );
                            } else {
                                entry.status = JobStatus::Failed;
                                entry.completed_at = Some(OffsetDateTime::now_utc());
                                tracing::error!(
                                    %job_id, %job_type,
                                    attempts = entry.attempts,
                                    %error_msg,
                                    "job permanently failed"
                                );
                            }
                            let _ = queue2.update(&entry).await;
                        }
                    }
                });
            }
        });

        tracing::info!("⏳ Worker running");
    }
}
