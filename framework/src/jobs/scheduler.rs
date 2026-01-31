use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio_cron_scheduler::{Job as CronJob, JobScheduler};

use super::traits::{Job, QueueProvider};
use super::JobError;

/// Cron and interval scheduling on top of any [`QueueProvider`].
///
/// The scheduler serializes each job once and re-enqueues a fresh [`JobEntry`]
/// on every trigger.
///
/// ```ignore
/// let mut scheduler = Scheduler::new(queue.clone()).await;
/// scheduler.cron("0 */5 * * * *", CleanupJob).await?;
/// scheduler.repeat(Duration::from_secs(60), HeartbeatJob).await?;
/// scheduler.start().await;
/// ```
pub struct Scheduler<Q: QueueProvider> {
    queue: Q,
    inner: JobScheduler,
}

impl<Q: QueueProvider> Scheduler<Q> {
    pub async fn new(queue: Q) -> Self {
        let inner = JobScheduler::new().await.unwrap();
        Self { queue, inner }
    }

    /// Enqueue a job on a cron schedule.
    ///
    /// Cron expression format:
    /// ```text
    /// sec   min   hour   day_of_month   month   day_of_week   year
    /// *     *     *      *              *       *             *
    /// ```
    pub async fn cron<J: Job>(
        &mut self,
        schedule: impl TryInto<cron::Schedule>,
        job: J,
    ) -> Result<(), JobError> {
        let schedule = schedule.try_into().map_err(|_| JobError::InvalidCron)?;
        if let Some(next) = schedule.upcoming(chrono::Utc).next() {
            tracing::debug!("Cron job '{}'. Next occurrence: {}", schedule, next);
        } else {
            tracing::warn!("Cron schedule '{}' will never fire", schedule);
            return Err(JobError::InvalidCron);
        }

        let payload = serde_json::to_value(&job)?;
        let job_type = J::JOB_TYPE;
        let opts = J::default_opts();
        let queue = self.queue.clone();

        let cron_job = CronJob::new_async(schedule, move |_uuid, _lock| {
            let payload = payload.clone();
            let queue = queue.clone();
            let opts = opts.clone();
            Box::pin(async move {
                let entry = super::build_entry(job_type, payload.clone(), &opts);
                if let Err(e) = queue.insert(&entry).await {
                    tracing::error!(error = %e, %job_type, "failed to enqueue scheduled job");
                }
            })
        })
        .unwrap();

        self.inner.add(cron_job).await?;
        Ok(())
    }

    /// Enqueue a job at a fixed interval.
    pub async fn repeat<J: Job>(
        &mut self,
        interval: impl TryInto<Duration>,
        job: J,
    ) -> Result<(), JobError> {
        let interval = interval
            .try_into()
            .map_err(|_| JobError::InvalidDuration)?;

        let payload = serde_json::to_value(&job)?;
        let job_type = J::JOB_TYPE;
        let opts = J::default_opts();
        let queue = self.queue.clone();

        let repeated_job = CronJob::new_repeated_async(interval, move |_uuid, _lock| {
            let payload = payload.clone();
            let queue = queue.clone();
            let opts = opts.clone();
            Box::pin(async move {
                let entry = super::build_entry(job_type, payload.clone(), &opts);
                if let Err(e) = queue.insert(&entry).await {
                    tracing::error!(error = %e, %job_type, "failed to enqueue repeated job");
                }
            })
        })
        .unwrap();

        self.inner.add(repeated_job).await?;
        Ok(())
    }

    /// Start the scheduler. This must be called after registering all cron/repeat jobs.
    pub async fn start(self) {
        self.inner.start().await.expect("scheduler start failed");
        tracing::info!("⏳ Scheduler running");
    }
}

// ---------------------------------------------------------------------------
// Schedule wrapper for serde convenience
// ---------------------------------------------------------------------------

/// Serde-friendly wrapper around [`cron::Schedule`].
#[derive(Debug, Clone)]
pub struct Schedule(cron::Schedule);

impl Serialize for Schedule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Schedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s)
            .map(Schedule)
            .map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for Schedule {
    type Target = cron::Schedule;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Schedule> for cron::Schedule {
    fn from(value: Schedule) -> Self {
        value.0
    }
}

impl From<&Schedule> for cron::Schedule {
    fn from(value: &Schedule) -> Self {
        value.0.clone()
    }
}
