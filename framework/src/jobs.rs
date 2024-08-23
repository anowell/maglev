use axum::async_trait;
use futures::Future;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::{collections::VecDeque, time::Duration};
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job as CronJob, JobScheduler, JobSchedulerError};
use tracing::Instrument;

#[derive(Debug, thiserror::Error)]
pub enum JobsError {
    #[error("invalid cron schedule")]
    InvalidCron,
    #[error("invalid duration")]
    InvalidDuration,
    #[error("job scheduling error {0}")]
    Schedule(#[from] JobSchedulerError),
}

pub struct JobQ<T: QueueProvider<S>, S> {
    provider: Arc<T>,
    scheduler: JobScheduler,
    state: S,
}

#[async_trait]
pub trait QueueProvider<S> {
    async fn enqueue(&self, job: Box<dyn Job<S>>);
    async fn dequeue(&self) -> Option<Box<dyn Job<S>>>;
}

pub struct MemoryQueue<S> {
    jobs: Mutex<VecDeque<Box<dyn Job<S>>>>,
}

impl<S> Default for MemoryQueue<S> {
    fn default() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
        }
    }
}

#[async_trait]
impl<S> QueueProvider<S> for MemoryQueue<S> {
    async fn enqueue(&self, job: Box<dyn Job<S>>) {
        let mut jobs = self.jobs.lock().await;
        jobs.push_back(job);
    }
    async fn dequeue(&self) -> Option<Box<dyn Job<S>>> {
        let mut jobs = self.jobs.lock().await;
        jobs.pop_front()
    }
}

impl<T: QueueProvider<S>, S> JobQ<T, S>
where
    T: Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    pub async fn new(provider: T, state: S) -> Self {
        let scheduler = JobScheduler::new().await.unwrap();
        JobQ {
            provider: Arc::new(provider),
            scheduler,
            state,
        }
    }

    pub async fn start(self) {
        let state = self.state.clone();
        let provider = self.provider.clone();

        // Spawn a thread to manage the queue
        log::trace!("spawning queue manager");
        tokio::spawn(async move {
            loop {
                if let Some(job) = provider.dequeue().await {
                    let state = state.clone();
                    // Spawn a job thread
                    tokio::spawn(
                        async move {
                            job.perform(state).await;
                        }
                        .instrument(tracing::info_span!("JobQ")),
                    );
                } else {
                    // Add some delay or backoff to avoid busy-waiting
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        });

        log::trace!("spawning cron scheduler");
        // Spawn a cron thread that populates the queue from cron jobs
        self.scheduler.start().await.expect("cron scheduler panic");
        log::info!("⏳ JobQ running")
    }

    pub async fn enqueue<J>(&self, job: J)
    where
        J: Job<S> + 'static,
    {
        log::trace!("job enqueue");
        let job = Box::new(job);
        self.provider.enqueue(job).await;
    }

    /// Runs a job on a cron schedule
    ///
    /// Cron expression formatted as:
    ///
    /// ```ignore
    /// sec   min   hour   day of month   month   day of week   year
    /// *     *     *      *              *       *             *
    /// ```
    pub async fn cron(
        &mut self,
        schedule: impl TryInto<cron::Schedule>,
        job: impl Job<S> + 'static,
    ) -> Result<(), JobsError> {
        let schedule = schedule.try_into().map_err(|_| JobsError::InvalidCron)?;
        if let Some(next) = schedule.upcoming(chrono::Utc).next() {
            tracing::debug!("Cron job '{}'. Next occurrence: {}", schedule, next);
        } else {
            tracing::warn!("Cron schedule '{}' will never fire", schedule);
            return Err(JobsError::InvalidCron);
        }

        let provider = self.provider.clone();
        let job = Arc::new(job);
        let cron_job = CronJob::new_async(schedule, move |_uuid, _lock| {
            let job = job.clone();
            let provider = provider.clone();
            Box::pin(async move {
                provider.enqueue(Box::new(job)).await;
            })
        })
        .unwrap();
        self.scheduler.add(cron_job).await?;
        Ok(())
    }

    pub async fn repeat(
        &mut self,
        interval: impl TryInto<Duration>,
        job: impl Job<S> + 'static,
    ) -> Result<(), JobsError> {
        let interval = interval
            .try_into()
            .map_err(|_| JobsError::InvalidDuration)?;
        let provider = self.provider.clone();
        let job = Arc::new(job);
        let repeated_job = CronJob::new_repeated_async(interval, move |_uuid, _lock| {
            let job = job.clone();
            let provider = provider.clone();
            Box::pin(async move {
                provider.enqueue(Box::new(job)).await;
            })
        })
        .unwrap();

        self.scheduler.add(repeated_job).await?;
        Ok(())
    }
}

#[async_trait]
pub trait Job<S>: Send + Sync
where
    S: Clone + Send + Sync + 'static,
{
    async fn perform(&self, ctx: S);
}

#[async_trait]
impl<F, Fut, S> Job<S> for F
where
    S: Clone + Send + Sync + 'static,
    F: Fn(S) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    async fn perform(&self, ctx: S) {
        (self)(ctx).await;
    }
}

#[async_trait]
impl<S, J> Job<S> for Arc<J>
where
    J: Job<S>,
    S: Clone + Send + Sync + 'static,
{
    async fn perform(&self, ctx: S) {
        self.deref().perform(ctx).await
    }
}

/// Schedule wrapper for serde convenience
/// Remove all this and rexport cron::Schedule
/// when https://github.com/zslayton/cron/pull/118 lands

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
        cron::Schedule::from_str(&s)
            .map(Schedule)
            .map_err(serde::de::Error::custom)
    }
}

impl Deref for Schedule {
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
