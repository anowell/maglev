use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::traits::Job;

type HandlerFn<S> = dyn Fn(serde_json::Value, Arc<S>) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>>> + Send>>
    + Send
    + Sync;

pub(crate) type BoxedHandler<S> = Arc<HandlerFn<S>>;

/// Maps job type strings to deserialization + execution logic.
///
/// Register each [`Job`] type before passing the registry to a [`Worker`](super::Worker).
pub struct JobRegistry<S: Send + Sync + 'static> {
    handlers: HashMap<&'static str, BoxedHandler<S>>,
}

impl<S: Send + Sync + 'static> JobRegistry<S> {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a [`Job`] type so the worker can deserialize and execute it.
    pub fn register<J: Job<Context = S>>(mut self) -> Self {
        let handler: BoxedHandler<S> = Arc::new(move |payload, ctx| {
            Box::pin(async move {
                let job: J = serde_json::from_value(payload)?;
                job.perform(&ctx).await
            })
        });
        self.handlers.insert(J::JOB_TYPE, handler);
        self
    }

    pub(crate) fn get(&self, job_type: &str) -> Option<&BoxedHandler<S>> {
        self.handlers.get(job_type)
    }
}

impl<S: Send + Sync + 'static> Default for JobRegistry<S> {
    fn default() -> Self {
        Self::new()
    }
}
