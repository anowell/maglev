use async_trait::async_trait;
use maglev::jobs::{Job, JobResult};
use serde::{Deserialize, Serialize};
use {{ state_path }};

#[derive(Serialize, Deserialize)]
pub struct {{ name|pascal_case }} {
    // TODO: add job fields
}

#[async_trait]
impl Job for {{ name|pascal_case }} {
    const JOB_TYPE: &'static str = "{{ name|snake_case }}";
    type Context = {{ state_type }};

    async fn perform(self, ctx: &Self::Context) -> JobResult {
        tracing::info!("performing job: {{ name|snake_case }}");
        Ok(None)
    }
}
