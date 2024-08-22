use axum::async_trait;
use maglev::jobs::Job;
use {{ state_path }};

#[derive(Debug)]
pub struct {{ name|pascal_case }};

#[async_trait]
impl Job<{{ state_type }}> for {{ name|pascal_case }} {
    async fn perform(&self, ctx: {{ state_type }}) {
        tracing::trace!("Starting job: {:?}", self);
    }
}

