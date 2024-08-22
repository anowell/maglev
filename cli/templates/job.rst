use {{ state_path }};

pub async fn {{ name|snake_case }}(ctx: {{ state_type }}) {
    tracing::trace!("Starting job: {{ name|snake_case }}");
}
