# Background Jobs

## Overview

Pluggable background job system with serializable jobs, retry logic, cron scheduling, and a trait-based storage backend.

## Architecture

**`Job` trait** — Serializable struct with typed execution logic. Each job type defines `JOB_TYPE` (string identifier), `Context` (app state), and `perform()`.

**`QueueProvider` trait** — 3-method interface for storage backends: `insert`, `claim_next`, `update`. Apps implement this with their own SQL.

**`Worker<Q, S>`** — Generic processor that polls any `QueueProvider`. Owns all state-transition logic: retry with exponential backoff (2^attempts, capped at 300s), expiry checks, concurrent execution via semaphore.

**`Scheduler<Q>`** — Enqueues jobs on cron expressions or fixed intervals.

**`MemoryQueue`** — In-memory `QueueProvider` for testing. Not durable.

## Key Types

- `JobEntry` — Serialized job representation (id, type, payload, status, attempts, timestamps, locking fields). Maps naturally to a DB row.
- `JobStatus` — Enum: Pending, Running, Completed, Failed, Expired.
- `JobOpts` — Per-job configuration: max_attempts, expires_in, delay.
- `JobRegistry<S>` — Maps job type strings to deserialization + execution handlers.

## Usage Pattern

```rust
// Define a job
#[derive(Serialize, Deserialize)]
struct SendEmail { to: String, subject: String }

#[async_trait]
impl Job for SendEmail {
    const JOB_TYPE: &'static str = "send_email";
    type Context = AppState;

    async fn perform(self, ctx: &AppState) -> JobResult {
        ctx.mailer.send(&self.to, &self.subject).await?;
        Ok(None)
    }
}

// Enqueue
enqueue(&queue, SendEmail { to, subject }).await?;

// Start worker
let registry = JobRegistry::new()
    .register::<SendEmail>();
Worker::new(queue, registry, app_state)
    .concurrency(4)
    .start();
```

## Persistence

Apps implement `QueueProvider` against their own database schema. Use `maglev generate queue` to scaffold a Postgres implementation with `FOR UPDATE SKIP LOCKED` for safe concurrent claiming.

See [principles.md](principles.md) — SQL lives in the app for compile-time verification.
