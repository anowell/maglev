# Background Jobs Architecture

## What Maglev Provides

**Background job system** with in-memory queue, cron scheduling, and pluggable storage via traits.

**Three scheduling modes**: One-time (enqueue), cron expressions, fixed intervals.

**`Job<S>` trait**: Auto-implemented for closures. Jobs receive cloned state and run fire-and-forget (no return value).

**`QueueProvider<S>` trait**: Abstract storage backend. Default `MemoryQueue` provided.

## Key Design Decisions

### Trait-Based Storage Abstraction

`QueueProvider<S>` decouples job mechanics from storage. Default `MemoryQueue` (VecDeque) for simplicity, but implement Redis/Postgres backends for production durability.

Two methods: `enqueue()` adds jobs, `dequeue()` retrieves (returns `Option`).

### State Cloning

Jobs receive `S: Clone`. Make state a struct of `Arc<_>` fields (pools, configs) to avoid expensive clones. Jobs can't mutate shared state directly - use interior mutability or DB for coordination.

### Fire-and-Forget Execution

`Job::perform()` has no return type. Jobs handle errors internally - log, store in DB, or re-enqueue as needed. No automatic retry logic (apps vary too much).

Pattern: Explicit retry loops inside job logic if needed.

### Closure Support

`Job<S>` auto-implemented for `Fn(S) -> impl Future`. Most jobs are closures capturing variables, not explicit structs. Simple and ergonomic.

Tradeoff: Can't serialize closures easily. For persistent queues, use struct-based jobs with serde.

**Note**: `Job<S>` and `QueueProvider<S>` use `#[async_trait]` because `Box<dyn Job<S>>` requires object-safe traits. Native async fn in traits isn't object-safe (returns `impl Future`). `async_trait` is zero-cost at runtime - generates `Pin<Box<...>>` boilerplate.

**Future consideration**: Persistent job queues using concrete struct types (not trait objects) could avoid `async_trait` entirely. Trade closure ergonomics for serializability and potentially simpler trait bounds.

### Two-Task Architecture

`start()` spawns two tokio tasks:
1. **Queue manager** - Dequeues and spawns job workers
2. **Cron scheduler** - Enqueues scheduled jobs

No concurrency limits built-in (jobs spawn immediately). Implement semaphore in `QueueProvider` if needed.

### In-Memory Queue Default

`MemoryQueue` is simple (VecDeque) but jobs lost on restart and not shared across instances. Fine for development, demos, or truly ephemeral tasks. Production apps should implement persistent `QueueProvider`.

### No Automatic Retries

Retry logic varies by job type (immediate retry vs exponential backoff vs DLQ). Better to be explicit in job code than provide one-size-fits-all mechanism.

### Cron via tokio-cron-scheduler

Standard cron syntax. Cron jobs enqueue through normal queue (not direct execution) enabling monitoring and backpressure.

## Extensibility

Implement `QueueProvider<S>` for persistent backends:
- **Postgres**: SELECT FOR UPDATE SKIP LOCKED pattern
- **Redis**: RPUSH/BLPOP with streams
- **Concurrency limits**: Wrap provider with semaphore

Struct-based jobs enable serialization (required for persistent queues). Closures work only with in-memory.

Monitoring via tracing spans or metrics in provider implementation.

## Current Limitations

No job arguments (closure captures only), no built-in retry, no graceful shutdown, in-memory queue not durable.

Future additions driven by real-world needs.
