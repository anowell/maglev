use maglev::jobs::{enqueue, Job, JobResult, MemoryQueue, QueueProvider};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct TestState;

#[derive(Serialize, Deserialize)]
struct TestJob {
    value: String,
}

#[async_trait::async_trait]
impl Job for TestJob {
    const JOB_TYPE: &'static str = "test_job";
    type Context = TestState;

    async fn perform(self, _ctx: &TestState) -> JobResult {
        Ok(None)
    }
}

#[tokio::test]
async fn memory_queue_enqueue_and_claim() {
    let queue = MemoryQueue::new();
    let job = TestJob {
        value: "hello".into(),
    };

    enqueue(&queue, job).await.unwrap();
    let claimed = queue.claim_next("test-worker").await.unwrap();

    assert!(claimed.is_some());
    assert_eq!(claimed.unwrap().job_type, "test_job");
}

#[tokio::test]
async fn memory_queue_empty_returns_none() {
    let queue = MemoryQueue::new();
    let claimed = queue.claim_next("test-worker").await.unwrap();

    assert!(claimed.is_none());
}
