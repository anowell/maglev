use maglev::jobs::{Job, MemoryQueue, QueueProvider};

#[derive(Clone)]
struct TestState {}

struct TestJob;

#[async_trait::async_trait]
impl Job<TestState> for TestJob {
    async fn perform(&self, _ctx: TestState) {
        // Job logic
    }
}

#[tokio::test]
async fn memory_queue_enqueue_dequeue() {
    let queue: MemoryQueue<TestState> = MemoryQueue::default();
    let job = Box::new(TestJob);

    queue.enqueue(job).await;
    let dequeued = queue.dequeue().await;

    assert!(dequeued.is_some());
}

#[tokio::test]
async fn memory_queue_empty_returns_none() {
    let queue: MemoryQueue<TestState> = MemoryQueue::default();
    let dequeued = queue.dequeue().await;

    assert!(dequeued.is_none());
}
