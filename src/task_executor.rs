use futures::channel::mpsc::Sender;
use futures::prelude::*;
use logging::{exception, trace_with_peers};

/// Provides a reason when client is shut down.
#[derive(Copy, Clone, Debug)]
pub enum ShutdownReason {
    /// The node shut down due to an error condition.
    Failure(&'static str),
}

impl ShutdownReason {
    pub fn message(&self) -> &'static str {
        match self {
            ShutdownReason::Failure(msg) => msg,
        }
    }
}

/// A wrapper over a runtime handle which can spawn async and blocking tasks.
#[derive(Clone)]
pub struct TaskExecutor {
    /// Sender given to tasks, so that if they encounter a state in which execution cannot
    /// continue they can request that everything shuts down.
    ///
    /// The task must provide a reason for shutting down.
    signal_tx: Sender<ShutdownReason>,
}

impl TaskExecutor {
    /// Create a new task executor.
    ///
    /// Note: this function is mainly useful in tests. A `TaskExecutor` should be normally obtained from
    /// a [`RuntimeContext`](struct.RuntimeContext.html)
    pub fn new(signal_tx: Sender<ShutdownReason>) -> Self {
        Self { signal_tx }
    }

    /// Spawn a task to monitor the completion of another task.
    ///
    /// If the other task exits by panicking, then the monitor task will shut down the executor.
    fn spawn_monitor<R: Send>(
        &self,
        task_handle: impl Future<Output = Result<R, tokio::task::JoinError>> + Send + 'static,
        name: &'static str,
    ) {
        let mut shutdown_sender = self.shutdown_sender();

        tokio::spawn(async move {
            if let Err(join_error) = task_handle.await {
                if let Ok(panic) = join_error.try_into_panic() {
                    let message = panic.downcast_ref::<&str>().unwrap_or(&"<none>");

                    exception!(
                        task_name = name,
                        message = message,
                        advice = "Please check above for a backtrace and notify the developers",
                        "Task panic. This is a bug!"
                    );
                    let _ =
                        shutdown_sender.try_send(ShutdownReason::Failure("Panic (fatal error)"));
                }
            }
        });
    }

    /// Spawn a future on the tokio runtime.
    ///
    /// The future is monitored via another spawned future to ensure that it doesn't panic. In case
    /// of a panic, the executor will be shut down via `self.signal_tx`.
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static, name: &'static str) {
        self.spawn_monitor(self.spawn_handle(task, name), name)
    }

    /// Spawn a future on the tokio runtime returning a join handle to the future.
    fn spawn_handle<R: Send + 'static>(
        &self,
        task: impl Future<Output = R> + Send + 'static,
        name: &'static str,
    ) -> tokio::task::JoinHandle<R> {
        let future = task.inspect(move |_| trace_with_peers!(task = name, "Async task completed"));

        tokio::spawn(future)
    }

    /// Get a channel to request shutting down.
    fn shutdown_sender(&self) -> Sender<ShutdownReason> {
        self.signal_tx.clone()
    }
}
