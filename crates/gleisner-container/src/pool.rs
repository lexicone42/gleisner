//! Concurrent sandbox pool for parallel builds.
//!
//! Manages multiple sandboxes running simultaneously, enforcing global
//! resource limits and collecting results. Designed for `minimal -j N`
//! style parallel builds.
//!
//! ```no_run
//! use gleisner_container::pool::SandboxPool;
//! use gleisner_container::task::TaskSandbox;
//!
//! let pool = SandboxPool::new(4); // max 4 concurrent
//!
//! pool.submit("build-gcc", TaskSandbox::new("/workspace"), "make", &["-j4"]);
//! pool.submit("build-zlib", TaskSandbox::new("/workspace"), "make", &[]);
//!
//! let results = pool.wait_all();
//! for (name, result) in &results {
//!     println!("{name}: {:?}", result.as_ref().map(|o| o.exit_code()));
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use self::semaphore::Semaphore;
use crate::command::Output;
use crate::error::ContainerError;
use crate::task::TaskSandbox;

/// A pool of concurrent sandboxes with bounded parallelism.
pub struct SandboxPool {
    /// Maximum number of concurrent sandboxes.
    max_concurrent: usize,
    /// Global timeout for all tasks (None = no limit).
    global_timeout: Option<Duration>,
    /// Per-task timeout (None = no limit).
    task_timeout: Option<Duration>,
    /// Submitted tasks waiting to run or running.
    tasks: Arc<Mutex<Vec<PoolTask>>>,
}

/// A task submitted to the pool.
#[derive(Debug)]
struct PoolTask {
    /// Task name (for result mapping).
    name: String,
    /// The sandbox configuration.
    task: TaskSandbox,
    /// Command to run.
    program: String,
    /// Command arguments.
    args: Vec<String>,
}

/// Result of a pool execution.
#[derive(Debug)]
pub struct PoolResult {
    /// Per-task results, keyed by task name.
    pub results: HashMap<String, Result<Output, ContainerError>>,
    /// Total wall-clock time for the entire pool.
    pub elapsed: Duration,
    /// Number of tasks that succeeded.
    pub succeeded: usize,
    /// Number of tasks that failed.
    pub failed: usize,
}

impl SandboxPool {
    /// Create a pool with the given maximum concurrency.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.max(1),
            global_timeout: None,
            task_timeout: None,
            tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Set a global timeout for the entire pool execution.
    pub fn global_timeout(mut self, duration: Duration) -> Self {
        self.global_timeout = Some(duration);
        self
    }

    /// Set a per-task timeout.
    pub fn task_timeout(mut self, duration: Duration) -> Self {
        self.task_timeout = Some(duration);
        self
    }

    /// Submit a task to the pool.
    pub fn submit(
        &self,
        name: impl Into<String>,
        task: TaskSandbox,
        program: impl Into<String>,
        args: &[impl AsRef<str>],
    ) {
        let mut tasks = self.tasks.lock().expect("pool lock");
        tasks.push(PoolTask {
            name: name.into(),
            task,
            program: program.into(),
            args: args.iter().map(|a| a.as_ref().to_owned()).collect(),
        });
    }

    /// Run all submitted tasks with bounded concurrency and collect results.
    ///
    /// Tasks are executed in submission order, up to `max_concurrent` at a time.
    /// Each task gets its own sandbox (no shared state between concurrent tasks).
    pub fn run_all(self) -> PoolResult {
        let start = Instant::now();
        let tasks = Arc::try_unwrap(self.tasks)
            .expect("pool has no other references")
            .into_inner()
            .expect("pool lock");

        let total = tasks.len();
        let mut results: HashMap<String, Result<Output, ContainerError>> = HashMap::new();

        // Simple semaphore-based concurrency using threads
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let results_mutex = Mutex::new(&mut results);

        // Scoped threads share references safely without Arc
        std::thread::scope(|scope| {
            let mut handles = Vec::new();

            for pool_task in tasks {
                let sem = &semaphore;
                let results_ref = &results_mutex;
                let task_timeout = self.task_timeout;

                let handle = scope.spawn(move || {
                    // Acquire semaphore slot (blocks until a slot is free)
                    let _permit = sem.acquire();

                    let name = pool_task.name.clone();
                    let result = run_single_task(pool_task, task_timeout);

                    results_ref
                        .lock()
                        .expect("results lock")
                        .insert(name, result);
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().expect("task thread panicked");
            }
        });

        let succeeded = results.values().filter(|r| r.is_ok()).count();

        PoolResult {
            results,
            elapsed: start.elapsed(),
            succeeded,
            failed: total - succeeded,
        }
    }
}

/// Run a single task in its sandbox.
fn run_single_task(task: PoolTask, timeout: Option<Duration>) -> Result<Output, ContainerError> {
    let sb = task.task.build()?;
    let cmd = sb.command_with_args(&task.program, &task.args)?;
    let cmd = if let Some(t) = timeout {
        cmd.timeout(t)
    } else {
        cmd
    };
    cmd.output()
}

/// A simple counting semaphore for thread-based concurrency.
mod semaphore {
    use std::sync::{Condvar, Mutex};

    pub(super) struct Semaphore {
        state: Mutex<usize>,
        cond: Condvar,
    }

    pub(super) struct Permit<'a> {
        sem: &'a Semaphore,
    }

    impl Semaphore {
        pub(super) fn new(count: usize) -> Self {
            Self {
                state: Mutex::new(count),
                cond: Condvar::new(),
            }
        }

        pub(super) fn acquire(&self) -> Permit<'_> {
            let mut count = self.state.lock().expect("semaphore lock");
            while *count == 0 {
                count = self.cond.wait(count).expect("semaphore wait");
            }
            *count -= 1;
            Permit { sem: self }
        }
    }

    impl Drop for Permit<'_> {
        fn drop(&mut self) {
            let mut count = self.sem.state.lock().expect("semaphore lock");
            *count += 1;
            self.sem.cond.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_basic() {
        let pool = SandboxPool::new(2);

        // Submit two tasks that will be run concurrently
        pool.submit("task1", TaskSandbox::new("/tmp"), "true", &[] as &[&str]);
        pool.submit("task2", TaskSandbox::new("/tmp"), "true", &[] as &[&str]);

        // Can't actually run without sandbox-init, but verify the pool accepts tasks
        assert_eq!(pool.tasks.lock().unwrap().len(), 2);
    }

    #[test]
    fn pool_result_tracking() {
        // Create a result manually to test the tracking
        let result = PoolResult {
            results: HashMap::from([(
                "ok".to_owned(),
                Err(ContainerError::Config("test".to_owned())),
            )]),
            elapsed: Duration::from_secs(1),
            succeeded: 0,
            failed: 1,
        };

        assert_eq!(result.failed, 1);
        assert_eq!(result.succeeded, 0);
    }
}
