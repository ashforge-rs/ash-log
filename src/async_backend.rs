//! Moving writes off the calling thread.
//!
//! # Why this exists
//!
//! Every built-in backend writes synchronously: [`log_audit`] returns only once
//! the event has reached the OS. That is the right default for an audit trail,
//! but it means a slow disk stalls whichever thread is serving a request, and
//! inside an async runtime it blocks a worker that could be running other tasks.
//!
//! [`AsyncBackend`] hands events to a dedicated writer thread through a bounded
//! queue. Callers pay an enqueue and return; the writer does the I/O.
//!
//! # When this actually helps
//!
//! Measured, not assumed (`cargo bench --features hmac-chain`):
//!
//! - **A burst that fits the queue**: 20 events to a 200us-per-write
//!   destination took **6.15ms synchronously, 24us enqueued** — roughly 250x.
//!   This is the case the type exists for: a request handler emitting a handful
//!   of events should not wait on a slow destination.
//! - **Sustained load beyond the drain rate**: no benefit at all. Once the queue
//!   saturates, enqueueing blocks and the caller waits anyway. The writer
//!   cannot outpace the destination it wraps; it can only defer the wait.
//! - **A fast local file**: a net *loss*. Enqueueing costs ~1.9us against
//!   ~1.1us for a page-cache-backed write, because the event is cloned and
//!   boxed on the way into the queue. Wrap a fast destination and you pay for
//!   the queue without getting anything for it.
//!
//! Use it when the destination is genuinely slow — a network target, a
//! congested disk, `fsync` per event — and traffic is bursty. Wrapping a local
//! file to "make logging async" makes it slower.
//!
//! # What is traded away
//!
//! An event that is queued is not yet written. A crash loses the queue, so this
//! is not appropriate for a record that must survive process death — the same
//! caveat as [`BufferedAuditBackend`](crate::BufferedAuditBackend), and for the
//! same reason.
//!
//! [`AsyncBackend::flush`] blocks until the queue has drained, and [`Drop`]
//! flushes, so a normal shutdown loses nothing.
//!
//! # Backpressure
//!
//! The queue is bounded. [`OverflowPolicy`] decides what a full queue means:
//! block the caller (never lose an event, but reintroduce the stall),
//! or drop and report (stay responsive, and know exactly how much was lost).
//! Neither is right for every deployment, which is why it must be chosen.
//!
//! [`log_audit`]: crate::AuditBackend::log_audit

use super::{AuditBackend, AuditEvent, ErrorSink, IgnoreErrors, WriteError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

/// What to do when the queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowPolicy {
    /// Block the caller until space frees up. No event is ever lost, but a
    /// stalled writer stalls producers — the behaviour of a synchronous
    /// backend, arrived at only under sustained overload.
    #[default]
    Block,
    /// Drop the event and report it to the error sink. Keeps producers moving
    /// at the cost of a gap in the record, which the sink makes visible.
    DropAndReport,
}

/// One unit of work for the writer thread.
enum Message {
    Audit(Box<AuditEvent>),
    Security(Box<serde_json::Value>),
    /// Drain marker: the writer replies once everything before it is written.
    Flush(SyncSender<()>),
}

/// Writes events on a dedicated thread.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let backend = AsyncBackend::builder(Arc::new(StdoutAuditBackend))
///     .capacity(4096)
///     .overflow(OverflowPolicy::DropAndReport)
///     .errors(Arc::new(StderrErrorSink))
///     .build();
///
/// let logger = Logger::builder(Arc::new(backend)).build();
/// logger.info("does not block on the write");
/// logger.flush(); // waits for the queue to drain
/// ```
pub struct AsyncBackend {
    sender: Mutex<Option<SyncSender<Message>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    policy: OverflowPolicy,
    dropped: Arc<AtomicU64>,
    errors: Arc<dyn ErrorSink>,
}

impl AsyncBackend {
    /// Start building an async backend wrapping `inner`.
    #[must_use]
    pub fn builder(inner: Arc<dyn AuditBackend>) -> AsyncBackendBuilder {
        AsyncBackendBuilder {
            inner,
            capacity: 1024,
            policy: OverflowPolicy::Block,
            errors: Arc::new(IgnoreErrors),
        }
    }

    /// Wrap `inner` with default settings: a 1024-event queue that blocks when
    /// full.
    #[must_use]
    pub fn new(inner: Arc<dyn AuditBackend>) -> Self {
        Self::builder(inner).build()
    }

    /// Events dropped because the queue was full.
    ///
    /// Always 0 under [`OverflowPolicy::Block`].
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Send one message, applying the overflow policy.
    fn send(&self, message: Message) {
        let guard = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sender) = guard.as_ref() else {
            return; // Already shut down.
        };

        match self.policy {
            OverflowPolicy::Block => {
                // A closed channel means the writer thread is gone; there is
                // nowhere to put the event and nothing useful to do about it.
                let _ = sender.send(message);
            }
            // The `Ok` and `Disconnected` arms are deliberately separate
            // despite both doing nothing: one is the success path, the other is
            // a dead writer with nowhere to put the event. Merging them would
            // hide that distinction from the next reader.
            #[allow(clippy::match_same_arms)]
            OverflowPolicy::DropAndReport => match sender.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    self.errors.on_error(&WriteError {
                        backend: "AsyncBackend",
                        source: std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "audit queue full",
                        ),
                        events_lost: 1,
                    });
                }
                Err(TrySendError::Disconnected(_)) => {}
            },
        }
    }

    /// Block until everything queued so far has been written.
    ///
    /// The flush marker is always sent with a blocking `send`, never through
    /// the overflow policy. Under `DropAndReport` a full queue would otherwise
    /// discard the marker itself, leaving nothing to acknowledge and making
    /// `flush` return while events were still queued.
    fn drain(&self) {
        let (ack, done) = std::sync::mpsc::sync_channel(1);
        {
            let guard = self
                .sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(sender) = guard.as_ref() else {
                return; // Already shut down; nothing is queued.
            };
            if sender.send(Message::Flush(ack)).is_err() {
                return; // The writer is gone; there is nothing to wait for.
            }
        }
        // A failed receive means the writer exited after accepting the marker.
        let _ = done.recv();
    }

    /// Stop the writer thread, draining first.
    fn shutdown(&self) {
        self.drain();
        // Dropping the sender closes the channel, which ends the writer loop.
        {
            let mut guard = self
                .sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = None;
        }
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            drop(handle.join());
        }
    }
}

impl AuditBackend for AsyncBackend {
    fn log_audit(&self, event: &AuditEvent) {
        self.send(Message::Audit(Box::new(event.clone())));
    }

    fn security_log(&self, event: &serde_json::Value) {
        self.send(Message::Security(Box::new(event.clone())));
    }

    fn flush(&self) {
        self.drain();
    }
}

impl Drop for AsyncBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for AsyncBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncBackend")
            .field("policy", &self.policy)
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}

/// The writer thread's loop.
fn run_writer(inner: &Arc<dyn AuditBackend>, receiver: &Receiver<Message>) {
    for message in receiver {
        match message {
            Message::Audit(event) => inner.log_audit(&event),
            Message::Security(event) => inner.security_log(&event),
            Message::Flush(ack) => {
                inner.flush();
                // A dropped receiver means the waiter gave up; carry on.
                let _ = ack.send(());
            }
        }
    }
    inner.flush();
}

/// Builder for [`AsyncBackend`].
pub struct AsyncBackendBuilder {
    inner: Arc<dyn AuditBackend>,
    capacity: usize,
    policy: OverflowPolicy,
    errors: Arc<dyn ErrorSink>,
}

impl AsyncBackendBuilder {
    /// Queue capacity in events. Defaults to 1024.
    ///
    /// A capacity of 0 is treated as 1: a zero-capacity channel would make
    /// every send wait for the writer, which defeats the purpose.
    #[must_use]
    pub const fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// What a full queue means. Defaults to [`OverflowPolicy::Block`].
    #[must_use]
    pub const fn overflow(mut self, policy: OverflowPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Where to report dropped events. Defaults to discarding the reports.
    #[must_use]
    pub fn errors(mut self, errors: Arc<dyn ErrorSink>) -> Self {
        self.errors = errors;
        self
    }

    /// Start the writer thread.
    ///
    /// # Panics
    ///
    /// Panics if the writer thread cannot be spawned. A logger that silently
    /// failed to start its writer would accept events and discard every one,
    /// which is worse than failing at construction.
    #[must_use]
    pub fn build(self) -> AsyncBackend {
        let (sender, receiver) = std::sync::mpsc::sync_channel(self.capacity.max(1));
        let inner = self.inner;
        let worker = std::thread::Builder::new()
            .name("ash-log-writer".to_string())
            .spawn(move || run_writer(&inner, &receiver))
            .expect("spawn the audit writer thread");

        AsyncBackend {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            policy: self.policy,
            dropped: Arc::new(AtomicU64::new(0)),
            errors: self.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult, CountingErrorSink};
    use std::sync::PoisonError;
    use std::time::Duration;

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);

    impl Collector {
        fn count(&self) -> usize {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
        }
    }

    impl AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    /// A backend that takes its time, standing in for a slow disk.
    struct SlowBackend {
        inner: Arc<Collector>,
        delay: Duration,
    }

    impl AuditBackend for SlowBackend {
        fn log_audit(&self, event: &AuditEvent) {
            std::thread::sleep(self.delay);
            self.inner.log_audit(event);
        }
    }

    fn event() -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .build()
    }

    #[test]
    fn test_events_reach_the_inner_backend() {
        let collector = Arc::new(Collector::default());
        let backend = AsyncBackend::new(collector.clone());

        for _ in 0..50 {
            backend.log_audit(&event());
        }
        backend.flush();

        assert_eq!(collector.count(), 50);
    }

    #[test]
    fn test_flush_waits_for_the_queue_to_drain() {
        let collector = Arc::new(Collector::default());
        let slow = Arc::new(SlowBackend {
            inner: collector.clone(),
            delay: Duration::from_millis(2),
        });
        let backend = AsyncBackend::new(slow);

        for _ in 0..10 {
            backend.log_audit(&event());
        }
        backend.flush();

        assert_eq!(
            collector.count(),
            10,
            "flush returns only once every queued event is written"
        );
    }

    #[test]
    fn test_dropping_the_backend_drains_the_queue() {
        let collector = Arc::new(Collector::default());
        {
            let backend = AsyncBackend::new(collector.clone());
            for _ in 0..20 {
                backend.log_audit(&event());
            }
        }
        assert_eq!(
            collector.count(),
            20,
            "shutdown flushes rather than discards"
        );
    }

    #[test]
    fn test_blocking_policy_loses_nothing_under_overload() {
        // A queue far smaller than the burst: with Block, every event still
        // arrives, because producers wait rather than discard.
        let collector = Arc::new(Collector::default());
        let slow = Arc::new(SlowBackend {
            inner: collector.clone(),
            delay: Duration::from_micros(200),
        });
        let backend = AsyncBackend::builder(slow)
            .capacity(4)
            .overflow(OverflowPolicy::Block)
            .build();

        for _ in 0..100 {
            backend.log_audit(&event());
        }
        backend.flush();

        assert_eq!(collector.count(), 100);
        assert_eq!(backend.dropped(), 0, "Block never drops");
    }

    #[test]
    fn test_drop_policy_reports_what_it_discards() {
        let collector = Arc::new(Collector::default());
        let slow = Arc::new(SlowBackend {
            inner: collector.clone(),
            delay: Duration::from_millis(5),
        });
        let sink = Arc::new(CountingErrorSink::new());
        let backend = AsyncBackend::builder(slow)
            .capacity(2)
            .overflow(OverflowPolicy::DropAndReport)
            .errors(sink.clone())
            .build();

        for _ in 0..200 {
            backend.log_audit(&event());
        }
        backend.flush();

        assert!(
            backend.dropped() > 0,
            "a tiny queue under a burst overflows"
        );
        assert_eq!(
            sink.events_lost(),
            backend.dropped(),
            "every dropped event is reported, so the gap is knowable"
        );
        assert_eq!(
            collector.count() as u64 + backend.dropped(),
            200,
            "written plus dropped accounts for everything submitted"
        );
    }

    #[test]
    fn test_producers_are_not_blocked_by_a_slow_writer() {
        // The point of the whole type: enqueueing must be much faster than the
        // underlying write.
        let collector = Arc::new(Collector::default());
        let slow = Arc::new(SlowBackend {
            inner: collector.clone(),
            delay: Duration::from_millis(10),
        });
        let backend = AsyncBackend::builder(slow).capacity(64).build();

        let start = std::time::Instant::now();
        for _ in 0..20 {
            backend.log_audit(&event());
        }
        let enqueue = start.elapsed();

        assert!(
            enqueue < Duration::from_millis(100),
            "20 enqueues took {enqueue:?}, but 20 synchronous writes would take 200ms"
        );
        backend.flush();
        assert_eq!(collector.count(), 20);
    }

    #[test]
    fn test_concurrent_producers_all_arrive() {
        let collector = Arc::new(Collector::default());
        let backend = Arc::new(AsyncBackend::new(collector.clone()));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let backend = backend.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    backend.log_audit(&event());
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker panicked");
        }
        backend.flush();

        assert_eq!(collector.count(), 400);
    }
}
