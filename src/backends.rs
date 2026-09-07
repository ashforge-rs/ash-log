//! Pluggable audit logging backends for writing events to various destinations.

use super::AuditEvent;
use std::io::Write;

/// Audit log backend trait. Synchronous writes ensure events persist before execution continues.
pub trait AuditBackend: Send + Sync {
    /// Write an audit event
    fn log_audit(&self, event: &AuditEvent);

    /// Write a raw OCSF (or other JSON) security event as a JSON line.
    ///
    /// The default implementation is a no-op.  Override this in backends that
    /// should persist OCSF events.  All built-in backends (`StdoutAuditBackend`,
    /// `StderrAuditBackend`, `MultiAuditBackend`) provide a real implementation.
    fn security_log(&self, event: &serde_json::Value) {
        let _ = event;
    }

    /// Flush buffered entries
    fn flush(&self) {
        // Default: no-op
    }
}

/// Writes audit events to stdout as JSON lines
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutAuditBackend;

impl AuditBackend for StdoutAuditBackend {
    fn log_audit(&self, event: &AuditEvent) {
        match serde_json::to_string(event) {
            Ok(json) => {
                println!("{json}");
            }
            Err(e) => {
                eprintln!("[AUDIT ERROR] Failed to serialize audit event: {e}");
            }
        }
    }

    fn security_log(&self, event: &serde_json::Value) {
        match serde_json::to_string(event) {
            Ok(json) => {
                println!("{json}");
            }
            Err(e) => {
                eprintln!("[AUDIT ERROR] Failed to serialize OCSF event: {e}");
            }
        }
    }

    fn flush(&self) {
        drop(std::io::stdout().flush());
    }
}

/// Writes audit events to stderr as JSON lines
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrAuditBackend;

impl AuditBackend for StderrAuditBackend {
    fn log_audit(&self, event: &AuditEvent) {
        match serde_json::to_string(event) {
            Ok(json) => {
                eprintln!("{json}");
            }
            Err(e) => {
                eprintln!("[AUDIT ERROR] Failed to serialize audit event: {e}");
            }
        }
    }

    fn security_log(&self, event: &serde_json::Value) {
        match serde_json::to_string(event) {
            Ok(json) => {
                eprintln!("{json}");
            }
            Err(e) => {
                eprintln!("[AUDIT ERROR] Failed to serialize OCSF event: {e}");
            }
        }
    }

    fn flush(&self) {
        drop(std::io::stderr().flush());
    }
}

/// Discards all audit events (testing only)
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAuditBackend;

impl AuditBackend for NoopAuditBackend {
    fn log_audit(&self, _event: &AuditEvent) {
        // Intentionally discard
    }
}

/// Writes audit events to multiple backends simultaneously
pub struct MultiAuditBackend {
    backends: Vec<Box<dyn AuditBackend>>,
}

impl MultiAuditBackend {
    /// Create a new multi-backend logger
    #[must_use]
    pub fn new(backends: Vec<Box<dyn AuditBackend>>) -> Self {
        Self { backends }
    }

    /// Create a new multi-backend logger from Arc-wrapped backends
    #[must_use]
    pub fn from_arcs(backends: Vec<std::sync::Arc<dyn AuditBackend>>) -> Self {
        Self {
            backends: backends
                .into_iter()
                .map(|b| -> Box<dyn AuditBackend> { Box::new(b) })
                .collect(),
        }
    }

    /// Add a backend
    pub fn add_backend(&mut self, backend: Box<dyn AuditBackend>) {
        self.backends.push(backend);
    }
}

impl AuditBackend for MultiAuditBackend {
    fn log_audit(&self, event: &AuditEvent) {
        for backend in &self.backends {
            backend.log_audit(event);
        }
    }

    fn security_log(&self, event: &serde_json::Value) {
        for backend in &self.backends {
            backend.security_log(event);
        }
    }

    fn flush(&self) {
        for backend in &self.backends {
            backend.flush();
        }
    }
}

/// One buffered entry, tagged so it replays through the matching backend method.
enum BufferedEntry {
    Audit(Box<AuditEvent>),
    Security(Box<serde_json::Value>),
}

/// Buffers events in memory, writing them to an inner backend only when the
/// buffer fills or [`flush`](AuditBackend::flush) is called.
///
/// This trades the crate's default durability guarantee for throughput: an
/// event still buffered when the process dies abruptly is lost. Use it only
/// where that is acceptable — high-volume telemetry, not the compliance trail.
/// For the default synchronous behaviour, use the inner backend directly.
///
/// Audit and security events share one queue and drain in FIFO order, so
/// sequence numbers and checksums applied by an
/// [`AuditIntegrity`](crate::AuditIntegrity) reach the inner backend in
/// the order they were generated.
///
/// # Flush on drop
///
/// The [`Drop`] impl flushes, giving the equivalent of Go's `defer sync()`.
/// Rust runs destructors only on normal scope exit and unwinding, so buffered
/// events are still lost on [`std::process::exit`], a panic under
/// `panic = "abort"`, or SIGKILL. Call `flush()` explicitly at shutdown paths
/// that bypass unwinding.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
///
/// let backend = BufferedAuditBackend::new(StdoutAuditBackend, 128);
///
/// let event = AuditEvent::builder()
///     .event_type(AuditEventType::MethodInvocation)
///     .result(AuditResult::Success)
///     .build();
///
/// backend.log_audit(&event);      // buffered, not yet written
/// assert_eq!(backend.buffered(), 1);
///
/// backend.flush();                // now written to stdout
/// assert_eq!(backend.buffered(), 0);
/// ```
pub struct BufferedAuditBackend<B: AuditBackend> {
    inner: B,
    buffer: std::sync::Mutex<Vec<BufferedEntry>>,
    capacity: usize,
}

impl<B: AuditBackend> BufferedAuditBackend<B> {
    /// Create a buffered backend that flushes to `inner` once `capacity`
    /// events have accumulated.
    ///
    /// A `capacity` of 0 is treated as 1, making every write pass straight
    /// through to the inner backend.
    #[must_use]
    pub fn new(inner: B, capacity: usize) -> Self {
        Self {
            inner,
            buffer: std::sync::Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of events currently buffered and not yet written.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.lock().len()
    }

    /// Flush any pending events and return the inner backend.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.drain_to_inner();
        // Take `inner` out by value. `Self` implements `Drop`, so it cannot be
        // destructured; replacing the buffer is unnecessary since the drained
        // `Vec` is empty and dropping it is a no-op.
        let mut this = std::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never read or dropped again, so moving `inner` out
        // cannot cause a double free or a read of moved-from memory.
        let inner = unsafe { std::ptr::read(&raw const this.inner) };
        // `ManuallyDrop` suppresses every field's destructor, not just
        // `inner`'s, so drop the buffer explicitly rather than leaking its
        // allocation. It was drained above, so no events are discarded.
        // SAFETY: `this.buffer` is valid and initialised here, and is never
        // accessed again afterwards.
        unsafe { std::ptr::drop_in_place(&raw mut this.buffer) };
        inner
    }

    /// Lock the buffer, recovering the contents if another thread panicked
    /// while holding the lock. A poisoned buffer still holds valid events, and
    /// discarding audit records because an unrelated thread panicked would be a
    /// worse failure than continuing.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<BufferedEntry>> {
        self.buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drain buffered events into the inner backend and flush it.
    ///
    /// The lock is released before writing so a slow inner backend does not
    /// block concurrent producers.
    fn drain_to_inner(&self) {
        let drained = {
            let mut buffer = self.lock();
            if buffer.is_empty() {
                return;
            }
            std::mem::take(&mut *buffer)
        };

        for entry in drained {
            match entry {
                BufferedEntry::Audit(event) => self.inner.log_audit(&event),
                BufferedEntry::Security(event) => self.inner.security_log(&event),
            }
        }
        self.inner.flush();
    }

    /// Buffer one entry, draining first if it fills the buffer.
    fn push(&self, entry: BufferedEntry) {
        let full = {
            let mut buffer = self.lock();
            buffer.push(entry);
            buffer.len() >= self.capacity
        };

        if full {
            self.drain_to_inner();
        }
    }
}

impl<B: AuditBackend> AuditBackend for BufferedAuditBackend<B> {
    fn log_audit(&self, event: &AuditEvent) {
        self.push(BufferedEntry::Audit(Box::new(event.clone())));
    }

    fn security_log(&self, event: &serde_json::Value) {
        self.push(BufferedEntry::Security(Box::new(event.clone())));
    }

    fn flush(&self) {
        self.drain_to_inner();
    }
}

impl<B: AuditBackend> Drop for BufferedAuditBackend<B> {
    fn drop(&mut self) {
        self.drain_to_inner();
    }
}

/// A shared backend is itself a backend, so an `Arc<dyn AuditBackend>` composes
/// wherever a concrete one does — most usefully as the inner backend of a
/// [`BufferedAuditBackend`], which requires a sized type.
///
/// `?Sized` covers the erased `Arc<dyn AuditBackend>` as well as `Arc<T>` for a
/// concrete `T`.
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let shared: Arc<dyn AuditBackend> = Arc::new(StdoutAuditBackend);
/// let buffered = BufferedAuditBackend::new(shared.clone(), 128);
/// ```
impl<T: AuditBackend + ?Sized> AuditBackend for std::sync::Arc<T> {
    fn log_audit(&self, event: &AuditEvent) {
        (**self).log_audit(event);
    }

    fn security_log(&self, event: &serde_json::Value) {
        (**self).security_log(event);
    }

    fn flush(&self) {
        (**self).flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult};

    #[test]
    fn test_noop_backend() {
        let backend = NoopAuditBackend;
        let event = AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .build();

        backend.log_audit(&event); // Should not panic
        backend.flush(); // Should not panic
    }

    #[test]
    fn test_multi_backend() {
        let multi =
            MultiAuditBackend::new(vec![Box::new(NoopAuditBackend), Box::new(NoopAuditBackend)]);

        let event = AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .result(AuditResult::Success)
            .build();

        multi.log_audit(&event);
        multi.flush();
    }

    /// Counts writes so tests can observe when the buffer actually drains.
    #[derive(Default)]
    struct CountingBackend {
        audits: std::sync::atomic::AtomicUsize,
        securities: std::sync::atomic::AtomicUsize,
        flushes: std::sync::atomic::AtomicUsize,
    }

    impl CountingBackend {
        fn audits(&self) -> usize {
            self.audits.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl AuditBackend for CountingBackend {
        fn log_audit(&self, _event: &AuditEvent) {
            self.audits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        fn security_log(&self, _event: &serde_json::Value) {
            self.securities
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        fn flush(&self) {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn test_event() -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .build()
    }

    #[test]
    fn test_buffered_backend_defers_writes_until_flush() {
        let inner = std::sync::Arc::new(CountingBackend::default());
        let buffered = BufferedAuditBackend::new(inner.clone(), 10);

        buffered.log_audit(&test_event());
        buffered.log_audit(&test_event());

        assert_eq!(buffered.buffered(), 2);
        assert_eq!(inner.audits(), 0, "nothing written before flush");

        buffered.flush();

        assert_eq!(buffered.buffered(), 0);
        assert_eq!(inner.audits(), 2, "flush wrote both events");
    }

    #[test]
    fn test_buffered_backend_flushes_when_capacity_reached() {
        let buffered = BufferedAuditBackend::new(CountingBackend::default(), 3);

        buffered.log_audit(&test_event());
        buffered.log_audit(&test_event());
        assert_eq!(buffered.buffered(), 2, "below capacity");

        buffered.log_audit(&test_event());
        assert_eq!(buffered.buffered(), 0, "drained at capacity");
        assert_eq!(buffered.into_inner().audits(), 3);
    }

    #[test]
    fn test_buffered_backend_zero_capacity_writes_through() {
        let buffered = BufferedAuditBackend::new(CountingBackend::default(), 0);

        buffered.log_audit(&test_event());
        assert_eq!(buffered.buffered(), 0);
        assert_eq!(buffered.into_inner().audits(), 1);
    }

    #[test]
    fn test_buffered_backend_flushes_on_drop() {
        let inner = std::sync::Arc::new(CountingBackend::default());

        {
            let buffered = BufferedAuditBackend::new(inner.clone(), 100);
            buffered.log_audit(&test_event());
            buffered.log_audit(&test_event());
            assert_eq!(inner.audits(), 0, "still buffered while in scope");
        }

        assert_eq!(inner.audits(), 2, "drop flushed the buffer");
    }

    #[test]
    fn test_buffered_backend_preserves_order_across_event_kinds() {
        /// Records the interleaving of audit and security writes.
        #[derive(Default)]
        struct OrderBackend(std::sync::Mutex<Vec<&'static str>>);

        impl AuditBackend for OrderBackend {
            fn log_audit(&self, _event: &AuditEvent) {
                self.0.lock().unwrap().push("audit");
            }

            fn security_log(&self, _event: &serde_json::Value) {
                self.0.lock().unwrap().push("security");
            }
        }

        let buffered = BufferedAuditBackend::new(OrderBackend::default(), 100);

        buffered.log_audit(&test_event());
        buffered.security_log(&serde_json::json!({"class_uid": 3002}));
        buffered.log_audit(&test_event());

        let inner = buffered.into_inner();
        let order = inner.0.lock().unwrap().clone();
        assert_eq!(order, vec!["audit", "security", "audit"]);
    }

    #[test]
    fn test_buffered_backend_survives_poisoned_lock() {
        let buffered =
            std::sync::Arc::new(BufferedAuditBackend::new(CountingBackend::default(), 100));

        let poisoner = std::sync::Arc::clone(&buffered);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.buffer.lock().unwrap();
            panic!("poison the buffer lock");
        });
        assert!(handle.join().is_err(), "helper thread should have panicked");

        // The lock is poisoned, but buffered events must still be recoverable.
        buffered.log_audit(&test_event());
        buffered.flush();
        assert_eq!(buffered.buffered(), 0);
    }
}
