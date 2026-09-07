//! Reporting writes that did not happen.
//!
//! # Why this exists
//!
//! Tamper evidence proves that nothing in the log was altered. It says nothing
//! about what never reached the log at all: a full disk, a broken pipe, or a
//! revoked file handle ends the audit trail silently, and the surviving entries
//! still verify perfectly. An attacker who can fill a disk can therefore stop
//! the record without leaving a mark in it.
//!
//! [`AuditBackend::log_audit`](crate::AuditBackend::log_audit) returns `()` and
//! cannot be changed to return a `Result` without breaking every implementation
//! downstream. Instead a backend reports failures to an [`ErrorSink`], which the
//! application installs where it can act on them — a metric, an alert, or a
//! panic if the deployment would rather stop than log unwitnessed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A write that did not reach its destination.
#[derive(Debug)]
pub struct WriteError {
    /// Which backend failed, for attributing the fault in a fan-out.
    pub backend: &'static str,
    /// What went wrong.
    pub source: std::io::Error,
    /// Events lost to this failure. Usually 1, but a buffered backend can lose
    /// a whole batch at once.
    pub events_lost: u64,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: audit write failed, {} event(s) lost: {}",
            self.backend, self.events_lost, self.source
        )
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Receives write failures reported by a backend.
///
/// Implementations must not panic on the write path unless stopping the process
/// is the intended response, and must not themselves log through the failing
/// backend.
pub trait ErrorSink: Send + Sync {
    /// Report one failed write.
    fn on_error(&self, error: &WriteError);
}

/// Discards failures. The default, preserving the behaviour of backends that
/// predate this trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct IgnoreErrors;

impl ErrorSink for IgnoreErrors {
    fn on_error(&self, _error: &WriteError) {}
}

/// Writes failures to stderr.
///
/// The obvious default for a service that already collects stderr. Uses stderr
/// specifically so a failing stdout backend cannot swallow the report of its own
/// failure.
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrErrorSink;

impl ErrorSink for StderrErrorSink {
    fn on_error(&self, error: &WriteError) {
        // Deliberately `eprintln!` rather than a logger: reporting a logging
        // failure through the logger risks recursing into the same fault.
        eprintln!("ash-log: {error}");
    }
}

/// Counts failures and lost events without storing them.
///
/// Suitable for exporting as a metric. A non-zero
/// [`events_lost`](Self::events_lost) means the audit record is incomplete,
/// which no amount of chain verification will reveal.
#[derive(Debug, Default)]
pub struct CountingErrorSink {
    failures: AtomicU64,
    events_lost: AtomicU64,
}

impl CountingErrorSink {
    /// A sink with both counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of failed writes reported.
    #[must_use]
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Total events lost across all failures.
    #[must_use]
    pub fn events_lost(&self) -> u64 {
        self.events_lost.load(Ordering::Relaxed)
    }

    /// Whether any write has failed.
    ///
    /// Check this alongside chain verification: a verified chain that lost
    /// events is a complete record of an incomplete history.
    #[must_use]
    pub fn had_failures(&self) -> bool {
        self.failures() > 0
    }
}

impl ErrorSink for CountingErrorSink {
    fn on_error(&self, error: &WriteError) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.events_lost
            .fetch_add(error.events_lost, Ordering::Relaxed);
    }
}

/// Calls a closure for each failure.
///
/// ```rust
/// use ash_log::*;
/// use std::sync::{Arc, Mutex};
///
/// let seen = Arc::new(Mutex::new(Vec::new()));
/// let captured = seen.clone();
/// let sink = FnErrorSink::new(move |error| {
///     captured.lock().unwrap().push(error.to_string());
/// });
/// # let _ = sink;
/// ```
pub struct FnErrorSink<F: Fn(&WriteError) + Send + Sync>(F);

impl<F: Fn(&WriteError) + Send + Sync> FnErrorSink<F> {
    /// Wrap `f` as an error sink.
    pub const fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F: Fn(&WriteError) + Send + Sync> ErrorSink for FnErrorSink<F> {
    fn on_error(&self, error: &WriteError) {
        (self.0)(error);
    }
}

impl<T: ErrorSink + ?Sized> ErrorSink for Arc<T> {
    fn on_error(&self, error: &WriteError) {
        (**self).on_error(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(events_lost: u64) -> WriteError {
        WriteError {
            backend: "TestBackend",
            source: std::io::Error::other("disk full"),
            events_lost,
        }
    }

    #[test]
    fn test_counting_sink_accumulates_losses() {
        let sink = CountingErrorSink::new();
        assert!(!sink.had_failures());

        sink.on_error(&error(1));
        sink.on_error(&error(64));

        assert_eq!(sink.failures(), 2);
        assert_eq!(sink.events_lost(), 65, "a batch loss counts every event");
        assert!(sink.had_failures());
    }

    #[test]
    fn test_error_displays_backend_and_loss() {
        let rendered = error(3).to_string();
        assert!(
            rendered.contains("TestBackend"),
            "names the failing backend"
        );
        assert!(rendered.contains('3'), "states how many events were lost");
        assert!(rendered.contains("disk full"), "includes the cause");
    }

    #[test]
    fn test_fn_sink_receives_errors() {
        let count = Arc::new(AtomicU64::new(0));
        let seen = count.clone();
        let sink = FnErrorSink::new(move |_| {
            seen.fetch_add(1, Ordering::Relaxed);
        });

        sink.on_error(&error(1));
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
