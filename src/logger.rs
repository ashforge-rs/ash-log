//! A logger that owns a backend, an integrity mechanism, and an admission
//! policy, so events are filtered before they are stamped.
//!
//! # Why this type exists
//!
//! [`AuditIntegrity::add_integrity`] advances the chain every time it is
//! called. Dropping an event *after* stamping therefore leaves a gap, and the
//! resulting log fails verification even though nobody tampered with it. The
//! only safe order is to decide admission first and stamp second.
//!
//! [`Logger`] makes that order structural rather than a convention: filtering
//! happens inside [`Logger::log`], before the integrity mechanism is consulted,
//! so a caller cannot get it wrong.

use super::{
    AuditBackend, AuditEvent, AuditIntegrity, AuditSeverity, LiveFilter, NoRedaction, Provenance,
    Redactor, Scope,
};
#[cfg(feature = "hlc")]
use super::{EventClock, HlcClock, HlcTimestamp};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// Encodes an [`AuditSeverity`] as a `u8` for atomic storage, preserving order.
fn level_to_u8(level: AuditSeverity) -> u8 {
    match level {
        AuditSeverity::Trace => 0,
        AuditSeverity::Debug => 1,
        AuditSeverity::Info => 2,
        AuditSeverity::Warning => 3,
        AuditSeverity::Error => 4,
        AuditSeverity::Critical => 5,
    }
}

/// Inverse of [`level_to_u8`]. Out-of-range values clamp to the most
/// restrictive level, so a corrupted store can never widen what is admitted.
fn u8_to_level(raw: u8) -> AuditSeverity {
    match raw {
        0 => AuditSeverity::Trace,
        1 => AuditSeverity::Debug,
        2 => AuditSeverity::Info,
        3 => AuditSeverity::Warning,
        4 => AuditSeverity::Error,
        _ => AuditSeverity::Critical,
    }
}

/// Writes audit events, applying a two-tier admission policy before any
/// integrity metadata is attached.
///
/// # Admission policy
///
/// - **Security events** — every [`AuditEventType`](crate::AuditEventType)
///   except [`Diagnostic`](crate::AuditEventType::Diagnostic) — are always
///   written, whatever the level threshold is. An operational setting must not
///   be able to shrink the compliance record.
/// - **Diagnostic events** are written only when their severity is at least the
///   configured minimum level.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = Logger::builder(Arc::new(StdoutAuditBackend))
///     .integrity(Arc::new(SequenceIntegrity::new()))
///     .min_level(AuditSeverity::Warning)
///     .build();
///
/// // Dropped: diagnostic below the threshold.
/// logger.log(AuditEvent::diagnostic("cache warm").severity(AuditSeverity::Debug).build());
///
/// // Written: security events ignore the threshold entirely.
/// logger.log(
///     AuditEvent::builder()
///         .event_type(AuditEventType::AuthenticationAttempt)
///         .principal("alice@example.com")
///         .result(AuditResult::Success)
///         .severity(AuditSeverity::Info)
///         .build(),
/// );
/// ```
pub struct Logger {
    backend: Arc<dyn AuditBackend>,
    integrity: Arc<dyn AuditIntegrity>,
    min_level: AtomicU8,
    identity: Provenance,
    redactor: Arc<dyn Redactor>,
    filter: Option<LiveFilter>,
    #[cfg(feature = "hlc")]
    clock: Option<Arc<HlcClock>>,
}

impl Logger {
    /// Start building a logger writing to `backend`.
    #[must_use]
    pub fn builder(backend: Arc<dyn AuditBackend>) -> LoggerBuilder {
        LoggerBuilder {
            backend,
            integrity: None,
            min_level: AuditSeverity::Info,
            identity: Provenance::new(),
            redactor: None,
            filter: None,
            #[cfg(feature = "hlc")]
            clock: None,
        }
    }

    /// The current minimum level for diagnostic events.
    #[must_use]
    pub fn min_level(&self) -> AuditSeverity {
        u8_to_level(self.min_level.load(Ordering::Relaxed))
    }

    /// Change the minimum level for diagnostic events at runtime.
    ///
    /// Security events are unaffected: they are admitted at any threshold.
    pub fn set_min_level(&self, level: AuditSeverity) {
        self.min_level.store(level_to_u8(level), Ordering::Relaxed);
    }

    /// Whether `event` would be written at the current threshold.
    ///
    /// Useful to skip building an expensive event that would be dropped. The
    /// answer can change between this call and [`log`](Self::log) if another
    /// thread adjusts the level; that only affects diagnostics.
    #[must_use]
    pub fn admits(&self, event: &AuditEvent) -> bool {
        if event.event_type.is_security_relevant() {
            return true;
        }
        event.severity >= self.threshold_for(event)
    }

    /// The threshold applying to `event`.
    ///
    /// A per-module directive wins where one matches; otherwise the logger's
    /// own level decides. A filter can therefore both loosen and tighten the
    /// base threshold for a specific module, which is the point of having one.
    fn threshold_for(&self, event: &AuditEvent) -> AuditSeverity {
        let Some(filter) = &self.filter else {
            return self.min_level();
        };
        let Some(module) = event.provenance.module.as_deref() else {
            return self.min_level();
        };
        if filter.is_empty() {
            return self.min_level();
        }
        filter.level_for(module)
    }

    /// The filter applied to diagnostics, if one is configured.
    #[must_use]
    pub fn filter(&self) -> Option<&LiveFilter> {
        self.filter.as_ref()
    }

    /// Whether a diagnostic at `severity` from `module` would be recorded.
    ///
    /// The diagnostic macros call this before formatting their arguments, so a
    /// dropped record costs a threshold lookup rather than an allocation. It
    /// consults the per-module filter, which the logger's base level alone
    /// cannot do — without it a directive could only ever tighten the base
    /// threshold, never loosen it for one module.
    ///
    /// Security events are not routed through here: they are admitted
    /// unconditionally.
    #[must_use]
    pub fn admits_diagnostic(&self, severity: AuditSeverity, module: &str) -> bool {
        let threshold = match &self.filter {
            Some(filter) if !filter.is_empty() => filter.level_for(module),
            _ => self.min_level(),
        };
        severity >= threshold
    }

    /// Stamp `event` with the configured clock, if there is one.
    ///
    /// A clock error never costs an event: the record is written without an
    /// `hlc` field rather than dropped. Losing the causal ordering of one entry
    /// is a far smaller failure than losing the entry.
    #[cfg(feature = "hlc")]
    fn stamp_hlc(&self, event: &mut AuditEvent) {
        if event.hlc.is_some() {
            return; // An explicit timestamp on the event wins.
        }
        if let Some(clock) = &self.clock
            && let Ok(timestamp) = clock.now()
        {
            event.hlc = Some(EventClock::from(timestamp));
        }
    }

    /// Advance this logger's clock past a timestamp observed from elsewhere.
    ///
    /// Call this when a request arrives carrying an upstream timestamp. Every
    /// event this logger records afterwards is then ordered strictly after the
    /// upstream event, without the two hosts' wall clocks having to agree.
    ///
    /// Returns the resulting timestamp, or the clock error. An error means the
    /// observation was rejected — most often because the peer's timestamp is
    /// implausibly far ahead — and this logger's ordering is unaffected.
    ///
    /// Does nothing and returns `Ok` with the current time if no clock is
    /// configured.
    ///
    /// # Errors
    ///
    /// Returns [`HlcError`](crate::HlcError) if the system clock is before the
    /// Unix epoch, the observed timestamp exceeds the clock's maximum drift, or
    /// the logical counter would overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ash_log::*;
    /// use std::sync::Arc;
    ///
    /// let clock = Arc::new(HlcClock::new());
    /// let logger = Logger::builder(Arc::new(NoopAuditBackend))
    ///     .clock(clock.clone())
    ///     .build();
    ///
    /// // A timestamp that arrived on an inbound request.
    /// let upstream = HlcClock::new().now().unwrap();
    /// logger.observe_hlc(upstream).unwrap();
    ///
    /// // Events recorded from here on are ordered after `upstream`.
    /// assert!(upstream < logger.hlc_now().unwrap());
    /// ```
    #[cfg(feature = "hlc")]
    pub fn observe_hlc(&self, observed: HlcTimestamp) -> Result<HlcTimestamp, crate::HlcError> {
        match &self.clock {
            Some(clock) => clock.recv(observed),
            None => Ok(observed),
        }
    }

    /// The current timestamp from this logger's clock, for stamping an outgoing
    /// request so a downstream service can order its events after this one.
    ///
    /// Returns `None` when no clock is configured or the clock errored.
    #[cfg(feature = "hlc")]
    #[must_use]
    pub fn hlc_now(&self) -> Option<HlcTimestamp> {
        self.clock.as_ref().and_then(|clock| clock.now().ok())
    }

    /// Apply the admission policy, then stamp and write the event.
    ///
    /// Filtering happens *before* [`AuditIntegrity::add_integrity`], so a
    /// dropped event never consumes a chain position and the resulting log
    /// verifies.
    pub fn log(&self, event: AuditEvent) {
        if !self.admits(&event) {
            return;
        }

        let mut event = event;
        if !self.identity.is_empty() {
            event.provenance = std::mem::take(&mut event.provenance).or_fill_from(&self.identity);
        }
        // Scope fields fill in before redaction, so anything a scope supplies
        // is scrubbed on the same terms as a call site's own metadata.
        Scope::apply_current(&mut event);
        #[cfg(feature = "hlc")]
        self.stamp_hlc(&mut event);
        // Before `add_integrity`: a secret scrubbed afterwards would leave a
        // MAC over the unredacted value, so the log would leak *and* fail to
        // verify.
        self.redactor.redact_event(&mut event);
        self.integrity.add_integrity(&mut event);
        self.backend.log_audit(&event);
    }

    /// Write a diagnostic record at `level`, subject to the level filter.
    #[track_caller]
    pub fn diagnostic<S: Into<String>>(&self, level: AuditSeverity, message: S) {
        self.log(
            AuditEvent::diagnostic(message)
                .severity(level)
                .provenance(Provenance::capture())
                .build(),
        );
    }

    /// Write a [`Trace`](AuditSeverity::Trace) diagnostic.
    #[track_caller]
    pub fn trace<S: Into<String>>(&self, message: S) {
        self.diagnostic(AuditSeverity::Trace, message);
    }

    /// Write a [`Debug`](AuditSeverity::Debug) diagnostic.
    #[track_caller]
    pub fn debug<S: Into<String>>(&self, message: S) {
        self.diagnostic(AuditSeverity::Debug, message);
    }

    /// Write an [`Info`](AuditSeverity::Info) diagnostic.
    #[track_caller]
    pub fn info<S: Into<String>>(&self, message: S) {
        self.diagnostic(AuditSeverity::Info, message);
    }

    /// Write a [`Warning`](AuditSeverity::Warning) diagnostic.
    #[track_caller]
    pub fn warn<S: Into<String>>(&self, message: S) {
        self.diagnostic(AuditSeverity::Warning, message);
    }

    /// Write an [`Error`](AuditSeverity::Error) diagnostic.
    #[track_caller]
    pub fn error<S: Into<String>>(&self, message: S) {
        self.diagnostic(AuditSeverity::Error, message);
    }

    /// Flush the underlying backend.
    pub fn flush(&self) {
        self.backend.flush();
    }

    /// The service identity stamped on every event this logger writes.
    #[must_use]
    pub fn identity(&self) -> &Provenance {
        &self.identity
    }

    /// The backend this logger writes to.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn AuditBackend> {
        &self.backend
    }

    /// The integrity mechanism applied to admitted events.
    #[must_use]
    pub fn integrity(&self) -> &Arc<dyn AuditIntegrity> {
        &self.integrity
    }
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger")
            .field("min_level", &self.min_level())
            .finish_non_exhaustive()
    }
}

/// Builder for [`Logger`].
pub struct LoggerBuilder {
    backend: Arc<dyn AuditBackend>,
    integrity: Option<Arc<dyn AuditIntegrity>>,
    min_level: AuditSeverity,
    identity: Provenance,
    redactor: Option<Arc<dyn Redactor>>,
    filter: Option<LiveFilter>,
    #[cfg(feature = "hlc")]
    clock: Option<Arc<HlcClock>>,
}

impl LoggerBuilder {
    /// Set the integrity mechanism. Defaults to
    /// [`NoIntegrity`](crate::NoIntegrity).
    #[must_use]
    pub fn integrity(mut self, integrity: Arc<dyn AuditIntegrity>) -> Self {
        self.integrity = Some(integrity);
        self
    }

    /// Set the minimum level for diagnostic events. Defaults to
    /// [`Info`](AuditSeverity::Info).
    #[must_use]
    pub fn min_level(mut self, level: AuditSeverity) -> Self {
        self.min_level = level;
        self
    }

    /// Set the service identity stamped on every event.
    ///
    /// Fields left unset on an individual event are filled from this, so a
    /// service name, version, and host are recorded once rather than at every
    /// call site. Identity is part of the signed event, not `metadata`.
    #[must_use]
    pub fn identity(mut self, identity: Provenance) -> Self {
        self.identity = identity;
        self
    }

    /// Give the logger a Hybrid Logical Clock.
    ///
    /// Every event it writes is then stamped with a monotonic causal
    /// timestamp, inside the signed canonical form. Share one `Arc<HlcClock>`
    /// across the loggers of a single service so their events stay mutually
    /// ordered.
    #[cfg(feature = "hlc")]
    #[must_use]
    pub fn clock(mut self, clock: Arc<HlcClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Set the redactor applied to every event before it is stamped.
    ///
    /// Defaults to [`NoRedaction`], so redaction is opt-in.
    #[must_use]
    pub fn redact(mut self, redactor: Arc<dyn Redactor>) -> Self {
        self.redactor = Some(redactor);
        self
    }

    /// Apply per-module level directives on top of the base threshold.
    ///
    /// The handle can be updated at runtime, retuning this logger without
    /// rebuilding it. Only diagnostics are affected; security events are
    /// admitted whatever any filter says.
    #[must_use]
    pub fn filter(mut self, filter: LiveFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Build the logger.
    #[must_use]
    pub fn build(self) -> Logger {
        Logger {
            backend: self.backend,
            integrity: self
                .integrity
                .unwrap_or_else(|| Arc::new(crate::NoIntegrity)),
            min_level: AtomicU8::new(level_to_u8(self.min_level)),
            identity: self.identity,
            redactor: self.redactor.unwrap_or_else(|| Arc::new(NoRedaction)),
            filter: self.filter,
            #[cfg(feature = "hlc")]
            clock: self.clock,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult, NoopAuditBackend, SequenceIntegrity};
    use std::sync::Mutex;

    /// Captures written events so tests can assert on what survived filtering.
    #[derive(Default)]
    struct CapturingBackend(Mutex<Vec<AuditEvent>>);

    impl CapturingBackend {
        fn events(&self) -> Vec<AuditEvent> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl AuditBackend for CapturingBackend {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event.clone());
        }
    }

    fn security_event(severity: AuditSeverity) -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .result(AuditResult::Success)
            .severity(severity)
            .build()
    }

    fn logger_at(level: AuditSeverity) -> (Logger, Arc<CapturingBackend>) {
        let backend = Arc::new(CapturingBackend::default());
        let logger = Logger::builder(backend.clone())
            .integrity(Arc::new(SequenceIntegrity::new()))
            .min_level(level)
            .build();
        (logger, backend)
    }

    #[test]
    fn test_diagnostics_below_the_threshold_are_dropped() {
        let (logger, backend) = logger_at(AuditSeverity::Warning);

        logger.trace("trace");
        logger.debug("debug");
        logger.info("info");
        logger.warn("warning");
        logger.error("error");

        let written: Vec<AuditSeverity> = backend.events().iter().map(|e| e.severity).collect();
        assert_eq!(
            written,
            vec![AuditSeverity::Warning, AuditSeverity::Error],
            "only diagnostics at or above the threshold are written"
        );
    }

    #[test]
    fn test_security_events_ignore_the_threshold() {
        // The whole point of the two-tier policy: an operational setting must
        // not be able to shrink the compliance record.
        let (logger, backend) = logger_at(AuditSeverity::Critical);

        logger.log(security_event(AuditSeverity::Trace));
        logger.log(security_event(AuditSeverity::Info));
        logger.diagnostic(AuditSeverity::Info, "should be dropped");

        let events = backend.events();
        assert_eq!(events.len(), 2, "both security events survive");
        assert!(
            events.iter().all(|e| e.event_type.is_security_relevant()),
            "only the diagnostic was filtered"
        );
    }

    #[test]
    fn test_admits_matches_what_log_writes() {
        let (logger, backend) = logger_at(AuditSeverity::Warning);

        let low = AuditEvent::diagnostic("low")
            .severity(AuditSeverity::Debug)
            .build();
        let high = AuditEvent::diagnostic("high")
            .severity(AuditSeverity::Error)
            .build();

        assert!(!logger.admits(&low));
        assert!(logger.admits(&high));

        logger.log(low);
        logger.log(high);
        assert_eq!(backend.events().len(), 1, "admits agreed with log");
    }

    #[test]
    fn test_min_level_is_adjustable_at_runtime() {
        let (logger, backend) = logger_at(AuditSeverity::Error);
        assert_eq!(logger.min_level(), AuditSeverity::Error);

        logger.info("dropped");
        logger.set_min_level(AuditSeverity::Debug);
        logger.info("kept");

        assert_eq!(logger.min_level(), AuditSeverity::Debug);
        let events = backend.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message.as_deref(), Some("kept"));
    }

    #[test]
    fn test_level_round_trips_through_atomic_storage() {
        for level in [
            AuditSeverity::Trace,
            AuditSeverity::Debug,
            AuditSeverity::Info,
            AuditSeverity::Warning,
            AuditSeverity::Error,
            AuditSeverity::Critical,
        ] {
            assert_eq!(u8_to_level(level_to_u8(level)), level);
        }
        // An out-of-range value must clamp to the most restrictive level rather
        // than widening what is admitted.
        assert_eq!(u8_to_level(200), AuditSeverity::Critical);
    }

    #[test]
    fn test_default_builder_uses_noop_integrity_and_info() {
        let logger = Logger::builder(Arc::new(NoopAuditBackend)).build();
        assert_eq!(logger.min_level(), AuditSeverity::Info);
        logger.debug("dropped by default threshold");
    }

    #[test]
    fn test_filtered_events_do_not_consume_a_sequence_number() {
        // Regression guard for the ordering hazard: a dropped event must never
        // advance the integrity mechanism.
        let (logger, backend) = logger_at(AuditSeverity::Error);

        logger.debug("dropped");
        logger.debug("dropped");
        logger.error("kept");

        let events = backend.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .metadata
                .get("sequence")
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "the first written event must hold sequence 0, not 2"
        );
    }

    #[cfg(feature = "hlc")]
    mod hlc {
        use super::*;
        use crate::{EventClock, HlcClock};

        #[test]
        fn test_events_are_stamped_when_a_clock_is_configured() {
            let backend = Arc::new(CapturingBackend::default());
            let logger = Logger::builder(backend.clone())
                .clock(Arc::new(HlcClock::new()))
                .build();

            logger.info("first");
            logger.info("second");

            let events = backend.events();
            let first = events[0].hlc.expect("stamped");
            let second = events[1].hlc.expect("stamped");
            assert!(
                first.happened_before(second),
                "later events carry strictly later timestamps"
            );
        }

        #[test]
        fn test_no_clock_leaves_the_field_absent() {
            let backend = Arc::new(CapturingBackend::default());
            let logger = Logger::builder(backend.clone()).build();

            logger.info("unstamped");

            assert_eq!(
                backend.events()[0].hlc,
                None,
                "the field costs nothing until a clock is configured"
            );
        }

        #[test]
        fn test_stamps_are_monotonic_across_threads() {
            // One clock shared by several loggers must still produce a total
            // order, or concurrent events could not be sequenced.
            let backend = Arc::new(CapturingBackend::default());
            let clock = Arc::new(HlcClock::new());
            let logger = Arc::new(
                Logger::builder(backend.clone())
                    .clock(clock.clone())
                    .build(),
            );

            let mut handles = Vec::new();
            for n in 0..8 {
                let logger = logger.clone();
                handles.push(std::thread::spawn(move || {
                    for i in 0..16 {
                        logger.info(format!("thread {n} event {i}"));
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("worker thread panicked");
            }

            let mut stamps: Vec<EventClock> = backend
                .events()
                .iter()
                .map(|e| e.hlc.expect("stamped"))
                .collect();
            assert_eq!(stamps.len(), 128);

            let before = stamps.len();
            stamps.sort_unstable();
            stamps.dedup();
            assert_eq!(
                stamps.len(),
                before,
                "every event gets a distinct timestamp, so the order is total"
            );
        }

        #[test]
        fn test_an_explicit_timestamp_on_the_event_wins() {
            let backend = Arc::new(CapturingBackend::default());
            let logger = Logger::builder(backend.clone())
                .clock(Arc::new(HlcClock::new()))
                .build();

            let pinned = EventClock {
                physical: 1,
                logical: 2,
            };
            logger.log(
                AuditEvent::diagnostic("preset")
                    .severity(AuditSeverity::Info)
                    .hlc(pinned)
                    .build(),
            );

            assert_eq!(
                backend.events()[0].hlc,
                Some(pinned),
                "a caller-supplied timestamp is not overwritten"
            );
        }

        #[test]
        fn test_observe_advances_the_clock_past_an_upstream_timestamp() {
            // The cross-service case: events recorded after observing an
            // upstream timestamp must be ordered after it, whatever the local
            // wall clock says.
            let backend = Arc::new(CapturingBackend::default());
            let logger = Logger::builder(backend.clone())
                .clock(Arc::new(HlcClock::new()))
                .build();

            let upstream = HlcClock::new().now().expect("system clock is sane");
            logger.observe_hlc(upstream).expect("observation accepted");
            logger.info("after the upstream event");

            let stamped = backend.events()[0].hlc.expect("stamped");
            assert!(
                EventClock::from(upstream).happened_before(stamped),
                "local events are ordered after the observed timestamp"
            );
        }

        #[test]
        fn test_observe_without_a_clock_is_inert() {
            let logger = Logger::builder(Arc::new(NoopAuditBackend)).build();
            let upstream = HlcClock::new().now().unwrap();

            assert_eq!(
                logger.observe_hlc(upstream),
                Ok(upstream),
                "a logger with no clock has no ordering to advance"
            );
            assert_eq!(logger.hlc_now(), None);
        }

        #[test]
        fn test_filtered_events_do_not_consume_a_timestamp() {
            // Stamping happens after the admission check, so a dropped
            // diagnostic must not advance the clock.
            let backend = Arc::new(CapturingBackend::default());
            let clock = Arc::new(HlcClock::new());
            let logger = Logger::builder(backend.clone())
                .clock(clock.clone())
                .min_level(AuditSeverity::Error)
                .build();

            logger.info("dropped");
            let before = clock.last();
            logger.info("also dropped");
            assert_eq!(
                clock.last(),
                before,
                "filtered events never reach the clock"
            );

            logger.error("written");
            assert!(backend.events()[0].hlc.is_some());
        }
    }
}
