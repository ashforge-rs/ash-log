//! Per-module filtering, retuned while the logger runs.
//!
//! A filter tunes operational noise. It must never be able to shrink the audit
//! record: security events are admitted whatever any directive says.

use ash_log::{
    AuditBackend, AuditEvent, AuditSeverity, FilterDirectives, LiveFilter, ash_audit, ash_debug,
    ash_info, ash_logger, ash_trace,
};
use std::sync::{Arc, Mutex, PoisonError};

#[derive(Default)]
struct Collector(Mutex<Vec<AuditEvent>>);

impl Collector {
    fn take(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .split_off(0)
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

#[test]
fn test_a_filter_can_loosen_the_base_threshold_for_one_module() {
    let backend = Arc::new(Collector::default());
    // This test module's path is what directives must name.
    let filter = LiveFilter::parse(&format!("warn,{}=trace", module_path!()));
    let logger = ash_logger!(
        backend: backend.clone(),
        filter: filter.clone(),
        min_level: AuditSeverity::Warning,
    );

    ash_trace!(logger, "below the base threshold, above the module's");
    let events = backend.take();
    assert_eq!(
        events.len(),
        1,
        "the per-module directive admits what the base level would drop"
    );
}

#[test]
fn test_a_filter_can_tighten_the_base_threshold_for_one_module() {
    let backend = Arc::new(Collector::default());
    let filter = LiveFilter::parse(&format!("trace,{}=error", module_path!()));
    let logger = ash_logger!(
        backend: backend.clone(),
        filter: filter.clone(),
        min_level: AuditSeverity::Trace,
    );

    ash_info!(logger, "dropped by the module directive");
    assert!(backend.take().is_empty());

    ash_log::ash_error!(logger, "admitted");
    assert_eq!(backend.take().len(), 1);
}

#[test]
fn test_reloading_retunes_a_running_logger() {
    let backend = Arc::new(Collector::default());
    let filter = LiveFilter::parse("info");
    let logger = ash_logger!(
        backend: backend.clone(),
        filter: filter.clone(),
        min_level: AuditSeverity::Trace,
    );

    ash_debug!(logger, "not recorded at info");
    assert!(backend.take().is_empty());

    // No rebuild: the same logger picks up the new directives.
    filter.reload("debug");
    ash_debug!(logger, "recorded now");
    assert_eq!(backend.take().len(), 1);

    filter.set(FilterDirectives::parse("error"));
    ash_debug!(logger, "silenced again");
    assert!(backend.take().is_empty());
}

#[test]
fn test_a_filter_cannot_shrink_the_audit_record() {
    // The invariant that matters: an operational knob must not be able to
    // suppress a security event, however restrictive it is set.
    let backend = Arc::new(Collector::default());
    let filter = LiveFilter::parse("critical");
    let logger = ash_logger!(
        backend: backend.clone(),
        filter: filter.clone(),
        min_level: AuditSeverity::Critical,
    );

    ash_info!(logger, "dropped: a diagnostic");
    ash_audit!(
        logger,
        AuthenticationAttempt,
        Success,
        principal = "alice",
        severity = AuditSeverity::Trace
    );

    let events = backend.take();
    assert_eq!(events.len(), 1, "only the security event survives");
    assert!(events[0].event_type.is_security_relevant());
}

#[test]
fn test_no_filter_leaves_the_base_threshold_in_charge() {
    let backend = Arc::new(Collector::default());
    let logger = ash_logger!(
        backend: backend.clone(),
        min_level: AuditSeverity::Warning,
    );

    ash_info!(logger, "dropped");
    ash_log::ash_warn!(logger, "kept");

    assert_eq!(
        backend.take().len(),
        1,
        "behaviour is unchanged without a filter"
    );
}

#[test]
fn test_an_empty_filter_defers_to_the_base_threshold() {
    let backend = Arc::new(Collector::default());
    let logger = ash_logger!(
        backend: backend.clone(),
        filter: LiveFilter::parse(""),
        min_level: AuditSeverity::Warning,
    );

    ash_info!(logger, "dropped by the base threshold");
    assert!(
        backend.take().is_empty(),
        "an empty filter constrains nothing and does not loosen anything either"
    );
}
