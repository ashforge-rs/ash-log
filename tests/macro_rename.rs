//! The `ash_` prefix exists so that `use ash_log::*` stays safe next to the
//! other logging crates. These tests pin both halves of that claim: the short
//! names are reachable by renaming at the import site, and the prefixed names
//! coexist with `tracing`'s macros in one scope.

use ash_log::*;
use std::sync::Arc;

mod renamed {
    use super::{AuditSeverity, NoopAuditBackend};
    use ash_log::{ash_audit as audit, ash_info as info, ash_logger as logger, ash_warn as warn};
    use std::sync::Arc;

    #[test]
    fn test_short_names_via_rename() {
        let log = logger!(
            backend: Arc::new(NoopAuditBackend),
            min_level: AuditSeverity::Trace,
        );

        info!(log, "renamed import works");
        warn!(log, "with {} args", 1);
        audit!(log, AdminAction, Success, method = "rotate");
    }
}

#[cfg(feature = "tracing")]
mod coexistence {
    //! The collision case the prefix is for: both crates glob-imported at once.
    use ash_log::*;
    use std::sync::Arc;
    use tracing::*;

    #[test]
    fn test_prefixed_names_do_not_collide_with_tracing() {
        let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));

        // `info!` here is unambiguously tracing's; ash-log's is `ash_info!`.
        info!("a tracing event");
        ash_info!(logger, "an ash-log event");
        ash_audit!(logger, AuthenticationAttempt, Success);
    }
}

/// A backend that keeps what it is given, so the assertions can inspect it.
#[derive(Default)]
struct Collector(std::sync::Mutex<Vec<ash_log::AuditEvent>>);

impl ash_log::AuditBackend for Collector {
    fn log_audit(&self, event: &ash_log::AuditEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

#[test]
fn test_macros_work_through_the_public_crate_surface() {
    // The unit tests exercise the macros from inside the crate, where `$crate`
    // resolves trivially. This one runs them as a downstream user would.
    let backend = Arc::new(Collector::default());
    let logger = ash_log::ash_logger!(
        backend: backend.clone(),
        min_level: AuditSeverity::Debug,
        service: "downstream",
    );

    ash_log::ash_trace!(logger, "filtered out");
    ash_log::ash_debug!(logger, "kept {}", 1);
    ash_log::ash_error!(logger, "failed"; code = 500);
    ash_log::ash_audit!(logger, SecurityViolation, Denied, principal = "mallory");

    let events = backend
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

    assert_eq!(events.len(), 3, "the trace record was filtered");
    assert_eq!(events[0].message.as_deref(), Some("kept 1"));
    assert_eq!(events[1].metadata["code"], 500);
    assert_eq!(events[2].event_type, AuditEventType::SecurityViolation);
    assert_eq!(events[2].result, AuditResult::Denied);
    assert_eq!(
        events[2].provenance.service.as_deref(),
        Some("downstream"),
        "logger identity reaches events built by the macro"
    );
}

/// A shared backend composing as an inner backend is a public guarantee the
/// `buffered:` key depends on, so it is pinned from outside the crate.
#[test]
fn test_arc_backend_composes_as_a_backend() {
    let shared: Arc<dyn AuditBackend> = Arc::new(Collector::default());
    let buffered = BufferedAuditBackend::new(shared.clone(), 2);

    let event = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .result(AuditResult::Success)
        .build();

    buffered.log_audit(&event);
    assert_eq!(buffered.buffered(), 1, "held below capacity");
    buffered.flush();
    assert_eq!(buffered.buffered(), 0, "drained to the shared backend");
}
