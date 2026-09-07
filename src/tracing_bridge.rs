//! Routes [`tracing`] events into a [`Logger`].
//!
//! This is the supported way to capture application logging, including output
//! from third-party crates that already use `tracing` or the `log` facade. It
//! replaces any attempt to capture `println!`: a `tracing` event arrives with a
//! level, a target module, a source location, and named fields, all as
//! structured data, so the resulting record can be classified honestly and
//! signed. Captured stdout text has none of that.
//!
//! # Example
//!
//! ```rust
//! use ash_log::*;
//! use std::sync::Arc;
//! use tracing_subscriber::layer::SubscriberExt;
//! use tracing_subscriber::util::SubscriberInitExt;
//!
//! let logger = Arc::new(
//!     Logger::builder(Arc::new(StdoutAuditBackend))
//!         .min_level(AuditSeverity::Info)
//!         .build(),
//! );
//!
//! tracing_subscriber::registry()
//!     .with(AshLogLayer::new(logger))
//!     .init();
//!
//! tracing::info!(user = "alice", "login succeeded");
//! ```
//!
//! # Level mapping
//!
//! | `tracing` | [`AuditSeverity`] |
//! |-----------|-------------------|
//! | `TRACE`   | [`Trace`](AuditSeverity::Trace) |
//! | `DEBUG`   | [`Debug`](AuditSeverity::Debug) |
//! | `INFO`    | [`Info`](AuditSeverity::Info) |
//! | `WARN`    | [`Warning`](AuditSeverity::Warning) |
//! | `ERROR`   | [`Error`](AuditSeverity::Error) |
//!
//! `tracing` has no level above `ERROR`, so a bridged event is never
//! [`Critical`](AuditSeverity::Critical) and is always a
//! [`Diagnostic`](crate::AuditEventType::Diagnostic) record. Security events
//! are logged directly through [`Logger`], never through this bridge — a
//! diagnostic must not be able to claim a security classification it has not
//! earned.

use super::{AuditEvent, AuditSeverity, Logger, Provenance};
use std::sync::Arc;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};

/// Field name `tracing` uses for the formatted message of an event.
const MESSAGE_FIELD: &str = "message";

/// Translate a [`tracing::Level`] into an [`AuditSeverity`].
fn map_level(level: tracing::Level) -> AuditSeverity {
    match level {
        tracing::Level::TRACE => AuditSeverity::Trace,
        tracing::Level::DEBUG => AuditSeverity::Debug,
        tracing::Level::INFO => AuditSeverity::Info,
        tracing::Level::WARN => AuditSeverity::Warning,
        tracing::Level::ERROR => AuditSeverity::Error,
    }
}

/// Collects an event's message and its remaining fields as metadata.
#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl FieldCollector {
    /// Record one field, keeping `message` separate from the rest.
    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        if field.name() == MESSAGE_FIELD {
            self.message = match value {
                serde_json::Value::String(s) => Some(s),
                other => Some(other.to_string()),
            };
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, serde_json::Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, serde_json::Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field, serde_json::Value::from(format!("{value:?}")));
    }
}

/// A [`tracing_subscriber`] layer that writes every event it sees to a
/// [`Logger`] as a diagnostic record.
///
/// Level filtering stays with the `Logger`, so one threshold governs both
/// directly-logged and bridged events. Use `tracing`'s own filtering as well if
/// you want to avoid the cost of constructing events that would be dropped.
pub struct AshLogLayer {
    logger: Arc<Logger>,
}

impl AshLogLayer {
    /// Bridge `tracing` events into `logger`.
    #[must_use]
    pub fn new(logger: Arc<Logger>) -> Self {
        Self { logger }
    }

    /// The logger this layer writes to.
    #[must_use]
    pub fn logger(&self) -> &Arc<Logger> {
        &self.logger
    }
}

impl std::fmt::Debug for AshLogLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AshLogLayer").finish_non_exhaustive()
    }
}

impl<S: tracing::Subscriber> Layer<S> for AshLogLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let severity = map_level(*metadata.level());

        // Skip the work of collecting fields for an event that will be dropped.
        // Bridged events are always diagnostics, so the level decides alone.
        if severity < self.logger.min_level() {
            return;
        }

        let mut collector = FieldCollector::default();
        event.record(&mut collector);

        let mut provenance = Provenance::new().with_module(metadata.target());
        if let Some(file) = metadata.file() {
            provenance = provenance.with_file(file);
        }
        if let Some(line) = metadata.line() {
            provenance = provenance.with_line(line);
        }
        provenance.thread = std::thread::current().name().map(ToString::to_string);
        provenance.pid = Some(std::process::id());

        let mut builder = AuditEvent::diagnostic(collector.message.unwrap_or_default())
            .severity(severity)
            .provenance(provenance);

        for (key, value) in collector.fields {
            builder = builder.metadata(key, value);
        }

        self.logger.log(builder.build());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditBackend, AuditEventType};
    use std::sync::{Mutex, PoisonError};
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);

    impl Collector {
        fn events(&self) -> Vec<AuditEvent> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
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

    /// Run `body` with a subscriber bridging into a fresh collector.
    fn with_bridge<F: FnOnce()>(min_level: AuditSeverity, body: F) -> Vec<AuditEvent> {
        let collector = Arc::new(Collector::default());
        let logger = Arc::new(
            Logger::builder(collector.clone())
                .min_level(min_level)
                .build(),
        );
        let subscriber = tracing_subscriber::registry().with(AshLogLayer::new(logger));
        tracing::subscriber::with_default(subscriber, body);
        collector.events()
    }

    #[test]
    fn test_levels_map_across() {
        for (level, expected) in [
            (tracing::Level::TRACE, AuditSeverity::Trace),
            (tracing::Level::DEBUG, AuditSeverity::Debug),
            (tracing::Level::INFO, AuditSeverity::Info),
            (tracing::Level::WARN, AuditSeverity::Warning),
            (tracing::Level::ERROR, AuditSeverity::Error),
        ] {
            assert_eq!(map_level(level), expected);
        }
    }

    #[test]
    fn test_event_becomes_a_diagnostic_record() {
        let events = with_bridge(AuditSeverity::Trace, || {
            tracing::info!("service started");
        });

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::Diagnostic);
        assert_eq!(events[0].severity, AuditSeverity::Info);
        assert_eq!(events[0].message.as_deref(), Some("service started"));
    }

    #[test]
    fn test_structured_fields_become_metadata() {
        let events = with_bridge(AuditSeverity::Trace, || {
            tracing::warn!(user = "alice", attempts = 3, ok = false, "rate limited");
        });

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.message.as_deref(), Some("rate limited"));
        assert_eq!(
            event
                .metadata
                .get("user")
                .and_then(serde_json::Value::as_str),
            Some("alice")
        );
        assert_eq!(
            event
                .metadata
                .get("attempts")
                .and_then(serde_json::Value::as_i64),
            Some(3)
        );
        assert_eq!(
            event
                .metadata
                .get("ok")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn test_provenance_records_the_emitting_module_and_location() {
        let events = with_bridge(AuditSeverity::Trace, || {
            tracing::error!("disk failure");
        });

        let provenance = &events[0].provenance;
        assert_eq!(provenance.module.as_deref(), Some(module_path!()));
        assert_eq!(provenance.file.as_deref(), Some(file!()));
        assert!(provenance.line.is_some());
        assert!(provenance.pid.is_some());
    }

    #[test]
    fn test_bridged_events_respect_the_logger_threshold() {
        let events = with_bridge(AuditSeverity::Warning, || {
            tracing::debug!("noise");
            tracing::info!("also noise");
            tracing::warn!("kept");
            tracing::error!("also kept");
        });

        let levels: Vec<AuditSeverity> = events.iter().map(|e| e.severity).collect();
        assert_eq!(levels, vec![AuditSeverity::Warning, AuditSeverity::Error]);
    }

    #[test]
    fn test_bridged_events_are_never_security_relevant() {
        // A diagnostic must not be able to claim a security classification.
        let events = with_bridge(AuditSeverity::Trace, || {
            tracing::error!("authentication failed");
        });

        assert!(
            !events[0].event_type.is_security_relevant(),
            "a bridged event must never enter the security tier"
        );
    }

    #[test]
    fn test_event_without_a_message_still_records() {
        let events = with_bridge(AuditSeverity::Trace, || {
            tracing::info!(counter = 7);
        });

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message.as_deref(), Some(""));
        assert_eq!(
            events[0]
                .metadata
                .get("counter")
                .and_then(serde_json::Value::as_i64),
            Some(7)
        );
    }
}
