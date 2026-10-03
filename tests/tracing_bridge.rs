//! End-to-end tests for the `tracing` bridge.
//!
//! These check the property that motivates the bridge: an ordinary
//! `tracing::info!` call becomes a tamper-evident, verifiable chain entry
//! carrying its own provenance.

#![cfg(all(feature = "tracing", feature = "hmac-chain"))]

use ash_log::{
    AshLogLayer, AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity, ChainError,
    HmacChainIntegrity, Logger, NoopAuditBackend, Provenance,
};
use std::sync::{Arc, Mutex, PoisonError};
use tracing_subscriber::layer::SubscriberExt as _;

const KEY: &[u8] = b"tracing-bridge-key-32-bytes-ok!!!";

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

/// Build a chained logger bridged to `tracing`, run `body`, return what was written.
fn run<F: FnOnce(&Arc<Logger>)>(min_level: AuditSeverity, body: F) -> Vec<AuditEvent> {
    let collector = Arc::new(Collector::default());
    let logger = Arc::new(
        Logger::builder(collector.clone())
            .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
            .min_level(min_level)
            .identity(
                Provenance::new()
                    .with_service("auth-api")
                    .with_version("0.2.0"),
            )
            .build(),
    );
    let subscriber = tracing_subscriber::registry().with(AshLogLayer::new(Arc::clone(&logger)));
    tracing::subscriber::with_default(subscriber, || body(&logger));
    collector.events()
}

#[test]
fn a_tracing_event_becomes_a_verifiable_chain_entry() {
    let events = run(AuditSeverity::Trace, |_| {
        tracing::info!(user = "alice", "login succeeded");
    });

    assert_eq!(events.len(), 1);
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&events),
        Ok(1),
        "a bridged event must be signed like any other"
    );
}

#[test]
fn tampering_with_a_bridged_message_is_detected() {
    let events = run(AuditSeverity::Trace, |_| {
        tracing::error!("payment declined");
    });

    let line = serde_json::to_string(&events[0]).expect("serializes");
    let forged = line.replace("payment declined", "payment approved");
    assert_ne!(line, forged);

    let parsed: AuditEvent = serde_json::from_str(&forged).expect("parses");
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&[parsed]),
        Err(ChainError::MacMismatch { index: 0 })
    );
}

#[test]
fn bridged_and_direct_events_share_one_chain() {
    let events = run(AuditSeverity::Trace, |logger| {
        tracing::info!("starting up");
        logger.log(
            AuditEvent::builder()
                .event_type(AuditEventType::AuthenticationAttempt)
                .principal("alice@example.com")
                .result(AuditResult::Success)
                .build(),
        );
        tracing::warn!("token cache cold");
    });

    assert_eq!(events.len(), 3);
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&events),
        Ok(3),
        "both sources interleave in a single verifiable chain"
    );
}

#[test]
fn filtered_bridged_events_do_not_gap_the_chain() {
    // The H1 hazard, reached through the bridge rather than directly.
    let events = run(AuditSeverity::Warning, |logger| {
        for i in 0..5 {
            tracing::debug!(i, "dropped");
            tracing::warn!(i, "kept");
        }
        logger.log(
            AuditEvent::builder()
                .event_type(AuditEventType::SecurityViolation)
                .result(AuditResult::Violation)
                .severity(AuditSeverity::Trace)
                .build(),
        );
    });

    assert_eq!(events.len(), 6, "5 warnings plus the security event");
    assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&events), Ok(6));
}

#[test]
fn logger_identity_reaches_bridged_events() {
    let events = run(AuditSeverity::Trace, |_| {
        tracing::info!("hello");
    });

    let provenance = &events[0].provenance;
    assert_eq!(provenance.service.as_deref(), Some("auth-api"));
    assert_eq!(provenance.version.as_deref(), Some("0.2.0"));
    assert_eq!(
        provenance.module.as_deref(),
        Some(module_path!()),
        "the emitting module is recorded"
    );
}

#[test]
fn concurrent_bridged_events_verify_when_sorted() {
    let collector = Arc::new(Collector::default());
    let logger = Arc::new(
        Logger::builder(collector.clone())
            .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
            .min_level(AuditSeverity::Trace)
            .build(),
    );
    let subscriber = tracing_subscriber::registry().with(AshLogLayer::new(Arc::clone(&logger)));

    // `with_default` installs a thread-local subscriber, which spawned threads
    // would not see, so use a dispatch each worker enters explicitly.
    let dispatch = tracing::Dispatch::new(subscriber);
    std::thread::scope(|scope| {
        for thread_id in 0..4 {
            let dispatch = dispatch.clone();
            scope.spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    for i in 0..10 {
                        tracing::info!(thread_id, i, "concurrent");
                    }
                });
            });
        }
    });

    let events = collector.events();
    assert_eq!(events.len(), 40);
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_unordered(&events),
        Ok(40),
        "concurrently bridged events must verify like any other concurrent log"
    );
}

/// Every field type `tracing` can record must survive the bridge as usable
/// metadata. Coverage showed the numeric and error recorders were never
/// exercised, so a field of those types could have been silently dropped.
#[test]
fn every_field_type_reaches_the_event_as_metadata() {
    let backend = Arc::new(Collector::default());
    let logger = Arc::new(Logger::builder(backend.clone()).build());
    let subscriber = tracing_subscriber::registry().with(AshLogLayer::new(logger));

    tracing::subscriber::with_default(subscriber, || {
        let failure = std::io::Error::other("disk unavailable");
        tracing::info!(
            count = 42_u64,
            offset = -7_i64,
            ratio = 0.25_f64,
            enabled = true,
            name = "worker",
            error = &failure as &(dyn std::error::Error + 'static),
            "field types"
        );
    });

    let events = backend.events();
    let metadata = &events[0].metadata;

    assert_eq!(metadata["count"], serde_json::json!(42));
    assert_eq!(metadata["offset"], serde_json::json!(-7));
    assert_eq!(metadata["ratio"], serde_json::json!(0.25));
    assert_eq!(metadata["enabled"], serde_json::json!(true));
    assert_eq!(metadata["name"], serde_json::json!("worker"));
    assert!(
        metadata["error"]
            .as_str()
            .is_some_and(|s| s.contains("disk unavailable")),
        "an error field is rendered via Display, not dropped: {:?}",
        metadata["error"]
    );
}

/// The layer exposes the logger it wraps, so a caller can retune it without
/// keeping a second handle.
#[test]
fn the_layer_exposes_its_logger() {
    let logger = Arc::new(
        Logger::builder(Arc::new(NoopAuditBackend))
            .min_level(AuditSeverity::Warning)
            .build(),
    );
    let layer = AshLogLayer::new(logger);

    assert_eq!(layer.logger().min_level(), AuditSeverity::Warning);
    layer.logger().set_min_level(AuditSeverity::Trace);
    assert_eq!(layer.logger().min_level(), AuditSeverity::Trace);
}
