//! Redaction must happen before the event is stamped.
//!
//! Scrubbing a secret *after* `add_integrity` would leave a MAC computed over
//! the unredacted value. The log would then both leak the secret and fail to
//! verify — the worst of both outcomes. `Logger::log` fixes the order, and
//! these tests pin it against a real chain.

#![cfg(feature = "hmac-chain")]

use ash_log::{
    AuditEvent, AuditSeverity, HmacChainIntegrity, KeyRedactor, Logger, REDACTED, ash_audit,
    ash_info, ash_logger,
};
use std::sync::{Arc, Mutex, PoisonError};

const KEY: &[u8] = b"redaction-test-key-32-bytes-ok!!!";

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

impl ash_log::AuditBackend for Collector {
    fn log_audit(&self, event: &AuditEvent) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
    }
}

fn logger(backend: Arc<Collector>) -> Logger {
    ash_logger!(
        backend: backend,
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
        redact: Arc::new(KeyRedactor::default()),
        min_level: AuditSeverity::Trace,
    )
}

#[test]
fn test_redacted_events_still_verify() {
    // The ordering guarantee: what was signed is what was written.
    let backend = Arc::new(Collector::default());
    let logger = logger(backend.clone());

    ash_info!(logger, "login attempt"; password = "hunter2", user = "alice");
    ash_audit!(logger, AuthenticationAttempt, Success,
        principal = "alice@example.com";
        api_key = "sk-live-secret",
    );

    let events = backend.events();
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&events),
        Ok(2),
        "the MAC covers the redacted value, so the chain verifies"
    );
}

#[test]
fn test_the_secret_never_reaches_the_backend() {
    let backend = Arc::new(Collector::default());
    let logger = logger(backend.clone());

    ash_info!(logger, "login"; password = "hunter2", token = "sk-live-abc");

    let events = backend.events();
    let line = serde_json::to_string(&events[0]).expect("serializes");
    assert!(
        !line.contains("hunter2"),
        "the password must not appear anywhere in the written line"
    );
    assert!(!line.contains("sk-live-abc"), "nor the token");
    assert_eq!(events[0].metadata["password"], serde_json::json!(REDACTED));
}

#[test]
fn test_non_secrets_survive_redaction() {
    let backend = Arc::new(Collector::default());
    let logger = logger(backend.clone());

    ash_audit!(logger, AuthorizationCheck, Denied,
        principal = "alice@example.com",
        method = "transfer";
        amount = 500,
        reason = "insufficient funds",
    );

    let event = &backend.events()[0];
    assert_eq!(
        event.principal.as_deref(),
        Some("alice@example.com"),
        "the audit subject is not a secret and must be preserved"
    );
    assert_eq!(event.metadata["amount"], serde_json::json!(500));
    assert_eq!(
        event.metadata["reason"],
        serde_json::json!("insufficient funds")
    );
}

#[test]
fn test_restoring_a_redacted_value_breaks_the_chain() {
    // Because redaction precedes stamping, the placeholder is what is signed.
    // Substituting the original secret back in is tampering, and is detected.
    let backend = Arc::new(Collector::default());
    let logger = logger(backend.clone());

    ash_info!(logger, "login"; password = "hunter2");

    let mut events = backend.events();
    events[0]
        .metadata
        .insert("password".to_string(), serde_json::json!("hunter2"));

    assert!(
        HmacChainIntegrity::new(KEY).verify_chain(&events).is_err(),
        "putting the secret back is a detectable modification"
    );
}

#[test]
fn test_a_logger_without_a_redactor_is_unchanged() {
    // Redaction is opt-in, so an existing deployment behaves exactly as before.
    let backend = Arc::new(Collector::default());
    let logger = ash_logger!(
        backend: backend.clone(),
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
        min_level: AuditSeverity::Trace,
    );

    ash_info!(logger, "login"; password = "hunter2");

    assert_eq!(
        backend.events()[0].metadata["password"],
        serde_json::json!("hunter2"),
        "no redactor configured means no redaction"
    );
}
