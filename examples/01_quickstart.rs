//! Basic audit logging: build events, add integrity metadata, write JSON lines.
//!
//! ```text
//! cargo run --example 01_quickstart
//! ```

use ash_log::{
    AuditBackend, AuditEvent, AuditEventType, AuditIntegrity, AuditResult, AuditSeverity,
    SequenceIntegrity, StdoutAuditBackend,
};

fn main() {
    let backend = StdoutAuditBackend;
    let integrity = SequenceIntegrity::new();

    // A successful login.
    let mut login = AuditEvent::builder()
        .event_type(AuditEventType::AuthenticationAttempt)
        .principal("alice@example.com")
        .method("password_login")
        .result(AuditResult::Success)
        .correlation_id("req-8f21")
        .build();
    integrity.add_integrity(&mut login);
    backend.log_audit(&login);

    // A denied authorization check. Severity defaults to Critical for a denial,
    // so it does not need to be set explicitly.
    let mut denied = AuditEvent::builder()
        .event_type(AuditEventType::AuthorizationCheck)
        .principal("alice@example.com")
        .method("transfer_funds")
        .result(AuditResult::Denied)
        .error("insufficient privileges")
        .params(serde_json::json!({ "amount": 5_000, "currency": "EUR" }))
        .correlation_id("req-8f21")
        .build();
    integrity.add_integrity(&mut denied);
    backend.log_audit(&denied);
    assert_eq!(denied.severity, AuditSeverity::Critical);

    // A rate-limit violation from a known address.
    let mut violation = AuditEvent::builder()
        .event_type(AuditEventType::SecurityViolation)
        .method("rate_limit")
        .result(AuditResult::Violation)
        .remote_addr("203.0.113.7:54321".parse().expect("valid address"))
        .build();
    violation.add_metadata("requests_per_minute", 4_200);
    integrity.add_integrity(&mut violation);
    backend.log_audit(&violation);

    backend.flush();
}
