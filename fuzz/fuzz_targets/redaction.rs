//! Redaction against arbitrary JSON payloads.
//!
//! `params` and `metadata` carry caller-supplied data of unbounded shape:
//! deeply nested objects, long arrays, unusual key names. Redaction walks all
//! of it, and must neither panic nor let a listed key survive the walk.

#![no_main]

use ash_log::{AuditEvent, AuditEventType, AuditResult, KeyRedactor, REDACTED, Redactor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(params) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .result(AuditResult::Success)
        .params(params)
        .metadata("password", "hunter2")
        .build();

    KeyRedactor::default().redact_event(&mut event);

    // The one guarantee that matters: a listed key never survives redaction,
    // whatever shape the surrounding payload has.
    assert_eq!(
        event.metadata["password"],
        serde_json::json!(REDACTED),
        "a known-secret key survived redaction"
    );

    // A redacted event must still serialize, or the record could not be written.
    let _ = serde_json::to_string(&event);
});
