//! Deserializing an `AuditEvent` from arbitrary JSON, then re-serializing.
//!
//! Every log line read back from disk goes through this path. A panic here is
//! reachable by anyone who can write a byte to the log file, and the crate's
//! own verifier reads exactly this way.
//!
//! The round-trip property matters for tamper evidence specifically: the MAC is
//! computed over the canonical form, so if serializing a deserialized event
//! does not reproduce it, a legitimate log could fail to verify after being
//! written and read back.

#![no_main]

use ash_log::AuditEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(event) = serde_json::from_str::<AuditEvent>(text) else {
        return;
    };

    // Serializing must not panic on anything that deserialized.
    let Ok(encoded) = serde_json::to_string(&event) else {
        return;
    };

    // And the result must parse back to the same value. If this fails, an
    // event could change identity by being written and read, which would break
    // verification of an untampered log.
    let decoded: AuditEvent = serde_json::from_str(&encoded).expect("re-parses");
    let re_encoded = serde_json::to_string(&decoded).expect("re-serializes");

    assert_eq!(
        encoded, re_encoded,
        "an event changed shape on a second round trip"
    );
});
