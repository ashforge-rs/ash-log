//! Chain verification against arbitrary JSON-lines input.
//!
//! This is the crate's most exposed surface: `ash-log-verify` reads a log file
//! that an attacker may have written to, and verification must reach a verdict
//! rather than panic. A crash here is a denial of service on the tool that
//! detects tampering — the one component that must keep working when a log is
//! hostile.
//!
//! The property asserted is total: for *any* input, verification returns
//! `Ok` or `Err`. It must never panic, and must never accept a chain it did
//! not actually verify.

#![no_main]

use ash_log::{AuditEvent, HmacChainIntegrity};
use libfuzzer_sys::fuzz_target;

const KEY: &[u8] = b"fuzzing-key-at-least-32-bytes-ok!";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Parse whatever lines deserialize; malformed ones are the CLI's problem,
    // not the verifier's.
    let events: Vec<AuditEvent> = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    if events.is_empty() {
        return;
    }

    let integrity = HmacChainIntegrity::new(KEY);

    // Must reach a verdict without panicking.
    let ordered = integrity.verify_chain(&events);
    let unordered = HmacChainIntegrity::new(KEY).verify_unordered(&events);

    // A chain that verifies must report exactly the number of entries it was
    // given: a verifier that accepts a prefix while claiming the whole would
    // hide a truncation.
    if let Ok(count) = ordered {
        assert_eq!(count, events.len(), "verify_chain miscounted");
    }
    if let Ok(count) = unordered {
        assert_eq!(count, events.len(), "verify_unordered miscounted");
    }

    // Verification must be deterministic: the same input twice gives the same
    // verdict. A verifier whose answer depends on hidden state could be walked
    // into accepting a forged log.
    let again = HmacChainIntegrity::new(KEY).verify_chain(&events);
    assert_eq!(ordered, again, "verification is not deterministic");
});
