//! End-to-end tamper-evidence tests against the public API.
//!
//! These exercise the guarantee the crate actually advertises: a log written
//! with [`HmacChainIntegrity`] cannot be modified without detection by someone
//! who lacks the key. Each test models a concrete attack on a serialized log.

#![cfg(feature = "hmac-chain")]

use ash_log::{
    AuditEvent, AuditEventType, AuditIntegrity, AuditResult, AuditSeverity, ChainError,
    HmacChainIntegrity,
};

const KEY: &[u8] = b"integration-test-key-32-bytes-ok!";
const OTHER_KEY: &[u8] = b"a-different-key-of-the-same-size!";

/// Write a signed log and return it as JSON lines, exactly as a backend would.
fn signed_log(principals: &[&str]) -> Vec<String> {
    let integrity = HmacChainIntegrity::new(KEY);
    principals
        .iter()
        .map(|p| {
            let mut event = AuditEvent::builder()
                .event_type(AuditEventType::AuthenticationAttempt)
                .principal(*p)
                .method("login")
                .result(AuditResult::Success)
                .build();
            integrity.add_integrity(&mut event);
            serde_json::to_string(&event).expect("event serializes")
        })
        .collect()
}

/// Parse JSON lines back into events, as the verifier does.
fn parse(lines: &[String]) -> Vec<AuditEvent> {
    lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("line parses"))
        .collect()
}

fn verify(lines: &[String]) -> Result<usize, ChainError> {
    HmacChainIntegrity::new(KEY).verify_chain(&parse(lines))
}

#[test]
fn intact_log_verifies_after_serialization_round_trip() {
    let log = signed_log(&["alice", "bob", "carol"]);
    assert_eq!(verify(&log), Ok(3));
}

#[test]
fn single_entry_log_verifies() {
    let log = signed_log(&["alice"]);
    assert_eq!(verify(&log), Ok(1));
}

#[test]
fn empty_log_verifies_vacuously() {
    assert_eq!(verify(&[]), Ok(0));
}

#[test]
fn editing_a_field_is_detected() {
    let mut log = signed_log(&["alice", "bob", "carol"]);
    log[1] = log[1].replace("bob", "mallory");

    assert_eq!(verify(&log), Err(ChainError::MacMismatch { index: 1 }));
}

#[test]
fn flipping_a_denial_to_success_is_detected() {
    let integrity = HmacChainIntegrity::new(KEY);
    let mut denied = AuditEvent::builder()
        .event_type(AuditEventType::AuthorizationCheck)
        .principal("mallory@example.com")
        .method("transfer_funds")
        .result(AuditResult::Denied)
        .build();
    integrity.add_integrity(&mut denied);

    let line = serde_json::to_string(&denied).expect("serializes");
    let forged = line.replace(r#""result":"denied""#, r#""result":"success""#);
    assert_ne!(line, forged, "the replacement must actually apply");

    assert_eq!(verify(&[forged]), Err(ChainError::MacMismatch { index: 0 }));
}

#[test]
fn deleting_an_entry_is_detected() {
    let mut log = signed_log(&["alice", "bob", "carol", "dave"]);
    log.remove(1);

    assert!(
        verify(&log).is_err(),
        "removing an entry must break the chain"
    );
}

#[test]
fn reordering_entries_is_detected() {
    let mut log = signed_log(&["alice", "bob", "carol"]);
    log.swap(0, 2);

    assert!(verify(&log).is_err(), "reordering must break the chain");
}

#[test]
fn duplicating_an_entry_is_detected() {
    let mut log = signed_log(&["alice", "bob"]);
    let replayed = log[0].clone();
    log.push(replayed);

    assert!(verify(&log).is_err(), "replaying an entry must be caught");
}

#[test]
fn inserting_a_forged_entry_is_detected() {
    let mut log = signed_log(&["alice", "bob"]);

    // An attacker signs a new entry with their own key and splices it in.
    let attacker = HmacChainIntegrity::new(OTHER_KEY);
    let mut forged = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .principal("mallory@example.com")
        .result(AuditResult::Success)
        .build();
    attacker.add_integrity(&mut forged);
    log.insert(1, serde_json::to_string(&forged).expect("serializes"));

    assert!(verify(&log).is_err(), "spliced entry must be caught");
}

/// The attack that defeats an unkeyed checksum: strip the integrity metadata,
/// edit the record, and re-stamp it with the library's own algorithm.
#[test]
fn restamping_without_the_key_is_detected() {
    let log = signed_log(&["alice", "bob", "carol"]);
    let mut events = parse(&log);

    events[1].principal = Some("mallory@example.com".to_string());
    events[1].metadata.remove("mac");
    events[1].metadata.remove("chain_index");

    HmacChainIntegrity::new(OTHER_KEY).add_integrity(&mut events[1]);

    assert!(
        HmacChainIntegrity::new(KEY).verify_chain(&events).is_err(),
        "re-stamping without the key must be caught"
    );
}

#[test]
fn verifying_with_the_wrong_key_fails_at_the_first_entry() {
    let log = signed_log(&["alice", "bob"]);
    let events = parse(&log);

    assert_eq!(
        HmacChainIntegrity::new(OTHER_KEY).verify_chain(&events),
        Err(ChainError::MacMismatch { index: 0 })
    );
}

#[test]
fn stripping_the_mac_entirely_is_detected() {
    let log = signed_log(&["alice", "bob"]);
    let mut events = parse(&log);
    events[1].metadata.remove("mac");

    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&events),
        Err(ChainError::MissingMac { index: 1 })
    );
}

/// Truncation is the documented limitation: a prefix of a valid chain is itself
/// a valid chain. This pins that behaviour so a future change cannot silently
/// alter it, and shows the index that lets a caller detect it.
#[test]
fn truncating_the_tail_verifies_but_shortens_the_index() {
    let log = signed_log(&["alice", "bob", "carol", "dave"]);
    let truncated = &log[..2];

    assert_eq!(verify(truncated), Ok(2), "a prefix is a valid chain");

    let last = parse(truncated);
    let last_index = last[1]
        .metadata
        .get("chain_index")
        .and_then(serde_json::Value::as_u64);
    assert_eq!(
        last_index,
        Some(1),
        "the recorded index reveals the true length"
    );
}

#[test]
fn chain_resumes_across_a_simulated_restart() {
    let integrity = HmacChainIntegrity::new(KEY);
    let mut first = AuditEvent::builder()
        .event_type(AuditEventType::AuthenticationAttempt)
        .principal("alice@example.com")
        .result(AuditResult::Success)
        .build();
    integrity.add_integrity(&mut first);

    let saved_mac = integrity.current_mac();
    let saved_index = integrity.next_index() - 1;
    drop(integrity);

    // Process restarts and picks the chain back up.
    let resumed = HmacChainIntegrity::resume(KEY, saved_mac, saved_index);
    let mut second = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .principal("alice@example.com")
        .result(AuditResult::Success)
        .build();
    resumed.add_integrity(&mut second);

    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&[first, second]),
        Ok(2)
    );
}

#[test]
fn a_fresh_chain_after_restart_fails_to_verify() {
    // Starting a new chain instead of resuming is a real operational mistake;
    // the verifier must not silently accept it.
    let first_run = signed_log(&["alice"]);
    let second_run = signed_log(&["bob"]);

    let mut combined = first_run;
    combined.extend(second_run);

    assert!(
        verify(&combined).is_err(),
        "a restarted chain must not verify as one stream"
    );
}

#[test]
fn tampering_is_reported_at_the_first_bad_entry() {
    let mut log = signed_log(&["a", "b", "c", "d", "e"]);
    log[3] = log[3].replace(r#""principal":"d""#, r#""principal":"X""#);

    match verify(&log) {
        Err(ChainError::MacMismatch { index }) => assert_eq!(index, 3),
        other => panic!("expected a mismatch at entry 3, got {other:?}"),
    }
}

#[test]
fn events_with_rich_metadata_still_verify() {
    let integrity = HmacChainIntegrity::new(KEY);
    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::SecurityViolation)
        .principal("alice@example.com")
        .method("delete_account")
        .result(AuditResult::Violation)
        .params(serde_json::json!({"account_id": 42, "cascade": true}))
        .error("policy P-17 forbids cascade delete")
        .build();
    event.add_metadata("region", "eu-west-1");
    event.add_metadata("attempt", 3);
    integrity.add_integrity(&mut event);

    let line = serde_json::to_string(&event).expect("serializes");
    assert_eq!(verify(std::slice::from_ref(&line)), Ok(1));

    // And a change buried in params is still caught.
    let forged = line.replace(r#""account_id":42"#, r#""account_id":99"#);
    assert_ne!(line, forged);
    assert_eq!(verify(&[forged]), Err(ChainError::MacMismatch { index: 0 }));
}

// --- Concurrency ------------------------------------------------------------

/// Events stamped under a lock are written to the backend afterwards, so a log
/// produced by several threads can hold entries out of chain order. That log is
/// untampered and must be verifiable.
#[test]
fn concurrently_written_log_verifies_with_verify_unordered() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let integrity = Arc::new(HmacChainIntegrity::new(KEY));
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seed = Arc::new(AtomicU64::new(0x9E37_79B9));

    let mut handles = Vec::new();
    for thread_id in 0..4 {
        let integrity = Arc::clone(&integrity);
        let written = Arc::clone(&written);
        let seed = Arc::clone(&seed);
        handles.push(std::thread::spawn(move || {
            for i in 0..15 {
                let mut event = AuditEvent::builder()
                    .event_type(AuditEventType::MethodInvocation)
                    .principal(format!("thread{thread_id}-{i}"))
                    .result(AuditResult::Success)
                    .build();
                integrity.add_integrity(&mut event);

                // Stand in for backend I/O, which is what opens the window
                // between stamping and writing.
                let jitter = (seed.fetch_add(2_654_435_761, Ordering::Relaxed) >> 13) % 400;
                std::thread::sleep(std::time::Duration::from_micros(jitter));

                written
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(event);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker thread completes");
    }

    let events = written
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(events.len(), 60);

    let verifier = HmacChainIntegrity::new(KEY);
    assert_eq!(
        verifier.verify_unordered(&events),
        Ok(60),
        "an untampered concurrent log must verify"
    );
}

#[test]
fn verify_unordered_still_detects_edits() {
    let log = signed_log(&["alice", "bob", "carol"]);
    let mut events = parse(&log);
    events.reverse(); // simulate out-of-order arrival
    events[0].principal = Some("mallory@example.com".to_string());

    assert!(
        HmacChainIntegrity::new(KEY)
            .verify_unordered(&events)
            .is_err(),
        "sorting must not weaken tamper detection"
    );
}

#[test]
fn verify_unordered_still_detects_deletion() {
    let log = signed_log(&["alice", "bob", "carol", "dave"]);
    let mut events = parse(&log);
    events.reverse();
    events.remove(1);

    assert!(
        HmacChainIntegrity::new(KEY)
            .verify_unordered(&events)
            .is_err()
    );
}

#[test]
fn verify_unordered_still_detects_replay() {
    let log = signed_log(&["alice", "bob", "carol"]);
    let mut events = parse(&log);
    let replayed = events[1].clone();
    events.push(replayed);

    assert!(
        HmacChainIntegrity::new(KEY)
            .verify_unordered(&events)
            .is_err(),
        "a duplicated entry must not be sorted into a valid-looking chain"
    );
}

#[test]
fn verify_unordered_rejects_entries_without_a_chain_index() {
    let log = signed_log(&["alice", "bob"]);
    let mut events = parse(&log);
    events[1].metadata.remove("chain_index");

    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_unordered(&events),
        Err(ChainError::MissingChainIndex { index: 1 })
    );
}

// --- Key handling -----------------------------------------------------------

#[test]
#[should_panic(expected = "non-empty key")]
fn empty_key_is_rejected_at_construction() {
    let _ = HmacChainIntegrity::new(b"");
}

#[test]
#[should_panic(expected = "non-empty key")]
fn empty_key_is_rejected_when_resuming() {
    let _ = HmacChainIntegrity::resume(b"", "seed", 0);
}

// --- Diagnostic records -----------------------------------------------------

/// The `message` field must be inside the MAC, or diagnostic text could be
/// rewritten without detection.
#[test]
fn tampering_with_a_diagnostic_message_is_detected() {
    let integrity = HmacChainIntegrity::new(KEY);
    let mut event = AuditEvent::diagnostic("disk usage 91%").build();
    integrity.add_integrity(&mut event);

    let line = serde_json::to_string(&event).expect("serializes");
    let forged = line.replace("disk usage 91%", "disk usage 12%");
    assert_ne!(line, forged, "the replacement must actually apply");

    assert_eq!(verify(&[forged]), Err(ChainError::MacMismatch { index: 0 }));
}

#[test]
fn diagnostic_records_chain_alongside_security_events() {
    let integrity = HmacChainIntegrity::new(KEY);

    let mut security = AuditEvent::builder()
        .event_type(AuditEventType::AuthenticationAttempt)
        .principal("alice@example.com")
        .result(AuditResult::Success)
        .build();
    integrity.add_integrity(&mut security);

    let mut diagnostic = AuditEvent::diagnostic("session cache primed")
        .severity(AuditSeverity::Debug)
        .build();
    integrity.add_integrity(&mut diagnostic);

    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&[security, diagnostic]),
        Ok(2),
        "one chain carries both tiers"
    );
}

// --- Two-tier filtering (H1) ------------------------------------------------

/// Regression guard for the ordering hazard. Filtering must happen before
/// stamping, or dropped events leave gaps and an untampered log fails to
/// verify. This drives the real `Logger` rather than reproducing its logic.
#[test]
fn a_filtered_chain_still_verifies() {
    use ash_log::{Logger, StdoutAuditBackend};
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);
    impl ash_log::AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    let collector = Arc::new(Collector::default());
    let logger = Logger::builder(collector.clone())
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Error)
        .build();

    // A realistic mix: noisy diagnostics interleaved with security events.
    for i in 0..5 {
        logger.debug(format!("chatter {i}"));
        logger.log(
            AuditEvent::builder()
                .event_type(AuditEventType::AuthorizationCheck)
                .principal(format!("user{i}@example.com"))
                .result(AuditResult::Success)
                .severity(AuditSeverity::Info)
                .build(),
        );
    }
    logger.error("disk nearly full");

    let written = collector
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();

    assert_eq!(
        written.len(),
        6,
        "5 security events (below threshold, still kept) plus 1 error diagnostic"
    );
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&written),
        Ok(6),
        "dropping diagnostics must not gap the chain"
    );

    let _ = StdoutAuditBackend;
}

/// The compliance record must survive the most restrictive threshold.
#[test]
fn security_events_are_chained_at_the_highest_threshold() {
    use ash_log::Logger;
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);
    impl ash_log::AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    let collector = Arc::new(Collector::default());
    let logger = Logger::builder(collector.clone())
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Critical)
        .build();

    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::SecurityViolation)
            .result(AuditResult::Violation)
            .severity(AuditSeverity::Trace) // lowest possible severity
            .build(),
    );
    logger.info("dropped");

    let written = collector
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();

    assert_eq!(written.len(), 1, "the violation survived a Critical filter");
    assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&written), Ok(1));
}

/// Changing the level mid-stream must not corrupt the chain.
#[test]
fn runtime_level_changes_leave_the_chain_verifiable() {
    use ash_log::Logger;
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);
    impl ash_log::AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    let collector = Arc::new(Collector::default());
    let logger = Logger::builder(collector.clone())
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Error)
        .build();

    logger.info("dropped");
    logger.set_min_level(AuditSeverity::Debug);
    logger.info("kept");
    logger.set_min_level(AuditSeverity::Critical);
    logger.info("dropped again");
    logger.error("still dropped, below critical");

    let written = collector
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();

    assert_eq!(written.len(), 1);
    assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&written), Ok(1));
}

// --- Provenance -------------------------------------------------------------

/// Provenance must be inside the MAC, or "what emitted this" could be rewritten
/// without detection — which would make it advisory rather than provable.
#[test]
fn tampering_with_provenance_is_detected() {
    use ash_log::Provenance;

    let integrity = HmacChainIntegrity::new(KEY);
    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::AdminAction)
        .principal("root@example.com")
        .result(AuditResult::Success)
        .provenance(
            Provenance::new()
                .with_file("src/admin.rs")
                .with_line(42)
                .with_service("auth-api")
                .with_host("node-1"),
        )
        .build();
    integrity.add_integrity(&mut event);

    let line = serde_json::to_string(&event).expect("serializes");

    // Each of these rewrites the record of where the action came from.
    for (from, to) in [
        ("src/admin.rs", "src/harmless.rs"),
        ("\"line\":42", "\"line\":7"),
        ("auth-api", "billing-api"),
        ("node-1", "node-9"),
    ] {
        let forged = line.replace(from, to);
        assert_ne!(line, forged, "the replacement {from:?} must actually apply");
        assert_eq!(
            verify(&[forged]),
            Err(ChainError::MacMismatch { index: 0 }),
            "rewriting {from:?} went undetected"
        );
    }
}

#[test]
fn logger_identity_is_stamped_and_signed() {
    use ash_log::{Logger, Provenance};
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);
    impl ash_log::AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    let collector = Arc::new(Collector::default());
    let logger = Logger::builder(collector.clone())
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .identity(
            Provenance::new()
                .with_service("auth-api")
                .with_version("0.2.0")
                .with_host("node-1"),
        )
        .build();

    logger.error("token store unreachable");

    let written = collector
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(written.len(), 1);

    let event = &written[0];
    // Service identity comes from the logger.
    assert_eq!(event.provenance.service.as_deref(), Some("auth-api"));
    assert_eq!(event.provenance.version.as_deref(), Some("0.2.0"));
    assert_eq!(event.provenance.host.as_deref(), Some("node-1"));
    // Call-site location comes from the caller, not from inside the crate.
    assert_eq!(
        event.provenance.file.as_deref(),
        Some(file!()),
        "the emitting call site must be recorded, not a file inside ash-log"
    );
    assert!(event.provenance.pid.is_some());

    assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&written), Ok(1));
}
