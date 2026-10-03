//! Rotating the chain key, and keeping two writers out of one chain.

#![cfg(feature = "hmac-chain")]

use ash_log::{
    AuditEvent, AuditEventType, AuditIntegrity, AuditResult, ChainError, HmacChainIntegrity,
    RotationError,
};

const KEY_A: &[u8] = b"key-a-at-least-32-bytes-long!!!!!";
const KEY_B: &[u8] = b"key-b-at-least-32-bytes-long!!!!!";

fn event(n: usize) -> AuditEvent {
    AuditEvent::builder()
        .event_type(AuditEventType::AdminAction)
        .method(format!("action{n}"))
        .result(AuditResult::Success)
        .build()
}

fn stamp(integrity: &HmacChainIntegrity, n: usize) -> AuditEvent {
    let mut event = event(n);
    integrity.add_integrity(&mut event);
    event
}

#[test]
fn test_a_chain_verifies_across_a_key_rotation() {
    // The point of rotation: continuity is preserved, so the whole stream
    // verifies as one chain even though two keys signed it.
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("2026-q1");

    let mut events: Vec<AuditEvent> = (0..3).map(|n| stamp(&integrity, n)).collect();
    integrity.rotate_to(KEY_B, "2026-q2").expect("rotation");
    events.extend((3..6).map(|n| stamp(&integrity, n)));

    assert_eq!(
        integrity.verify_chain(&events),
        Ok(6),
        "entries signed with either key verify in one pass"
    );
    assert_eq!(integrity.key_id(), Some("2026-q2"));
    assert_eq!(integrity.retired_key_ids(), vec!["2026-q1"]);
}

#[test]
fn test_entries_name_the_key_that_signed_them() {
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("old");
    let first = stamp(&integrity, 0);
    integrity.rotate_to(KEY_B, "new").expect("rotation");
    let second = stamp(&integrity, 1);

    assert_eq!(first.metadata["key_id"], serde_json::json!("old"));
    assert_eq!(second.metadata["key_id"], serde_json::json!("new"));
}

#[test]
fn test_the_key_id_is_covered_by_the_mac() {
    // An attacker who could relabel an entry could point it at a key they
    // control, so the identifier must be signed like everything else.
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("old");
    let mut events = vec![stamp(&integrity, 0)];
    integrity.rotate_to(KEY_B, "new").expect("rotation");
    events.push(stamp(&integrity, 1));

    events[0]
        .metadata
        .insert("key_id".to_string(), serde_json::json!("new"));

    assert_eq!(
        integrity.verify_chain(&events),
        Err(ChainError::MacMismatch { index: 0 }),
        "relabelling an entry's key is detected"
    );
}

#[test]
fn test_a_verifier_without_the_retired_key_says_so() {
    // A fresh verifier holding only the current key cannot check older
    // entries, and must report that clearly rather than as tampering.
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("old");
    let mut events = vec![stamp(&integrity, 0)];
    integrity.rotate_to(KEY_B, "new").expect("rotation");
    events.push(stamp(&integrity, 1));

    let partial = HmacChainIntegrity::new(KEY_B).with_key_id("new");
    assert_eq!(
        partial.verify_chain(&events),
        Err(ChainError::UnknownKeyId {
            index: 0,
            key_id: "old".to_string(),
        }),
        "a missing key is reported as such, not as a MAC mismatch"
    );
}

#[test]
fn test_rotation_requires_a_key_id() {
    let mut integrity = HmacChainIntegrity::new(KEY_A);
    assert_eq!(
        integrity.rotate_to(KEY_B, "new"),
        Err(RotationError::NoKeyId),
        "without an id, entries could not say which key signed them"
    );
}

#[test]
fn test_rotation_rejects_a_reused_identifier() {
    // Reusing an id for different key material would make entries signed with
    // the earlier key impossible to verify.
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("k1");
    assert_eq!(
        integrity.rotate_to(KEY_B, "k1"),
        Err(RotationError::DuplicateKeyId("k1".to_string()))
    );

    integrity.rotate_to(KEY_B, "k2").expect("distinct id");
    assert_eq!(
        integrity.rotate_to(KEY_A, "k1"),
        Err(RotationError::DuplicateKeyId("k1".to_string())),
        "a retired id is still taken"
    );
}

#[test]
fn test_rotation_rejects_an_empty_key() {
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("k1");
    assert_eq!(integrity.rotate_to(b"", "k2"), Err(RotationError::EmptyKey));
}

#[test]
fn test_tampering_is_still_detected_after_rotation() {
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("old");
    let mut events: Vec<AuditEvent> = (0..3).map(|n| stamp(&integrity, n)).collect();
    integrity.rotate_to(KEY_B, "new").expect("rotation");
    events.extend((3..6).map(|n| stamp(&integrity, n)));

    // Edit an entry signed with the retired key.
    events[1].method = Some("rewritten".to_string());
    assert!(
        integrity.verify_chain(&events).is_err(),
        "rotation does not weaken detection of edits to older entries"
    );
}

#[test]
fn test_two_writers_in_one_chain_are_reported_as_such() {
    // Each writer keeps its own index and previous-MAC state, so interleaving
    // them cannot produce a valid chain. The error must say that, rather than
    // looking like an attack.
    let alpha = HmacChainIntegrity::new(KEY_A).writer("alpha");
    let beta = HmacChainIntegrity::new(KEY_A).writer("beta");

    let events = vec![stamp(&alpha, 0), stamp(&beta, 1)];

    match alpha.verify_chain(&events) {
        Err(ChainError::MixedWriters {
            index,
            expected,
            found,
        }) => {
            assert_eq!(index, 1);
            assert_eq!(expected, "alpha");
            assert_eq!(found, "beta");
        }
        other => panic!("expected MixedWriters, got {other:?}"),
    }
}

#[test]
fn test_the_mixed_writer_error_explains_the_fix() {
    let alpha = HmacChainIntegrity::new(KEY_A).writer("alpha");
    let beta = HmacChainIntegrity::new(KEY_A).writer("beta");
    let events = vec![stamp(&alpha, 0), stamp(&beta, 1)];

    let message = alpha
        .verify_chain(&events)
        .expect_err("mixed writers")
        .to_string();

    assert!(message.contains("alpha") && message.contains("beta"));
    assert!(
        message.contains("two processes cannot share one chain"),
        "the message names the actual mistake: {message}"
    );
}

#[test]
fn test_one_writer_verifies_normally() {
    let integrity = HmacChainIntegrity::new(KEY_A).writer("alpha");
    let events: Vec<AuditEvent> = (0..4).map(|n| stamp(&integrity, n)).collect();

    assert_eq!(integrity.verify_chain(&events), Ok(4));
    assert_eq!(events[0].metadata["writer"], serde_json::json!("alpha"));
}

#[test]
fn test_a_chain_without_identifiers_is_unchanged() {
    // Neither field is stamped unless configured, so chains written before
    // these features canonicalize and verify exactly as before.
    let integrity = HmacChainIntegrity::new(KEY_A);
    let events: Vec<AuditEvent> = (0..3).map(|n| stamp(&integrity, n)).collect();

    for event in &events {
        assert!(!event.metadata.contains_key("key_id"));
        assert!(!event.metadata.contains_key("writer"));
    }
    assert_eq!(HmacChainIntegrity::new(KEY_A).verify_chain(&events), Ok(3));
}
