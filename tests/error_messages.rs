//! Error messages are part of the interface.
//!
//! A verifier's output is what an operator reads at 3am when a chain fails.
//! These assert the messages name the problem and, where there is one, the fix.

#![cfg(feature = "hmac-chain")]

use ash_log::{ChainError, RotationError};

#[test]
fn test_chain_errors_name_the_offending_entry() {
    let cases: Vec<(ChainError, &str)> = vec![
        (ChainError::MissingMac { index: 3 }, "mac"),
        (ChainError::NotCanonicalizable { index: 3 }, "canonicalized"),
        (ChainError::MissingChainIndex { index: 3 }, "chain_index"),
        (ChainError::MacMismatch { index: 3 }, "altered"),
        (ChainError::IndexMismatch { index: 3, found: 9 }, "position"),
    ];

    for (error, expected_word) in cases {
        let rendered = error.to_string();
        assert!(
            rendered.contains('3'),
            "every chain error names the entry: {rendered}"
        );
        assert!(
            rendered.contains(expected_word),
            "expected {expected_word:?} in: {rendered}"
        );
    }
}

#[test]
fn test_unknown_key_error_names_the_key() {
    let rendered = ChainError::UnknownKeyId {
        index: 2,
        key_id: "2026-q1".to_string(),
    }
    .to_string();

    assert!(rendered.contains("2026-q1"), "names the key: {rendered}");
    assert!(
        rendered.contains("does not hold"),
        "distinguishes a missing key from tampering: {rendered}"
    );
}

#[test]
fn test_rotation_errors_explain_the_refusal() {
    assert!(
        RotationError::NoKeyId.to_string().contains("with_key_id"),
        "names the method that fixes it"
    );
    assert!(
        RotationError::EmptyKey.to_string().contains("no security"),
        "says why an empty key is refused"
    );
    assert!(
        RotationError::DuplicateKeyId("k1".to_string())
            .to_string()
            .contains("k1"),
        "names the duplicated identifier"
    );
}

#[test]
fn test_chain_errors_are_comparable() {
    // Callers match on these to decide whether to alert; equality is part of
    // the contract.
    assert_eq!(
        ChainError::MacMismatch { index: 1 },
        ChainError::MacMismatch { index: 1 }
    );
    assert_ne!(
        ChainError::MacMismatch { index: 1 },
        ChainError::MacMismatch { index: 2 }
    );
}
