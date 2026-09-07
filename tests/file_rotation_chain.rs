//! A hash chain that spans rotated files is still one chain.
//!
//! Rotation renames files; it does not restart the chain. Concatenating the
//! rotated files in order must therefore verify exactly as an unrotated log
//! would, or rotation would silently destroy tamper evidence.

#![cfg(feature = "hmac-chain")]

use ash_log::{AuditEvent, AuditSeverity, FileBackend, HmacChainIntegrity, Logger, RotationPolicy};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const KEY: &[u8] = b"rotation-test-key-32-bytes-long!!";

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("ash-log-rot-{name}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&path));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// Read every file in `dir` and return the events in chain order.
///
/// Ordering by `chain_index` rather than by filename is what a real consumer
/// does: rotated names embed a timestamp, but several rotations within one
/// second fall back to a numeric suffix that does not sort lexicographically
/// (`.10` before `.2`). The chain carries its own order, so use it.
fn collect_chain(dir: &Path, _live: &str) -> Vec<AuditEvent> {
    let mut events: Vec<AuditEvent> = std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.path())
        .flat_map(|path| {
            std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str::<AuditEvent>(line).expect("line parses"))
                .collect::<Vec<_>>()
        })
        .collect();

    events.sort_by_key(|e| {
        e.metadata
            .get("chain_index")
            .and_then(serde_json::Value::as_u64)
            .expect("chained events carry an index")
    });
    events
}

#[test]
fn test_a_chain_spanning_rotated_files_verifies() {
    let dir = TempDir::new("chain");
    let path = dir.0.join("audit.jsonl");

    let backend = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(400))
        .build()
        .expect("open");

    let logger = Logger::builder(Arc::new(backend))
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Trace)
        .build();

    for n in 0..40 {
        logger.info(format!("event {n}"));
    }
    logger.flush();

    let files = std::fs::read_dir(&dir.0).expect("read dir").count();
    assert!(files > 1, "the log actually rotated, found {files} file(s)");

    let events = collect_chain(&dir.0, "audit.jsonl");
    assert_eq!(events.len(), 40, "no events lost across rotation");
    assert_eq!(
        HmacChainIntegrity::new(KEY).verify_chain(&events),
        Ok(40),
        "the chain is continuous across the file boundary"
    );
}

#[test]
fn test_tampering_is_still_detected_after_rotation() {
    let dir = TempDir::new("tamper");
    let path = dir.0.join("audit.jsonl");

    let backend = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(400))
        .build()
        .expect("open");

    let logger = Logger::builder(Arc::new(backend))
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Trace)
        .build();

    for n in 0..40 {
        logger.info(format!("event {n}"));
    }
    logger.flush();

    let mut events = collect_chain(&dir.0, "audit.jsonl");
    // Edit an entry in an archived file, the one an attacker would reach for
    // precisely because it is no longer being written.
    events[3].message = Some("rewritten".to_string());

    assert!(
        HmacChainIntegrity::new(KEY).verify_chain(&events).is_err(),
        "an edit to a rotated-away entry is still detected"
    );
}

#[test]
fn test_dropping_a_rotated_file_is_detected() {
    // Deleting a whole archive is the obvious attack once a log is split, and
    // the chain must reject it rather than accept the remainder.
    let dir = TempDir::new("drop");
    let path = dir.0.join("audit.jsonl");

    let backend = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(400))
        .build()
        .expect("open");

    let logger = Logger::builder(Arc::new(backend))
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Trace)
        .build();

    for n in 0..40 {
        logger.info(format!("event {n}"));
    }
    logger.flush();

    let mut events = collect_chain(&dir.0, "audit.jsonl");
    let removed = events.remove(5);
    assert!(
        HmacChainIntegrity::new(KEY).verify_chain(&events).is_err(),
        "removing entry {:?} breaks the chain",
        removed.message
    );
}
