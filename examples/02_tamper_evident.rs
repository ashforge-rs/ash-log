//! Tamper-evident logging with an HMAC hash chain, and what detection looks like.
//!
//! ```text
//! cargo run --features hmac-chain --example 02_tamper_evident
//! ```

use ash_log::{AuditEvent, AuditEventType, AuditIntegrity, AuditResult, HmacChainIntegrity};

/// In production this comes from a KMS or secrets manager, never a literal, and
/// never from the log it protects.
const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

fn main() {
    // --- Write a short audit trail ---------------------------------------
    let integrity = HmacChainIntegrity::new(KEY);
    let mut log: Vec<AuditEvent> = Vec::new();

    for (principal, allowed) in [
        ("alice@example.com", true),
        ("mallory@example.com", false),
        ("bob@example.com", true),
    ] {
        let mut event = AuditEvent::builder()
            .event_type(AuditEventType::AuthorizationCheck)
            .principal(principal)
            .method("transfer_funds")
            .result(if allowed {
                AuditResult::Success
            } else {
                AuditResult::Denied
            })
            .build();
        integrity.add_integrity(&mut event);
        log.push(event);
    }

    let verifier = HmacChainIntegrity::new(KEY);
    println!(
        "intact chain           -> {:?}",
        verifier.verify_chain(&log)
    );

    // --- Now attack it ----------------------------------------------------

    // 1. Rewrite a denial into a success.
    let mut edited = log.clone();
    edited[1].result = AuditResult::Success;
    println!("edited a result        -> {}", describe(&verifier, &edited));

    // 2. Delete the inconvenient entry entirely.
    let mut deleted = log.clone();
    deleted.remove(1);
    println!(
        "deleted an entry       -> {}",
        describe(&verifier, &deleted)
    );

    // 3. Re-stamp the forged entry with the library's own algorithm, but
    //    without the key. This is the attack an unkeyed checksum cannot survive.
    let mut restamped = log.clone();
    restamped[1].result = AuditResult::Success;
    restamped[1].metadata.remove("mac");
    restamped[1].metadata.remove("chain_index");
    HmacChainIntegrity::new(b"the-attackers-own-key-32-bytes!!!").add_integrity(&mut restamped[1]);
    println!(
        "re-stamped without key -> {}",
        describe(&verifier, &restamped)
    );

    // 4. Truncation is the documented limit: a prefix of a valid chain is
    //    itself valid, so it must be caught by comparing the expected length.
    let truncated = &log[..2];
    println!(
        "truncated the tail     -> {} (use --expect-count to catch this)",
        describe(&verifier, truncated)
    );

    println!("\nVerify a log file from the shell:");
    println!("  cat audit.log | ash-log-verify --key-env AUDIT_KEY --expect-count 3");
}

/// Render a verification outcome as a single line.
fn describe(verifier: &HmacChainIntegrity, events: &[AuditEvent]) -> String {
    match verifier.verify_chain(events) {
        Ok(n) => format!("VERIFIED ({n} entries)"),
        Err(e) => format!("DETECTED: {e}"),
    }
}
