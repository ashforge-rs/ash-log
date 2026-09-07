//! Recording — and proving — where an event came from.
//!
//! Provenance is a field on the event, not loose metadata, so it is inside the
//! signed canonical form. Rewriting where an action came from fails
//! verification.
//!
//! ```text
//! cargo run --features hmac-chain --example 05_provenance
//! ```

use ash_log::{
    AuditEvent, AuditEventType, AuditIntegrity, AuditResult, HmacChainIntegrity, Provenance,
};

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

fn main() {
    let integrity = HmacChainIntegrity::new(KEY);

    // Call-site fields are captured automatically by `diagnostic`, which is
    // `#[track_caller]`; service identity is normally set once on a Logger.
    let mut event = AuditEvent::diagnostic("nightly reconciliation finished")
        .provenance(
            Provenance::capture()
                .with_module(module_path!())
                .with_service("ledger-worker")
                .with_version(env!("CARGO_PKG_VERSION"))
                .with_host("node-eu-west-1a"),
        )
        .build();
    integrity.add_integrity(&mut event);

    let p = &event.provenance;
    println!("emitted from");
    println!("  file    {}", p.file.as_deref().unwrap_or("-"));
    println!("  line    {}", p.line.map_or("-".into(), |l| l.to_string()));
    println!("  module  {}", p.module.as_deref().unwrap_or("-"));
    println!("  thread  {}", p.thread.as_deref().unwrap_or("-"));
    println!("  pid     {}", p.pid.map_or("-".into(), |v| v.to_string()));
    println!("  service {}", p.service.as_deref().unwrap_or("-"));
    println!("  version {}", p.version.as_deref().unwrap_or("-"));
    println!("  host    {}", p.host.as_deref().unwrap_or("-"));

    // Provenance is signed, so it cannot be quietly rewritten.
    let verifier = HmacChainIntegrity::new(KEY);
    let line = serde_json::to_string(&event).expect("serializes");
    println!(
        "\nas written -> {:?}",
        verifier.verify_chain(std::slice::from_ref(&event))
    );

    println!("\nrewriting provenance in the log file:");
    for (label, from, to) in [
        ("host", "node-eu-west-1a", "node-us-east-1c"),
        ("service", "ledger-worker", "test-harness"),
    ] {
        let forged: AuditEvent =
            serde_json::from_str(&line.replace(from, to)).expect("still valid JSON");
        let outcome = match verifier.verify_chain(std::slice::from_ref(&forged)) {
            Ok(_) => "VERIFIED — provenance was not protected!".to_string(),
            Err(e) => format!("DETECTED: {e}"),
        };
        println!("  changed {label:<8} -> {outcome}");
    }

    // Provenance costs nothing when unused: it serializes away entirely.
    let plain = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .result(AuditResult::Success)
        .build();
    let plain_line = serde_json::to_string(&plain).expect("serializes");
    println!(
        "\nevent without provenance contains \"provenance\": {}",
        plain_line.contains("provenance")
    );
}
