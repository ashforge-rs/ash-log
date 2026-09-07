//! Logging from several threads, and why verification needs `--unordered`.
//!
//! Events are stamped under a lock but written to the backend afterwards, so a
//! log produced by multiple threads can hold entries out of chain order. Such a
//! log is untampered — but strict verification checks position and rejects it.
//!
//! ```text
//! cargo run --features hmac-chain --example 07_concurrent_logging
//! ```

use ash_log::{
    AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity, HmacChainIntegrity,
    Logger,
};
use std::sync::{Arc, Mutex, PoisonError};

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

/// Adds a little latency on write, standing in for real backend I/O.
#[derive(Default)]
struct SlowCollector(Mutex<Vec<AuditEvent>>);

impl SlowCollector {
    fn events(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl AuditBackend for SlowCollector {
    fn log_audit(&self, event: &AuditEvent) {
        // Real backends do I/O here, and that latency varies per write; that
        // variation is what opens the reordering window. Derive a pseudo-random
        // delay from the event's own chain index so the example is repeatable.
        let index = event
            .metadata
            .get("chain_index")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let jitter = index.wrapping_mul(2_654_435_761) >> 13;
        std::thread::sleep(std::time::Duration::from_micros(jitter % 500));
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
    }
}

fn main() {
    let collector = Arc::new(SlowCollector::default());
    let logger = Arc::new(
        Logger::builder(collector.clone())
            .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
            .min_level(AuditSeverity::Info)
            .build(),
    );

    std::thread::scope(|scope| {
        for worker in 0..4 {
            let logger = Arc::clone(&logger);
            scope.spawn(move || {
                for i in 0..10 {
                    logger.log(
                        AuditEvent::builder()
                            .event_type(AuditEventType::MethodInvocation)
                            .principal(format!("worker-{worker}"))
                            .method("handle_request")
                            .result(AuditResult::Success)
                            .correlation_id(format!("req-{worker}-{i}"))
                            .build(),
                    );
                }
            });
        }
    });

    let events = collector.events();
    let indices: Vec<u64> = events
        .iter()
        .map(|e| {
            e.metadata
                .get("chain_index")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX)
        })
        .collect();
    let in_order = indices.windows(2).all(|w| w[0] < w[1]);

    println!("{} events from 4 threads", events.len());
    println!("written in chain order? {in_order}");
    println!(
        "first indices as written: {:?}",
        &indices[..12.min(indices.len())]
    );

    let verifier = HmacChainIntegrity::new(KEY);
    println!("\nverify_chain (strict, position-checked):");
    match verifier.verify_chain(&events) {
        Ok(n) => println!("  Ok({n})"),
        Err(e) => println!("  {e}"),
    }

    println!("\nverify_unordered (sorts by chain_index first):");
    match verifier.verify_unordered(&events) {
        Ok(n) => println!("  Ok({n}) — the log was never tampered with"),
        Err(e) => println!("  {e}"),
    }

    // Sorting does not weaken detection.
    let mut tampered = events.clone();
    tampered[3].principal = Some("mallory".to_string());
    println!("\nafter editing one entry, verify_unordered still rejects it:");
    match verifier.verify_unordered(&tampered) {
        Ok(n) => println!("  Ok({n}) — BUG: tampering went undetected!"),
        Err(e) => println!("  {e}"),
    }

    println!("\nFrom the shell, use --unordered for logs written concurrently:");
    println!("  cat audit.log | ash-log-verify --key-env AUDIT_KEY --unordered");
}
