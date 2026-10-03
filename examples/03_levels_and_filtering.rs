//! Level filtering and the two-tier admission policy.
//!
//! Security events are always recorded; only diagnostics are filtered. This
//! exists so an operational setting cannot shrink the compliance record.
//!
//! ```text
//! cargo run --features hmac-chain --example 03_levels_and_filtering
//! ```

use ash_log::{
    AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity, HmacChainIntegrity,
    Logger, Provenance,
};
use std::sync::{Arc, Mutex, PoisonError};

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

/// Keeps written events so the example can report on what survived.
#[derive(Default)]
struct Collector(Mutex<Vec<AuditEvent>>);

impl Collector {
    fn take(&self) -> Vec<AuditEvent> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl AuditBackend for Collector {
    fn log_audit(&self, event: &AuditEvent) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
    }
}

fn main() {
    let collector = Arc::new(Collector::default());
    let logger = Logger::builder(collector.clone())
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Warning)
        .identity(
            Provenance::new()
                .with_service("payments-api")
                .with_version(env!("CARGO_PKG_VERSION")),
        )
        .build();

    println!("min_level = {}\n", logger.min_level());

    // Diagnostics: only Warning and above survive.
    logger.trace("connection pool statistics gathered");
    logger.debug("cache warm complete");
    logger.info("worker started");
    logger.warn("token cache cold, falling back to origin");
    logger.error("upstream ledger unreachable");

    // Security events: written regardless of the threshold. Note the severity
    // here is Info, well below the Warning threshold.
    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .principal("alice@example.com")
            .result(AuditResult::Success)
            .severity(AuditSeverity::Info)
            .build(),
    );

    let written = collector.take();
    println!("wrote {} of 6 events:", written.len());
    for event in &written {
        let kind = if event.event_type.is_security_relevant() {
            "security "
        } else {
            "diagnostic"
        };
        println!(
            "  [{:<8}] {kind}  {}",
            event.severity.to_string(),
            event.message.as_deref().unwrap_or("<security event>")
        );
    }

    // Dropping diagnostics must not gap the chain: filtering happens before
    // integrity metadata is attached.
    println!(
        "\nchain over the surviving events -> {:?}",
        HmacChainIntegrity::new(KEY).verify_chain(&written)
    );

    // The threshold is adjustable at runtime.
    println!("\nlowering the threshold to Debug:");
    logger.set_min_level(AuditSeverity::Debug);
    logger.debug("now this is recorded");
    for event in &collector.take() {
        println!(
            "  [{:<8}] {}",
            event.severity.to_string(),
            event.message.as_deref().unwrap_or("")
        );
    }

    // Even at the most restrictive setting, security events still land.
    println!("\nraising the threshold to Critical:");
    logger.set_min_level(AuditSeverity::Critical);
    logger.error("dropped: diagnostics are filtered");
    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::SecurityViolation)
            .method("rate_limit")
            .result(AuditResult::Violation)
            .severity(AuditSeverity::Trace) // the lowest severity there is
            .build(),
    );
    let final_batch = collector.take();
    println!(
        "  {} event(s) written — the violation survives a Critical filter",
        final_batch.len()
    );
}
