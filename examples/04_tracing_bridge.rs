//! Routing ordinary `tracing` logs into a tamper-evident chain.
//!
//! Application logging — including from third-party crates already using
//! `tracing` or the `log` facade — becomes signed and verifiable, while keeping
//! its level, module, source location, and structured fields.
//!
//! ```text
//! cargo run --features "tracing hmac-chain" --example 04_tracing_bridge
//! ```

use ash_log::{
    AshLogLayer, AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity,
    HmacChainIntegrity, Logger, Provenance,
};
use std::sync::{Arc, Mutex, PoisonError};
use tracing_subscriber::layer::SubscriberExt as _;

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

#[derive(Default)]
struct Collector(Mutex<Vec<AuditEvent>>);

impl Collector {
    fn events(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
    let logger = Arc::new(
        Logger::builder(collector.clone())
            .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
            .min_level(AuditSeverity::Info)
            .identity(Provenance::new().with_service("checkout-api"))
            .build(),
    );

    let subscriber = tracing_subscriber::registry().with(AshLogLayer::new(Arc::clone(&logger)));

    tracing::subscriber::with_default(subscriber, || {
        // Ordinary application logging. Structured fields are preserved.
        tracing::debug!(pool_size = 8, "dropped: below the Info threshold");
        tracing::info!(user = "alice", cart_items = 3, "checkout started");
        tracing::warn!(retries = 2, "payment gateway slow");
        tracing::error!(order = "ord-7781", "payment declined");

        // A security decision is logged directly, never through the bridge, so
        // it keeps a real classification and bypasses level filtering.
        logger.log(
            AuditEvent::builder()
                .event_type(AuditEventType::AuthorizationCheck)
                .principal("alice@example.com")
                .method("place_order")
                .result(AuditResult::Success)
                .build(),
        );
    });

    let events = collector.events();
    println!("captured {} events\n", events.len());

    for event in &events {
        let tier = if event.event_type.is_security_relevant() {
            "security"
        } else {
            "diagnostic"
        };
        let where_from = match (&event.provenance.module, event.provenance.line) {
            (Some(module), Some(line)) => format!("{module}:{line}"),
            _ => "-".to_string(),
        };
        println!(
            "[{:<7}] {:<10} {:<34} from {where_from}",
            event.severity.to_string(),
            tier,
            event.message.as_deref().unwrap_or("<security event>"),
        );
        if !event.metadata.is_empty() {
            let fields: Vec<String> = event
                .metadata
                .iter()
                .filter(|(k, _)| k.as_str() != "mac" && k.as_str() != "chain_index")
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            if !fields.is_empty() {
                println!("            fields: {}", fields.join(" "));
            }
        }
    }

    println!(
        "\nwhole chain verifies -> {:?}",
        HmacChainIntegrity::new(KEY).verify_chain(&events)
    );
    println!("note: bridged events are always diagnostics, so application logging");
    println!("      can never claim a security classification it has not earned.");
}
