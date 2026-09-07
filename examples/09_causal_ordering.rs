//! Ordering events by causality rather than by a system clock.
//!
//! `timestamp` comes from the system clock, which can move backwards: NTP steps
//! it, a VM resumes from a snapshot, an operator corrects it. The log still
//! verifies when that happens, but its timestamps stop describing the order
//! things occurred in. A Hybrid Logical Clock timestamp is monotonic by
//! construction, and lives inside the signed canonical form.
//!
//! ```text
//! cargo run --features "hlc hmac-chain" --example 09_causal_ordering
//! ```

use ash_log::{
    AuditBackend, AuditEvent, EventClock, HlcClock, HmacChainIntegrity, Logger, ash_audit,
    ash_info, ash_logger,
};
use std::sync::{Arc, Mutex, PoisonError};

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

#[derive(Default)]
struct Collector(Mutex<Vec<AuditEvent>>);

impl Collector {
    fn take(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .split_off(0)
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

fn show(label: &str, events: &[AuditEvent]) {
    println!("{label}");
    for event in events {
        let clock = event.hlc.expect("a clock is configured");
        println!(
            "  ({:>20}, {}) {}",
            clock.physical,
            clock.logical,
            event
                .message
                .clone()
                .unwrap_or_else(|| format!("{:?}", event.event_type)),
        );
    }
}

fn main() {
    // One service: a shared clock stamps every event with a monotonic
    // timestamp, inside the signed form.
    let collector = Arc::new(Collector::default());
    let gateway_clock = Arc::new(HlcClock::new());
    let gateway = ash_logger!(
        backend: collector.clone(),
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
        clock: gateway_clock.clone(),
        service: "gateway",
    );

    ash_info!(gateway, "request received");
    ash_audit!(gateway, AuthenticationAttempt, Success, principal = "alice");
    ash_info!(gateway, "forwarding to payments");

    let gateway_events = collector.take();
    show("gateway:", &gateway_events);

    // Timestamps are strictly increasing, so the order is recoverable from the
    // log alone — no reliance on the entries' arrival order.
    let stamps: Vec<EventClock> = gateway_events
        .iter()
        .map(|e| e.hlc.expect("stamped"))
        .collect();
    assert!(stamps.windows(2).all(|w| w[0].happened_before(w[1])));
    println!("  -> strictly increasing\n");

    // A second service. Its wall clock is irrelevant: what orders its events
    // after the gateway's is `observe_hlc` on the inbound timestamp.
    let downstream = ash_logger!(
        backend: collector.clone(),
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
        clock: Arc::new(HlcClock::new()),
        service: "payments",
    );

    // The gateway stamps the outgoing request; the payments service observes it.
    let handoff = gateway.hlc_now().expect("clock is configured");
    downstream
        .observe_hlc(handoff)
        .expect("upstream timestamp accepted");

    ash_info!(downstream, "request accepted from gateway");
    ash_audit!(downstream, MethodInvocation, Success, method = "transfer");

    let downstream_events = collector.take();
    show(
        "payments (after observing the gateway's timestamp):",
        &downstream_events,
    );

    let last_gateway = stamps.last().copied().expect("gateway logged");
    let first_downstream = downstream_events[0].hlc.expect("stamped");
    println!(
        "  -> every payments event is provably after the gateway's: {}",
        last_gateway.happened_before(first_downstream)
    );

    // The timestamp is part of the canonical form, so backdating an entry to
    // hide the true order breaks the chain.
    println!("\nbackdating an entry to reorder the record:");
    let mut tampered = downstream_events;
    tampered[1].hlc = Some(EventClock {
        physical: 1,
        logical: 0,
    });
    println!(
        "  {:?}",
        HmacChainIntegrity::new(KEY).verify_chain(&tampered)
    );

    // A logger without a clock writes no `hlc` field at all, so logs and chains
    // from either configuration verify with the same code.
    let plain = Logger::builder(collector.clone()).build();
    plain.info("no clock configured");
    println!(
        "\nwithout a clock -> hlc field is {:?}",
        collector.take()[0].hlc
    );
}
