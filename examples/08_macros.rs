//! Every macro in the crate, on one page.
//!
//! The macros are a shorthand over `Logger` and `AuditEvent`; nothing here is
//! unreachable through the builders. What they add is that the level check
//! happens *before* the message is formatted, and that `module_path!` is
//! captured, which `#[track_caller]` cannot see.
//!
//! ```text
//! cargo run --features hmac-chain --example 08_macros
//! ```

// Exported names carry an `ash_` prefix so `use ash_log::*` is safe next to
// `tracing` or `log`. Rename at the import site to opt into the short forms:
// `use ash_log::{ash_info as info, ash_warn as warn};`
use ash_log::{
    AuditBackend, AuditEvent, AuditResult, AuditSeverity, HmacChainIntegrity, Provenance,
    ash_audit, ash_debug, ash_error, ash_info, ash_logger, ash_trace, ash_warn,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

/// Keeps written events so the example can report on what survived.
#[derive(Default)]
struct Collector(Mutex<Vec<AuditEvent>>);

impl Collector {
    /// Drain what has been written since the last call, for reporting.
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

fn print_events(events: &[AuditEvent]) {
    for event in events {
        let kind = if event.event_type.is_security_relevant() {
            "security  "
        } else {
            "diagnostic"
        };
        let body = event
            .message
            .clone()
            .unwrap_or_else(|| format!("{:?}", event.event_type));
        println!("  [{:<8}] {kind} {body}", event.severity.to_string());
        if !event.metadata.is_empty() {
            let mut pairs: Vec<String> = event
                .metadata
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            pairs.sort();
            println!("               metadata: {}", pairs.join(" "));
        }
    }
}

fn main() {
    let collector = Arc::new(Collector::default());
    // Every event ever written, so the chain can be verified from its start.
    let mut chain: Vec<AuditEvent> = Vec::new();

    // `ash_logger!` — every key is optional and order does not matter. The
    // service identity keys build the Provenance for you, so the common case
    // never names the type.
    let logger = ash_logger!(
        backend: collector.clone(),
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
        min_level: AuditSeverity::Warning,
        service: "payments-api",
        version: env!("CARGO_PKG_VERSION"),
        host: "pod-7",
    );

    println!("min_level = {}\n", logger.min_level());

    // The five level macros. Only Warning and above survive the threshold.
    println!("diagnostics at min_level = Warning:");
    ash_trace!(logger, "connection pool statistics gathered");
    ash_debug!(logger, "cache warm complete");
    ash_info!(logger, "worker started");
    ash_warn!(logger, "token cache cold, falling back to origin");
    ash_error!(logger, "upstream ledger unreachable");
    let batch = collector.take();
    print_events(&batch);
    chain.extend(batch);

    // Format arguments are `format!`'s, including inline captures.
    println!("\nformat arguments and metadata:");
    let port = 8443;
    let (attempt, max) = (2, 5);
    ash_warn!(logger, "listening on port {port}");
    ash_error!(logger, "retry {} of {}", attempt, max);
    // Pairs after `;` become event metadata.
    ash_error!(logger, "upload failed"; retries = 3, bucket = "audit-eu");
    let batch = collector.take();
    print_events(&batch);
    chain.extend(batch);

    // Filtering happens before the arguments are evaluated, so a dropped
    // record costs an atomic load rather than an allocation. This is the
    // reason these are macros and not functions taking a String.
    let renders = Arc::new(AtomicUsize::new(0));
    let expensive = || {
        renders.fetch_add(1, Ordering::Relaxed);
        "a costly summary"
    };
    ash_debug!(logger, "{}", expensive()); // below threshold
    ash_warn!(logger, "{}", expensive()); // admitted
    println!(
        "\nformatted {} of 2 arguments — the filtered one was never rendered",
        renders.load(Ordering::Relaxed)
    );
    chain.extend(collector.take());

    // `ash_audit!` writes the security tier: never filtered, whatever the
    // threshold. The event type and result are bare variant names.
    println!("\nsecurity events (threshold still Warning):");
    ash_audit!(
        logger,
        AuthenticationAttempt,
        Success,
        principal = "alice@example.com",
        severity = AuditSeverity::Info
    );

    // Fields before `;` are builder methods; pairs after it are metadata.
    ash_audit!(logger, SecurityViolation, Denied,
        principal = "bob@example.com",
        method = "transfer",
        error = "rate limit exceeded";
        attempts = 5,
        limit = 3,
    );

    // A fully qualified result works wherever a bare variant does.
    ash_audit!(
        logger,
        ConnectionClosed,
        AuditResult::NotApplicable,
        correlation_id = "req-7f3a"
    );

    let security = collector.take();
    print_events(&security);
    chain.extend(security);

    // Raising the threshold to the maximum silences diagnostics entirely and
    // leaves the compliance record untouched.
    println!("\nat min_level = Critical:");
    logger.set_min_level(AuditSeverity::Critical);
    ash_error!(logger, "dropped: diagnostics are filtered");
    ash_audit!(
        logger,
        AdminAction,
        Success,
        method = "rotate_keys",
        severity = AuditSeverity::Trace
    );
    let final_batch = collector.take();
    print_events(&final_batch);
    chain.extend(final_batch.clone());

    // Every macro stamps call-site provenance. `capture()` supplies the thread
    // and pid; the macro adds file, line, and the module path.
    let sample = &final_batch[0];
    println!("\nprovenance on the admin action:");
    println!(
        "  {}:{} in {}",
        sample.provenance.file.as_deref().unwrap_or("?"),
        sample.provenance.line.unwrap_or(0),
        sample.provenance.module.as_deref().unwrap_or("?"),
    );
    println!(
        "  service={} version={} host={}",
        sample.provenance.service.as_deref().unwrap_or("?"),
        sample.provenance.version.as_deref().unwrap_or("?"),
        sample.provenance.host.as_deref().unwrap_or("?"),
    );

    // `buffered:` wraps the backend so writes accumulate and flush in batches,
    // trading write syscalls for latency. The buffer drains at capacity, on
    // `flush()`, and on drop.
    let batched = Arc::new(Collector::default());
    let buffered_logger = ash_logger!(
        backend: batched.clone(),
        buffered: 4,
        integrity: Arc::new(HmacChainIntegrity::new(KEY)),
    );

    println!("\nbuffered logger (capacity 4):");
    for n in 1..=3 {
        ash_info!(buffered_logger, "queued event {n}");
    }
    println!(
        "  after 3 writes -> {} reached the backend",
        batched.take().len()
    );

    ash_info!(buffered_logger, "queued event 4");
    println!(
        "  after the 4th  -> {} drained at capacity",
        batched.take().len()
    );

    ash_warn!(buffered_logger, "a partial batch");
    buffered_logger.flush();
    println!(
        "  after flush()  -> {} drained explicitly",
        batched.take().len()
    );

    // Identity that the three shorthand keys cannot express goes through an
    // explicit `identity:` key.
    let custom = ash_logger!(
        backend: collector.clone(),
        identity: Provenance::new()
            .with_service("gateway")
            .with_module("edge::ingress"),
    );
    ash_info!(custom, "explicit identity");
    // A separate logger with its own (default) integrity, so this event is not
    // part of the chain built above.
    println!(
        "\nexplicit identity -> service={:?}",
        collector.take()[0].provenance.service
    );

    // Dropped records never consumed a chain position, so everything the
    // macros admitted verifies as one unbroken chain.
    println!(
        "\nchain over all {} admitted events -> {:?}",
        chain.len(),
        HmacChainIntegrity::new(KEY).verify_chain(&chain)
    );
}
