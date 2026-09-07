//! A production-shaped configuration, using everything added in 0.3.0.
//!
//! Rotating file output behind a non-blocking writer, with redaction, scoped
//! request context, per-module filtering, and write failures surfaced.
//!
//! ```text
//! cargo run --features hmac-chain --example 10_production_setup
//! ```

use ash_log::{
    AsyncBackend, AuditEvent, CountingErrorSink, FileBackend, HmacChainIntegrity, KeyRedactor,
    LiveFilter, OverflowPolicy, RotationPolicy, Scope, ash_audit, ash_debug, ash_info, ash_logger,
};
use std::path::PathBuf;
use std::sync::Arc;

const KEY: &[u8] = b"example-key-at-least-32-bytes!!!!";

/// A scratch directory removed when the example ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("ash-log-example-{}", std::process::id()));
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

fn main() {
    let dir = TempDir::new();
    let path = dir.0.join("audit.jsonl");

    // Write failures must be visible: a verified chain that lost events is a
    // complete record of an incomplete history.
    let errors = Arc::new(CountingErrorSink::new());

    // A rotating file, wrapped in a writer thread so request threads never wait
    // on the disk.
    let file = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(4096).keeping(5))
        .errors(errors.clone())
        .build()
        .expect("open the audit log");

    let backend = AsyncBackend::builder(Arc::new(file))
        .capacity(2048)
        .overflow(OverflowPolicy::Block)
        .errors(errors.clone())
        .build();

    // Per-module levels, retunable at runtime without rebuilding the logger.
    let filter = LiveFilter::parse("info");

    let logger = ash_logger!(
        backend: Arc::new(backend),
        integrity: Arc::new(
            HmacChainIntegrity::new(KEY)
                .with_key_id("2026-q1")
                .writer("api-01"),
        ),
        redact: Arc::new(KeyRedactor::default()),
        filter: filter.clone(),
        service: "payments-api",
        version: env!("CARGO_PKG_VERSION"),
    );

    // Bind request context once, at the edge. Every event inside inherits it.
    {
        let _scope = Scope::new()
            .correlation_id("req-7f3a")
            .principal("alice@example.com")
            .with("tenant", "acme")
            .enter();

        ash_info!(logger, "request received");

        // Secrets are scrubbed before the event is stamped, so the MAC covers
        // the placeholder and the log both verifies and stays clean.
        ash_info!(logger, "authenticating"; password = "hunter2", api_key = "sk-live-1");

        ash_audit!(logger, AuthenticationAttempt, Success);
        ash_audit!(logger, MethodInvocation, Success, method = "transfer");

        ash_debug!(logger, "not recorded: below the info threshold");
    }

    // Outside the scope, events carry no correlation ID.
    ash_info!(logger, "idle");

    // Retune without a restart.
    filter.reload("debug");
    ash_debug!(logger, "recorded now that the filter says debug");

    logger.flush();

    // Inspect what was written.
    let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
        .expect("read the log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parses"))
        .collect();

    println!("wrote {} events to {}\n", events.len(), path.display());
    for event in &events {
        let correlation = event.correlation_id.as_deref().unwrap_or("-");
        let body = event
            .message
            .clone()
            .unwrap_or_else(|| format!("{:?}", event.event_type));
        println!("  [{correlation:<8}] {body}");
    }

    let secrets = events.iter().find(|e| e.metadata.contains_key("password"));
    if let Some(event) = secrets {
        println!("\nredaction:");
        println!("  password = {}", event.metadata["password"]);
        println!("  api_key  = {}", event.metadata["api_key"]);
    }

    println!(
        "\nscoped context reached {} of {} events",
        events.iter().filter(|e| e.correlation_id.is_some()).count(),
        events.len()
    );

    println!(
        "chain -> {:?}",
        HmacChainIntegrity::new(KEY)
            .with_key_id("2026-q1")
            .writer("api-01")
            .verify_chain(&events)
    );

    println!(
        "write failures: {} ({} events lost)",
        errors.failures(),
        errors.events_lost()
    );

    // A missing entry is still detected, whatever else is configured.
    let mut tampered = events.clone();
    if tampered.len() > 1 {
        tampered.remove(1);
        println!(
            "after deleting one entry -> {:?}",
            HmacChainIntegrity::new(KEY)
                .with_key_id("2026-q1")
                .writer("api-01")
                .verify_chain(&tampered)
        );
    }
}
