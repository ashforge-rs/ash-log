//! Every Rust snippet from the README, compiled as written.
use ash_log::*;
use std::sync::Arc;

#[test]
fn quick_start() {
    // Uses the real default (stdout); kept as the README shows it.
    let logger = ash_logger!();
    ash_info!(logger, "server listening on port {}", 8443);
    ash_warn!(logger, "cache miss"; key = "session:abc");
    ash_error!(logger, "upstream unreachable");
}

#[test]
fn logging_section() {
    let logger = ash_logger!(
        backend: Arc::new(StdoutAuditBackend),
        integrity: Arc::new(SequenceIntegrity::new()),
        min_level: AuditSeverity::Warning,
        service: "payments-api",
        version: env!("CARGO_PKG_VERSION"),
    );
    let _ = &logger;

    let logger = ash_logger!(backend: Arc::new(StdoutAuditBackend), buffered: 128);
    ash_info!(logger, "queued, not yet written");
    logger.flush();
}

#[test]
fn levels_section() {
    let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
    let (port, attempt, max) = (8443, 2, 5);
    ash_trace!(logger, "connection pool statistics gathered");
    ash_debug!(logger, "cache warm complete");
    ash_info!(logger, "listening on port {port}");
    ash_warn!(logger, "retry {} of {}", attempt, max);
    ash_error!(logger, "upload failed"; retries = 3, bucket = "audit-eu");
    let _ = max;
}

#[test]
fn audit_section() {
    let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
    ash_audit!(
        logger,
        AuthenticationAttempt,
        Success,
        principal = "alice@example.com"
    );

    ash_audit!(logger, SecurityViolation, Denied,
        principal = "bob@example.com",
        method = "transfer",
        error = "rate limit exceeded";
        attempts = 5,
        limit = 3,
    );
}

#[test]
fn builders_section() {
    let backend = Arc::new(NoopAuditBackend);
    let integrity = SequenceIntegrity::new();

    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::AuthenticationAttempt)
        .principal("alice@example.com")
        .method("login")
        .result(AuditResult::Success)
        .build();

    integrity.add_integrity(&mut event);
    backend.log_audit(&event);
}

#[cfg(feature = "hmac-chain")]
#[test]
fn tamper_evidence_section() {
    // The README reads the key from the environment; set it here so the
    // snippet's shape is exercised end to end.
    unsafe { std::env::set_var("AUDIT_KEY", "example-key-at-least-32-bytes!!!!") };
    let key = std::env::var("AUDIT_KEY").expect("AUDIT_KEY must be set");

    let logger = ash_logger!(
        backend: Arc::new(NoopAuditBackend),
        integrity: Arc::new(HmacChainIntegrity::new(key.as_bytes())),
    );
    ash_audit!(logger, AdminAction, Success);

    let last_mac = HmacChainIntegrity::new(key.as_bytes()).current_mac();
    let last_index = 0;
    let integrity = HmacChainIntegrity::resume(key.as_bytes(), &last_mac, last_index);
    let _ = integrity;
}

#[cfg(feature = "tracing")]
#[test]
fn tracing_section() {
    use tracing_subscriber::layer::SubscriberExt;

    let logger = Arc::new(Logger::builder(Arc::new(NoopAuditBackend)).build());
    // `.init()` would set a global subscriber and collide across tests; the
    // layer construction is what the snippet demonstrates.
    let _subscriber = tracing_subscriber::registry().with(AshLogLayer::new(logger));
    tracing::info!(user = "alice", "login succeeded");
}

#[cfg(feature = "hlc")]
#[test]
fn causal_ordering_section() {
    let logger = ash_logger!(
        backend: Arc::new(NoopAuditBackend),
        clock: Arc::new(HlcClock::new()),
    );

    ash_info!(logger, "first");
    ash_info!(logger, "second"); // provably ordered after the first

    let inbound = HlcClock::new().now().unwrap();
    logger
        .observe_hlc(inbound)
        .expect("upstream timestamp accepted");
    ash_info!(logger, "ordered after the upstream event");
}

#[test]
fn backends_and_errors_section() {
    let errors = Arc::new(CountingErrorSink::new());
    let _ = errors.clone();
    assert!(!errors.had_failures());
}

#[test]
fn scoped_context_section() {
    let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
    let _scope = Scope::new()
        .correlation_id("req-7f3a")
        .principal("alice@example.com")
        .with("tenant", "acme")
        .enter();

    ash_info!(logger, "handling request");
    ash_audit!(logger, MethodInvocation, Success, method = "transfer");
}

#[test]
fn redaction_section() {
    let logger = ash_logger!(
        backend: Arc::new(NoopAuditBackend),
        redact: Arc::new(KeyRedactor::default()),
    );
    ash_info!(logger, "login"; password = "hunter2", user = "alice");
}

#[test]
fn runtime_filtering_section() {
    let filter = LiveFilter::parse("info,my_app::db=trace,hyper=warn");
    let logger = ash_logger!(
        backend: Arc::new(NoopAuditBackend),
        filter: filter.clone(),
    );
    let _ = &logger;
    filter.reload("debug,hyper=error");
}

#[cfg(feature = "hmac-chain")]
#[test]
fn key_rotation_section() -> Result<(), RotationError> {
    const KEY_A: &[u8] = b"key-a-at-least-32-bytes-long!!!!!";
    const KEY_B: &[u8] = b"key-b-at-least-32-bytes-long!!!!!";
    let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("2026-q1");
    integrity.rotate_to(KEY_B, "2026-q2")?;
    Ok(())
}

#[cfg(feature = "hmac-chain")]
#[test]
fn one_writer_per_chain_section() {
    const KEY: &[u8] = b"key-at-least-32-bytes-long!!!!!!!";
    let integrity = HmacChainIntegrity::new(KEY).writer("api-01");
    let _ = integrity;
}

#[test]
fn composed_backends_section() -> Result<(), std::io::Error> {
    // The README uses /var/log; a scratch path exercises the same shape.
    let mut path = std::env::temp_dir();
    path.push(format!("ash-log-readme-{}.jsonl", std::process::id()));

    let file = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(64 * 1024 * 1024).keeping(10))
        .build()?;

    let backend = AsyncBackend::builder(Arc::new(file))
        .overflow(OverflowPolicy::Block)
        .build();
    drop(backend);
    drop(std::fs::remove_file(&path));
    Ok(())
}
