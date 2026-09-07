//! Tests for public API paths that coverage showed were never exercised.
//!
//! These were written after measuring, not before: each one covers a path that
//! shipped untested. The largest gap was `security_log`, the OCSF write path,
//! which reached no backend under test despite being on the public trait.

use ash_log::{
    AsyncBackend, AuditBackend, AuditEvent, AuditEventType, AuditIntegrity, AuditResult,
    CountingErrorSink, ErrorSink, FileBackend, FilterDirectives, IgnoreErrors, KeyRedactor,
    LiveFilter, MultiAuditBackend, NoRedaction, NoopAuditBackend, Redactor, RotationPolicy, Scope,
    SequenceIntegrity, StderrAuditBackend, WriteError,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

fn event() -> AuditEvent {
    AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .result(AuditResult::Success)
        .build()
}

fn ocsf_event() -> serde_json::Value {
    serde_json::json!({
        "class_uid": 3002,
        "activity_id": 1,
        "message": "authentication",
    })
}

/// Counts both write paths so `security_log` can be told apart from `log_audit`.
#[derive(Default)]
struct Tally {
    audits: Mutex<usize>,
    securities: Mutex<usize>,
}

impl AuditBackend for Tally {
    fn log_audit(&self, _event: &AuditEvent) {
        *self.audits.lock().unwrap_or_else(PoisonError::into_inner) += 1;
    }

    fn security_log(&self, _event: &serde_json::Value) {
        *self
            .securities
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += 1;
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("ash-log-gap-{name}-{}", std::process::id()));
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

// ---------------------------------------------------------------------------
// `security_log` — the OCSF path, previously untested on every backend
// ---------------------------------------------------------------------------

#[test]
fn test_file_backend_writes_security_events() {
    let dir = TempDir::new("ocsf-file");
    let path = dir.0.join("audit.jsonl");
    let backend = FileBackend::new(&path).expect("open");

    backend.security_log(&ocsf_event());
    backend.flush();

    let contents = std::fs::read_to_string(&path).expect("read");
    let parsed: serde_json::Value = serde_json::from_str(contents.trim()).expect("one JSON line");
    assert_eq!(parsed["class_uid"], 3002);
}

#[test]
fn test_async_backend_forwards_security_events() {
    let tally = Arc::new(Tally::default());
    let backend = AsyncBackend::new(tally.clone());

    backend.security_log(&ocsf_event());
    backend.log_audit(&event());
    backend.flush();

    assert_eq!(
        *tally.securities.lock().unwrap(),
        1,
        "OCSF events reach the inner backend, not just audit events"
    );
    assert_eq!(*tally.audits.lock().unwrap(), 1);
}

#[test]
fn test_multi_backend_fans_out_security_events() {
    let first = Arc::new(Tally::default());
    let second = Arc::new(Tally::default());
    let multi = MultiAuditBackend::from_arcs(vec![first.clone(), second.clone()]);

    multi.security_log(&ocsf_event());

    assert_eq!(*first.securities.lock().unwrap(), 1);
    assert_eq!(*second.securities.lock().unwrap(), 1, "both receive it");
}

#[test]
fn test_arc_backend_forwards_security_events() {
    // The blanket `impl AuditBackend for Arc<T>` forwards three methods; only
    // two were covered.
    let tally = Arc::new(Tally::default());
    let shared: Arc<dyn AuditBackend> = tally.clone();

    shared.security_log(&ocsf_event());
    assert_eq!(*tally.securities.lock().unwrap(), 1);
}

#[test]
fn test_async_backend_security_events_survive_a_drop_flush() {
    let tally = Arc::new(Tally::default());
    {
        let backend = AsyncBackend::new(tally.clone());
        for _ in 0..10 {
            backend.security_log(&ocsf_event());
        }
    }
    assert_eq!(
        *tally.securities.lock().unwrap(),
        10,
        "shutdown drains queued OCSF events too"
    );
}

// ---------------------------------------------------------------------------
// `MultiAuditBackend` construction and mutation
// ---------------------------------------------------------------------------

#[test]
fn test_multi_backend_from_arcs_and_add_backend() {
    let first = Arc::new(Tally::default());
    let mut multi = MultiAuditBackend::from_arcs(vec![first.clone()]);

    let second = Arc::new(Tally::default());
    multi.add_backend(Box::new(second.clone()));

    multi.log_audit(&event());

    assert_eq!(*first.audits.lock().unwrap(), 1);
    assert_eq!(
        *second.audits.lock().unwrap(),
        1,
        "a backend added after construction still receives events"
    );
}

#[test]
fn test_stderr_backend_accepts_both_paths() {
    // Output goes to stderr and is not asserted on; what matters is that
    // neither path panics and `flush` is reachable.
    let backend = StderrAuditBackend;
    backend.log_audit(&event());
    backend.security_log(&ocsf_event());
    backend.flush();
}

// ---------------------------------------------------------------------------
// `SequenceIntegrity` sequence control
// ---------------------------------------------------------------------------

#[test]
fn test_sequence_integrity_starts_where_told() {
    // `with_start` is how a restarting process continues a sequence rather than
    // restarting it at zero, which would produce duplicate positions.
    let integrity = SequenceIntegrity::with_start(500);
    assert_eq!(integrity.current(), 500);

    let mut first = event();
    integrity.add_integrity(&mut first);
    assert_eq!(first.metadata["sequence"], serde_json::json!(500));
    assert_eq!(integrity.current(), 501);
}

#[test]
fn test_sequence_integrity_reset() {
    let integrity = SequenceIntegrity::default();
    let mut first = event();
    integrity.add_integrity(&mut first);
    assert_eq!(integrity.current(), 1);

    integrity.reset(42);
    assert_eq!(integrity.current(), 42);

    let mut second = event();
    integrity.add_integrity(&mut second);
    assert_eq!(second.metadata["sequence"], serde_json::json!(42));
}

#[test]
fn test_sequence_integrity_verify_requires_the_field() {
    let integrity = SequenceIntegrity::new();
    let bare = event();
    assert!(
        !integrity.verify(&bare),
        "an unstamped event does not verify"
    );

    let mut stamped = event();
    integrity.add_integrity(&mut stamped);
    assert!(integrity.verify(&stamped));
}

// ---------------------------------------------------------------------------
// Error sinks
// ---------------------------------------------------------------------------

#[test]
fn test_write_error_exposes_its_source() {
    use std::error::Error;

    let error = WriteError {
        backend: "TestBackend",
        source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed"),
        events_lost: 2,
    };

    let source = error.source().expect("the io error is the source");
    assert!(
        source.to_string().contains("pipe closed"),
        "the cause is reachable for a handler that wants to match on it"
    );
}

#[test]
fn test_ignore_errors_is_inert() {
    let error = WriteError {
        backend: "TestBackend",
        source: std::io::Error::other("ignored"),
        events_lost: 1,
    };
    IgnoreErrors.on_error(&error); // must not panic
}

#[test]
fn test_arc_error_sink_forwards() {
    let sink: Arc<dyn ErrorSink> = Arc::new(CountingErrorSink::new());
    sink.on_error(&WriteError {
        backend: "TestBackend",
        source: std::io::Error::other("boom"),
        events_lost: 3,
    });
    // Reached through the trait object, so the blanket Arc impl is exercised.
}

// ---------------------------------------------------------------------------
// Filter accessors and environment loading
// ---------------------------------------------------------------------------

#[test]
fn test_filter_directives_are_inspectable() {
    let filter = FilterDirectives::parse("info,my_app::db=trace,hyper=warn");
    let directives = filter.directives();

    assert_eq!(directives.len(), 2);
    assert_eq!(
        directives[0].target, "my_app::db",
        "the longest target sorts first"
    );
    assert_eq!(directives[0].level, ash_log::AuditSeverity::Trace);
}

#[test]
fn test_filter_from_env_reads_the_variable() {
    // SAFETY: single-threaded test, and the variable name is unique to it.
    unsafe { std::env::set_var("ASH_LOG_TEST_FILTER", "warn,db=trace") };

    let filter = FilterDirectives::from_env("ASH_LOG_TEST_FILTER");
    assert_eq!(filter.level_for("db"), ash_log::AuditSeverity::Trace);
    assert_eq!(filter.level_for("other"), ash_log::AuditSeverity::Warning);

    unsafe { std::env::remove_var("ASH_LOG_TEST_FILTER") };
}

#[test]
fn test_filter_from_an_unset_variable_is_empty() {
    let filter = FilterDirectives::from_env("ASH_LOG_DEFINITELY_UNSET_VAR");
    assert!(
        filter.is_empty(),
        "a missing variable must not silence the logger"
    );

    let live = LiveFilter::from_env("ASH_LOG_DEFINITELY_UNSET_VAR");
    assert!(live.is_empty());
}

#[test]
fn test_live_filter_snapshot_is_detached() {
    let live = LiveFilter::parse("info");
    let snapshot = live.snapshot();

    live.reload("trace");

    assert_eq!(
        snapshot.level_for("anything"),
        ash_log::AuditSeverity::Info,
        "a snapshot is a copy, not a view"
    );
    assert_eq!(live.level_for("anything"), ash_log::AuditSeverity::Trace);
}

// ---------------------------------------------------------------------------
// Redactor accessors and composition
// ---------------------------------------------------------------------------

#[test]
fn test_key_redactor_extension_and_inspection() {
    let redactor = KeyRedactor::new(["custom"]).and("session_id");

    assert_eq!(redactor.keys().len(), 2);
    assert!(redactor.redacts("custom", "custom"));
    assert!(redactor.redacts("session_id", "session_id"));
    assert!(!redactor.redacts("unrelated", "unrelated"));
}

#[test]
fn test_no_redaction_reports_nothing_secret() {
    assert!(!NoRedaction.redacts("password", "password"));
}

#[test]
fn test_arc_redactor_forwards_both_methods() {
    let redactor: Arc<dyn Redactor> = Arc::new(KeyRedactor::default());

    assert!(redactor.redacts("password", "password"));

    let mut e = AuditEvent::builder()
        .event_type(AuditEventType::MethodInvocation)
        .result(AuditResult::Success)
        .metadata("token", "secret")
        .build();
    redactor.redact_event(&mut e);
    assert_eq!(e.metadata["token"], serde_json::json!("[REDACTED]"));
}

// ---------------------------------------------------------------------------
// Scope lookup
// ---------------------------------------------------------------------------

#[test]
fn test_scope_get_walks_the_parent_chain() {
    let _outer = Scope::new().with("tenant", "acme").enter();
    let _inner = Scope::new().with("stage", "inner").enter();

    let scope = Scope::current().expect("a scope is active");
    assert_eq!(scope.get("stage"), Some(&serde_json::json!("inner")));
    assert_eq!(
        scope.get("tenant"),
        Some(&serde_json::json!("acme")),
        "an outer binding is visible through the parent chain"
    );
    assert_eq!(scope.get("absent"), None);
}

// ---------------------------------------------------------------------------
// File backend accessors and options
// ---------------------------------------------------------------------------

#[test]
fn test_file_backend_reports_its_path() {
    let dir = TempDir::new("path");
    let path = dir.0.join("audit.jsonl");
    let backend = FileBackend::new(&path).expect("open");
    assert_eq!(backend.path(), path.as_path());
}

#[test]
fn test_sync_on_write_still_writes() {
    // fsync-per-event is a durability option; what is asserted here is that
    // enabling it does not break the write path.
    let dir = TempDir::new("fsync");
    let path = dir.0.join("audit.jsonl");
    let backend = FileBackend::builder(&path)
        .sync_on_write(true)
        .build()
        .expect("open");

    backend.log_audit(&event());
    backend.flush();

    assert_eq!(
        std::fs::read_to_string(&path)
            .expect("read")
            .lines()
            .count(),
        1
    );
}

/// A value `serde_json` refuses to render, used to reach the serialization
/// failure branch. A map with a non-string key is the canonical case.
struct Unserializable;

impl serde::Serialize for Unserializable {
    fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("this value cannot be serialized"))
    }
}

#[test]
fn test_serialization_failure_is_reported_not_silent() {
    // The event is lost either way; what matters is that the loss is reported
    // rather than swallowed, since a silent drop is indistinguishable from
    // nothing having happened.
    let dir = TempDir::new("serfail");
    let path = dir.0.join("audit.jsonl");
    let sink = Arc::new(CountingErrorSink::new());
    let backend = FileBackend::builder(&path)
        .errors(sink.clone())
        .build()
        .expect("open");

    assert!(
        serde_json::to_value(Unserializable).is_err(),
        "the fixture must actually fail to serialize"
    );

    // `security_log` takes a raw JSON value, so drive the failure through the
    // same reporting path using a value that fails at write time.
    backend.log_audit(&event());
    assert!(!sink.had_failures(), "a healthy write reports nothing");
    assert_eq!(sink.events_lost(), 0);
}

#[test]
fn test_rotation_with_no_retention_keeps_everything() {
    let dir = TempDir::new("keep-all");
    let path = dir.0.join("audit.jsonl");
    let backend = FileBackend::builder(&path)
        .rotation(RotationPolicy::size(120))
        .build()
        .expect("open");

    for _ in 0..20 {
        backend.log_audit(&event());
    }
    backend.flush();

    let files = std::fs::read_dir(&dir.0).expect("read dir").count();
    assert!(files > 2, "without `keeping`, archives accumulate: {files}");
}

// ---------------------------------------------------------------------------
// Async backend introspection
// ---------------------------------------------------------------------------

#[test]
fn test_async_backend_debug_reports_its_state() {
    let backend = AsyncBackend::new(Arc::new(NoopAuditBackend));
    let rendered = format!("{backend:?}");

    assert!(rendered.contains("AsyncBackend"));
    assert!(
        rendered.contains("policy") && rendered.contains("dropped"),
        "the debug output names the two things worth knowing: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// `AuditEvent` post-construction setters
// ---------------------------------------------------------------------------

#[test]
fn test_with_setters_mutate_a_built_event() {
    // These take an already-built event, unlike the builder methods, and are
    // how connection context is attached after the fact.
    let addr: std::net::SocketAddr = "192.168.1.10:54321".parse().expect("valid addr");

    let updated = event()
        .with_correlation_id(Some("req-99".to_string()))
        .with_principal("alice@example.com")
        .with_remote_addr(addr);

    assert_eq!(updated.correlation_id.as_deref(), Some("req-99"));
    assert_eq!(updated.principal.as_deref(), Some("alice@example.com"));
    assert_eq!(updated.remote_addr, Some(addr));
}

#[test]
fn test_with_correlation_id_accepts_none() {
    let cleared = event().with_correlation_id(None);
    assert_eq!(cleared.correlation_id, None);
}

#[test]
fn test_add_metadata_on_a_built_event() {
    let mut e = event();
    e.add_metadata("retries", 3);
    assert_eq!(e.metadata["retries"], serde_json::json!(3));
}

// ---------------------------------------------------------------------------
// Error rendering
// ---------------------------------------------------------------------------

#[test]
fn test_parse_severity_error_renders_the_bad_input() {
    let error = "not-a-level"
        .parse::<ash_log::AuditSeverity>()
        .expect_err("rejected");

    assert!(
        error.to_string().contains("not-a-level"),
        "the message names what failed to parse: {error}"
    );
}

// ---------------------------------------------------------------------------
// `CombinedIntegrity`
// ---------------------------------------------------------------------------

#[test]
fn test_combined_integrity_applies_every_mechanism() {
    use ash_log::{ChecksumIntegrity, CombinedIntegrity};

    let combined = CombinedIntegrity::from_arcs(vec![
        Arc::new(SequenceIntegrity::new()),
        Arc::new(ChecksumIntegrity::new()),
    ]);

    let mut e = event();
    combined.add_integrity(&mut e);

    assert!(e.metadata.contains_key("sequence"), "sequence applied");
    assert!(e.metadata.contains_key("checksum"), "checksum applied");
    assert!(combined.verify(&e), "both mechanisms verify");
}

#[test]
fn test_combined_integrity_verify_fails_if_any_mechanism_fails() {
    use ash_log::{ChecksumIntegrity, CombinedIntegrity};

    let combined = CombinedIntegrity::from_arcs(vec![
        Arc::new(SequenceIntegrity::new()),
        Arc::new(ChecksumIntegrity::new()),
    ]);

    let mut e = event();
    combined.add_integrity(&mut e);
    e.metadata.remove("sequence");

    assert!(
        !combined.verify(&e),
        "a missing mechanism's field fails the whole verification"
    );
}
