//! Benchmarks for the claims made in the documentation.
//!
//! Each group exists to put a number on something the crate asserts:
//!
//! - Filtered records skip formatting, so a dropped log is near-free.
//! - Integrity mechanisms differ in cost, and `HmacChainIntegrity` is the
//!   expensive one.
//! - The async backend moves write latency off the calling thread.
//! - Redaction costs something, and that cost scales with payload size.
//!
//! ```text
//! cargo bench --features hmac-chain
//! ```

use ash_log::{
    AsyncBackend, AuditBackend, AuditEvent, AuditEventType, AuditIntegrity, AuditResult,
    AuditSeverity, ChecksumIntegrity, FileBackend, HmacChainIntegrity, KeyRedactor, Logger,
    NoIntegrity, NoRedaction, NoopAuditBackend, Redactor, Scope, SequenceIntegrity, ash_info,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const KEY: &[u8] = b"benchmark-key-at-least-32-bytes!!";

fn event() -> AuditEvent {
    AuditEvent::builder()
        .event_type(AuditEventType::AuthenticationAttempt)
        .principal("alice@example.com")
        .method("login")
        .result(AuditResult::Success)
        .build()
}

/// A scratch directory removed when the benchmark ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("ash-log-bench-{name}-{}", std::process::id()));
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

/// Event construction, the floor under every other measurement.
fn bench_event_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("event");

    group.bench_function("builder", |b| {
        b.iter(|| black_box(event()));
    });

    group.bench_function("diagnostic_with_provenance", |b| {
        b.iter(|| {
            black_box(
                AuditEvent::diagnostic("a message")
                    .severity(AuditSeverity::Info)
                    .build(),
            )
        });
    });

    group.bench_function("serialize_to_json", |b| {
        let event = event();
        b.iter(|| black_box(serde_json::to_string(&event).expect("serializes")));
    });

    group.finish();
}

/// The cost of each integrity mechanism, which is the main knob a deployment
/// chooses between.
fn bench_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity");

    group.bench_function("none", |b| {
        let integrity = NoIntegrity;
        b.iter_batched_ref(event, |e| integrity.add_integrity(e), BatchSize::SmallInput);
    });

    group.bench_function("sequence", |b| {
        let integrity = SequenceIntegrity::new();
        b.iter_batched_ref(event, |e| integrity.add_integrity(e), BatchSize::SmallInput);
    });

    group.bench_function("checksum", |b| {
        let integrity = ChecksumIntegrity::new();
        b.iter_batched_ref(event, |e| integrity.add_integrity(e), BatchSize::SmallInput);
    });

    group.bench_function("hmac_chain", |b| {
        let integrity = HmacChainIntegrity::new(KEY);
        b.iter_batched_ref(event, |e| integrity.add_integrity(e), BatchSize::SmallInput);
    });

    group.finish();
}

/// Verification throughput: what a CI job checking a log actually pays.
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.sample_size(20);

    for size in [100usize, 1_000, 10_000] {
        let integrity = HmacChainIntegrity::new(KEY);
        let events: Vec<AuditEvent> = (0..size)
            .map(|_| {
                let mut e = event();
                integrity.add_integrity(&mut e);
                e
            })
            .collect();

        group.throughput(criterion::Throughput::Elements(size as u64));
        group.bench_function(format!("chain_{size}"), |b| {
            let verifier = HmacChainIntegrity::new(KEY);
            b.iter(|| black_box(verifier.verify_chain(&events).expect("verifies")));
        });
    }

    group.finish();
}

/// The claim that a filtered record skips formatting entirely.
fn bench_filtering(c: &mut Criterion) {
    let mut group = c.benchmark_group("filtering");

    let logger = Logger::builder(Arc::new(NoopAuditBackend))
        .min_level(AuditSeverity::Error)
        .build();

    group.bench_function("dropped_diagnostic", |b| {
        b.iter(|| {
            ash_info!(logger, "an expensive {} to format", black_box(42));
        });
    });

    let admitting = Logger::builder(Arc::new(NoopAuditBackend))
        .min_level(AuditSeverity::Trace)
        .build();

    group.bench_function("admitted_diagnostic", |b| {
        b.iter(|| {
            ash_info!(admitting, "an expensive {} to format", black_box(42));
        });
    });

    group.finish();
}

/// End-to-end logger cost with each layer switched on, so the price of each
/// feature is visible rather than assumed.
fn bench_logger_layers(c: &mut Criterion) {
    let mut group = c.benchmark_group("logger");

    let plain = Logger::builder(Arc::new(NoopAuditBackend))
        .min_level(AuditSeverity::Trace)
        .build();
    group.bench_function("noop_backend", |b| {
        b.iter(|| plain.log(event()));
    });

    let chained = Logger::builder(Arc::new(NoopAuditBackend))
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .min_level(AuditSeverity::Trace)
        .build();
    group.bench_function("hmac_chain", |b| {
        b.iter(|| chained.log(event()));
    });

    let redacting = Logger::builder(Arc::new(NoopAuditBackend))
        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
        .redact(Arc::new(KeyRedactor::default()))
        .min_level(AuditSeverity::Trace)
        .build();
    group.bench_function("hmac_chain_and_redaction", |b| {
        b.iter(|| redacting.log(event()));
    });

    group.bench_function("hmac_chain_redaction_and_scope", |b| {
        let _scope = Scope::new()
            .correlation_id("req-7f3a")
            .principal("alice@example.com")
            .with("tenant", "acme")
            .enter();
        b.iter(|| redacting.log(event()));
    });

    group.finish();
}

/// Redaction cost against payload size: a key-name walk is O(payload).
fn bench_redaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("redaction");

    for fields in [1usize, 10, 100] {
        let mut builder = AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success);
        for n in 0..fields {
            builder = builder.metadata(format!("field_{n}"), n as u64);
        }
        let template = builder.build();

        let redactor = KeyRedactor::default();
        group.bench_function(format!("key_redactor_{fields}_fields"), |b| {
            b.iter_batched_ref(
                || template.clone(),
                |e| redactor.redact_event(e),
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("no_redaction_{fields}_fields"), |b| {
            b.iter_batched_ref(
                || template.clone(),
                |e| NoRedaction.redact_event(e),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// The claim that the async backend moves write latency off the caller.
///
/// Measured against a real file, since a noop inner backend would make the
/// comparison meaningless.
fn bench_backends(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend_write");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(6));

    let dir = TempDir::new("sync");
    let sync_backend = FileBackend::new(dir.0.join("audit.jsonl")).expect("open the audit log");
    group.bench_function("file_synchronous", |b| {
        let event = event();
        b.iter(|| sync_backend.log_audit(&event));
    });

    let async_dir = TempDir::new("async");
    let inner = FileBackend::new(async_dir.0.join("audit.jsonl")).expect("open the audit log");
    let async_backend = AsyncBackend::builder(Arc::new(inner))
        .capacity(8192)
        .build();
    group.bench_function("file_via_async_enqueue", |b| {
        let event = event();
        b.iter(|| async_backend.log_audit(&event));
    });

    let noop = NoopAuditBackend;
    group.bench_function("noop_baseline", |b| {
        let event = event();
        b.iter(|| noop.log_audit(&event));
    });

    // The case `AsyncBackend` exists for. A page-cache-backed local file is
    // fast enough that enqueueing costs more than writing, so the type only
    // pays off against a destination that is genuinely slow: a network target,
    // a congested disk, or a remote log service. `SlowBackend` stands in for
    // one at a fixed 50us.
    let slow = Arc::new(SlowBackend {
        delay: Duration::from_micros(50),
    });
    group.bench_function("slow_synchronous", |b| {
        let event = event();
        b.iter(|| slow.log_audit(&event));
    });

    // Sustained load: producers outrun the writer, the queue saturates, and
    // enqueueing blocks. `AsyncBackend` cannot beat the destination it wraps
    // when the arrival rate exceeds the drain rate — it only defers the wait.
    let via_async = AsyncBackend::builder(slow.clone()).capacity(8192).build();
    group.bench_function("slow_via_async_sustained", |b| {
        let event = event();
        b.iter(|| via_async.log_audit(&event));
    });

    group.finish();
}

/// A burst that fits the queue, which is what `AsyncBackend` is actually for:
/// a request handler emitting a handful of events should not wait on the
/// destination, even when the destination is slow.
fn bench_burst_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("burst");
    group.sample_size(20);

    const BURST: usize = 20;
    let delay = Duration::from_micros(200);

    group.bench_function("slow_synchronous", |b| {
        let slow = SlowBackend { delay };
        let event = event();
        b.iter(|| {
            for _ in 0..BURST {
                slow.log_audit(&event);
            }
        });
    });

    group.bench_function("slow_via_async", |b| {
        let event = event();
        // `iter_custom` so the backend's `Drop` — which flushes and waits for
        // the whole burst to reach the destination — falls outside the timed
        // region. What a request handler experiences is the enqueue, not the
        // drain; timing the drain would measure the destination, which is the
        // thing being avoided.
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let backend = AsyncBackend::builder(Arc::new(SlowBackend { delay }))
                    .capacity(1024)
                    .build();
                let start = std::time::Instant::now();
                for _ in 0..BURST {
                    backend.log_audit(&event);
                }
                total += start.elapsed();
                drop(backend);
            }
            total
        });
    });

    group.finish();
}

/// A backend whose write takes a fixed, non-trivial amount of time, standing in
/// for a network or congested-disk destination.
struct SlowBackend {
    delay: Duration,
}

impl AuditBackend for SlowBackend {
    fn log_audit(&self, _event: &AuditEvent) {
        std::thread::sleep(self.delay);
    }
}

/// Contended logging, which is the shape a real service produces.
fn bench_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention");
    group.sample_size(20);

    for threads in [1usize, 4, 8] {
        group.bench_function(format!("{threads}_threads_hmac_chain"), |b| {
            b.iter_custom(|iters| {
                let logger = Arc::new(
                    Logger::builder(Arc::new(NoopAuditBackend))
                        .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
                        .min_level(AuditSeverity::Trace)
                        .build(),
                );
                let per_thread = (iters as usize).div_ceil(threads);

                let start = std::time::Instant::now();
                std::thread::scope(|scope| {
                    for _ in 0..threads {
                        let logger = logger.clone();
                        scope.spawn(move || {
                            for _ in 0..per_thread {
                                logger.log(event());
                            }
                        });
                    }
                });
                start.elapsed()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_construction,
    bench_integrity,
    bench_verification,
    bench_filtering,
    bench_logger_layers,
    bench_redaction,
    bench_backends,
    bench_burst_latency,
    bench_contention,
);
criterion_main!(benches);
