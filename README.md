# ash-log

[![CI](https://github.com/ashforge-rs/ash-log/actions/workflows/rust.yml/badge.svg)](https://github.com/ashforge-rs/ash-log/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/ash-log.svg)](https://crates.io/crates/ash-log)
[![docs.rs](https://docs.rs/ash-log/badge.svg)](https://docs.rs/ash-log)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Structured logging for Rust, with a security audit extension.

Application logs and security events share one pipeline: both are structured
JSON-lines records with levels, provenance, and pluggable backends. Security
events additionally bypass level filtering and can be committed to a keyed hash
chain, making after-the-fact modification detectable.

## Quick start

```toml
[dependencies]
ash-log = "0.1"
```

```rust
use ash_log::*;

let logger = ash_logger!();

ash_info!(logger, "server listening on port {}", 8443);
ash_warn!(logger, "cache miss"; key = "session:abc");
ash_error!(logger, "upstream unreachable");
```

Minimum supported Rust version: **1.88**.

## Contents

- [Logging](#logging)
- [Audit events](#audit-events)
- [Backends](#backends)
- [Scoped context](#scoped-context)
- [Redaction](#redaction)
- [Runtime filtering](#runtime-filtering)
- [Causal ordering](#causal-ordering)
- [Integrity mechanisms](#integrity-mechanisms)
- [Tamper evidence](#tamper-evidence)
- [Event structure](#event-structure)
- [Performance](#performance)
- [Feature flags](#feature-flags)
- [Examples](#examples)
- [Development](#development)

## Logging

`ash_logger!` builds a logger from named parts. Every key is optional and order
does not matter:

```rust
use ash_log::*;
use std::sync::Arc;

let logger = ash_logger!(
    backend: Arc::new(StdoutAuditBackend),
    integrity: Arc::new(SequenceIntegrity::new()),
    min_level: AuditSeverity::Warning,
    service: "payments-api",
    version: env!("CARGO_PKG_VERSION"),
);
```

The `service`, `version`, and `host` keys assemble the service identity stamped
on every event. A `buffered:` key wraps the backend so writes accumulate and
flush in batches:

```rust
# use ash_log::*; use std::sync::Arc;
let logger = ash_logger!(backend: Arc::new(StdoutAuditBackend), buffered: 128);

ash_info!(logger, "queued, not yet written");
logger.flush(); // drains; so does reaching capacity, or dropping the logger
```

Events still queued are lost if the process exits without unwinding, so call
`flush()` on shutdown paths that bypass destructors.

### Levels

Five macros cover the diagnostic tier. They take `format!` arguments, and pairs
after a `;` become event metadata:

```rust
# use ash_log::*; use std::sync::Arc;
# let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
# let (port, attempt, max) = (8443, 2, 5);
ash_trace!(logger, "connection pool statistics gathered");
ash_debug!(logger, "cache warm complete");
ash_info!(logger, "listening on port {port}");
ash_warn!(logger, "retry {} of {}", attempt, max);
ash_error!(logger, "upload failed"; retries = 3, bucket = "audit-eu");
```

Levels are `Trace < Debug < Info < Warning < Error < Critical`. The threshold is
set with `min_level` and adjustable at runtime via `set_min_level`. These macros
check the level *before* evaluating their arguments, so a filtered record costs
an atomic load rather than an allocation.

Every macro records call-site provenance: file, line, module, thread, and pid.

### Naming

Macros are exported with an `ash_` prefix so `use ash_log::*` is safe alongside
other logging crates. Rename at the import site for the short forms:

```rust
use ash_log::{ash_info as info, ash_warn as warn, ash_error as error};
```

Expansions refer to this crate through `$crate`, so renaming or shadowing at the
call site cannot change what a macro resolves to.

### Capturing `tracing` events (`tracing` feature)

`AshLogLayer` routes `tracing` events into a `Logger`, so logging from
third-party crates flows through the same pipeline:

```rust
use ash_log::*;
use std::sync::Arc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

let logger = Arc::new(Logger::builder(Arc::new(StdoutAuditBackend)).build());
tracing_subscriber::registry().with(AshLogLayer::new(logger)).init();

tracing::info!(user = "alice", "login succeeded");
```

Levels map `TRACE→Trace` … `ERROR→Error`, and named fields become metadata.
Bridged events are always `Diagnostic` records — a diagnostic cannot claim a
security classification it has not earned.

## Audit events

`ash_audit!` writes the security tier: authentication, authorization, method
invocations, configuration changes, and policy violations. Fields before the `;`
are builder methods; pairs after it are metadata:

```rust
# use ash_log::*; use std::sync::Arc;
# let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
ash_audit!(logger, AuthenticationAttempt, Success,
    principal = "alice@example.com");

ash_audit!(logger, SecurityViolation, Denied,
    principal = "bob@example.com",
    method = "transfer",
    error = "rate limit exceeded";
    attempts = 5,
    limit = 3,
);
```

Security events are written regardless of the level threshold, so an operational
setting cannot shrink the audit record. Only `Diagnostic` events are filtered.

Filtering happens *before* integrity metadata is attached. A dropped event that
had already been stamped would leave a gap in the hash chain, and the log would
then fail to verify despite being untampered. `Logger::log` enforces that order.

The builders underneath are public, if you prefer them to the macros:

```rust
use ash_log::*;
use std::sync::Arc;

let backend = Arc::new(StdoutAuditBackend);
let integrity = SequenceIntegrity::new();

let mut event = AuditEvent::builder()
    .event_type(AuditEventType::AuthenticationAttempt)
    .principal("alice@example.com")
    .method("login")
    .result(AuditResult::Success)
    .build();

integrity.add_integrity(&mut event);
backend.log_audit(&event);
```

## Backends

| Backend | Description |
|---------|-------------|
| `StdoutAuditBackend` | JSON lines to stdout |
| `StderrAuditBackend` | JSON lines to stderr |
| `FileBackend` | Appends to a file, with size/age rotation and retention |
| `AsyncBackend` | Moves writes to a dedicated thread, with bounded backpressure |
| `MultiAuditBackend` | Fan-out to several backends at once |
| `BufferedAuditBackend` | Buffers in memory until full, flushed, or dropped |
| `NoopAuditBackend` | Discards events — testing only |

Implement `AuditBackend` for anything else. `Arc<dyn AuditBackend>` implements
the trait, so backends compose — a rotating file behind a writer thread is the
usual production shape:

```rust,no_run
# use ash_log::*; use std::sync::Arc;
let file = FileBackend::builder("/var/log/audit.jsonl")
    .rotation(RotationPolicy::size(64 * 1024 * 1024).keeping(10))
    .build()?;

let backend = AsyncBackend::builder(Arc::new(file))
    .overflow(OverflowPolicy::Block)
    .build();
# Ok::<(), std::io::Error>(())
```

`FileBackend::reopen()` closes and reopens the path, which is what `logrotate`
needs after moving a file aside — wire it to `SIGHUP`.

`AsyncBackend` requires an `OverflowPolicy` decision: `Block` never loses an
event but can stall producers under sustained overload; `DropAndReport` stays
responsive and reports every discard.

It pays off for **bursts to a slow destination** — 20 events to a 200µs-per-write
target take 6.15ms synchronously against 24µs enqueued. It does *not* help under
sustained load beyond the drain rate, and wrapping a fast local file is a net
loss (~1.9µs to enqueue against ~1.1µs to write). See [Performance](#performance).

### Write failures

`log_audit` returns `()`, so a full disk would otherwise end the audit trail in
silence — tamper evidence proves nothing was *edited*, not that anything was
*written*. Backends report failures to an `ErrorSink`:

```rust
# use ash_log::*; use std::sync::Arc;
let errors = Arc::new(CountingErrorSink::new());
# let _ = errors.clone();

// ... later, alongside chain verification:
assert!(!errors.had_failures(), "the audit record is incomplete");
```

`StderrErrorSink`, `FnErrorSink`, and `IgnoreErrors` (the default) are also
provided.

## Scoped context

Binding a correlation ID to every call by hand means it goes missing from
exactly the events that need it. A `Scope` binds fields for a region, and events
recorded inside inherit them:

```rust
# use ash_log::*; use std::sync::Arc;
# let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
let _scope = Scope::new()
    .correlation_id("req-7f3a")
    .principal("alice@example.com")
    .with("tenant", "acme")
    .enter();

ash_info!(logger, "handling request");
ash_audit!(logger, MethodInvocation, Success, method = "transfer");
```

Nested scopes inherit and shadow. An explicit value on an event always wins — a
scope supplies defaults, it never overwrites what a call site stated.

Scopes are thread-local, and a spawned thread starts clean: implicit inheritance
would attach a stale correlation ID to unrelated work. Carry one across a
boundary explicitly with `Scope::current()` and `ScopeFields::enter()`.

## Redaction

Nothing stops a password reaching the log by default. A `Redactor` scrubs
secrets *before* the event is stamped, so the MAC covers the placeholder — a
value scrubbed afterwards would leak and fail verification:

```rust
# use ash_log::*; use std::sync::Arc;
let logger = ash_logger!(
    backend: Arc::new(StdoutAuditBackend),
    redact: Arc::new(KeyRedactor::default()),
);

// `password` is on the default denylist.
ash_info!(logger, "login"; password = "hunter2", user = "alice");
```

`KeyRedactor` matches a 17-entry default denylist case-insensitively, ignoring
separators so `X-API-Key`, `x_api_key`, and `apiKey` all match. Use `.exact()`
for equality matching, `.and()` to extend the list, or `FnRedactor` for
arbitrary logic.

A key-name denylist cannot recognise a secret under an innocuous name, or one
embedded in free text. Treat it as a backstop, not a licence to pass credentials
to the logger.

## Runtime filtering

A single threshold forces a choice between one noisy module and visibility
everywhere else. `FilterDirectives` takes `RUST_LOG`-style strings:

```rust
# use ash_log::*; use std::sync::Arc;
let filter = LiveFilter::parse("info,my_app::db=trace,hyper=warn");
let logger = ash_logger!(
    backend: Arc::new(StdoutAuditBackend),
    filter: filter.clone(),
);

// Retune a running logger without rebuilding it.
filter.reload("debug,hyper=error");
```

The most specific directive wins regardless of the order it was written in, and
prefix matching respects `::` boundaries, so `my_app` does not capture
`my_application`. A malformed directive is skipped rather than fatal.

Filters constrain diagnostics only. Security events are admitted whatever any
directive says.

## Causal ordering

`timestamp` comes from the system clock, which can move backwards — NTP steps
it, a VM resumes from a snapshot, an operator corrects it by hand. The log keeps
verifying when that happens, because `chain_index` is monotonic regardless, but
its timestamps stop describing the order events actually occurred in.

The `hlc` feature adds a Hybrid Logical Clock timestamp that is monotonic by
construction:

```toml
[dependencies]
ash-log = { version = "0.1", features = ["hlc"] }
```

```rust
# use ash_log::*; use std::sync::Arc;
let logger = ash_logger!(
    backend: Arc::new(StdoutAuditBackend),
    clock: Arc::new(HlcClock::new()),
);

ash_info!(logger, "first");
ash_info!(logger, "second"); // provably ordered after the first
```

Across services, `observe_hlc` carries the ordering over a request boundary.
The caller stamps an outgoing request with `hlc_now()`; the receiver observes
that timestamp before recording its own events, which are then provably ordered
after the caller's — without the two hosts' clocks agreeing:

```rust
# use ash_log::*; use std::sync::Arc;
# let logger = ash_logger!(backend: Arc::new(NoopAuditBackend), clock: Arc::new(HlcClock::new()));
# let inbound = HlcClock::new().now().unwrap();
logger.observe_hlc(inbound).expect("upstream timestamp accepted");
ash_info!(logger, "ordered after the upstream event");
```

The timestamp is part of the canonical form, so it is covered by the integrity
mechanism: backdating an entry to disguise the true order breaks the chain.

Events written without a clock carry no `hlc` field, and their canonical bytes
are unchanged, so logs produced with and without this feature verify with the
same code. A clock error never costs an event — the record is written without
the field rather than dropped.

## Integrity mechanisms

| Mechanism | Guarantee |
|-----------|-----------|
| `NoIntegrity` | None |
| `SequenceIntegrity` | Monotonic sequence numbers for ordering |
| `ChecksumIntegrity` | Unkeyed hash — detects corruption, not tampering |
| `CombinedIntegrity` | Composes several mechanisms |
| `HmacChainIntegrity` | Keyed HMAC-SHA256 chain — the only tamper-evident option (feature `hmac-chain`) |

`ChecksumIntegrity` uses an unkeyed hash covering a subset of fields. Anyone
editing a log line can recompute it, so it detects accidental corruption and
truncated writes, not deliberate modification.

## Tamper evidence

Enable the `hmac-chain` feature for logs that must resist deliberate
modification:

```toml
[dependencies]
ash-log = { version = "0.1", features = ["hmac-chain"] }
```

Each entry is stamped with `mac = HMAC-SHA256(key, prev_mac || canonical(event))`
and a `chain_index`. The MAC covers the entire event and is keyed with a secret,
so no field can be altered silently; because it also covers the previous MAC,
entries cannot be deleted, reordered, or inserted.

```rust
use ash_log::*;
use std::sync::Arc;

// Load the key from a KMS or secrets manager. Use at least 32 random bytes,
// and never write it to the log it protects.
let key = std::env::var("AUDIT_KEY").expect("AUDIT_KEY must be set");

let logger = ash_logger!(
    backend: Arc::new(StdoutAuditBackend),
    integrity: Arc::new(HmacChainIntegrity::new(key.as_bytes())),
);
```

Across a restart, resume the chain rather than starting a new one. Persist
`current_mac()` and the last index at shutdown, then:

```rust
let integrity = HmacChainIntegrity::resume(key.as_bytes(), &last_mac, last_index);
```

### Key rotation

Name the signing key, then rotate without restarting the chain. Entries signed
with the retired key still verify, because it is retained:

```rust
# use ash_log::*;
# const KEY_A: &[u8] = b"key-a-at-least-32-bytes-long!!!!!";
# const KEY_B: &[u8] = b"key-b-at-least-32-bytes-long!!!!!";
let mut integrity = HmacChainIntegrity::new(KEY_A).with_key_id("2026-q1");
// ... events signed with the first key ...
integrity.rotate_to(KEY_B, "2026-q2")?;
// ... the chain continues; the whole stream still verifies in one pass.
# Ok::<(), RotationError>(())
```

`key_id` is stamped before hashing, so relabelling an entry to point at an
attacker-controlled key is detected. A verifier lacking a retired key reports
`ChainError::UnknownKeyId` rather than a misleading MAC mismatch.

### One writer per chain

Two processes must never share a chain: each keeps its own index and
previous-MAC state, so their entries interleave into a stream that verifies as
tampered. Name each writer to make that mistake diagnosable:

```rust
# use ash_log::*;
# const KEY: &[u8] = b"key-at-least-32-bytes-long!!!!!!!";
let integrity = HmacChainIntegrity::new(KEY).writer("api-01");
```

A mixed stream then reports `ChainError::MixedWriters`, naming both writers,
instead of a bare MAC mismatch that reads as an attack. Give each process its
own chain, its own key, or serialize writes through one process.

### Verifying

`ash-log-verify` reads JSON-lines events from stdin:

```bash
cargo install ash-log --features hmac-chain

cat audit.log | ash-log-verify --key-env AUDIT_KEY
# OK: 1043 entries verified, chain intact (last chain_index 1042)
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Chain verified |
| `1` | Tampering detected |
| `2` | Usage or input error |

Key sources are `--key-env <VAR>` (recommended), `--key-file <PATH>`, or
`--key <SECRET>` (visible in the process list). Use `--quiet` in scripts to rely
on the exit code alone.

### Scope

| Attack | Detected |
|--------|----------|
| Editing any field of any entry | Yes |
| Deleting, reordering, or inserting entries | Yes |
| Re-stamping a forged entry without the key | Yes |
| Removing entries from the end (truncation) | Only with `--expect-count <N>` |
| An attacker holding the key | No |

A prefix of a valid chain is itself a valid chain, so truncation cannot be
detected from the log alone. Pass `--expect-count`, or compare the reported
`last chain_index` against a count recorded elsewhere.

Events are stamped under a lock but written afterwards, so concurrent producers
can reach the log out of chain order. Such a log is untampered, but strict
verification rejects it because it checks position. Pass `--unordered` (or use
`verify_unordered`) when several threads share a chain; it sorts by
`chain_index` first and still rejects edits, deletions, and replays.

Tampering is made detectable, not impossible. Ship entries off-box or to WORM
storage promptly, so an attacker never controls the only copy.

## Event structure

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `SystemTime` | Nanosecond-precision event time |
| `event_type` | Enum | `Diagnostic`, or one of nine security event types |
| `result` | Enum | `success`, `failure`, `denied`, `violation`, `not_applicable` |
| `severity` | Enum | `trace`, `debug`, `info`, `warning`, `error`, `critical` |
| `message` | `Option<String>` | Human-readable text, mainly on diagnostics |
| `principal` | `Option<String>` | Authenticated user or principal |
| `method` | `Option<String>` | Method or resource name |
| `correlation_id` | `Option<String>` | Correlation ID across a request chain |
| `remote_addr` | `Option<SocketAddr>` | Client address |
| `params` | `Option<Value>` | Sanitized request parameters |
| `error` | `Option<String>` | Error detail where applicable |
| `metadata` | `HashMap` | Additional context, plus integrity fields |
| `provenance` | `Provenance` | File, line, module, thread, pid, service identity |
| `hlc` | `Option<EventClock>` | Monotonic causal timestamp (feature `hlc`) |

`provenance` is part of the canonical form rather than free-form metadata, so it
is covered by the integrity mechanism: rewriting where an action came from fails
verification.

## Performance

Measured with `cargo bench --features hmac-chain` on a single machine; treat the
ratios as meaningful and the absolute numbers as indicative.

### Where the time goes

| Operation | Cost |
|---|---|
| Build an event | 112 ns |
| Serialize to JSON | 319 ns |
| `SequenceIntegrity` | 88 ns |
| `ChecksumIntegrity` | 218 ns |
| **`HmacChainIntegrity`** | **4.46 µs** |
| Redaction, 10 metadata fields | 1.69 µs |
| Write one line to a file | 1.18 µs |

Tamper evidence dominates everything else: a full `Logger::log` with an HMAC
chain costs ~4.6 µs, of which ~97% is the MAC. Budget for that, or pick a
cheaper mechanism where the compliance record does not need to resist deliberate
modification.

Verification runs at roughly **220 000 entries/second**, so a million-entry log
checks in about 4.5 seconds.

### Filtering is nearly free

A dropped diagnostic costs **2.7 ns** against 1.18 µs for an admitted one — a
440x difference. The level check happens before the format arguments are
evaluated, so leaving `trace!` calls in hot paths is cheap when the level is
raised.

### Concurrency

The chain serializes on a single mutex, so throughput does not scale with cores:

| Threads | Time per event |
|---|---|
| 1 | 7.6 µs |
| 4 | 31.6 µs |
| 8 | 33.7 µs |

Four threads take four times as long per event as one. This is inherent — a hash
chain is a sequential structure — but it means a chained logger is a contention
point under heavy concurrent load. Give each writer its own chain if that
matters, which the `writer` identity supports.

### When `AsyncBackend` pays off

| Scenario | Synchronous | Via `AsyncBackend` |
|---|---|---|
| Burst of 20 to a 200 µs destination | 6.30 ms | **22 µs** |
| Sustained load past the drain rate | 113 µs | 120 µs |
| Fast local file | 1.18 µs | 1.98 µs |

It is for **bursts to a slow destination**, where it is roughly 280x better. It
does not help under sustained overload — the queue saturates and the caller
waits regardless — and wrapping a fast local file is a net loss, because the
event is cloned and boxed on the way into the queue.

## Feature flags

| Feature | Default | Enables |
|---------|---------|---------|
| *(none)* | Yes | Core events, macros, backends, sequence and checksum integrity |
| `hmac-chain` | | `HmacChainIntegrity` and the `ash-log-verify` binary |
| `tracing` | | `AshLogLayer`, routing `tracing` events into a `Logger` |
| `hlc` | | Monotonic causal timestamps on events |
| `ocsf` | | OCSF 1.8.0 event types, schema validation, and `ocsf_codegen` |

## Examples

Ten runnable examples live in [`examples/`](examples/), each printing what it
demonstrates:

```bash
cargo run --example 01_quickstart
cargo run --features hmac-chain --example 08_macros
cargo run --features hmac-chain --example 02_tamper_evident
```

`10_production_setup` is the configuration to copy; `08_macros` covers the macro
surface; `02_tamper_evident` runs four attacks against a signed log rather than
describing them. See
[examples/README.md](examples/README.md) for the full list.

## Development

```bash
make ci          # format check, lint, test matrix, docs — everything CI runs
make test        # cargo test --all-features
make test-matrix # test each feature combination independently
make lint        # clippy --all-features --all-targets -D warnings
```

```bash
make coverage    # line coverage for shipped library code
make bench       # criterion benchmarks
make fuzz        # every fuzz target, 60s each (needs nightly)
```

`make help` lists every target. Commits follow
[Conventional Commits](https://www.conventionalcommits.org/) and are linted in
CI; see [CONTRIBUTING.md](CONTRIBUTING.md).

See [SECURITY.md](SECURITY.md) for the vulnerability-reporting process and a
precise statement of this crate's security properties and limitations.

## License

Apache-2.0

---

*Portions of this repository were generated with the assistance of AI tools.*
