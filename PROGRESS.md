# ash-log 0.1.0 — Progress

Working notes for the initial release. The crate is unpublished; history was
squashed to a single commit, so the phases below are a record of how the design
was arrived at rather than a sequence of shipped versions.

**Status: complete.** 341 tests (all features), 96.57% line coverage, clippy and
fmt clean, zero failures across every feature combination, all ten examples run,
five fuzz targets clean over 46.8M executions.

---

## Scope

Accepted, in priority order. Numbering follows the original gap list, so the
declined items are absent by design rather than by omission.

| # | Item | Why it matters | Status |
|---|------|----------------|--------|
| 1 | **File backend + rotation** | No way to write to a file today; every user reimplements it. Needs size/time rotation and SIGHUP reopen for logrotate. | ✅ done |
| 11 | **Write-failure signalling** | `log_audit` returns `()`, so a full disk silently ends the audit trail. Tamper evidence proves nothing was edited, not that anything was written. | ✅ done |
| 2 | **Field redaction** | `params` is documented "sanitized" but nothing sanitizes it. Secrets reaching an audit log are an active liability. | ✅ done |
| 3 | **Scoped context** | `correlation_id` is threaded by hand into every call. Bind once per request and inherit, like MDC / contextvars / `tracing` spans. | ✅ done |
| 4 | **Non-blocking writer** | Writes are synchronous under a lock; a slow disk stalls request threads. | ✅ done |
| 7 | **Runtime reconfiguration** | No per-module filtering and no way to retune levels without holding the `Logger`. | ✅ done |
| 12 | **Multi-process chaining** | Two processes sharing one chain corrupt it, and nothing warns. | ✅ done |
| 10 | **Chain key rotation** | One key for the process lifetime; no path to rotate without breaking continuity. | ✅ done |
| 6 | **Async-aware API** | A blocking `log()` inside an async task occupies the executor thread. | ✅ done |

**Declined:** 5 (sampling / rate limiting), 8 (`log` facade capture), 9
(alternative output formats).

---

## Ordering rationale

Dependencies, not the priority order above, decide the build sequence:

1. **11 before 1** — the file backend is the first thing that can realistically
   fail a write, so the error channel must exist before it does.
2. **4 after 1** — a non-blocking writer needs a real blocking backend to wrap.
3. **12 and 10 after 1** — both are about chains that outlive one process, which
   is only observable once logs land in a file.
4. **3 before 4** — scoped context must be captured at the call site, before any
   handoff to a writer thread.
5. **6 last** — it composes the non-blocking writer rather than adding new
   machinery.

---

## Hazards (carried forward, must not regress)

**H1 — Filter before stamp.** `add_integrity` advances the chain only when
called. Filtering *after* stamping punches holes and the chain fails to verify;
`verify_unordered` does not rescue it. `Logger::log` enforces the order
structurally.

**H2 — New enum variants break old verifiers.** New code reads old logs; old
verifiers reject new logs. Roll verifiers out before producers.

**H3 (new) — The canonical form is a compatibility surface.** Any field added to
`AuditEvent` changes what gets signed unless it is skipped when absent.
`tests/hlc_compat.rs` pins real pre-feature bytes; every new field needs the
same treatment.

**H4 (new) — Redaction must run before stamping.** A secret scrubbed *after*
`add_integrity` leaves a MAC over the unredacted value, so the log both leaks
and fails to verify. Same ordering discipline as H1.

---

## Log

### Setup
- Started this tracker after the core (events, integrity, logger, provenance,
  tracing bridge, macros, HLC) was in place at 215 tests.

### 11 — write-failure signalling (done)
- New `src/error.rs`. `log_audit` cannot start returning `Result` without
  breaking every downstream impl, so backends report to an `ErrorSink` instead:
  additive, and existing backends keep compiling untouched.
- `WriteError` carries the backend name, the `io::Error`, and `events_lost` —
  a count, because a buffered backend loses a whole batch at once.
- Sinks: `IgnoreErrors` (default, preserves old behaviour), `StderrErrorSink`
  (stderr specifically, so a failing stdout backend cannot swallow the report of
  its own failure), `CountingErrorSink` (metric-shaped), `FnErrorSink`.
- `CountingErrorSink::had_failures()` is the check that pairs with chain
  verification: a verified chain that lost events is a complete record of an
  incomplete history.

### 1 — file backend + rotation (done)
- New `src/file.rs`. `FileBackend` appends JSON lines, flushing every line —
  an event sitting in a userspace buffer is one a crash loses. `sync_on_write`
  opts into `fsync` for power-loss durability at ~10x the cost.
- `RotationPolicy` by size, age, or both, with `keeping(n)` retention. Rotated
  names embed a Unix timestamp plus a tiebreak counter.
- `reopen()` for the `logrotate`/SIGHUP case.
- Opens with `append`, never truncate: truncating on restart would destroy the
  audit record, the worst available failure mode. Pinned by a test.
- 11 unit tests plus `tests/file_rotation_chain.rs` (3 tests) proving a chain
  spanning rotated files verifies, and that editing or deleting an *archived*
  entry is still detected.

**Two findings while testing:**
- Deleting a file out from under an open handle is not a write failure on Unix —
  the write succeeds and the data is simply unreachable. Documented in a test
  named for the behaviour, since it is exactly why SIGHUP → `reopen` matters.
- Reassembling rotated files by filename is wrong: two rotations in one second
  produce `.10` sorting before `.2`. Sort entries by `chain_index` instead.
  Fixed in the test and documented in the module header.

### 2 — field redaction (done)
- New `src/redact.rs`. `Redactor` trait; `KeyRedactor` with a 17-entry default
  denylist, `NoRedaction` (the default, so redaction is opt-in), `FnRedactor`.
- **H4 enforced structurally:** `Logger::log` redacts before `add_integrity`, so
  the MAC covers the placeholder. `tests/redaction_ordering.rs` (5 tests) pins
  it, including that substituting the original secret back in is detected as
  tampering.
- `redact:` key on `ash_logger!`.
- Typed fields (`principal`, `method`) are deliberately not redacted: they are
  the audit record's subject, not incidental payload. Pinned by a test.

**Bug found while testing:** the first substring matcher lowercased but did not
strip separators, so `X-API-Key` did not match a listed `api_key` — a hyphenated
header, which is the shape most secrets actually arrive in, would have leaked.
Added `normalize()` stripping non-alphanumerics; `x-api-key`, `x_api_key`, and
`apiKey` now all match.

Also corrected a wrong test expectation rather than the code: `tokens` matches
the listed `token` by substring, so the whole array is replaced instead of each
element being walked. That is the right direction to err in, and is now stated
in a test named for the behaviour.

### 3 — scoped context (done)
- New `src/context.rs`. `Scope` binds `correlation_id`, `principal`, and
  arbitrary metadata for a region; `ScopeGuard` restores the previous on drop.
  Nested scopes inherit and shadow.
- Applied in `Logger::log` *before* redaction, so scope-supplied metadata is
  scrubbed on the same terms as a call site's own.
- An explicit value on the event always wins — a scope supplies defaults, it
  never overwrites a stated principal. Pinned by a test.
- Thread-local, and a spawned thread deliberately starts clean: implicit
  inheritance would attach a stale correlation ID to unrelated work. Carrying
  one across a boundary is explicit via `Scope::current()` + `enter()`.

### 4 + 6 — non-blocking writer / async-aware (done)
- New `src/async_backend.rs`. `AsyncBackend` hands events to a dedicated writer
  thread over a bounded channel, so callers pay an enqueue rather than an I/O
  wait. This is also the answer to 6: a blocking `log()` inside an async task no
  longer occupies the executor thread.
- `OverflowPolicy` is a required choice, not a default that hides a tradeoff:
  `Block` never loses an event but can stall producers under sustained
  overload; `DropAndReport` stays responsive and reports every discard to the
  error sink, so the gap is knowable.
- `flush()` blocks until the queue drains; `Drop` shuts the writer down cleanly.

**Bug found while testing:** `flush()` originally sent its drain marker through
the overflow policy, so under `DropAndReport` a full queue discarded the *marker
itself* — nothing acknowledged, and `flush` returned with events still queued.
Caught by an accounting assertion (written + dropped == submitted) reporting
198/200. The marker now always uses a blocking send.

### 7 — runtime reconfiguration (done)
- New `src/filter.rs`. `FilterDirectives::parse` takes `RUST_LOG`-style strings
  (`info,my_app::db=debug,hyper=warn`); `LiveFilter` wraps them behind an
  `RwLock` so a clone held by an admin endpoint retunes running loggers.
- Longest-target-first matching, so the most specific directive wins regardless
  of the order it was written in. Prefix matching respects `::` boundaries, so
  `my_app` does not silently capture `my_application`.
- A malformed directive is skipped, not fatal: a typo must not silence the
  logger entirely.
- `filter:` key on `ash_logger!`. Security events are still unconditional — a
  filter tunes noise and cannot shrink the audit record. Pinned by a test.

**Design flaw found while testing:** the diagnostic macros' cheap pre-check
compared against `min_level()` directly, so a per-module directive could only
ever *tighten* the base threshold — a `module=trace` under a `warn` base was
dropped before the filter was consulted. Added `Logger::admits_diagnostic`,
which takes `module_path!()` and consults the filter, keeping the pre-check
(and the lazy-formatting guarantee) intact.

### 10 + 12 — key rotation / multi-process chaining (done)
- `HmacChainIntegrity::with_key_id` names the signing key; `rotate_to` swaps in
  a new one while retaining the old for verification. Continuity is preserved:
  the chain is not restarted, and a stream signed by two keys verifies in one
  pass.
- Rotation is refused without a key id, on an empty key, or on a reused
  identifier — the last would make entries signed with the earlier key
  unverifiable.
- `key_id` is stamped *before* hashing, so it is covered by the MAC. Relabelling
  an entry to point at an attacker-controlled key is detected.
- New `ChainError::UnknownKeyId` distinguishes "I do not hold that key" from
  tampering.
- `HmacChainIntegrity::writer` names the producing process. Two writers sharing
  one chain now yield `ChainError::MixedWriters`, whose message names the actual
  mistake, instead of a bare MAC mismatch that reads as an attack.
- Both fields are absent unless configured, so pre-existing chains canonicalize
  and verify unchanged (H3). `tests/hlc_compat.rs` still passes.

---

## Status

All nine accepted items are implemented.

| Combination | Tests |
|---|---|
| `--no-default-features` | 148 |
| `hlc` | 161 |
| `tracing` | 158 |
| `ocsf` | 174 |
| `hmac-chain` | 244 |
| `hlc hmac-chain` | 261 |
| `tracing hmac-chain` | 260 |
| `--all-features` | **303** |

Zero failures in every combination; clippy clean under `pedantic`;
`cargo fmt --check` clean; all ten examples run.

### New modules

| File | Item | Provides |
|---|---|---|
| `src/error.rs` | 11 | `ErrorSink`, `WriteError`, four sink implementations |
| `src/file.rs` | 1 | `FileBackend`, `RotationPolicy`, `reopen()` |
| `src/redact.rs` | 2 | `Redactor`, `KeyRedactor`, `FnRedactor` |
| `src/context.rs` | 3 | `Scope`, `ScopeFields`, `ScopeGuard` |
| `src/async_backend.rs` | 4, 6 | `AsyncBackend`, `OverflowPolicy` |
| `src/filter.rs` | 7 | `FilterDirectives`, `LiveFilter` |
| `src/hmac_chain.rs` | 10, 12 | `with_key_id`, `rotate_to`, `writer` |

### Bugs found by tests, not by inspection

1. **`flush()` could return with events still queued.** The drain marker was
   sent through the overflow policy, so `DropAndReport` discarded the marker
   itself under load. Caught by an accounting assertion (written + dropped ==
   submitted) reporting 198/200. The marker now always blocks.
2. **A hyphenated secret would have leaked.** The redactor lowercased but did
   not strip separators, so `X-API-Key` missed a listed `api_key` — the shape
   most secrets actually arrive in.
3. **Per-module directives could not loosen the base threshold.** The macros'
   cheap pre-check compared against `min_level()` directly and dropped records
   before the filter was consulted. Fixed with `Logger::admits_diagnostic`,
   keeping the lazy-formatting guarantee.

### Behaviours documented rather than fixed

- Deleting a file out from under an open handle is not a write failure on Unix:
  the write succeeds and the data is unreachable. This is precisely why SIGHUP
  must be wired to `reopen()`.
- Rotated files must be reassembled by sorting entries on `chain_index`, not by
  filename — two rotations in one second yield `.10` sorting before `.2`.

### Ordering invariants now enforced in `Logger::log`

    admit → scope → hlc → redact → integrity → write

Each step must precede the next: filtering before stamping (H1), redaction
before stamping (H4), and scope before redaction so scope-supplied metadata is
scrubbed on the same terms as a call site's own.

### Local checks were running on the wrong toolchain

The squashed commit failed CI on three counts that every local check had passed.
The cause: this environment's default toolchain is nightly, while CI pins
`dtolnay/rust-toolchain@stable`. Clippy's lint set differs between them, and
`cargo doc` resolved a `cfg`-gated intra-doc link on nightly that stable
rejected.

- `src/file.rs` — `map(..).unwrap_or(..)` on a `Result` (`clippy::map_unwrap_or`)
- `src/filter.rs` — `sort_by` where `sort_by_key` applies
  (`clippy::unnecessary_sort_by`)
- `src/logger.rs` — `[`HlcError`]` unresolved under `-D warnings`, because the
  re-export only exists with the `hlc` feature; now written as an explicit
  `crate::` path

**Verify with `cargo +stable`, not the default toolchain.** `make ci` runs
whatever `cargo` resolves to, which is not necessarily what CI runs. Worth
pinning in `rust-toolchain.toml` so the two cannot drift again.

### Remaining before publishing

- `SECURITY.md`: document redaction ordering, the write-failure channel, and the
  one-writer-per-chain rule.
- Add `hlc` to the CI workflow's feature matrix (`make test-matrix` already
  covers it).
- `cargo publish --dry-run`, then publish.
- Consider a `rust-toolchain.toml` pinning stable, so local checks and CI cannot
  diverge the way they did above.

---

## Coverage

Measured with `cargo-llvm-cov`. `make coverage` reports it; `make coverage-check`
fails below a 95% floor.

Build-time code generation (`codegen_shared.rs`, the `ocsf_codegen` binary) is
excluded: it runs during development, not in anything shipped, and counting it
understates library coverage by roughly seven points.

| | Before | After |
|---|---|---|
| Lines | 92.49% | **96.57%** |
| Functions | 88.87% | **96.95%** |
| Regions | 93.35% | **96.84%** |
| Tests | 303 | **341** |

### What measurement found

Coverage was run *before* writing any of these tests, and the gaps it exposed
were not where I would have guessed.

**`security_log` was untested on every backend.** The OCSF write path is on the
public `AuditBackend` trait and reached `FileBackend`, `AsyncBackend`,
`MultiAuditBackend`, `StderrAuditBackend`, and the blanket `Arc` impl — with no
test anywhere. A whole public code path had shipped unexercised. Now covered by
five tests in `tests/coverage_gaps.rs`.

**The `tracing` bridge dropped three field types silently.** `record_u64`,
`record_f64`, and `record_error` were never exercised, so a numeric or error
field could have gone missing without any test noticing. Now covered by
`every_field_type_reaches_the_event_as_metadata`.

**Sequence control was untested.** `SequenceIntegrity::with_start`, `current`,
and `reset` — the API a restarting process uses to continue a sequence rather
than restart at zero and produce duplicate positions — had no coverage.

**Error messages had none.** A verifier's output is what an operator reads when
a chain fails at 3am. `tests/error_messages.rs` now asserts that each error
names the offending entry, and that the actionable ones name the fix.

Also closed: `MultiAuditBackend::{from_arcs, add_backend}`, `CombinedIntegrity`,
the `AuditEvent::with_*` post-construction setters, `FilterDirectives::from_env`,
`LiveFilter::snapshot`, `KeyRedactor::{and, keys}`, and `ScopeFields::get`.

### What remains uncovered, and why

- `ocsf/schema.rs` (85.9%) — validation branches for malformed schema documents.
- `bin/verify.rs` (92.8%) — CLI argument-error paths; the exit codes themselves
  are covered by `tests/cli_verify.rs`.
- `logger.rs` (95.5%) — mostly `Debug` impls and poison-recovery arms that need
  a panicking thread to reach.
- `backends.rs` (90.6%) — the `Err` arms of `serde_json::to_string` on stdout and
  stderr. Reaching them needs an event that fails to serialize, which the typed
  `AuditEvent` cannot produce.

These are diminishing returns rather than blind spots. The floor is set at 95%
to catch regressions, not to chase the last few points.

### Honest caveat

96.57% line coverage means the lines ran, not that the behaviour is right. Every
test here was written by the same author as the code, so they encode the same
assumptions — including any wrong ones. Coverage is a floor on how much went
unexercised, not a ceiling on correctness.

---

## Benchmarks

`cargo bench --features hmac-chain`, via `make bench`. Criterion, eight groups
covering event construction, each integrity mechanism, verification throughput,
filtering, the full logger stack, redaction against payload size, backend write
paths, and contention.

Written to check claims the documentation was already making without evidence.
Two of those claims turned out to be wrong.

### Finding 1 — redaction was 9x slower than it needed to be

`KeyRedactor::redacts` called `normalize()` on **every listed key for every
checked field**: 17 keys x 100 fields = 1700 `String` allocations per event.
Redacting a 100-field payload cost **170 us**, about 1000x building the event
it was attached to, and dominated the entire logging path.

The denylist is now normalized once at construction. Same behaviour, same tests:

| Fields | Before | After |
|---|---|---|
| 1 | 1.59 us | 0.17 us |
| 10 | 16.6 us | 1.69 us |
| 100 | 170 us | 21.5 us |

This was invisible to correctness testing — every redaction test passed both
before and after. Only measurement found it.

### Finding 2 — `AsyncBackend` was oversold

The module documentation implied it avoids write stalls generally. Measured, it
is far more situational:

| Scenario | Synchronous | Via `AsyncBackend` |
|---|---|---|
| Burst of 20 to a 200us destination | 6.30 ms | **22 us** |
| Sustained load past the drain rate | 113 us | 120 us |
| Fast local file | 1.18 us | 1.98 us |

It is excellent for bursts to a slow destination (~280x), useless under
sustained overload, and a **net loss** wrapping a fast local file — the event is
cloned and boxed on the way into the queue, which costs more than a page-cache
write. Module docs and README now say exactly this.

### Other numbers worth knowing

- **HMAC chaining dominates**: 4.46 us against 88 ns for a sequence number.
  ~97% of a chained `Logger::log`.
- **Verification**: ~220 000 entries/second, so a million-entry log checks in
  about 4.5 seconds.
- **Filtering is nearly free**: a dropped diagnostic is 2.7 ns against 1.18 us
  admitted, 440x. The lazy-formatting claim holds.
- **The chain does not scale with cores**: 4 threads take 4x longer per event
  than 1. Inherent to a sequential hash chain, but it makes a chained logger a
  contention point under load. Worth knowing before deploying one.

## Fuzzing

`cargo +nightly fuzz`, via `make fuzz`. Five targets on the untrusted-input
surfaces, run for 46.8M total executions with **zero crashes**.

| Target | Executions | Property asserted |
|---|---|---|
| `verify_chain` | 5.0M | Verification always reaches a verdict, never miscounts, and is deterministic |
| `event_roundtrip` | 8.2M | An event survives serialize/deserialize unchanged |
| `redaction` | 4.6M | A listed key never survives redaction, whatever the payload shape |
| `filter_directives` | 0.7M | Parsing is total; directives stay ordered most-specific-first |
| `severity_parse` | 28.4M | Any level that parses round-trips through its own name |

`verify_chain` is the one that matters most: `ash-log-verify` reads files an
attacker may have written to, and a panic there is a denial of service on the
very tool that detects tampering.

Also checked by hand, since fuzzers rarely generate extreme nesting: JSON nested
100, 1 000, and 10 000 levels deep against the recursive redaction walk. No
stack overflow — `serde_json`'s own recursion limit rejects the input first.

Corpora and artifacts are gitignored; the targets are committed.
