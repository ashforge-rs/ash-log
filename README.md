# ash-log

[![CI](https://github.com/ashforge-rs/ash-log/actions/workflows/rust.yml/badge.svg)](https://github.com/ashforge-rs/ash-log/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/ash-log.svg)](https://crates.io/crates/ash-log)
[![docs.rs](https://docs.rs/ash-log/badge.svg)](https://docs.rs/ash-log)

Structured logging for Rust, with a security audit extension.

> **Disclaimer:** this repository contains AI-generated code.

Application logs and security events share one pipeline: both are structured
JSON-lines records with levels, provenance and pluggable backends. Security
events also bypass level filtering, and can be committed to a keyed hash chain
so that later modification is detectable.

## Installation

```sh
cargo add ash-log
# with tamper-evident hash chaining
cargo add ash-log --features hmac-chain
```

## Quick start

```rust
use ash_log::*;

let logger = ash_logger!();

ash_info!(logger, "server listening on port {}", 8443);
ash_warn!(logger, "cache miss"; key = "session:abc");
ash_error!(logger, "upstream unreachable");
```

`ash_logger!` takes optional named parts (`backend`, `integrity`, `min_level`,
`service`, `version`, `host`, `redact`, `filter`, `clock`, `buffered`) in any
order:

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

## Logging and audit events

Five macros cover diagnostics: `ash_trace!`, `ash_debug!`, `ash_info!`,
`ash_warn!` and `ash_error!`. They take `format!` arguments, and `key = value`
pairs after a `;` become event metadata. The level is checked before the
arguments are evaluated, so a filtered call costs an atomic load. Every macro
records call-site provenance: file, line, module, thread and pid.

`ash_audit!` writes the security tier: authentication, authorization, method
invocations, configuration changes and policy violations.

```rust
use ash_log::*;
use std::sync::Arc;

let logger = ash_logger!(backend: Arc::new(StdoutAuditBackend));

ash_audit!(logger, AuthenticationAttempt, Success, principal = "alice@example.com");

ash_audit!(logger, SecurityViolation, Denied,
    principal = "bob@example.com",
    method = "transfer",
    error = "rate limit exceeded";
    attempts = 5,
    limit = 3,
);
```

Security events are written whatever the level threshold, so an operational
setting can't shrink the audit record. Filtering happens before integrity
metadata is attached, so a dropped diagnostic never leaves a gap in a hash
chain.

The macros are prefixed with `ash_` so that `use ash_log::*` is safe next to
other logging crates. Rename them at the import site if you prefer short
names: `use ash_log::{ash_info as info, ash_warn as warn};`.

## What's included

- **Backends:** stdout, stderr, a rotating `FileBackend` (with `reopen()` for
  logrotate), `AsyncBackend` (a writer thread with an explicit overflow policy),
  `MultiAuditBackend` (fan-out) and `BufferedAuditBackend`. Implement
  `AuditBackend` for anything else.
- **Write-failure reporting:** backends report I/O failures to an `ErrorSink`,
  so a full disk doesn't end the audit trail silently.
- **Scoped context:** `Scope` binds a correlation ID, principal and other
  fields for a region of code. Events recorded inside inherit them.
- **Redaction:** `KeyRedactor` scrubs secrets by key name before an event is
  stamped. It is a backstop, not a licence to pass credentials to the logger.
- **Runtime filtering:** `LiveFilter` takes `RUST_LOG`-style directives and can
  be reloaded on a running logger.
- **Causal ordering** (`hlc`): Hybrid Logical Clock timestamps that stay
  monotonic when the system clock moves backwards, and can carry ordering across
  service boundaries.
- **`tracing` bridge** (`tracing`): `AshLogLayer` routes `tracing` events into
  a `Logger`.
- **OCSF** (`ocsf`): OCSF 1.8.0 event types and schema validation.

## Tamper evidence

With the `hmac-chain` feature, `HmacChainIntegrity` stamps each entry with
`mac = HMAC-SHA256(key, prev_mac || canonical(event))` and a `chain_index`. The
MAC covers the whole event and the previous MAC, so editing, deleting,
reordering or inserting entries is detectable.

```rust,no_run
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

The chain can be resumed across restarts (`HmacChainIntegrity::resume`), and
keys can be rotated without breaking it (`with_key_id` and `rotate_to`). Give
each writing process its own chain. Name writers with `.writer("api-01")` so a
mixed stream is reported as such instead of as tampering.

Verify a log with the bundled CLI:

```sh
cargo install ash-log --features hmac-chain

ash-log-verify --key-env AUDIT_KEY < audit.log
# OK: 1043 entries verified, chain intact (last chain_index 1042)
```

The exit code is `0` if the chain verifies, `1` if tampering is detected and
`2` on a usage or input error.

| Attack | Detected |
|---|---|
| Editing any field of any entry | Yes |
| Deleting, reordering or inserting entries | Yes |
| Re-stamping a forged entry without the key | Yes |
| Removing entries from the end (truncation) | Only with `--expect-count <N>` |
| An attacker holding the key | No |

When several threads share a chain, entries can reach the log out of order.
Verify such logs with `--unordered`. Tampering is made detectable, not
impossible, so ship entries off the host or to WORM storage promptly. See
[SECURITY.md](SECURITY.md) for the full statement of guarantees and limits.

The HMAC dominates the cost of a chained log entry (about 4.5 µs per event on
the reference machine, against well under 1 µs without it). Run
`cargo bench --features hmac-chain` for numbers on your hardware.

## Cargo features

| Feature | Default | Enables |
|---|---|---|
| *(none)* | yes | Events, macros, backends, sequence and checksum integrity |
| `hmac-chain` | | `HmacChainIntegrity` and the `ash-log-verify` binary |
| `tracing` | | `AshLogLayer`, routing `tracing` events into a `Logger` |
| `hlc` | | Hybrid Logical Clock timestamps on events |
| `ocsf` | | OCSF 1.8.0 event types, schema validation and `ocsf_codegen` |

## Examples

Ten runnable examples live in [`examples/`](examples/), and
[examples/README.md](examples/README.md) describes each one.

```sh
cargo run --example 01_quickstart
cargo run --features hmac-chain --example 02_tamper_evident
cargo run --features hmac-chain --example 10_production_setup
```

## Minimum supported Rust version

Rust 1.88 or later.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see
[SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
