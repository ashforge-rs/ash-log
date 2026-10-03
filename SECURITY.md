# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

`ash-log` is pre-1.0. Only the latest minor release receives security fixes.

## Reporting a Vulnerability

Please report security issues responsibly and in private.

- Do **not** open a public issue.
- Use GitHub's **Security Advisories**: go to the repository → **Security** →
  **Report a vulnerability**.

Include a clear description, steps to reproduce, the potential impact, and any
suggested fix. You can expect an initial response within a reasonable timeframe.

## Security Properties of This Crate

`ash-log` writes audit logs. What it does and does not guarantee:

### Tamper evidence

`HmacChainIntegrity` (feature `hmac-chain`) is the **only** mechanism in this
crate that resists deliberate tampering. It keys an HMAC-SHA256 chain with a
secret, so an attacker without the key cannot alter, delete, reorder, or insert
entries undetected.

`ChecksumIntegrity` uses an **unkeyed** hash and covers only a subset of event
fields. Anyone can recompute it, so it detects accidental corruption **only**.
Do not rely on it for tamper evidence.

`SequenceIntegrity` records ordering metadata but its `verify` only checks that
a sequence field is present. It is not an integrity mechanism on its own.

### Two-tier admission

`Logger` applies a deliberate split. Security events — every `AuditEventType`
except `Diagnostic` — are always written to the chain, regardless of the
configured level. Only diagnostic records are subject to level filtering.

This exists so that an operational setting cannot shrink the compliance record.
If a runtime log level gated chain admission, anyone able to change a config
value could quietly drop audit entries, and the shortened chain would still
verify perfectly.

Filtering happens **before** integrity metadata is attached. Dropping an event
after stamping would leave a gap in the chain and the log would fail to verify
despite no tampering; `Logger::log` enforces the safe order so callers cannot
get it wrong.

### Provenance

`Provenance` (source file, line, module, thread, pid, service, version, host) is
a field on the event, not `metadata`, so it is inside the signed canonical form.
Rewriting where an action came from fails verification.

### The `tracing` bridge

`AshLogLayer` records every bridged event as a `Diagnostic`, so application
logging can never claim a security classification. Bridged events are subject to
the level filter like any other diagnostic. Do not route security decisions
through the bridge — log those directly with a specific `AuditEventType`.

Note that `tracing` events carry whatever the caller put in them. The bridge
does not sanitize fields; the same care about secrets in log content applies.

### Known limitations

- **Truncation.** A prefix of a valid hash chain is itself a valid chain, so
  removing entries from the end cannot be detected from the log alone. Use
  `ash-log-verify --expect-count <N>`, or compare the reported final
  `chain_index` against a count recorded elsewhere.
- **Concurrent producers.** Events are stamped under a lock but written to the
  backend afterwards, so a log written by several threads can contain entries
  out of chain order. Such a log is untampered; verify it with
  `ash-log-verify --unordered` or `HmacChainIntegrity::verify_unordered`, which
  sorts by `chain_index` first while still rejecting edits, deletions, and
  replays. Strict `verify_chain` reports these as tampering.
- **Key compromise.** An attacker who obtains the HMAC key can rewrite the
  entire chain. Tampering is made *detectable*, not impossible. Ship entries
  off-box or to WORM storage promptly so an attacker never controls the only
  copy.
- **Buffered events.** `BufferedAuditBackend` holds events in memory. Its flush
  on drop does not run on `std::process::exit`, a panic under `panic = "abort"`,
  or SIGKILL. Prefer unbuffered backends for a compliance trail.

### Key management

The HMAC key must be at least 32 random bytes, loaded from a KMS, secrets
manager, or environment variable. Never hard-code it, and never write it to the
log it protects. Prefer `--key-env` or `--key-file` over `--key` when running
`ash-log-verify`, since command-line arguments are visible in the process list.

### Log content

This crate serializes whatever you put in an event. Audit records frequently
attract data-protection obligations (GDPR, HIPAA). Sanitize `params` and
`metadata` before logging; nothing here redacts secrets for you.
