//! Verifies an `ash-log` HMAC hash chain read from stdin.
//!
//! Reads JSON-lines audit events (the format written by `StdoutAuditBackend`)
//! and checks that every entry's chained MAC is intact, reporting the first
//! entry that fails.
//!
//! # Usage
//!
//! ```text
//! cat audit.log | ash-log-verify --key-env AUDIT_KEY
//! cat concurrent.log | ash-log-verify --key-env AUDIT_KEY --unordered
//! ash-log-verify --key-file /run/secrets/audit.key < audit.log
//! journalctl -u myservice -o cat | ash-log-verify --key-env AUDIT_KEY --quiet
//! ```
//!
//! The key must match the one used to write the log. Prefer `--key-env` or
//! `--key-file` over `--key`, which exposes the secret in the process list.
//!
//! # Truncation
//!
//! A prefix of a valid chain is itself a valid chain, so removing entries from
//! the *end* cannot be detected from the log alone. The verifier always reports
//! the last chain index it saw; pass `--expect-count <N>` (or compare that
//! index against a value recorded elsewhere) to detect a truncated tail.
//!
//! # Exit codes
//!
//! - `0` — every entry verified
//! - `1` — tampering detected (altered, removed, reordered, or truncated entry)
//! - `2` — usage or input error (bad key, malformed JSON)

use ash_log::{AuditEvent, ChainError, HmacChainIntegrity};
use std::io::{BufRead, Write};

/// Exit code signalling a broken chain.
const EXIT_TAMPERED: i32 = 1;
/// Exit code signalling bad usage or unreadable input.
const EXIT_USAGE: i32 = 2;

const USAGE: &str = "\
ash-log-verify — verify an ash-log HMAC hash chain from stdin

USAGE:
    ash-log-verify (--key-env <VAR> | --key-file <PATH> | --key <SECRET>) [OPTIONS]

KEY SOURCES (exactly one required):
    --key-env <VAR>     Read the key from an environment variable (recommended)
    --key-file <PATH>   Read the key from a file; trailing newline is stripped
    --key <SECRET>      Literal key. Visible in the process list — avoid in production.

OPTIONS:
    --expect-count <N>  Require exactly N entries. Detects a truncated tail,
                        which a hash chain cannot reveal on its own.
    --unordered         Sort entries by chain_index before verifying. Use this
                        when several threads wrote to the same chain, since
                        entries can then reach the log out of chain order.
    -q, --quiet         Print nothing; communicate only via exit code
    -h, --help          Show this help

EXIT CODES:
    0  chain verified
    1  tampering detected
    2  usage or input error";

/// Where the verification key comes from.
enum KeySource {
    Env(String),
    File(String),
    Literal(String),
}

/// Parsed command line.
struct Args {
    key: KeySource,
    quiet: bool,
    expect_count: Option<usize>,
    unordered: bool,
}

/// Parse arguments, returning an error message on misuse.
fn parse_args() -> Result<Args, String> {
    let mut key: Option<KeySource> = None;
    let mut quiet = false;
    let mut expect_count = None;
    let mut unordered = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        let mut take_value = |flag: &str| {
            args.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };

        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-q" | "--quiet" => quiet = true,
            "--unordered" => unordered = true,
            "--key-env" => key = Some(KeySource::Env(take_value("--key-env")?)),
            "--key-file" => key = Some(KeySource::File(take_value("--key-file")?)),
            "--key" => key = Some(KeySource::Literal(take_value("--key")?)),
            "--expect-count" => {
                let raw = take_value("--expect-count")?;
                expect_count = Some(
                    raw.parse::<usize>()
                        .map_err(|_| format!("--expect-count needs a number, got {raw}"))?,
                );
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }

    key.map(|key| Args {
        key,
        quiet,
        expect_count,
        unordered,
    })
    .ok_or_else(|| "no key given; pass --key-env, --key-file, or --key".to_string())
}

/// Resolve the key source to raw bytes.
fn resolve_key(source: &KeySource) -> Result<Vec<u8>, String> {
    match source {
        KeySource::Env(var) => std::env::var(var)
            .map(String::into_bytes)
            .map_err(|_| format!("environment variable {var} is not set")),
        KeySource::File(path) => std::fs::read(path)
            .map(|mut bytes| {
                // Tolerate the trailing newline a file-based secret usually has.
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                }
                bytes
            })
            .map_err(|e| format!("cannot read key file {path}: {e}")),
        KeySource::Literal(literal) => Ok(literal.clone().into_bytes()),
    }
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(EXIT_USAGE);
        }
    };

    let key = match resolve_key(&args.key) {
        Ok(key) => key,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(EXIT_USAGE);
        }
    };

    if key.is_empty() {
        eprintln!("error: key is empty");
        std::process::exit(EXIT_USAGE);
    }

    let mut events = Vec::new();
    let stdin = std::io::stdin();
    for (line_number, line) in stdin.lock().lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("error: reading stdin at line {}: {e}", line_number + 1);
                std::process::exit(EXIT_USAGE);
            }
        };

        // Skip blank lines so a trailing newline or a padded log is not an error.
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<AuditEvent>(&line) {
            Ok(event) => events.push(event),
            Err(e) => {
                eprintln!(
                    "error: line {} is not a valid audit event: {e}",
                    line_number + 1
                );
                std::process::exit(EXIT_USAGE);
            }
        }
    }

    if events.is_empty() {
        if !args.quiet {
            eprintln!("error: no events on stdin");
        }
        std::process::exit(EXIT_USAGE);
    }

    let integrity = HmacChainIntegrity::new(&key);
    let mut stdout = std::io::stdout().lock();

    let result = if args.unordered {
        integrity.verify_unordered(&events)
    } else {
        integrity.verify_chain(&events)
    };

    match result {
        Ok(count) => {
            if let Some(expected) = args.expect_count
                && count != expected
            {
                if !args.quiet {
                    let _ = writeln!(
                        stdout,
                        "TAMPERED: expected {expected} entries but found {count} — \
                         the log was truncated or padded"
                    );
                }
                std::process::exit(EXIT_TAMPERED);
            }

            if !args.quiet {
                let last_index = events
                    .last()
                    .and_then(|e| e.metadata.get("chain_index"))
                    .and_then(serde_json::Value::as_u64);
                match last_index {
                    Some(index) => {
                        let _ = writeln!(
                            stdout,
                            "OK: {count} entries verified, chain intact (last chain_index {index})"
                        );
                    }
                    None => {
                        let _ = writeln!(stdout, "OK: {count} entries verified, chain intact");
                    }
                }
                if args.expect_count.is_none() {
                    let _ = writeln!(
                        stdout,
                        "note: a truncated tail cannot be detected from the log alone; \
                         use --expect-count to check for missing trailing entries"
                    );
                }
            }
        }
        Err(e) => {
            if !args.quiet {
                let _ = writeln!(stdout, "TAMPERED: {e}");
                if !args.unordered && matches!(e, ChainError::IndexMismatch { .. }) {
                    let _ = writeln!(
                        stdout,
                        "hint: if several threads wrote this log, entries may be out of \
                         chain order — retry with --unordered before assuming tampering"
                    );
                }
                let _ = writeln!(
                    stdout,
                    "note: entries before the reported index are intact; \
                     everything from it onward is untrusted"
                );
            }
            std::process::exit(EXIT_TAMPERED);
        }
    }
}
