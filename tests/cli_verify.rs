//! Tests for the `ash-log-verify` binary.
//!
//! These spawn the real binary, feed it JSON lines on stdin, and assert on its
//! exit code and output — the contract a CI pipeline actually depends on.

#![cfg(feature = "hmac-chain")]

use ash_log::{AuditEvent, AuditEventType, AuditIntegrity, AuditResult, HmacChainIntegrity};
use std::io::Write;
use std::process::{Command, Stdio};

const KEY: &str = "cli-test-key-that-is-32-bytes-ok!";

/// Exit code for a broken chain.
const EXIT_TAMPERED: i32 = 1;
/// Exit code for usage or input errors.
const EXIT_USAGE: i32 = 2;

/// Path to the binary under test, provided by Cargo for integration tests.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_ash-log-verify")
}

/// Build a signed log as JSON lines.
fn signed_log(count: usize) -> String {
    let integrity = HmacChainIntegrity::new(KEY.as_bytes());
    (0..count)
        .map(|i| {
            let mut event = AuditEvent::builder()
                .event_type(AuditEventType::AuthenticationAttempt)
                .principal(format!("user{i}@example.com"))
                .method("login")
                .result(AuditResult::Success)
                .build();
            integrity.add_integrity(&mut event);
            serde_json::to_string(&event).expect("serializes")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// What the binary produced.
struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run the binary with `args`, writing `stdin_data` to its stdin.
fn run(args: &[&str], stdin_data: &str, key_env: Option<&str>) -> Output {
    let mut command = Command::new(binary());
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Clear any inherited value so tests never depend on the outer environment.
    command.env_remove("AUDIT_KEY");
    if let Some(key) = key_env {
        command.env("AUDIT_KEY", key);
    }

    let mut child = command.spawn().expect("binary starts");
    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        // The binary may exit before reading stdin (for example on a key
        // error), closing the pipe. That is correct behaviour, so a broken
        // pipe here is not a test failure; the exit code is what matters.
        match stdin.write_all(stdin_data.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("writing to stdin failed: {e}"),
        }
    }

    let out = child.wait_with_output().expect("binary runs to completion");
    Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn intact_log_exits_zero() {
    let out = run(&["--key-env", "AUDIT_KEY"], &signed_log(3), Some(KEY));

    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stdout.contains("OK: 3 entries verified"));
    assert!(
        out.stdout.contains("last chain_index 2"),
        "should report the final index: {}",
        out.stdout
    );
}

#[test]
fn tampered_log_exits_one() {
    let log = signed_log(3).replace("user1@example.com", "mallory@example.com");
    let out = run(&["--key-env", "AUDIT_KEY"], &log, Some(KEY));

    assert_eq!(out.code, Some(EXIT_TAMPERED));
    assert!(
        out.stdout.contains("TAMPERED"),
        "stdout was: {}",
        out.stdout
    );
    assert!(out.stdout.contains("entry 1"), "should name the entry");
}

#[test]
fn deleted_entry_exits_one() {
    let log = signed_log(4);
    let kept: Vec<&str> = log
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| l)
        .collect();
    let out = run(&["--key-env", "AUDIT_KEY"], &kept.join("\n"), Some(KEY));

    assert_eq!(out.code, Some(EXIT_TAMPERED));
    assert!(out.stdout.contains("TAMPERED"));
}

#[test]
fn wrong_key_exits_one() {
    let out = run(
        &["--key-env", "AUDIT_KEY"],
        &signed_log(2),
        Some("a-totally-different-key-32-bytes!"),
    );

    assert_eq!(out.code, Some(EXIT_TAMPERED));
    assert!(out.stdout.contains("entry 0"));
}

#[test]
fn truncation_passes_without_expect_count() {
    // Documented limitation, pinned so it cannot change silently.
    let log = signed_log(4);
    let head: Vec<&str> = log.lines().take(2).collect();
    let out = run(&["--key-env", "AUDIT_KEY"], &head.join("\n"), Some(KEY));

    assert_eq!(out.code, Some(0));
    assert!(
        out.stdout.contains("truncated tail cannot be detected"),
        "must warn about the limitation: {}",
        out.stdout
    );
}

#[test]
fn truncation_is_caught_with_expect_count() {
    let log = signed_log(4);
    let head: Vec<&str> = log.lines().take(2).collect();
    let out = run(
        &["--key-env", "AUDIT_KEY", "--expect-count", "4"],
        &head.join("\n"),
        Some(KEY),
    );

    assert_eq!(out.code, Some(EXIT_TAMPERED));
    assert!(out.stdout.contains("expected 4 entries but found 2"));
}

#[test]
fn expect_count_matching_passes() {
    let out = run(
        &["--key-env", "AUDIT_KEY", "--expect-count", "3"],
        &signed_log(3),
        Some(KEY),
    );

    assert_eq!(out.code, Some(0), "stdout: {}", out.stdout);
}

#[test]
fn quiet_mode_prints_nothing_on_success() {
    let out = run(
        &["--key-env", "AUDIT_KEY", "--quiet"],
        &signed_log(2),
        Some(KEY),
    );

    assert_eq!(out.code, Some(0));
    assert!(out.stdout.is_empty(), "stdout was: {}", out.stdout);
}

#[test]
fn quiet_mode_prints_nothing_on_failure() {
    let log = signed_log(2).replace("user0@example.com", "mallory@example.com");
    let out = run(&["--key-env", "AUDIT_KEY", "-q"], &log, Some(KEY));

    assert_eq!(out.code, Some(EXIT_TAMPERED), "exit code still signals");
    assert!(out.stdout.is_empty(), "stdout was: {}", out.stdout);
}

#[test]
fn blank_lines_are_skipped() {
    let log = signed_log(3);
    let padded = format!("\n{}\n\n", log.replace('\n', "\n\n"));
    let out = run(&["--key-env", "AUDIT_KEY"], &padded, Some(KEY));

    assert_eq!(
        out.code,
        Some(0),
        "stdout: {} stderr: {}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn literal_key_flag_works() {
    let out = run(&["--key", KEY], &signed_log(2), None);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
}

#[test]
fn key_file_works_and_strips_trailing_newline() {
    let dir = std::env::temp_dir().join(format!("ash-log-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("audit.key");
    // Written with a trailing newline, as a secrets mount usually is.
    std::fs::write(&path, format!("{KEY}\n")).expect("writes key file");

    let out = run(
        &["--key-file", path.to_str().expect("utf-8 path")],
        &signed_log(2),
        None,
    );

    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
}

#[test]
fn missing_key_is_a_usage_error() {
    let out = run(&[], &signed_log(1), Some(KEY));

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("no key given"));
}

#[test]
fn unset_key_env_is_a_usage_error() {
    let out = run(&["--key-env", "AUDIT_KEY"], &signed_log(1), None);

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("not set"), "stderr: {}", out.stderr);
}

#[test]
fn unreadable_key_file_is_a_usage_error() {
    let out = run(
        &["--key-file", "/nonexistent/path/to/key"],
        &signed_log(1),
        None,
    );

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("cannot read key file"));
}

#[test]
fn malformed_json_is_a_usage_error() {
    let out = run(&["--key-env", "AUDIT_KEY"], "this is not json\n", Some(KEY));

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(
        out.stderr.contains("line 1"),
        "should name the line: {}",
        out.stderr
    );
}

#[test]
fn empty_input_is_a_usage_error() {
    let out = run(&["--key-env", "AUDIT_KEY"], "", Some(KEY));

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("no events"));
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let out = run(
        &["--key-env", "AUDIT_KEY", "--nonsense"],
        &signed_log(1),
        Some(KEY),
    );

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("unrecognised argument"));
}

#[test]
fn non_numeric_expect_count_is_a_usage_error() {
    let out = run(
        &["--key-env", "AUDIT_KEY", "--expect-count", "many"],
        &signed_log(1),
        Some(KEY),
    );

    assert_eq!(out.code, Some(EXIT_USAGE));
    assert!(out.stderr.contains("--expect-count needs a number"));
}

#[test]
fn help_exits_zero_and_describes_usage() {
    let out = run(&["--help"], "", None);

    assert_eq!(out.code, Some(0));
    assert!(out.stdout.contains("USAGE"));
    assert!(out.stdout.contains("--key-env"));
    assert!(out.stdout.contains("EXIT CODES"));
}

/// Build a log whose entries are shuffled out of chain order, as a
/// concurrently-written log can be, without altering any entry.
fn out_of_order_log(count: usize) -> String {
    let mut lines: Vec<&str> = Vec::new();
    let log = signed_log(count);
    lines.extend(log.lines());
    // Swap two adjacent entries: valid data, wrong order.
    lines.swap(1, 2);
    lines.join("\n")
}

#[test]
fn out_of_order_log_fails_strict_verification_with_a_hint() {
    let out = run(&["--key-env", "AUDIT_KEY"], &out_of_order_log(4), Some(KEY));

    assert_eq!(out.code, Some(EXIT_TAMPERED));
    assert!(
        out.stdout.contains("--unordered"),
        "should point at the flag rather than just crying tampering: {}",
        out.stdout
    );
}

#[test]
fn out_of_order_log_passes_with_unordered() {
    let out = run(
        &["--key-env", "AUDIT_KEY", "--unordered"],
        &out_of_order_log(4),
        Some(KEY),
    );

    assert_eq!(out.code, Some(0), "stdout: {}", out.stdout);
    assert!(out.stdout.contains("OK: 4 entries verified"));
}

#[test]
fn unordered_still_rejects_a_tampered_log() {
    let log = out_of_order_log(4).replace("user3@example.com", "mallory@example.com");
    let out = run(&["--key-env", "AUDIT_KEY", "--unordered"], &log, Some(KEY));

    assert_eq!(
        out.code,
        Some(EXIT_TAMPERED),
        "--unordered must not become an escape hatch: {}",
        out.stdout
    );
}

#[test]
fn unordered_appears_in_help() {
    let out = run(&["--help"], "", None);
    assert!(out.stdout.contains("--unordered"));
}
