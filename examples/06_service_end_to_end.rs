//! A realistic service setup: write a signed log to a file, then verify it with
//! the `ash-log-verify` CLI.
//!
//! ```text
//! export AUDIT_KEY="a-real-secret-of-at-least-32-byt"
//! cargo run --features hmac-chain --example 06_service_end_to_end
//! ```
//!
//! The example writes `audit.log` in a temporary directory and prints the exact
//! commands to verify it.

use ash_log::{
    AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity, HmacChainIntegrity,
    Logger, Provenance,
};
use std::io::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

/// Appends JSON lines to a file. A real deployment would ship these off-box
/// promptly, so an attacker never controls the only copy.
struct FileBackend(Mutex<std::fs::File>);

impl FileBackend {
    fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(Mutex::new(std::fs::File::create(path)?)))
    }
}

impl AuditBackend for FileBackend {
    fn log_audit(&self, event: &AuditEvent) {
        let Ok(line) = serde_json::to_string(event) else {
            eprintln!("[AUDIT ERROR] failed to serialize event");
            return;
        };
        let mut file = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = writeln!(file, "{line}") {
            eprintln!("[AUDIT ERROR] failed to write audit event: {e}");
        }
    }

    fn flush(&self) {
        let mut file = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = file.flush();
    }
}

fn main() -> std::io::Result<()> {
    // In production this comes from a KMS or secrets manager. The fallback here
    // only exists so the example runs without setup.
    let key = std::env::var("AUDIT_KEY")
        .unwrap_or_else(|_| "example-key-at-least-32-bytes!!!!".to_string());

    let dir = std::env::temp_dir().join("ash-log-example");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("audit.log");

    let logger = Logger::builder(Arc::new(FileBackend::create(&path)?))
        .integrity(Arc::new(HmacChainIntegrity::new(key.as_bytes())))
        .min_level(AuditSeverity::Info)
        .identity(
            Provenance::new()
                .with_service("orders-api")
                .with_version(env!("CARGO_PKG_VERSION")),
        )
        .build();

    // --- A day in the life of a service ----------------------------------
    logger.info("service started");

    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .principal("alice@example.com")
            .method("password_login")
            .result(AuditResult::Success)
            .correlation_id("req-1001")
            .build(),
    );

    logger.debug("dropped: below the Info threshold");

    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::AuthorizationCheck)
            .principal("mallory@example.com")
            .method("refund_order")
            .result(AuditResult::Denied)
            .error("role lacks refund permission")
            .correlation_id("req-1002")
            .build(),
    );

    logger.warn("payment gateway latency above target");

    logger.log(
        AuditEvent::builder()
            .event_type(AuditEventType::AdminAction)
            .principal("ops@example.com")
            .method("rotate_api_keys")
            .result(AuditResult::Success)
            .build(),
    );

    logger.flush();

    let written = std::fs::read_to_string(&path)?.lines().count();
    println!("wrote {written} entries to {}", path.display());
    println!("(one diagnostic was filtered out by the Info threshold)\n");

    println!("Verify it:");
    println!("  export AUDIT_KEY={key:?}");
    println!(
        "  cargo run --features hmac-chain --bin ash-log-verify -- \\\n    --key-env AUDIT_KEY --expect-count {written} < {}",
        path.display()
    );
    println!("\nOr, once installed:");
    println!(
        "  ash-log-verify --key-env AUDIT_KEY --expect-count {written} < {}",
        path.display()
    );
    println!("\nTry tampering first, and watch it fail:");
    println!(
        "  sed -i 's/denied/success/' {} && ash-log-verify --key-env AUDIT_KEY < {}",
        path.display(),
        path.display()
    );

    Ok(())
}
