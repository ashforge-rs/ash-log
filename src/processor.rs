//! Helper functions for logging security audit events.

use super::{AuditBackend, AuditEvent, AuditEventType, AuditIntegrity, AuditResult, AuditSeverity};
use std::net::SocketAddr;

/// Log authentication/authorization events.
///
/// # Arguments
/// - `backend` – destination for the audit event
/// - `integrity` – integrity mechanism to apply before writing
/// - `method` – the method or resource being accessed
/// - `remote_addr` – remote address of the client, if known
/// - `principal` – authenticated principal (user ID, API key, etc.), if known
/// - `allowed` – whether access was granted
pub fn log_auth_event(
    backend: &dyn AuditBackend,
    integrity: &dyn AuditIntegrity,
    method: &str,
    remote_addr: Option<SocketAddr>,
    principal: Option<&str>,
    allowed: bool,
) {
    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::AuthorizationCheck)
        .method(method)
        .result(if allowed {
            AuditResult::Success
        } else {
            AuditResult::Denied
        })
        .severity(if allowed {
            AuditSeverity::Info
        } else {
            AuditSeverity::Critical
        });

    if let Some(addr) = remote_addr {
        event = event.remote_addr(addr);
    }

    if let Some(p) = principal {
        event = event.principal(p);
    }

    let mut evt = event.build();
    integrity.add_integrity(&mut evt);
    backend.log_audit(&evt);
}

/// Log security policy violations (rate limits, banned IPs, etc.).
///
/// # Arguments
/// - `backend` – destination for the audit event
/// - `integrity` – integrity mechanism to apply before writing
/// - `violation_type` – short descriptor of the violation (e.g. `"rate_limit_exceeded"`)
/// - `remote_addr` – remote address of the client, if known
/// - `principal` – authenticated principal, if known
pub fn log_security_violation(
    backend: &dyn AuditBackend,
    integrity: &dyn AuditIntegrity,
    violation_type: &str,
    remote_addr: Option<SocketAddr>,
    principal: Option<&str>,
) {
    let mut event = AuditEvent::builder()
        .event_type(AuditEventType::SecurityViolation)
        .result(AuditResult::Violation)
        .severity(AuditSeverity::Critical)
        .metadata("violation_type", violation_type);

    if let Some(addr) = remote_addr {
        event = event.remote_addr(addr);
    }

    if let Some(p) = principal {
        event = event.principal(p);
    }

    let mut evt = event.build();
    integrity.add_integrity(&mut evt);
    backend.log_audit(&evt);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoIntegrity, NoopAuditBackend};

    #[test]
    fn test_log_auth_event_allowed() {
        let backend = NoopAuditBackend;
        let integrity = NoIntegrity;
        log_auth_event(
            &backend,
            &integrity,
            "read_data",
            Some("127.0.0.1:1234".parse().unwrap()),
            Some("alice@example.com"),
            true,
        );
    }

    #[test]
    fn test_log_auth_event_denied() {
        let backend = NoopAuditBackend;
        let integrity = NoIntegrity;
        log_auth_event(&backend, &integrity, "admin_action", None, None, false);
    }

    #[test]
    fn test_log_security_violation() {
        let backend = NoopAuditBackend;
        let integrity = NoIntegrity;
        log_security_violation(
            &backend,
            &integrity,
            "rate_limit_exceeded",
            Some("192.168.1.1:9000".parse().unwrap()),
            Some("api_key:abc123"),
        );
    }
}
