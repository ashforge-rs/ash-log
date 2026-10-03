//! OCSF (Open Cybersecurity Schema Framework) 1.8.0 support for ash-log.
//!
//! All types in this module are **generated at compile time** from
//! `schemas/ocsf-1.8.0.json` by `build.rs` (which uses the shared logic in
//! `src/codegen_shared.rs`).  The standalone binary `ocsf_codegen` exposes
//! the same generator so you can inspect or extend the output.
//!
//! # Feature flag
//!
//! This module is compiled only when the `ocsf` Cargo feature is enabled:
//!
//! ```toml
//! [dependencies]
//! ash-log = { version = "*", features = ["ocsf"] }
//! ```
//!
//! # Supported event classes (OCSF 1.8.0)
//!
//! | Struct | `class_uid` | Category | Description |
//! |--------|------------|----------|-------------|
//! | `OcsfAuthentication` | 3002 | IAM | Logon / logoff events |
//! | `OcsfAccountChange` | 3001 | IAM | Account management |
//! | `OcsfAuthorizeSession` | 3003 | IAM | Privilege assignment |
//! | `OcsfNetworkActivity` | 4001 | Network | Connections and traffic |
//! | `OcsfProcessActivity` | 1007 | System | Process lifecycle |
//! | `OcsfDetectionFinding` | 2004 | Findings | Alert / detection |
//! | `OcsfVulnerabilityFinding` | 2002 | Findings | CVE / weakness reports |
//! | `OcsfApiActivity` | 6003 | Application | CRUD API calls |
//!
//! # Quick start
//!
//! ```rust,no_run
//! use ash_log::ocsf::{
//!     OcsfAuthentication, OcsfAuthActivityId,
//!     OcsfMetadata, OcsfProduct, OcsfSeverityId, OcsfStatusId,
//!     OcsfUser, OcsfNetworkEndpoint,
//!     log_ocsf_event_validated,
//! };
//! use ash_log::StdoutAuditBackend;
//!
//! let product = OcsfProduct::new("my-service", "MyOrg");
//! let metadata = OcsfMetadata::from_product(product);
//!
//! let event = OcsfAuthentication::builder()
//!     .activity_id(OcsfAuthActivityId::Logon)
//!     .time(1_700_000_000_000)
//!     .metadata(metadata)
//!     .severity_id(OcsfSeverityId::Informational)
//!     .user(OcsfUser::with_name("alice"))
//!     .src_endpoint(OcsfNetworkEndpoint::from_ip("192.168.1.1"))
//!     .status_id(OcsfStatusId::Success)
//!     .build();
//!
//! log_ocsf_event_validated(&StdoutAuditBackend, &event).unwrap();
//! ```

pub mod schema;

// Pull in all generated types (enums, objects, event structs, builders).
// The file is produced by build.rs at compile time using src/codegen_shared.rs.
include!(concat!(env!("OUT_DIR"), "/ocsf_generated.rs"));

use crate::AuditBackend;
use serde::Serialize;

/// Marker trait for all OCSF event structs.
///
/// Implement this on custom event classes to make them usable with
/// [`log_ocsf_event`] and [`log_ocsf_event_validated`].
///
/// The generated event classes already implement this trait.
pub trait OcsfEvent: Serialize {
    /// The OCSF `class_uid` for this event class.
    fn class_uid(&self) -> i32;

    /// The OCSF `category_uid` for this event class.
    fn category_uid(&self) -> i32;
}

/// Serialize an OCSF event and write it to `backend` via
/// [`AuditBackend::security_log`].
///
/// Serialization errors are printed to stderr and the event is not logged.
pub fn log_ocsf_event<E: OcsfEvent>(backend: &dyn AuditBackend, event: &E) {
    match serde_json::to_value(event) {
        Ok(json) => backend.security_log(&json),
        Err(e) => eprintln!("[OCSF ERROR] Failed to serialize OCSF event: {e}"),
    }
}

/// Validate an OCSF event against the schema, then write it to `backend`.
///
/// Returns an error if validation fails; the event is **not** logged in that
/// case.
///
/// # Errors
///
/// Returns [`schema::OcsfValidationError`] when validation fails.
pub fn log_ocsf_event_validated<E: OcsfEvent>(
    backend: &dyn AuditBackend,
    event: &E,
) -> Result<(), schema::OcsfValidationError> {
    match serde_json::to_value(event) {
        Ok(json) => {
            schema::validate_ocsf_event(&json)?;
            backend.security_log(&json);
            Ok(())
        }
        Err(e) => Err(schema::OcsfValidationError {
            details: vec![format!("serialization failed: {e}")],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta() -> OcsfMetadata {
        OcsfMetadata::from_product(OcsfProduct::new("TestApp", "TestOrg"))
    }

    // ── Authentication ────────────────────────────────────────────────────────

    #[test]
    fn test_authentication_builder_and_trait() {
        let event = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::Logon)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .severity_id(OcsfSeverityId::Informational)
            .user(OcsfUser::with_name("alice"))
            .src_endpoint(OcsfNetworkEndpoint::from_ip("10.0.0.1"))
            .status_id(OcsfStatusId::Success)
            .build();

        assert_eq!(event.class_uid(), 3002);
        assert_eq!(event.category_uid(), 3);
        // type_uid = 3002 * 100 + 1 (Logon)
        assert_eq!(event.type_uid, 300_201);
    }

    #[test]
    fn test_authentication_new_activities_180() {
        let preauth = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::Preauth)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();
        assert_eq!(preauth.type_uid, 3002 * 100 + 6);

        let switch = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::AccountSwitch)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();
        assert_eq!(switch.type_uid, 3002 * 100 + 7);
    }

    // ── Account Change ────────────────────────────────────────────────────────

    #[test]
    fn test_account_change_builder() {
        let event = OcsfAccountChange::builder()
            .activity_id(OcsfAccountChangeActivityId::Create)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .user(OcsfUser::with_name("bob"))
            .build();

        assert_eq!(event.class_uid(), 3001);
        assert_eq!(event.category_uid(), 3);
        // type_uid = 3001 * 100 + 1 (Create)
        assert_eq!(event.type_uid, 300_101);
    }

    // ── Authorize Session ─────────────────────────────────────────────────────

    #[test]
    fn test_authorize_session_builder() {
        let event = OcsfAuthorizeSession::builder()
            .activity_id(OcsfAuthorizeSessionActivityId::Assign)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();

        assert_eq!(event.class_uid(), 3003);
        assert_eq!(event.type_uid, 300_301);
    }

    // ── Network Activity ──────────────────────────────────────────────────────

    #[test]
    fn test_network_activity_listen_180() {
        let event = OcsfNetworkActivity::builder()
            .activity_id(OcsfNetworkActivityId::Listen)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .src_endpoint(OcsfNetworkEndpoint::from_ip("0.0.0.0"))
            .build();

        assert_eq!(event.class_uid(), 4001);
        // type_uid = 4001 * 100 + 7 (Listen)
        assert_eq!(event.type_uid, 400_107);
    }

    #[test]
    fn test_network_activity_open() {
        let event = OcsfNetworkActivity::builder()
            .activity_id(OcsfNetworkActivityId::Open)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .bytes_in(1024)
            .bytes_out(2048)
            .build();

        assert_eq!(event.class_uid(), 4001);
        assert_eq!(event.type_uid, 400_101);
    }

    // ── Process Activity ──────────────────────────────────────────────────────

    #[test]
    fn test_process_activity_builder() {
        let event = OcsfProcessActivity::builder()
            .activity_id(OcsfProcessActivityId::Launch)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .process(OcsfProcess {
                pid: Some(1234),
                name: Some("bash".to_string()),
                cmd_line: Some("/bin/bash -i".to_string()),
                uid: None,
                file_path: None,
                parent_process_pid: None,
            })
            .build();

        assert_eq!(event.class_uid(), 1007);
        assert_eq!(event.type_uid, 100_701);
    }

    #[test]
    fn test_process_activity_set_user_id_180() {
        let event = OcsfProcessActivity::builder()
            .activity_id(OcsfProcessActivityId::SetUserId)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();
        // type_uid = 1007 * 100 + 5 (SetUserId)
        assert_eq!(event.type_uid, 100_705);
    }

    // ── Detection Finding ─────────────────────────────────────────────────────

    #[test]
    fn test_detection_finding_builder() {
        let info = OcsfFindingInfo::new("RULE-001", "Suspicious login");
        let event = OcsfDetectionFinding::builder()
            .activity_id(OcsfDetectionFindingActivityId::Create)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .finding_info(info)
            .severity_id(OcsfSeverityId::High)
            .is_alert(true)
            .build();

        assert_eq!(event.class_uid(), 2004);
        assert_eq!(event.category_uid(), 2);
        assert_eq!(event.type_uid, 200_401);
    }

    // ── Vulnerability Finding ─────────────────────────────────────────────────

    #[test]
    fn test_vulnerability_finding_builder() {
        let info = OcsfFindingInfo::new("CVE-2024-0001", "Critical buffer overflow");
        let vuln = OcsfVulnerability {
            cve_uid: Some("CVE-2024-0001".to_string()),
            desc: Some("Heap buffer overflow in libssl".to_string()),
            severity: Some("Critical".to_string()),
            fix_available: Some(true),
            references: None,
        };
        let event = OcsfVulnerabilityFinding::builder()
            .activity_id(OcsfVulnerabilityFindingActivityId::Create)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .finding_info(info)
            .vulnerabilities(vec![vuln])
            .severity_id(OcsfSeverityId::Critical)
            .build();

        assert_eq!(event.class_uid(), 2002);
        assert_eq!(event.type_uid, 200_201);
    }

    // ── API Activity ──────────────────────────────────────────────────────────

    #[test]
    fn test_api_activity_builder() {
        let event = OcsfApiActivity::builder()
            .activity_id(OcsfApiActivityId::Read)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .api(OcsfApi {
                service_name: Some("s3".to_string()),
                operation: Some("GetObject".to_string()),
                version: Some("2006-03-01".to_string()),
                request_uid: Some("abc-123".to_string()),
            })
            .build();

        assert_eq!(event.class_uid(), 6003);
        assert_eq!(event.category_uid(), 6);
        // type_uid = 6003 * 100 + 2 (Read)
        assert_eq!(event.type_uid, 600_302);
    }

    // ── Cross-cutting ─────────────────────────────────────────────────────────

    #[test]
    fn test_log_ocsf_event_with_noop_backend() {
        use crate::NoopAuditBackend;
        let event = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::Logoff)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();
        log_ocsf_event(&NoopAuditBackend, &event);
    }

    #[test]
    fn test_log_ocsf_event_validated_passes() {
        use crate::NoopAuditBackend;
        let event = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::Logon)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .severity_id(OcsfSeverityId::Informational)
            .status_id(OcsfStatusId::Success)
            .build();
        assert!(log_ocsf_event_validated(&NoopAuditBackend, &event).is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let event = OcsfAuthentication::builder()
            .activity_id(OcsfAuthActivityId::Logon)
            .time(1_700_000_000_000)
            .metadata(make_meta())
            .build();

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 3002);
        assert_eq!(json["category_uid"], 3);
        assert!(json["metadata"]["product"]["name"].is_string());
    }

    #[test]
    fn test_metadata_version_is_180() {
        let meta = make_meta();
        assert_eq!(meta.version, "1.8.0");
    }
}
