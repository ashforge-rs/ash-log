//! # ash-log
//!
//! Security audit logging for Rust applications.
//!
//! Provides structured audit logging for security events including authentication,
//! authorization, method invocations, and policy violations.
//!
//! For logs that must resist deliberate modification, enable the `hmac-chain`
//! feature and use [`HmacChainIntegrity`]. The default [`ChecksumIntegrity`] uses
//! an unkeyed hash and detects only accidental corruption.
//!
//! **Features**: append-only logs, integrity verification, pluggable backends.
//!
//! ## Quick start
//!
//! ```rust
//! use ash_log::*;
//! use std::sync::Arc;
//!
//! let backend = Arc::new(StdoutAuditBackend);
//! let integrity = SequenceIntegrity::new();
//!
//! let mut event = AuditEvent::builder()
//!     .event_type(AuditEventType::AuthenticationAttempt)
//!     .principal("alice@example.com")
//!     .result(AuditResult::Success)
//!     .build();
//!
//! integrity.add_integrity(&mut event);
//! backend.log_audit(&event);
//! ```

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod async_backend;
mod backends;
mod context;
mod error;
mod file;
mod filter;
#[cfg(feature = "hlc")]
mod hlc;
mod integrity;
mod logger;
mod macros;
mod processor;
mod provenance;
mod redact;

#[cfg(feature = "tracing")]
mod tracing_bridge;

#[cfg(feature = "hmac-chain")]
mod hmac_chain;

#[cfg(feature = "ocsf")]
pub mod ocsf;

pub use async_backend::*;
pub use backends::*;
pub use context::*;
pub use error::*;
pub use file::*;
pub use filter::*;
#[cfg(feature = "hlc")]
pub use hlc::*;
#[cfg(feature = "hmac-chain")]
pub use hmac_chain::*;
pub use integrity::*;
pub use logger::*;
pub use processor::*;
pub use provenance::*;
pub use redact::*;
#[cfg(feature = "tracing")]
pub use tracing_bridge::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

/// A security audit event representing a significant action or decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Precise timestamp with nanosecond precision
    #[serde(with = "system_time_format")]
    pub timestamp: SystemTime,

    /// Type of audit event
    pub event_type: AuditEventType,

    /// Unique correlation ID spanning the request chain
    pub correlation_id: Option<String>,

    /// Remote address of the client
    pub remote_addr: Option<SocketAddr>,

    /// Principal identifier (user ID, API key, certificate DN, etc.)
    pub principal: Option<String>,

    /// Method or action being performed
    pub method: Option<String>,

    /// Result of the action
    pub result: AuditResult,

    /// Event severity level
    pub severity: AuditSeverity,

    /// Additional context and metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Request parameters (sanitized)
    pub params: Option<serde_json::Value>,

    /// Error message if result is Failure or Denied
    pub error: Option<String>,

    /// Human-readable message.
    ///
    /// Primarily carried by [`AuditEventType::Diagnostic`] records. It is part
    /// of the canonical form, so it is covered by any integrity mechanism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Where the event was emitted from.
    ///
    /// Part of the canonical form, so provenance is covered by any integrity
    /// mechanism: it can be proved, not merely recorded.
    #[serde(default, skip_serializing_if = "Provenance::is_empty")]
    pub provenance: Provenance,

    /// Monotonic causal timestamp, when the logger was given a clock.
    ///
    /// [`timestamp`](Self::timestamp) comes from the system clock and can move
    /// backwards; this cannot. It is part of the canonical form, so the causal
    /// ordering is covered by the integrity mechanism. Absent unless the `hlc`
    /// feature is enabled and a clock is configured, and skipped when absent,
    /// so events written without it canonicalize exactly as before.
    #[cfg(feature = "hlc")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<EventClock>,
}

/// Types of recorded events.
///
/// Every variant except [`Diagnostic`](Self::Diagnostic) is security-relevant
/// and is always admitted to the audit chain regardless of level filtering; see
/// [`is_security_relevant`](Self::is_security_relevant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEventType {
    /// Connection established
    ConnectionEstablished,

    /// Connection closed
    ConnectionClosed,

    /// Authentication attempt (login, certificate validation, etc.)
    AuthenticationAttempt,

    /// Authorization check (access control decision)
    AuthorizationCheck,

    /// RPC method invocation
    MethodInvocation,

    /// Error occurred during processing
    ErrorOccurred,

    /// Security policy violation (rate limit, size limit, banned IP, etc.)
    SecurityViolation,

    /// Configuration change (admin action)
    ConfigurationChange,

    /// System administrative action
    AdminAction,

    /// A diagnostic or operational log record carrying a human-readable
    /// message rather than a security decision.
    ///
    /// Unlike every other variant, this one is **not** security-relevant, so it
    /// is subject to level filtering and may legitimately be dropped. Use it for
    /// application logging; use a specific variant for anything that belongs in
    /// the compliance record.
    Diagnostic,
}

impl AuditEventType {
    /// Whether this event type is security-relevant and must therefore always
    /// reach the audit chain, regardless of any level filtering.
    ///
    /// This is the admission policy for the crate's two tiers: security events
    /// are recorded unconditionally, so an operational log level cannot shrink
    /// the compliance record, while diagnostic events are subject to the
    /// configured minimum level.
    ///
    /// The `match` below is deliberately exhaustive with no wildcard arm: a new
    /// variant will fail to compile until its tier is stated explicitly, rather
    /// than silently defaulting into one.
    ///
    /// ```rust
    /// # use ash_log::AuditEventType;
    /// assert!(AuditEventType::SecurityViolation.is_security_relevant());
    /// ```
    #[must_use]
    pub const fn is_security_relevant(self) -> bool {
        match self {
            Self::ConnectionEstablished
            | Self::ConnectionClosed
            | Self::AuthenticationAttempt
            | Self::AuthorizationCheck
            | Self::MethodInvocation
            | Self::ErrorOccurred
            | Self::SecurityViolation
            | Self::ConfigurationChange
            | Self::AdminAction => true,
            Self::Diagnostic => false,
        }
    }
}

/// Result of an audited action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditResult {
    /// Action succeeded
    Success,

    /// Action failed due to error
    Failure,

    /// Action denied by policy
    Denied,

    /// Action resulted in security violation
    Violation,

    /// No pass/fail outcome applies.
    ///
    /// Used by [`AuditEventType::Diagnostic`] records, which report something
    /// that happened rather than the outcome of a security decision.
    NotApplicable,
}

/// Severity level of an audit event, ordered from least to most severe.
///
/// Variants are declared in ascending order of severity, and `Ord` is derived
/// from that order, so `severity >= min_level` is a valid level filter.
///
/// ```rust
/// # use ash_log::AuditSeverity;
/// assert!(AuditSeverity::Critical > AuditSeverity::Info);
/// assert!(AuditSeverity::Error > AuditSeverity::Warning);
/// ```
///
/// # Compatibility
///
/// The enum is `#[non_exhaustive]`, and adding a variant is asymmetric: new
/// code reads old logs, but an older verifier rejects a level it does not know.
/// Roll verifiers out before the producers that write new levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditSeverity {
    /// Fine-grained diagnostic detail. Noisy; normally filtered out.
    Trace,

    /// Diagnostic detail useful when developing or debugging.
    Debug,

    /// Normal operation worth recording.
    Info,

    /// An anomaly that did not cause a failure.
    Warning,

    /// An operation failed.
    Error,

    /// A security-significant event.
    Critical,
}

impl AuditSeverity {
    /// The lowest severity, useful as a permissive filter threshold.
    pub const MIN: Self = Self::Trace;

    /// The highest severity, useful as a restrictive filter threshold.
    pub const MAX: Self = Self::Critical;

    /// The lower-case name of this level, as it appears in serialized events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AuditSeverity {
    type Err = ParseSeverityError;

    /// Parse a level from its name, case-insensitively.
    ///
    /// Accepts the serialized names, plus `warn` for `Warning` and `crit` for
    /// `Critical`, since both are common in configuration files.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "crit" | "critical" => Ok(Self::Critical),
            _ => Err(ParseSeverityError(s.to_string())),
        }
    }
}

/// Returned when a string does not name an [`AuditSeverity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSeverityError(String);

impl std::fmt::Display for ParseSeverityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown severity {:?}; expected one of trace, debug, info, warning, error, critical",
            self.0
        )
    }
}

impl std::error::Error for ParseSeverityError {}

impl AuditEvent {
    /// Start building a diagnostic log record.
    ///
    /// Pre-sets [`AuditEventType::Diagnostic`],
    /// [`AuditResult::NotApplicable`], and the message, so a message-shaped log
    /// line does not have to invent a security classification it does not have.
    /// The default severity is [`AuditSeverity::Info`]; set an explicit level
    /// with [`severity`](AuditEventBuilder::severity).
    ///
    /// Diagnostic records are subject to level filtering, unlike every other
    /// event type.
    ///
    /// ```rust
    /// # use ash_log::*;
    /// let event = AuditEvent::diagnostic("cache warm complete")
    ///     .severity(AuditSeverity::Debug)
    ///     .build();
    ///
    /// assert_eq!(event.event_type, AuditEventType::Diagnostic);
    /// assert!(!event.event_type.is_security_relevant());
    /// assert_eq!(event.message.as_deref(), Some("cache warm complete"));
    /// ```
    #[must_use]
    #[track_caller]
    pub fn diagnostic<S: Into<String>>(message: S) -> AuditEventBuilder {
        AuditEventBuilder::default()
            .event_type(AuditEventType::Diagnostic)
            .result(AuditResult::NotApplicable)
            .message(message)
            .provenance(Provenance::capture())
    }

    /// Create a new audit event builder
    #[must_use]
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder::default()
    }

    /// Add a metadata entry
    pub fn add_metadata<K: Into<String>, V: Into<serde_json::Value>>(&mut self, key: K, value: V) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Set the correlation ID from a request
    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: Option<String>) -> Self {
        self.correlation_id = correlation_id;
        self
    }

    /// Set the principal from connection context
    #[must_use]
    pub fn with_principal<S: Into<String>>(mut self, principal: S) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Set the remote address
    #[must_use]
    pub fn with_remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }
}

/// Builder for creating audit events
#[derive(Debug, Default)]
pub struct AuditEventBuilder {
    event_type: Option<AuditEventType>,
    correlation_id: Option<String>,
    remote_addr: Option<SocketAddr>,
    principal: Option<String>,
    method: Option<String>,
    result: Option<AuditResult>,
    severity: Option<AuditSeverity>,
    metadata: HashMap<String, serde_json::Value>,
    params: Option<serde_json::Value>,
    error: Option<String>,
    message: Option<String>,
    provenance: Provenance,
    #[cfg(feature = "hlc")]
    hlc: Option<EventClock>,
}

impl AuditEventBuilder {
    /// Set event type
    #[must_use]
    pub fn event_type(mut self, event_type: AuditEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Set correlation ID
    #[must_use]
    pub fn correlation_id<S: Into<String>>(mut self, id: S) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set remote address
    #[must_use]
    pub fn remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Set principal
    #[must_use]
    pub fn principal<S: Into<String>>(mut self, principal: S) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Set method name
    #[must_use]
    pub fn method<S: Into<String>>(mut self, method: S) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set result
    #[must_use]
    pub fn result(mut self, result: AuditResult) -> Self {
        self.result = Some(result);
        self
    }

    /// Set severity
    #[must_use]
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Add metadata entry
    #[must_use]
    pub fn metadata<K: Into<String>, V: Into<serde_json::Value>>(
        mut self,
        key: K,
        value: V,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set sanitized parameters
    #[must_use]
    pub fn params(mut self, params: serde_json::Value) -> Self {
        self.params = Some(params);
        self
    }

    /// Set where the event was emitted from.
    #[must_use]
    pub fn provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Set the monotonic causal timestamp.
    ///
    /// Normally supplied by the [`Logger`] from its configured clock rather
    /// than set here; this exists for events built by hand.
    #[cfg(feature = "hlc")]
    #[must_use]
    pub fn hlc(mut self, hlc: EventClock) -> Self {
        self.hlc = Some(hlc);
        self
    }

    /// Set the human-readable message.
    #[must_use]
    pub fn message<S: Into<String>>(mut self, message: S) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set error message
    #[must_use]
    pub fn error<S: Into<String>>(mut self, error: S) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Build the audit event
    ///
    /// # Panics
    /// Panics if `event_type` or `result` were not set
    #[must_use]
    #[allow(clippy::panic)]
    pub fn build(self) -> AuditEvent {
        let event_type = self
            .event_type
            .unwrap_or_else(|| panic!("event_type is required for AuditEvent"));
        let result = self
            .result
            .unwrap_or_else(|| panic!("result is required for AuditEvent"));

        // Determine default severity based on result. `NotApplicable` carries no
        // outcome, so it defaults to `Info` and callers are expected to set an
        // explicit level on diagnostic records.
        let severity = self.severity.unwrap_or(match result {
            AuditResult::Success | AuditResult::NotApplicable => AuditSeverity::Info,
            AuditResult::Failure => AuditSeverity::Warning,
            AuditResult::Denied | AuditResult::Violation => AuditSeverity::Critical,
        });

        AuditEvent {
            timestamp: SystemTime::now(),
            event_type,
            correlation_id: self.correlation_id,
            remote_addr: self.remote_addr,
            principal: self.principal,
            method: self.method,
            result,
            severity,
            metadata: self.metadata,
            params: self.params,
            error: self.error,
            message: self.message,
            provenance: self.provenance,
            #[cfg(feature = "hlc")]
            hlc: self.hlc,
        }
    }
}

/// Custom serialization for `SystemTime` to include nanosecond precision
mod system_time_format {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        #[allow(clippy::arithmetic_side_effects)] // Nanosecond calculation for timestamp
        let nanos = duration.as_secs() * 1_000_000_000 + u64::from(duration.subsec_nanos());
        serializer.serialize_u64(nanos)
    }

    #[allow(clippy::arithmetic_side_effects, clippy::as_conversions)] // Timestamp serialization math
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let nanos = u64::deserialize(deserializer)?;
        let secs = nanos / 1_000_000_000;
        // Safe: modulo operation ensures value < 1_000_000_000, fits in u32
        let subsec_nanos = (nanos % 1_000_000_000) as u32;
        Ok(UNIX_EPOCH + std::time::Duration::new(secs, subsec_nanos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .principal("user@example.com")
            .method("login")
            .result(AuditResult::Success)
            .build();

        assert_eq!(event.event_type, AuditEventType::AuthenticationAttempt);
        assert_eq!(event.principal, Some("user@example.com".to_string()));
        assert_eq!(event.result, AuditResult::Success);
        assert_eq!(event.severity, AuditSeverity::Info);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .principal("test_user")
            .method("get_balance")
            .result(AuditResult::Success)
            .build();

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("method_invocation"));
        assert!(json.contains("test_user"));
        assert!(json.contains("success"));
    }

    #[test]
    fn test_diagnostic_is_not_security_relevant() {
        assert!(!AuditEventType::Diagnostic.is_security_relevant());
    }

    #[test]
    fn test_diagnostic_builder_sets_a_truthful_classification() {
        let event = AuditEvent::diagnostic("cache warm complete").build();

        assert_eq!(event.event_type, AuditEventType::Diagnostic);
        assert_eq!(event.result, AuditResult::NotApplicable);
        assert_eq!(event.message.as_deref(), Some("cache warm complete"));
        // No outcome was claimed, so the level defaults to Info rather than
        // implying success.
        assert_eq!(event.severity, AuditSeverity::Info);
    }

    #[test]
    fn test_diagnostic_accepts_an_explicit_level() {
        let event = AuditEvent::diagnostic("connection retry")
            .severity(AuditSeverity::Warning)
            .build();

        assert_eq!(event.severity, AuditSeverity::Warning);
    }

    #[test]
    fn test_message_is_omitted_when_absent() {
        // Existing security events gain no empty field in their serialized form.
        let event = AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .result(AuditResult::Success)
            .build();

        let json = serde_json::to_string(&event).expect("serializes");
        assert!(
            !json.contains("message"),
            "absent message must not appear in the log line: {json}"
        );
    }

    #[test]
    fn test_message_round_trips() {
        let event = AuditEvent::diagnostic("disk usage 91%").build();
        let json = serde_json::to_string(&event).expect("serializes");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("deserializes");

        assert_eq!(parsed.message.as_deref(), Some("disk usage 91%"));
    }

    #[test]
    fn test_events_without_message_still_deserialize() {
        // A 0.1.0 log line has no `message` key at all.
        let line = r#"{"timestamp":0,"event_type":"method_invocation","correlation_id":null,
            "remote_addr":null,"principal":null,"method":null,"result":"success",
            "severity":"info","metadata":{},"params":null,"error":null}"#;
        let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");

        assert_eq!(parsed.message, None);
    }

    #[test]
    fn test_severity_is_ordered_ascending() {
        use AuditSeverity as S;
        let ascending = [
            S::Trace,
            S::Debug,
            S::Info,
            S::Warning,
            S::Error,
            S::Critical,
        ];
        for pair in ascending.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must sort below {:?}; level filtering depends on this",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(S::MIN, S::Trace);
        assert_eq!(S::MAX, S::Critical);
    }

    #[test]
    fn test_severity_round_trips_through_its_name() {
        use std::str::FromStr as _;
        for level in [
            AuditSeverity::Trace,
            AuditSeverity::Debug,
            AuditSeverity::Info,
            AuditSeverity::Warning,
            AuditSeverity::Error,
            AuditSeverity::Critical,
        ] {
            assert_eq!(AuditSeverity::from_str(level.as_str()), Ok(level));
            assert_eq!(level.to_string(), level.as_str());

            // The name must match the serialized form, or configuration files
            // and log lines would disagree about what a level is called.
            let json = serde_json::to_string(&level).expect("serializes");
            assert_eq!(json, format!("\"{}\"", level.as_str()));
        }
    }

    #[test]
    fn test_severity_parsing_is_lenient_about_case_and_aliases() {
        use std::str::FromStr as _;
        assert_eq!(AuditSeverity::from_str("WARN"), Ok(AuditSeverity::Warning));
        assert_eq!(
            AuditSeverity::from_str("  Critical "),
            Ok(AuditSeverity::Critical)
        );
        assert_eq!(AuditSeverity::from_str("crit"), Ok(AuditSeverity::Critical));
        assert!(AuditSeverity::from_str("verbose").is_err());
    }

    #[test]
    fn test_new_levels_deserialize_from_logs() {
        // A verifier must read every level a producer of the same version can
        // write, or a log would fail to deserialize rather than to verify.
        for name in ["trace", "debug", "info", "warning", "error", "critical"] {
            let parsed: AuditSeverity =
                serde_json::from_str(&format!("\"{name}\"")).expect("deserializes");
            assert_eq!(parsed.as_str(), name);
        }
    }

    #[test]
    fn test_security_relevance_classification() {
        // Every existing variant is security-relevant; only diagnostics are not.
        for event_type in [
            AuditEventType::ConnectionEstablished,
            AuditEventType::ConnectionClosed,
            AuditEventType::AuthenticationAttempt,
            AuditEventType::AuthorizationCheck,
            AuditEventType::MethodInvocation,
            AuditEventType::ErrorOccurred,
            AuditEventType::SecurityViolation,
            AuditEventType::ConfigurationChange,
            AuditEventType::AdminAction,
        ] {
            assert!(
                event_type.is_security_relevant(),
                "{event_type:?} must always be admitted to the audit chain"
            );
        }
    }

    #[test]
    fn test_severity_defaults() {
        let success = AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .build();
        assert_eq!(success.severity, AuditSeverity::Info);

        let denied = AuditEvent::builder()
            .event_type(AuditEventType::AuthorizationCheck)
            .result(AuditResult::Denied)
            .build();
        assert_eq!(denied.severity, AuditSeverity::Critical);
    }
}
