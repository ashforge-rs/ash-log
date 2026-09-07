//! Records where an event came from.
//!
//! Provenance answers "what emitted this?" — the source location, the module,
//! the thread and process, and the service identity. It lives on the event
//! itself rather than in `metadata`, so it is part of the canonical form and is
//! therefore covered by any integrity mechanism. That is the difference between
//! recording where a record came from and being able to *prove* it.

use serde::{Deserialize, Serialize};

/// Where an event was emitted from.
///
/// Call-site fields are captured automatically by
/// [`AuditEvent::diagnostic`](crate::AuditEvent::diagnostic) and the
/// [`Logger`](crate::Logger) methods via `#[track_caller]`; service identity is
/// set once when the logger is built.
///
/// Every field is optional so that provenance costs nothing when it is not
/// wanted, and so events written by earlier versions still deserialize.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Source file the event was emitted from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    /// Line within [`file`](Self::file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,

    /// Rust module path, when emitted through a macro that can capture it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,

    /// Name of the emitting thread, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,

    /// Process id of the emitting process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Logical service name, set once on the logger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// Service version, set once on the logger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Host the service is running on, set once on the logger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl Provenance {
    /// Empty provenance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture the caller's source location, thread name, and process id.
    ///
    /// `#[track_caller]` reports the location where the calling function was
    /// invoked, so this records the emitting call site rather than anything
    /// inside this crate.
    #[must_use]
    #[track_caller]
    pub fn capture() -> Self {
        let location = std::panic::Location::caller();
        Self {
            file: Some(location.file().to_string()),
            line: Some(location.line()),
            module: None,
            thread: std::thread::current().name().map(ToString::to_string),
            pid: Some(std::process::id()),
            ..Self::default()
        }
    }

    /// Whether every field is unset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Set the source file.
    #[must_use]
    pub fn with_file<S: Into<String>>(mut self, file: S) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set the source line.
    #[must_use]
    pub const fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the module path.
    #[must_use]
    pub fn with_module<S: Into<String>>(mut self, module: S) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Set the service identity fields carried on every event.
    #[must_use]
    pub fn with_service<S: Into<String>>(mut self, service: S) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the service version.
    #[must_use]
    pub fn with_version<S: Into<String>>(mut self, version: S) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the host name.
    #[must_use]
    pub fn with_host<S: Into<String>>(mut self, host: S) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Fill any unset field in `self` from `other`.
    ///
    /// Used to layer a logger's service identity underneath a call site's
    /// location without overwriting what the call site already established.
    #[must_use]
    pub fn or_fill_from(mut self, other: &Self) -> Self {
        if self.file.is_none() {
            self.file.clone_from(&other.file);
        }
        if self.line.is_none() {
            self.line = other.line;
        }
        if self.module.is_none() {
            self.module.clone_from(&other.module);
        }
        if self.thread.is_none() {
            self.thread.clone_from(&other.thread);
        }
        if self.pid.is_none() {
            self.pid = other.pid;
        }
        if self.service.is_none() {
            self.service.clone_from(&other.service);
        }
        if self.version.is_none() {
            self.version.clone_from(&other.version);
        }
        if self.host.is_none() {
            self.host.clone_from(&other.host);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_records_the_call_site() {
        let provenance = Provenance::capture();

        assert_eq!(
            provenance.file.as_deref(),
            Some(file!()),
            "capture must report the caller's file, not one inside this crate"
        );
        assert!(provenance.line.is_some());
        assert_eq!(provenance.pid, Some(std::process::id()));
    }

    #[test]
    fn test_empty_provenance_serializes_to_an_empty_object() {
        let json = serde_json::to_string(&Provenance::new()).expect("serializes");
        assert_eq!(json, "{}", "unset provenance must not bloat a log line");
        assert!(Provenance::new().is_empty());
    }

    #[test]
    fn test_or_fill_from_does_not_overwrite() {
        let base = Provenance::new()
            .with_service("auth-api")
            .with_host("node-1")
            .with_file("base.rs");

        let merged = Provenance::new()
            .with_file("call-site.rs")
            .or_fill_from(&base);

        assert_eq!(
            merged.file.as_deref(),
            Some("call-site.rs"),
            "an established field wins over the fallback"
        );
        assert_eq!(merged.service.as_deref(), Some("auth-api"));
        assert_eq!(merged.host.as_deref(), Some("node-1"));
    }

    #[test]
    fn test_round_trips() {
        let provenance = Provenance::capture()
            .with_module("my_app::auth")
            .with_service("auth-api")
            .with_version("1.2.3");

        let json = serde_json::to_string(&provenance).expect("serializes");
        let parsed: Provenance = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(parsed, provenance);
    }

    #[test]
    fn test_missing_provenance_deserializes() {
        // A log line written before provenance existed.
        let parsed: Provenance = serde_json::from_str("{}").expect("deserializes");
        assert!(parsed.is_empty());
    }
}
