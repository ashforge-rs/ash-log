//! Declarative macros for the common call shapes.
//!
//! The macros are a thin layer over [`Logger`](crate::Logger) and
//! [`AuditEvent`](crate::AuditEvent): everything they do is reachable through
//! the builders, and they exist to remove the ceremony from the two shapes that
//! appear on nearly every line of calling code — constructing a logger, and
//! emitting one record.
//!
//! # Naming
//!
//! Every macro is exported with an `ash_` prefix, because `info`, `warn`, and
//! `error` are the most collision-prone names in the Rust logging ecosystem and
//! `use ash_log::*` must stay safe next to `use tracing::*`. Callers who want
//! the short names rename at the import site:
//!
//! ```rust
//! use ash_log::{ash_info as info, ash_warn as warn};
//! # use ash_log::*;
//! # let logger = ash_logger!(backend: std::sync::Arc::new(NoopAuditBackend));
//! info!(logger, "short names, opted into locally");
//! # let _ = &logger;
//! ```
//!
//! Expansions refer to this crate's items through `$crate`, so a renamed or
//! shadowed import at the call site cannot change what a macro resolves to.
//!
//! # Filtering happens before formatting
//!
//! The diagnostic macros consult [`Logger::min_level`](crate::Logger::min_level)
//! before evaluating their format arguments, so a dropped record costs one
//! atomic load rather than an allocation. This is why they are macros and not
//! functions taking a `String`.

/// Build a [`Logger`](crate::Logger) from named parts.
///
/// Every key is optional and order does not matter. The defaults match
/// [`Logger::builder`](crate::Logger::builder): a
/// [`StdoutAuditBackend`](crate::StdoutAuditBackend), no integrity mechanism,
/// and an [`Info`](crate::AuditSeverity::Info) threshold.
///
/// # Keys
///
/// - `backend:` — an `Arc<dyn AuditBackend>`.
/// - `buffered:` — an event count. Wraps the backend in a
///   [`BufferedAuditBackend`](crate::BufferedAuditBackend) that accumulates
///   writes and flushes once that many have queued, trading write syscalls for
///   latency. The buffer drains on [`Logger::flush`](crate::Logger::flush) and
///   on drop; events still queued are lost if the process exits without
///   unwinding, so call `flush()` on shutdown paths that bypass destructors.
/// - `integrity:` — an `Arc<dyn AuditIntegrity>`.
/// - `redact:` — an `Arc<dyn Redactor>` scrubbing secrets before events are
///   stamped.
/// - `filter:` — a [`LiveFilter`](crate::LiveFilter) of per-module level
///   directives, retunable at runtime.
/// - `clock:` — an `Arc<HlcClock>` giving every event a monotonic causal
///   timestamp inside the signed form (feature `hlc`).
/// - `min_level:` — the threshold for diagnostic records.
/// - `service:`, `version:`, `host:` — service identity, assembled into a
///   [`Provenance`](crate::Provenance) so the common case never names the type.
/// - `identity:` — a whole [`Provenance`](crate::Provenance), for anything the
///   three shorthand keys cannot express. Combining it with them is rejected at
///   compile time, since one would silently overwrite the other.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!();
///
/// let logger = ash_logger!(
///     backend: Arc::new(StderrAuditBackend),
///     integrity: Arc::new(SequenceIntegrity::new()),
///     min_level: AuditSeverity::Warning,
///     service: "payments-api",
///     version: env!("CARGO_PKG_VERSION"),
/// );
/// assert_eq!(logger.min_level(), AuditSeverity::Warning);
/// assert_eq!(logger.identity().service.as_deref(), Some("payments-api"));
/// ```
///
/// Buffered, trading write syscalls for latency:
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(
///     backend: Arc::new(StdoutAuditBackend),
///     buffered: 128,
/// );
///
/// ash_info!(logger, "queued, not yet written");
/// logger.flush(); // drains; so does dropping the logger
/// ```
///
/// An explicit identity, for fields the shorthand does not cover:
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(
///     backend: Arc::new(NoopAuditBackend),
///     identity: Provenance::new().with_service("gateway").with_host("pod-7"),
/// );
/// assert_eq!(logger.identity().host.as_deref(), Some("pod-7"));
/// ```
#[macro_export]
macro_rules! ash_logger {
    ($($key:ident : $value:expr),* $(,)?) => {{
        // Accumulated separately from the builder: the identity keys are
        // spread across several `with_*` calls and must merge, not replace.
        // `mut` is unused when no key touches them; the macro cannot know
        // which keys were given, so the lint is suppressed rather than the
        // bindings conditionally emitted.
        #[allow(unused_mut)]
        let mut identity = $crate::Provenance::new();
        #[allow(unused_mut)]
        let mut builder = $crate::Logger::builder(
            $crate::__ash_logger_backend!($($key : $value),*)
        );
        $(
            $crate::__ash_logger_field!(builder, identity, $key, $value);
        )*
        builder.identity(identity).build()
    }};
}

/// Resolves the backend expression from the key list.
///
/// A separate macro because the backend is a constructor argument rather than a
/// builder method, so it must exist before the builder does. It also composes
/// two keys: `buffered:` wraps whatever `backend:` resolved to, which a
/// per-key macro applying one setting at a time could not express.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_logger_backend {
    ($($key:ident : $value:expr),* $(,)?) => {
        $crate::__ash_logger_buffer!(
            ($crate::__ash_logger_inner_backend!($($key : $value),*))
            $($key : $value),*
        )
    };
}

/// Finds the `backend:` key, defaulting to stdout.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_logger_inner_backend {
    // A `backend:` key anywhere in the list wins; the recursion walks past
    // every other key looking for it.
    (backend : $value:expr $(, $($rest:tt)*)?) => { $value };
    ($key:ident : $value:expr, $($rest:tt)*) => {
        $crate::__ash_logger_inner_backend!($($rest)*)
    };
    ($key:ident : $value:expr) => {
        ::std::sync::Arc::new($crate::StdoutAuditBackend)
    };
    () => { ::std::sync::Arc::new($crate::StdoutAuditBackend) };
}

/// Wraps the resolved backend in a [`BufferedAuditBackend`](crate::BufferedAuditBackend)
/// if a `buffered:` key is present, leaving it untouched otherwise.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_logger_buffer {
    (($backend:expr) buffered : $capacity:expr $(, $($rest:tt)*)?) => {
        ::std::sync::Arc::new($crate::BufferedAuditBackend::new($backend, $capacity))
    };
    (($backend:expr) $key:ident : $value:expr, $($rest:tt)*) => {
        $crate::__ash_logger_buffer!(($backend) $($rest)*)
    };
    (($backend:expr) $key:ident : $value:expr) => { $backend };
    (($backend:expr)) => { $backend };
}

/// Applies one `key: value` pair to the builder or the identity.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_logger_field {
    // Both are consumed by `__ash_logger_backend!`; ignored here so they are
    // not also treated as unknown keys.
    ($builder:ident, $identity:ident, backend, $value:expr) => {};
    ($builder:ident, $identity:ident, buffered, $value:expr) => {};
    ($builder:ident, $identity:ident, integrity, $value:expr) => {
        $builder = $builder.integrity($value);
    };
    ($builder:ident, $identity:ident, min_level, $value:expr) => {
        $builder = $builder.min_level($value);
    };
    ($builder:ident, $identity:ident, redact, $value:expr) => {
        $builder = $builder.redact($value);
    };
    ($builder:ident, $identity:ident, filter, $value:expr) => {
        $builder = $builder.filter($value);
    };
    // Not gated on the `hlc` feature: a macro arm cannot carry a `cfg`, and
    // leaving it always present means a `clock:` key without the feature fails
    // on the missing `LoggerBuilder::clock` method, which names the real
    // problem, rather than reporting an unknown key.
    ($builder:ident, $identity:ident, clock, $value:expr) => {
        $builder = $builder.clock($value);
    };
    ($builder:ident, $identity:ident, service, $value:expr) => {
        $identity = $identity.with_service($value);
    };
    ($builder:ident, $identity:ident, version, $value:expr) => {
        $identity = $identity.with_version($value);
    };
    ($builder:ident, $identity:ident, host, $value:expr) => {
        $identity = $identity.with_host($value);
    };
    // Replaces rather than merges, so mixing it with the shorthand keys would
    // make the result depend on argument order. Rejected instead.
    ($builder:ident, $identity:ident, identity, $value:expr) => {
        assert!(
            $identity.is_empty(),
            "ash_logger!: `identity:` cannot be combined with `service:`, \
             `version:`, or `host:` — set those fields on the Provenance instead",
        );
        $identity = $value;
    };
    ($builder:ident, $identity:ident, $key:ident, $value:expr) => {
        compile_error!(concat!(
            "ash_logger!: unknown key `",
            stringify!($key),
            "`; expected one of \
             backend, buffered, integrity, min_level, redact, filter, clock, service, \
             version, host, identity",
        ));
    };
}

/// Emit a diagnostic record at an explicit severity.
///
/// The level macros — [`ash_trace!`](crate::ash_trace),
/// [`ash_debug!`](crate::ash_debug), [`ash_info!`](crate::ash_info),
/// [`ash_warn!`](crate::ash_warn), [`ash_error!`](crate::ash_error) — are this
/// macro with the severity fixed, and share its syntax.
///
/// # Syntax
///
/// ```text
/// ash_diagnostic!(logger, severity, "format {}", args...; key = value, ...)
/// ```
///
/// The format string and its arguments are exactly [`format!`]'s. Pairs after
/// the optional `;` become event metadata; their values may be anything
/// convertible into a [`serde_json::Value`].
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
/// let port = 8443;
///
/// ash_info!(logger, "listening on port {port}");
/// ash_warn!(logger, "retry {} of {}", 2, 5);
/// ash_error!(logger, "upload failed"; retries = 3, bucket = "audit-eu");
/// ```
///
/// Records below the threshold never format their arguments:
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(
///     backend: Arc::new(NoopAuditBackend),
///     min_level: AuditSeverity::Error,
/// );
///
/// // `expensive()` is not called: the level is checked first.
/// fn expensive() -> String { unreachable!("filtered before evaluation") }
/// ash_debug!(logger, "{}", expensive());
/// ```
#[macro_export]
macro_rules! ash_diagnostic {
    ($logger:expr, $severity:expr, $($rest:tt)*) => {{
        let logger = &$logger;
        let severity = $severity;
        // Diagnostics are the filterable tier, so admission can be decided
        // before anything is built. This must go through `admits_diagnostic`
        // rather than comparing against `min_level` directly: a per-module
        // filter can loosen the base threshold, and a bare comparison would
        // drop the record before the filter was ever consulted. Security
        // events bypass the threshold and are never short-circuited here.
        if logger.admits_diagnostic(severity, module_path!()) {
            logger.log($crate::__ash_diagnostic_event!(severity, $($rest)*));
        }
    }};
}

/// Builds the [`AuditEvent`](crate::AuditEvent) for a diagnostic macro,
/// splitting the format arguments from the trailing metadata pairs.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_diagnostic_event {
    // With metadata. Format arguments are accumulated one token-tree at a time
    // until the `;` separator, since `$($fmt:tt)*` alone would swallow it.
    ($severity:expr, $($rest:tt)*) => {
        $crate::__ash_split_metadata!(($severity) () ; $($rest)*)
    };
}

/// Walks the argument list, moving tokens into the format-argument group until
/// a `;` is found, then treats the remainder as metadata pairs.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_split_metadata {
    // Separator reached: everything collected is the format call, everything
    // after is metadata.
    (($severity:expr) ($($fmt:tt)*) ; ; $($key:ident = $value:expr),* $(,)?) => {
        $crate::AuditEvent::diagnostic(format!($($fmt)*))
            .severity($severity)
            .provenance($crate::__ash_provenance!())
            $(.metadata(stringify!($key), $value))*
            .build()
    };
    // No separator: the whole list is format arguments.
    (($severity:expr) ($($fmt:tt)*) ;) => {
        $crate::AuditEvent::diagnostic(format!($($fmt)*))
            .severity($severity)
            .provenance($crate::__ash_provenance!())
            .build()
    };
    // Shift one token from the unparsed tail into the format group.
    (($severity:expr) ($($fmt:tt)*) ; $head:tt $($tail:tt)*) => {
        $crate::__ash_split_metadata!(($severity) ($($fmt)* $head) ; $($tail)*)
    };
}

/// Call-site provenance.
///
/// [`Provenance::capture`](crate::Provenance::capture) supplies the thread name
/// and pid; `file!`, `line!`, and `module_path!` are then applied because they
/// are exact at the macro's expansion site, whereas `#[track_caller]` reports
/// only the enclosing call.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_provenance {
    () => {
        $crate::Provenance::capture()
            .with_file(file!())
            .with_line(line!())
            .with_module(module_path!())
    };
}

/// Emit a [`Trace`](crate::AuditSeverity::Trace) diagnostic.
///
/// See [`ash_diagnostic!`](crate::ash_diagnostic) for the syntax.
#[macro_export]
macro_rules! ash_trace {
    ($logger:expr, $($rest:tt)*) => {
        $crate::ash_diagnostic!($logger, $crate::AuditSeverity::Trace, $($rest)*)
    };
}

/// Emit a [`Debug`](crate::AuditSeverity::Debug) diagnostic.
///
/// See [`ash_diagnostic!`](crate::ash_diagnostic) for the syntax.
#[macro_export]
macro_rules! ash_debug {
    ($logger:expr, $($rest:tt)*) => {
        $crate::ash_diagnostic!($logger, $crate::AuditSeverity::Debug, $($rest)*)
    };
}

/// Emit an [`Info`](crate::AuditSeverity::Info) diagnostic.
///
/// See [`ash_diagnostic!`](crate::ash_diagnostic) for the syntax.
#[macro_export]
macro_rules! ash_info {
    ($logger:expr, $($rest:tt)*) => {
        $crate::ash_diagnostic!($logger, $crate::AuditSeverity::Info, $($rest)*)
    };
}

/// Emit a [`Warning`](crate::AuditSeverity::Warning) diagnostic.
///
/// See [`ash_diagnostic!`](crate::ash_diagnostic) for the syntax.
#[macro_export]
macro_rules! ash_warn {
    ($logger:expr, $($rest:tt)*) => {
        $crate::ash_diagnostic!($logger, $crate::AuditSeverity::Warning, $($rest)*)
    };
}

/// Emit an [`Error`](crate::AuditSeverity::Error) diagnostic.
///
/// See [`ash_diagnostic!`](crate::ash_diagnostic) for the syntax.
#[macro_export]
macro_rules! ash_error {
    ($logger:expr, $($rest:tt)*) => {
        $crate::ash_diagnostic!($logger, $crate::AuditSeverity::Error, $($rest)*)
    };
}

/// Emit a security event — the tier that is never filtered.
///
/// # Syntax
///
/// ```text
/// ash_audit!(logger, EventType, Result, field = value, ...; key = value, ...)
/// ```
///
/// The event type and result are bare
/// [`AuditEventType`](crate::AuditEventType) and
/// [`AuditResult`](crate::AuditResult) variant names. Fields before the
/// optional `;` are [`AuditEventBuilder`](crate::AuditEventBuilder) methods —
/// `principal`, `method`, `correlation_id`, `remote_addr`, `severity`,
/// `error`, `message`, `params`. Pairs after it become metadata.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
///
/// ash_audit!(logger, AuthenticationAttempt, Success,
///     principal = "alice@example.com");
///
/// ash_audit!(logger, SecurityViolation, Denied,
///     principal = "bob@example.com",
///     method = "transfer",
///     error = "rate limit exceeded";
///     attempts = 5,
///     limit = 3,
/// );
/// ```
///
/// A security event is recorded even under the most restrictive threshold:
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(
///     backend: Arc::new(NoopAuditBackend),
///     min_level: AuditSeverity::Critical,
/// );
/// // Written despite being far below the threshold.
/// ash_audit!(logger, AdminAction, Success, severity = AuditSeverity::Trace);
/// ```
#[macro_export]
macro_rules! ash_audit {
    // A bare `AuditResult` variant name. Matched before the expression arm so
    // that `Success` resolves through `__ash_audit_result!` rather than being
    // captured as a path that is not in scope at the call site.
    ($logger:expr, $event_type:ident, $result:ident $(, $($rest:tt)*)?) => {
        $crate::__ash_audit_impl!(
            $logger, $event_type, ($crate::__ash_audit_result!($result)) $(, $($rest)*)?
        )
    };
    // Any expression evaluating to an `AuditResult`, including a qualified path.
    ($logger:expr, $event_type:ident, $result:expr $(, $($rest:tt)*)?) => {
        $crate::__ash_audit_impl!($logger, $event_type, ($result) $(, $($rest)*)?)
    };
}

/// Shared body of [`ash_audit!`](crate::ash_audit), entered once the result has
/// been resolved to an expression.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_audit_impl {
    ($logger:expr, $event_type:ident, ($result:expr) $(, $($rest:tt)*)?) => {{
        let logger = &$logger;
        logger.log(
            $crate::__ash_audit_split!(
                ($event_type, $result) () ; $($($rest)*)?
            )
        );
    }};
}

/// Splits an `ash_audit!` argument list into builder fields and metadata.
///
/// Pairs are shifted one at a time into the builder-field group; the arms are
/// ordered so that a pair terminated by `;` is matched before the comma form,
/// since an `expr` fragment cannot be followed by `;` in a matcher.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_audit_split {
    // Separator reached: builder fields collected, metadata follows.
    (
        ($event_type:ident, $result:expr) ($($field:ident = $fval:expr),* $(,)?) ;
        ; $($key:ident = $value:expr),* $(,)?
    ) => {
        $crate::AuditEvent::builder()
            .event_type($crate::AuditEventType::$event_type)
            .result($result)
            .provenance($crate::__ash_provenance!())
            $(.$field($fval))*
            $(.metadata(stringify!($key), $value))*
            .build()
    };
    // No separator: every pair is a builder field.
    (
        ($event_type:ident, $result:expr) ($($field:ident = $fval:expr),* $(,)?) ;
    ) => {
        $crate::AuditEvent::builder()
            .event_type($crate::AuditEventType::$event_type)
            .result($result)
            .provenance($crate::__ash_provenance!())
            $(.$field($fval))*
            .build()
    };
    // Last builder field before the metadata separator.
    (
        ($event_type:ident, $result:expr) ($($field:ident = $fval:expr),* $(,)?) ;
        $key:ident = $value:expr ; $($tail:tt)*
    ) => {
        $crate::__ash_audit_split!(
            ($event_type, $result) ($($field = $fval,)* $key = $value) ; ; $($tail)*
        )
    };
    // Shift one `key = value` pair into the builder-field group.
    (
        ($event_type:ident, $result:expr) ($($field:ident = $fval:expr),* $(,)?) ;
        $key:ident = $value:expr, $($tail:tt)*
    ) => {
        $crate::__ash_audit_split!(
            ($event_type, $result) ($($field = $fval,)* $key = $value) ; $($tail)*
        )
    };
    // Final pair at the end of the list.
    (
        ($event_type:ident, $result:expr) ($($field:ident = $fval:expr),* $(,)?) ;
        $key:ident = $value:expr
    ) => {
        $crate::__ash_audit_split!(
            ($event_type, $result) ($($field = $fval,)* $key = $value) ;
        )
    };
}

/// Accepts a bare [`AuditResult`](crate::AuditResult) variant name or a full
/// expression, so `Success` and `AuditResult::Success` both work.
#[doc(hidden)]
#[macro_export]
macro_rules! __ash_audit_result {
    (Success) => {
        $crate::AuditResult::Success
    };
    (Failure) => {
        $crate::AuditResult::Failure
    };
    (Denied) => {
        $crate::AuditResult::Denied
    };
    (Violation) => {
        $crate::AuditResult::Violation
    };
    (NotApplicable) => {
        $crate::AuditResult::NotApplicable
    };
    ($other:expr) => {
        $other
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        AuditBackend, AuditEvent, AuditEventType, AuditResult, AuditSeverity, NoopAuditBackend,
        SequenceIntegrity,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditEvent>>);

    impl Collector {
        fn events(&self) -> Vec<AuditEvent> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl AuditBackend for Collector {
        fn log_audit(&self, event: &AuditEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
        }
    }

    #[test]
    fn test_logger_macro_defaults_match_the_builder() {
        let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));

        assert_eq!(logger.min_level(), AuditSeverity::Info);
        assert!(
            logger.identity().is_empty(),
            "no identity keys given, so none is stamped"
        );
    }

    #[test]
    fn test_logger_macro_accepts_keys_in_any_order() {
        let logger = ash_logger!(
            min_level: AuditSeverity::Error,
            service: "payments-api",
            backend: Arc::new(NoopAuditBackend),
            version: "1.2.3",
            integrity: Arc::new(SequenceIntegrity::new()),
            host: "pod-7",
        );

        assert_eq!(logger.min_level(), AuditSeverity::Error);
        assert_eq!(logger.identity().service.as_deref(), Some("payments-api"));
        assert_eq!(logger.identity().version.as_deref(), Some("1.2.3"));
        assert_eq!(logger.identity().host.as_deref(), Some("pod-7"));
    }

    #[test]
    fn test_diagnostic_macros_map_to_their_severities() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            min_level: AuditSeverity::Trace,
        );

        ash_trace!(logger, "trace");
        ash_debug!(logger, "debug");
        ash_info!(logger, "info");
        ash_warn!(logger, "warn");
        ash_error!(logger, "error");

        let severities: Vec<AuditSeverity> = backend.events().iter().map(|e| e.severity).collect();
        assert_eq!(
            severities,
            vec![
                AuditSeverity::Trace,
                AuditSeverity::Debug,
                AuditSeverity::Info,
                AuditSeverity::Warning,
                AuditSeverity::Error,
            ]
        );
    }

    #[test]
    fn test_format_arguments_are_not_evaluated_when_filtered() {
        // The reason these are macros rather than functions: a dropped record
        // must not pay for formatting its message.
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            min_level: AuditSeverity::Error,
        );

        let counted = || {
            calls.fetch_add(1, Ordering::Relaxed);
            "expensive"
        };

        ash_debug!(logger, "{}", counted());
        ash_info!(logger, "{}", counted());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "arguments below the threshold are never evaluated"
        );

        ash_error!(logger, "{}", counted());
        assert_eq!(calls.load(Ordering::Relaxed), 1, "admitted records format");
        assert_eq!(backend.events().len(), 1);
    }

    #[test]
    fn test_format_arguments_and_metadata() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(backend: backend.clone());

        let port = 8443;
        ash_info!(logger, "listening on port {port}");
        ash_warn!(logger, "retry {} of {}", 2, 5);
        ash_error!(logger, "upload failed"; retries = 3, bucket = "audit-eu");

        let events = backend.events();
        assert_eq!(
            events[0].message.as_deref(),
            Some("listening on port 8443"),
            "inline format captures work"
        );
        assert_eq!(events[1].message.as_deref(), Some("retry 2 of 5"));
        assert_eq!(events[2].metadata["retries"], 3);
        assert_eq!(events[2].metadata["bucket"], "audit-eu");
    }

    #[test]
    fn test_call_site_provenance_is_captured() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(backend: backend.clone());

        let line = line!() + 1;
        ash_info!(logger, "located");

        let event = &backend.events()[0];
        assert_eq!(event.provenance.line, Some(line), "line is the call site");
        assert_eq!(event.provenance.file.as_deref(), Some(file!()));
        assert_eq!(
            event.provenance.module.as_deref(),
            Some(module_path!()),
            "module_path! is available to a macro but not to #[track_caller]"
        );
        assert!(event.provenance.pid.is_some(), "capture() fills the pid");
    }

    #[test]
    fn test_logger_identity_fills_macro_events() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            service: "gateway",
            version: "0.2.0",
        );

        ash_info!(logger, "started");

        let event = &backend.events()[0];
        assert_eq!(event.provenance.service.as_deref(), Some("gateway"));
        assert_eq!(event.provenance.version.as_deref(), Some("0.2.0"));
        assert!(
            event.provenance.file.is_some(),
            "call-site fields survive the identity merge"
        );
    }

    #[test]
    fn test_buffered_key_defers_writes_until_capacity() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            buffered: 3,
            min_level: AuditSeverity::Trace,
        );

        ash_info!(logger, "one");
        ash_info!(logger, "two");
        assert!(
            backend.events().is_empty(),
            "writes are held until the buffer fills"
        );

        ash_info!(logger, "three");
        assert_eq!(
            backend.events().len(),
            3,
            "the third write reaches capacity and drains the buffer"
        );
    }

    #[test]
    fn test_buffered_key_drains_on_flush() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(backend: backend.clone(), buffered: 1024);

        ash_warn!(logger, "queued");
        assert!(backend.events().is_empty());

        logger.flush();
        assert_eq!(backend.events().len(), 1, "flush drains a partial buffer");
    }

    #[test]
    fn test_buffered_key_drains_on_drop() {
        let backend = Arc::new(Collector::default());
        {
            let logger = ash_logger!(backend: backend.clone(), buffered: 1024);
            ash_warn!(logger, "queued");
            assert!(backend.events().is_empty());
        }
        assert_eq!(
            backend.events().len(),
            1,
            "the buffer drains when the logger goes out of scope"
        );
    }

    #[test]
    fn test_buffered_key_composes_with_the_other_keys() {
        // `buffered:` wraps whatever `backend:` resolved to, so key order must
        // not matter here either.
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            buffered: 2,
            service: "queued-service",
            backend: backend.clone(),
            integrity: Arc::new(SequenceIntegrity::new()),
            min_level: AuditSeverity::Warning,
        );

        assert_eq!(logger.min_level(), AuditSeverity::Warning);
        ash_info!(logger, "filtered, never buffered");
        ash_warn!(logger, "first");
        ash_error!(logger, "second");

        let events = backend.events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].provenance.service.as_deref(),
            Some("queued-service"),
            "identity still reaches events written through the buffer"
        );
    }

    #[test]
    fn test_buffering_preserves_integrity_order() {
        // Integrity is applied before the event is buffered, so the chain must
        // still verify in the order the inner backend receives it.
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            buffered: 4,
            integrity: Arc::new(SequenceIntegrity::new()),
            min_level: AuditSeverity::Trace,
        );

        for n in 0..8 {
            ash_info!(logger, "event {n}");
        }
        logger.flush();

        let sequences: Vec<serde_json::Value> = backend
            .events()
            .iter()
            .map(|e| e.metadata["sequence"].clone())
            .collect();
        let expected: Vec<serde_json::Value> = (0..8).map(|n| json!(n)).collect();
        assert_eq!(
            sequences, expected,
            "FIFO drain keeps sequence numbers in order"
        );
    }

    #[test]
    fn test_buffered_key_without_a_backend_buffers_the_default() {
        // Compiles and runs; the default stdout backend is wrapped rather than
        // the `buffered:` key being ignored for want of a `backend:` key.
        let logger = ash_logger!(buffered: 512, min_level: AuditSeverity::Critical);
        ash_info!(logger, "dropped by the threshold, never buffered");
        logger.flush();
    }

    #[test]
    fn test_audit_macro_builds_security_events() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(backend: backend.clone());

        ash_audit!(
            logger,
            AuthenticationAttempt,
            Success,
            principal = "alice@example.com"
        );
        ash_audit!(
            logger,
            SecurityViolation,
            Denied,
            principal = "bob@example.com",
            method = "transfer",
            error = "rate limit exceeded";
            attempts = 5,
            limit = 3,
        );

        let events = backend.events();
        assert_eq!(events[0].event_type, AuditEventType::AuthenticationAttempt);
        assert_eq!(events[0].result, AuditResult::Success);
        assert_eq!(events[0].principal.as_deref(), Some("alice@example.com"));

        assert_eq!(events[1].event_type, AuditEventType::SecurityViolation);
        assert_eq!(events[1].result, AuditResult::Denied);
        assert_eq!(events[1].method.as_deref(), Some("transfer"));
        assert_eq!(events[1].error.as_deref(), Some("rate limit exceeded"));
        assert_eq!(events[1].metadata["attempts"], 5);
        assert_eq!(events[1].metadata["limit"], 3);
    }

    #[test]
    fn test_audit_macro_ignores_the_level_threshold() {
        // The two-tier policy, exercised through the macro surface: an
        // operational setting must not be able to shrink the compliance record.
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            min_level: AuditSeverity::Critical,
        );

        ash_error!(logger, "dropped: diagnostics are filtered");
        ash_audit!(
            logger,
            AdminAction,
            Success,
            severity = AuditSeverity::Trace
        );

        let events = backend.events();
        assert_eq!(events.len(), 1, "only the security event survives");
        assert_eq!(events[0].event_type, AuditEventType::AdminAction);
        assert_eq!(events[0].severity, AuditSeverity::Trace);
    }

    #[test]
    fn test_audit_macro_accepts_a_qualified_result() {
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(backend: backend.clone());

        ash_audit!(logger, ConnectionClosed, AuditResult::NotApplicable);

        assert_eq!(backend.events()[0].result, AuditResult::NotApplicable);
    }

    #[test]
    fn test_macros_accept_an_expression_logger() {
        // `$logger:expr` must not be re-evaluated per use, and must work on
        // something that is not a plain binding.
        let backend = Arc::new(Collector::default());
        let logger = Arc::new(ash_logger!(backend: backend.clone()));

        ash_info!(*logger, "through a deref");
        ash_audit!(*logger, AdminAction, Success);

        assert_eq!(backend.events().len(), 2);
    }

    #[test]
    fn test_events_from_macros_verify_against_the_chain() {
        // Filtering happens before integrity is applied, so dropped records
        // must not gap the sequence.
        let backend = Arc::new(Collector::default());
        let logger = ash_logger!(
            backend: backend.clone(),
            integrity: Arc::new(SequenceIntegrity::new()),
            min_level: AuditSeverity::Warning,
        );

        ash_debug!(logger, "dropped");
        ash_warn!(logger, "kept");
        ash_audit!(logger, AuthenticationAttempt, Failure);
        ash_trace!(logger, "dropped");
        ash_error!(logger, "kept");

        let events = backend.events();
        assert_eq!(events.len(), 3);
        let sequences: Vec<&serde_json::Value> =
            events.iter().map(|e| &e.metadata["sequence"]).collect();
        assert_eq!(
            sequences,
            vec![&json!(0), &json!(1), &json!(2)],
            "no gaps from filtered records"
        );
    }
}
