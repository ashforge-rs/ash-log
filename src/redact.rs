//! Removing secrets before they are recorded.
//!
//! # Why this runs where it does
//!
//! Redaction happens inside [`Logger::log`](crate::Logger::log), *before*
//! [`AuditIntegrity::add_integrity`](crate::AuditIntegrity::add_integrity). A
//! secret scrubbed afterwards would leave a MAC computed over the unredacted
//! value, so the log would both leak the secret and fail to verify. The
//! ordering is the same discipline that governs level filtering, and for the
//! same reason: it is enforced structurally rather than left to callers.
//!
//! # What it can and cannot do
//!
//! A key-name denylist catches the conventional cases — `password`, `token`,
//! `authorization` — and nothing more. It cannot recognise a secret that
//! arrives under an innocuous name, or one embedded in a free-text message.
//! Treat it as a backstop for mistakes, not as a licence to pass credentials
//! into the logger.

use super::AuditEvent;
use serde_json::Value;

/// What replaces a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Decides which fields are secret.
pub trait Redactor: Send + Sync {
    /// Whether the value stored under `key` should be replaced.
    ///
    /// `path` is the dotted route to the value, so a nested `user.password`
    /// can be distinguished from a top-level one.
    fn redacts(&self, key: &str, path: &str) -> bool;

    /// Rewrite an event in place.
    ///
    /// The default walks `metadata` and `params`, which is where caller-supplied
    /// data ends up. Typed fields such as `principal` are deliberately left
    /// alone: they are the audit record's subject, not incidental payload.
    fn redact_event(&self, event: &mut AuditEvent) {
        for (key, value) in &mut event.metadata {
            if self.redacts(key, key) {
                *value = Value::String(REDACTED.to_string());
            } else {
                redact_within(self, value, key);
            }
        }
        if let Some(params) = &mut event.params {
            redact_within(self, params, "params");
        }
    }
}

/// Walk a JSON value, replacing anything the redactor objects to.
fn redact_within<R: Redactor + ?Sized>(redactor: &R, value: &mut Value, path: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_path = format!("{path}.{key}");
                if redactor.redacts(key, &child_path) {
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact_within(redactor, child, &child_path);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                redact_within(redactor, item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

/// Redacts nothing. The default, so redaction is opt-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRedaction;

impl Redactor for NoRedaction {
    fn redacts(&self, _key: &str, _path: &str) -> bool {
        false
    }

    fn redact_event(&self, _event: &mut AuditEvent) {}
}

/// Redacts values whose key matches a denylist, case-insensitively.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(
///     backend: Arc::new(NoopAuditBackend),
///     redact: Arc::new(KeyRedactor::default().and("session_id")),
/// );
///
/// // `password` is on the default list; `session_id` was added above.
/// ash_info!(logger, "login"; password = "hunter2", session_id = "abc");
/// ```
#[derive(Debug, Clone)]
pub struct KeyRedactor {
    keys: Vec<String>,
    substring_match: bool,
}

impl KeyRedactor {
    /// The conventional secret-bearing key names.
    ///
    /// Matching is on substrings by default, so `api_key`, `apiKey`, and
    /// `x-api-key` are all caught by `key`.
    pub const DEFAULT_KEYS: &'static [&'static str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "auth",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "session",
        "cookie",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
        "pin",
    ];

    /// A redactor matching exactly `keys` and nothing else.
    #[must_use]
    pub fn new<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            keys: keys.into_iter().map(|k| normalize(&k.into())).collect(),
            substring_match: true,
        }
    }

    /// Add another key to the list.
    #[must_use]
    pub fn and<S: Into<String>>(mut self, key: S) -> Self {
        self.keys.push(normalize(&key.into()));
        self
    }

    /// Require the key to equal a listed name rather than contain it.
    ///
    /// Substring matching is the safer default — it catches `user_password` —
    /// but it also catches `password_last_changed_at`, which is not a secret.
    /// Switch to exact matching when the field names are known.
    #[must_use]
    pub const fn exact(mut self) -> Self {
        self.substring_match = false;
        self
    }

    /// The keys this redactor matches, in normalized form.
    ///
    /// Separators and case are stripped at construction, so `api_key` and
    /// `X-API-Key` both appear here as `apikey`.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
}

impl Default for KeyRedactor {
    /// A redactor loaded with [`DEFAULT_KEYS`](Self::DEFAULT_KEYS).
    fn default() -> Self {
        Self::new(Self::DEFAULT_KEYS.iter().copied())
    }
}

/// Lowercase `key` and strip separators, so `X-API-Key`, `x_api_key`, and
/// `apiKey` all normalize to `apikey` and match a listed `api_key`.
///
/// Applied to the denylist once at construction and to each checked field
/// once per call.
///
/// Without this a hyphenated header name slips past a denylist entry written
/// with underscores, which is the shape most secrets arrive in.
fn normalize(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

impl Redactor for KeyRedactor {
    fn redacts(&self, key: &str, _path: &str) -> bool {
        // `self.keys` is normalized once at construction, so this allocates
        // once per checked field rather than once per (field, listed key) pair.
        // Normalizing the list here instead cost ~1.7us per field on a 17-entry
        // denylist, which dominated the entire logging path.
        let key = normalize(key);
        if self.substring_match {
            self.keys.iter().any(|listed| key.contains(listed.as_str()))
        } else {
            self.keys.contains(&key)
        }
    }
}

/// Redacts whatever a closure objects to.
pub struct FnRedactor<F: Fn(&str, &str) -> bool + Send + Sync>(F);

impl<F: Fn(&str, &str) -> bool + Send + Sync> FnRedactor<F> {
    /// Wrap `f`, which receives the key and its dotted path.
    pub const fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F: Fn(&str, &str) -> bool + Send + Sync> Redactor for FnRedactor<F> {
    fn redacts(&self, key: &str, path: &str) -> bool {
        (self.0)(key, path)
    }
}

impl<T: Redactor + ?Sized> Redactor for std::sync::Arc<T> {
    fn redacts(&self, key: &str, path: &str) -> bool {
        (**self).redacts(key, path)
    }

    fn redact_event(&self, event: &mut AuditEvent) {
        (**self).redact_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult};
    use serde_json::json;

    fn event_with(metadata: Vec<(&str, Value)>, params: Option<Value>) -> AuditEvent {
        let mut builder = AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .result(AuditResult::Success);
        for (key, value) in metadata {
            builder = builder.metadata(key, value);
        }
        if let Some(params) = params {
            builder = builder.params(params);
        }
        builder.build()
    }

    #[test]
    fn test_default_keys_are_redacted_in_metadata() {
        let mut event = event_with(
            vec![
                ("password", json!("hunter2")),
                ("user", json!("alice")),
                ("api_key", json!("sk-live-123")),
            ],
            None,
        );

        KeyRedactor::default().redact_event(&mut event);

        assert_eq!(event.metadata["password"], json!(REDACTED));
        assert_eq!(event.metadata["api_key"], json!(REDACTED));
        assert_eq!(
            event.metadata["user"],
            json!("alice"),
            "non-secrets survive"
        );
    }

    #[test]
    fn test_matching_is_case_insensitive_and_substring() {
        let redactor = KeyRedactor::default();
        assert!(redactor.redacts("Authorization", "Authorization"));
        assert!(
            redactor.redacts("X-API-Key", "X-API-Key"),
            "separators must not defeat the match: a hyphenated header is the \
             shape most secrets arrive in"
        );
        assert!(
            redactor.redacts("apiKey", "apiKey"),
            "camelCase matches too"
        );
        assert!(redactor.redacts("user_password", "user_password"));
        assert!(!redactor.redacts("username", "username"));
    }

    #[test]
    fn test_exact_matching_avoids_false_positives() {
        // Substring matching catches `password_last_changed_at`, which is not a
        // secret. Exact matching is the opt-out.
        let loose = KeyRedactor::default();
        assert!(loose.redacts("password_last_changed_at", ""));

        let strict = KeyRedactor::default().exact();
        assert!(!strict.redacts("password_last_changed_at", ""));
        assert!(strict.redacts("password", ""));
    }

    #[test]
    fn test_nested_params_are_walked() {
        let mut event = event_with(
            vec![],
            Some(json!({
                "user": {
                    "name": "alice",
                    "password": "hunter2",
                },
                "items": [
                    { "token": "abc" },
                    { "label": "safe" },
                ],
            })),
        );

        KeyRedactor::default().redact_event(&mut event);

        let params = event.params.expect("params present");
        assert_eq!(params["user"]["password"], json!(REDACTED));
        assert_eq!(params["user"]["name"], json!("alice"));
        assert_eq!(
            params["items"][0]["token"],
            json!(REDACTED),
            "objects inside arrays are walked"
        );
        assert_eq!(params["items"][1]["label"], json!("safe"));
    }

    #[test]
    fn test_a_secret_named_container_is_replaced_whole() {
        // `tokens` matches the listed `token` by substring, so the entire array
        // goes rather than each element being inspected. Redacting more than
        // strictly necessary is the right direction to err in.
        let mut event = event_with(vec![], Some(json!({ "tokens": [{ "label": "safe" }] })));

        KeyRedactor::default().redact_event(&mut event);
        assert_eq!(event.params.expect("params")["tokens"], json!(REDACTED));
    }

    #[test]
    fn test_a_redacted_object_is_replaced_wholesale() {
        // If the key itself is secret, its entire subtree goes, rather than
        // being walked for individually-secret leaves.
        let mut event = event_with(
            vec![],
            Some(json!({ "credential": { "user": "alice", "pass": "x" } })),
        );

        KeyRedactor::default().redact_event(&mut event);

        assert_eq!(
            event.params.expect("params")["credential"],
            json!(REDACTED),
            "the whole subtree is replaced, not just its secret leaves"
        );
    }

    #[test]
    fn test_no_redaction_leaves_events_untouched() {
        let mut event = event_with(vec![("password", json!("hunter2"))], None);
        NoRedaction.redact_event(&mut event);
        assert_eq!(event.metadata["password"], json!("hunter2"));
    }

    #[test]
    fn test_fn_redactor_receives_the_path() {
        let mut event = event_with(vec![], Some(json!({ "outer": { "value": 1 }, "value": 2 })));

        // Path-sensitive: only the nested one goes.
        FnRedactor::new(|_key, path| path == "params.outer.value").redact_event(&mut event);

        let params = event.params.expect("params");
        assert_eq!(params["outer"]["value"], json!(REDACTED));
        assert_eq!(params["value"], json!(2), "the top-level value survives");
    }

    #[test]
    fn test_typed_fields_are_not_redacted() {
        // `principal` names the subject of the audit record. Redacting it would
        // destroy the log's purpose to protect data that is not a secret.
        let mut event = AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .principal("alice@example.com")
            .result(AuditResult::Success)
            .metadata("token", json!("secret"))
            .build();

        KeyRedactor::default().redact_event(&mut event);

        assert_eq!(event.principal.as_deref(), Some("alice@example.com"));
        assert_eq!(event.metadata["token"], json!(REDACTED));
    }
}
