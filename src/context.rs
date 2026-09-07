//! Fields bound once per request and inherited by every event.
//!
//! # Why this exists
//!
//! A correlation ID identifies a request across every event it produces, but
//! passing it explicitly to each call means threading it through every function
//! that might log. In practice that is not done, and the field ends up missing
//! from precisely the events that need it.
//!
//! A [`Scope`] binds fields for a region of code. Events recorded inside it
//! inherit them, so the correlation ID is attached once at the edge of the
//! request rather than at every call site.
//!
//! # Threads and tasks
//!
//! The active scope is thread-local. A spawned thread starts with no scope,
//! which is the safe default — inheriting one implicitly would attach a stale
//! correlation ID to unrelated work. Carry it across a boundary explicitly with
//! [`Scope::current`] and [`ScopeFields::enter`].
//!
//! The same applies to async tasks: an `.await` can resume on another thread,
//! so a scope held across one is not reliable. Bind fields inside the task, or
//! capture and re-enter them.

use super::AuditEvent;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

thread_local! {
    /// The innermost active scope on this thread.
    static ACTIVE: RefCell<Option<Arc<ScopeFields>>> = const { RefCell::new(None) };
}

/// Fields bound by a scope, and whatever its parent bound.
///
/// Cheap to clone: the parent chain is shared through [`Arc`].
#[derive(Debug, Default)]
pub struct ScopeFields {
    correlation_id: Option<String>,
    principal: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
    parent: Option<Arc<ScopeFields>>,
}

impl ScopeFields {
    /// The correlation ID bound here, or by the nearest enclosing scope.
    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref().or_else(|| {
            self.parent
                .as_ref()
                .and_then(|parent| parent.correlation_id())
        })
    }

    /// The principal bound here, or by the nearest enclosing scope.
    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal
            .as_deref()
            .or_else(|| self.parent.as_ref().and_then(|parent| parent.principal()))
    }

    /// Look up one metadata value, innermost binding first.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata
            .get(key)
            .or_else(|| self.parent.as_ref().and_then(|parent| parent.get(key)))
    }

    /// Every metadata key visible here, with inner bindings shadowing outer.
    #[must_use]
    pub fn metadata(&self) -> HashMap<String, serde_json::Value> {
        let mut merged = self
            .parent
            .as_ref()
            .map(|parent| parent.metadata())
            .unwrap_or_default();
        for (key, value) in &self.metadata {
            merged.insert(key.clone(), value.clone());
        }
        merged
    }

    /// Make these fields the active scope for as long as the guard lives.
    ///
    /// Used to carry a scope onto another thread:
    ///
    /// ```rust
    /// use ash_log::*;
    ///
    /// let _outer = Scope::new().correlation_id("req-1").enter();
    /// let carried = Scope::current().expect("a scope is active");
    ///
    /// std::thread::spawn(move || {
    ///     let _inner = carried.enter();
    ///     // Events here carry `req-1`.
    /// })
    /// .join()
    /// .unwrap();
    /// ```
    pub fn enter(self: Arc<Self>) -> ScopeGuard {
        let previous = ACTIVE.with(|active| active.borrow_mut().replace(self));
        ScopeGuard { previous }
    }

    /// Fill any field `event` has not set from these bindings.
    ///
    /// An explicit value on the event always wins: a scope supplies defaults,
    /// it does not override what a call site stated.
    pub fn apply(&self, event: &mut AuditEvent) {
        if event.correlation_id.is_none()
            && let Some(id) = self.correlation_id()
        {
            event.correlation_id = Some(id.to_string());
        }
        if event.principal.is_none()
            && let Some(principal) = self.principal()
        {
            event.principal = Some(principal.to_string());
        }
        for (key, value) in self.metadata() {
            event.metadata.entry(key).or_insert(value);
        }
    }
}

/// Builds a set of scope fields.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let logger = ash_logger!(backend: Arc::new(NoopAuditBackend));
///
/// let _scope = Scope::new()
///     .correlation_id("req-7f3a")
///     .principal("alice@example.com")
///     .with("tenant", "acme")
///     .enter();
///
/// // Both events carry the correlation ID, the principal, and `tenant`.
/// ash_info!(logger, "handling request");
/// ash_audit!(logger, MethodInvocation, Success, method = "transfer");
/// ```
#[derive(Debug, Default)]
pub struct Scope {
    fields: ScopeFields,
}

impl Scope {
    /// An empty scope. Entering it inherits the enclosing scope's fields.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the correlation ID.
    #[must_use]
    pub fn correlation_id<S: Into<String>>(mut self, id: S) -> Self {
        self.fields.correlation_id = Some(id.into());
        self
    }

    /// Bind the principal.
    #[must_use]
    pub fn principal<S: Into<String>>(mut self, principal: S) -> Self {
        self.fields.principal = Some(principal.into());
        self
    }

    /// Bind one metadata field.
    #[must_use]
    pub fn with<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.fields.metadata.insert(key.into(), value.into());
        self
    }

    /// Activate this scope until the returned guard is dropped.
    ///
    /// The enclosing scope, if any, becomes this one's parent, so its fields
    /// are still visible unless shadowed.
    pub fn enter(mut self) -> ScopeGuard {
        self.fields.parent = Scope::current();
        Arc::new(self.fields).enter()
    }

    /// The active scope on this thread, if any.
    #[must_use]
    pub fn current() -> Option<Arc<ScopeFields>> {
        ACTIVE.with(|active| active.borrow().clone())
    }

    /// Apply the active scope's fields to `event`, if there is one.
    pub fn apply_current(event: &mut AuditEvent) {
        if let Some(scope) = Self::current() {
            scope.apply(event);
        }
    }

    /// The active correlation ID, for stamping an outgoing request.
    #[must_use]
    pub fn current_correlation_id() -> Option<String> {
        Self::current().and_then(|scope| scope.correlation_id().map(ToString::to_string))
    }
}

/// Restores the previous scope when dropped.
///
/// Must be bound to a named variable: `let _guard = ...`. Binding to `_` drops
/// it immediately and the scope is never active.
#[must_use = "the scope ends as soon as the guard is dropped"]
#[derive(Debug)]
pub struct ScopeGuard {
    previous: Option<Arc<ScopeFields>>,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE.with(|active| {
            *active.borrow_mut() = previous;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult};
    use serde_json::json;

    fn event() -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .build()
    }

    #[test]
    fn test_fields_are_inherited_by_events() {
        let _scope = Scope::new()
            .correlation_id("req-1")
            .principal("alice")
            .with("tenant", "acme")
            .enter();

        let mut event = event();
        Scope::apply_current(&mut event);

        assert_eq!(event.correlation_id.as_deref(), Some("req-1"));
        assert_eq!(event.principal.as_deref(), Some("alice"));
        assert_eq!(event.metadata["tenant"], json!("acme"));
    }

    #[test]
    fn test_an_explicit_value_wins_over_the_scope() {
        // A scope supplies defaults; it must not overwrite what a call site
        // stated, or an event could be attributed to the wrong principal.
        let _scope = Scope::new()
            .correlation_id("req-1")
            .principal("alice")
            .enter();

        let mut event = AuditEvent::builder()
            .event_type(AuditEventType::MethodInvocation)
            .result(AuditResult::Success)
            .principal("bob")
            .build();
        Scope::apply_current(&mut event);

        assert_eq!(event.principal.as_deref(), Some("bob"));
        assert_eq!(
            event.correlation_id.as_deref(),
            Some("req-1"),
            "unset fields still come from the scope"
        );
    }

    #[test]
    fn test_nested_scopes_shadow_and_inherit() {
        let _outer = Scope::new()
            .correlation_id("req-1")
            .with("tenant", "acme")
            .with("stage", "outer")
            .enter();

        {
            let _inner = Scope::new().with("stage", "inner").enter();

            let mut event = event();
            Scope::apply_current(&mut event);

            assert_eq!(event.correlation_id.as_deref(), Some("req-1"), "inherited");
            assert_eq!(event.metadata["tenant"], json!("acme"), "inherited");
            assert_eq!(event.metadata["stage"], json!("inner"), "shadowed");
        }

        let mut after = event();
        Scope::apply_current(&mut after);
        assert_eq!(
            after.metadata["stage"],
            json!("outer"),
            "the inner scope ended with its guard"
        );
    }

    #[test]
    fn test_the_scope_ends_with_its_guard() {
        {
            let _scope = Scope::new().correlation_id("req-1").enter();
            assert!(Scope::current().is_some());
        }
        assert!(
            Scope::current().is_none(),
            "the guard restored the previous"
        );

        let mut event = event();
        Scope::apply_current(&mut event);
        assert_eq!(event.correlation_id, None);
    }

    #[test]
    fn test_a_spawned_thread_starts_with_no_scope() {
        // Implicit inheritance would attach a stale correlation ID to unrelated
        // work, so a new thread must start clean.
        let _scope = Scope::new().correlation_id("req-1").enter();

        let seen = std::thread::spawn(Scope::current_correlation_id)
            .join()
            .expect("thread panicked");

        assert_eq!(seen, None, "scopes do not leak across threads");
    }

    #[test]
    fn test_a_scope_can_be_carried_across_a_thread_boundary() {
        let _scope = Scope::new().correlation_id("req-1").enter();
        let carried = Scope::current().expect("active");

        let seen = std::thread::spawn(move || {
            let _entered = carried.enter();
            Scope::current_correlation_id()
        })
        .join()
        .expect("thread panicked");

        assert_eq!(seen.as_deref(), Some("req-1"), "explicitly carried over");
    }

    #[test]
    fn test_scopes_on_different_threads_are_independent() {
        let _scope = Scope::new().correlation_id("main").enter();

        let other = std::thread::spawn(|| {
            let _scope = Scope::new().correlation_id("worker").enter();
            Scope::current_correlation_id()
        })
        .join()
        .expect("thread panicked");

        assert_eq!(other.as_deref(), Some("worker"));
        assert_eq!(
            Scope::current_correlation_id().as_deref(),
            Some("main"),
            "the worker's scope did not disturb this thread"
        );
    }
}
