//! Level thresholds that vary by module, adjustable at runtime.
//!
//! # Why this exists
//!
//! A single global threshold forces a choice between drowning in one noisy
//! module's diagnostics and losing visibility everywhere else. Raising the
//! level to silence one component silences the rest with it.
//!
//! [`FilterDirectives`] applies a different threshold per module path, in the
//! shape most Rust developers already know from `RUST_LOG`:
//!
//! ```text
//! info,my_app::db=debug,hyper=warn
//! ```
//!
//! # This filters diagnostics only
//!
//! Security events are admitted whatever any threshold says. A filter tunes
//! operational noise; it cannot shrink the audit record, and a directive
//! naming a module that only emits security events has no effect.

use super::AuditSeverity;
use std::sync::{Arc, RwLock};

/// One `module=level` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Module prefix this applies to. Empty means the default for everything.
    pub target: String,
    /// Minimum severity admitted for that prefix.
    pub level: AuditSeverity,
}

/// A parsed set of per-module thresholds.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
///
/// let filter = FilterDirectives::parse("info,my_app::db=trace,hyper=warn");
///
/// assert_eq!(filter.level_for("my_app::db::pool"), AuditSeverity::Trace);
/// assert_eq!(filter.level_for("hyper::client"), AuditSeverity::Warning);
/// assert_eq!(filter.level_for("anything_else"), AuditSeverity::Info);
/// ```
#[derive(Debug, Clone, Default)]
pub struct FilterDirectives {
    default: Option<AuditSeverity>,
    directives: Vec<Directive>,
}

impl FilterDirectives {
    /// Parse a `RUST_LOG`-style directive string.
    ///
    /// Comma-separated entries, each either a bare level (the default for
    /// every module) or `target=level`. Unparseable entries are skipped rather
    /// than failing the whole string: a typo in one directive must not silence
    /// the logger entirely.
    #[must_use]
    pub fn parse(directives: &str) -> Self {
        let mut default = None;
        let mut parsed = Vec::new();

        for entry in directives.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            match entry.split_once('=') {
                None => {
                    if let Ok(level) = entry.parse::<AuditSeverity>() {
                        default = Some(level);
                    }
                }
                Some((target, level)) => {
                    if let Ok(level) = level.trim().parse::<AuditSeverity>() {
                        parsed.push(Directive {
                            target: target.trim().to_string(),
                            level,
                        });
                    }
                }
            }
        }

        // Longest target first, so the most specific rule wins regardless of
        // the order they were written in.
        parsed.sort_by_key(|d| std::cmp::Reverse(d.target.len()));

        Self {
            default,
            directives: parsed,
        }
    }

    /// Read directives from an environment variable.
    ///
    /// Returns an empty filter if the variable is unset, which admits
    /// everything the logger's own threshold admits.
    #[must_use]
    pub fn from_env(var: &str) -> Self {
        std::env::var(var).map_or_else(|_| Self::default(), |value| Self::parse(&value))
    }

    /// The threshold for `module`, falling back to `Trace` when nothing matches
    /// and no default was given — the filter then defers entirely to the
    /// logger's own level.
    #[must_use]
    pub fn level_for(&self, module: &str) -> AuditSeverity {
        self.directives
            .iter()
            .find(|d| module == d.target || module.starts_with(&format!("{}::", d.target)))
            .map_or_else(|| self.default.unwrap_or(AuditSeverity::Trace), |d| d.level)
    }

    /// Whether a default level was specified.
    #[must_use]
    pub fn has_default(&self) -> bool {
        self.default.is_some()
    }

    /// The parsed directives, most specific first.
    #[must_use]
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// Whether this filter says anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.directives.is_empty()
    }
}

/// A filter that can be replaced while the logger is running.
///
/// Cloning shares the same underlying filter, so a handle kept by an admin
/// endpoint retunes every logger built from it.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let filter = LiveFilter::new(FilterDirectives::parse("info"));
/// let logger = ash_logger!(
///     backend: Arc::new(NoopAuditBackend),
///     filter: filter.clone(),
///     min_level: AuditSeverity::Trace,
/// );
///
/// ash_debug!(logger, "not recorded at info");
///
/// // Retune without rebuilding the logger.
/// filter.set(FilterDirectives::parse("debug"));
/// ash_debug!(logger, "recorded now");
/// ```
#[derive(Debug, Clone, Default)]
pub struct LiveFilter {
    inner: Arc<RwLock<FilterDirectives>>,
}

impl LiveFilter {
    /// Wrap `directives` in a handle that can be updated later.
    #[must_use]
    pub fn new(directives: FilterDirectives) -> Self {
        Self {
            inner: Arc::new(RwLock::new(directives)),
        }
    }

    /// Parse and wrap a directive string.
    #[must_use]
    pub fn parse(directives: &str) -> Self {
        Self::new(FilterDirectives::parse(directives))
    }

    /// Read directives from an environment variable.
    #[must_use]
    pub fn from_env(var: &str) -> Self {
        Self::new(FilterDirectives::from_env(var))
    }

    /// Replace the directives. Takes effect on the next event.
    pub fn set(&self, directives: FilterDirectives) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = directives;
    }

    /// Replace the directives by parsing a new string.
    pub fn reload(&self, directives: &str) {
        self.set(FilterDirectives::parse(directives));
    }

    /// The threshold currently applying to `module`.
    #[must_use]
    pub fn level_for(&self, module: &str) -> AuditSeverity {
        self.read().level_for(module)
    }

    /// Whether the filter is empty, meaning it constrains nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// A snapshot of the current directives.
    #[must_use]
    pub fn snapshot(&self) -> FilterDirectives {
        self.read().clone()
    }

    /// Read the filter, recovering from a poisoned lock.
    ///
    /// A panic while holding the lock must not stop logging: the directives are
    /// still valid data, and refusing to log would be the worse outcome.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, FilterDirectives> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_bare_level_sets_the_default() {
        let filter = FilterDirectives::parse("warn");
        assert_eq!(filter.level_for("anything"), AuditSeverity::Warning);
        assert!(filter.has_default());
    }

    #[test]
    fn test_per_module_directives_override_the_default() {
        let filter = FilterDirectives::parse("info,my_app::db=trace,hyper=warn");

        assert_eq!(filter.level_for("my_app::db"), AuditSeverity::Trace);
        assert_eq!(filter.level_for("my_app::db::pool"), AuditSeverity::Trace);
        assert_eq!(filter.level_for("hyper::client"), AuditSeverity::Warning);
        assert_eq!(filter.level_for("my_app::api"), AuditSeverity::Info);
    }

    #[test]
    fn test_the_most_specific_directive_wins_regardless_of_order() {
        // Written least-specific first, so ordering must come from the match
        // logic rather than from how the string happened to be typed.
        let filter = FilterDirectives::parse("my_app=warn,my_app::db=trace");

        assert_eq!(filter.level_for("my_app::db::pool"), AuditSeverity::Trace);
        assert_eq!(filter.level_for("my_app::api"), AuditSeverity::Warning);
    }

    #[test]
    fn test_prefix_matching_respects_module_boundaries() {
        // `my_app` must not match `my_application`, or an unrelated crate would
        // silently inherit another's threshold.
        let filter = FilterDirectives::parse("error,my_app=trace");

        assert_eq!(filter.level_for("my_app::db"), AuditSeverity::Trace);
        assert_eq!(
            filter.level_for("my_application::db"),
            AuditSeverity::Error,
            "a longer name that merely starts with the target does not match"
        );
    }

    #[test]
    fn test_a_malformed_directive_is_skipped_not_fatal() {
        // A typo must not silence the logger, so bad entries are dropped and
        // the good ones still apply.
        let filter = FilterDirectives::parse("info,my_app::db=nonsense,hyper=warn");

        assert_eq!(filter.level_for("hyper"), AuditSeverity::Warning);
        assert_eq!(
            filter.level_for("my_app::db"),
            AuditSeverity::Info,
            "the unparseable directive falls back to the default"
        );
    }

    #[test]
    fn test_an_empty_filter_constrains_nothing() {
        let filter = FilterDirectives::parse("");
        assert!(filter.is_empty());
        assert_eq!(
            filter.level_for("anything"),
            AuditSeverity::Trace,
            "with nothing specified the logger's own threshold decides"
        );
    }

    #[test]
    fn test_levels_accept_the_usual_aliases() {
        let filter = FilterDirectives::parse("a=warn,b=warning,c=crit");
        assert_eq!(filter.level_for("a"), AuditSeverity::Warning);
        assert_eq!(filter.level_for("b"), AuditSeverity::Warning);
        assert_eq!(filter.level_for("c"), AuditSeverity::Critical);
    }

    #[test]
    fn test_live_filter_updates_are_visible_immediately() {
        let filter = LiveFilter::parse("info");
        assert_eq!(filter.level_for("app"), AuditSeverity::Info);

        filter.reload("app=trace,warn");
        assert_eq!(filter.level_for("app"), AuditSeverity::Trace);
        assert_eq!(filter.level_for("other"), AuditSeverity::Warning);
    }

    #[test]
    fn test_clones_share_one_filter() {
        // An admin endpoint holding a clone must be able to retune loggers
        // built from the original.
        let filter = LiveFilter::parse("info");
        let handle = filter.clone();

        handle.reload("trace");
        assert_eq!(
            filter.level_for("app"),
            AuditSeverity::Trace,
            "the update is visible through the original handle"
        );
    }

    #[test]
    fn test_whitespace_is_tolerated() {
        let filter = FilterDirectives::parse(" info , my_app::db = debug ");
        assert_eq!(filter.level_for("my_app::db"), AuditSeverity::Debug);
        assert_eq!(filter.level_for("other"), AuditSeverity::Info);
    }
}
