//! The filter directive parser, against arbitrary strings.
//!
//! Directives typically come from an environment variable or a config file, so
//! the input is operator-controlled rather than attacker-controlled — but a
//! panic here takes down the process at startup, and a typo must never be able
//! to do that.
//!
//! Two properties are asserted: parsing always succeeds (bad entries are
//! skipped, never fatal), and the result is usable for any module name.

#![no_main]

use ash_log::{FilterDirectives, LiveFilter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Parsing must be total: a malformed directive is skipped, not fatal,
    // because silencing a logger over a typo is the worse failure.
    let filter = FilterDirectives::parse(text);

    // Querying must be total too, for any module name including the input.
    let _ = filter.level_for("");
    let _ = filter.level_for(text);
    let _ = filter.level_for("my_app::db::pool");
    let _ = filter.is_empty();
    let _ = filter.has_default();

    // Directives must be sorted longest-target-first, or the most specific
    // rule would not win and a module could inherit the wrong threshold.
    let targets: Vec<usize> = filter.directives().iter().map(|d| d.target.len()).collect();
    assert!(
        targets.windows(2).all(|w| w[0] >= w[1]),
        "directives are not ordered most-specific-first: {targets:?}"
    );

    // The live wrapper must behave identically.
    let live = LiveFilter::parse(text);
    assert_eq!(live.level_for("my_app"), filter.level_for("my_app"));
    live.reload(text);
});
