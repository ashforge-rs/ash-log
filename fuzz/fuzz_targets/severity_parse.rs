//! `AuditSeverity::from_str`, against arbitrary strings.
//!
//! Levels arrive from config files and environment variables. Parsing must
//! reach a verdict for any input, and the round trip through `as_str` must be
//! stable — a level that does not survive being written and read back would
//! silently change what a deployment records.

#![no_main]

use ash_log::AuditSeverity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Must not panic on any input.
    let Ok(level) = text.parse::<AuditSeverity>() else {
        return;
    };

    // Anything that parses must round-trip through its canonical name, or a
    // level written to a config could read back as a different one.
    let name = level.as_str();
    assert_eq!(
        name.parse::<AuditSeverity>(),
        Ok(level),
        "`{text}` parsed to {level:?}, whose name `{name}` does not parse back"
    );

    // `Display` must agree with `as_str`, since both reach config files.
    assert_eq!(level.to_string(), name);
});
