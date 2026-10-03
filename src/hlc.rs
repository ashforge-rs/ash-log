//! Hybrid Logical Clock timestamps for events.
//!
//! # Why this exists
//!
//! Every event carries a [`SystemTime`](std::time::SystemTime), and a system
//! clock can move backwards: NTP steps it, a VM resumes from a snapshot, an
//! operator corrects it by hand. When that happens the audit log keeps
//! verifying — [`chain_index`](crate::HmacChainIntegrity) is monotonic whatever
//! the wall clock does — but the timestamps no longer describe the order things
//! actually happened in, which is most of what an audit log is for.
//!
//! A Hybrid Logical Clock timestamp is monotonic by construction. It tracks
//! wall time when wall time is sane, and falls back to a logical counter when
//! it is not, so `a.hlc < b.hlc` means `a` really was recorded first.
//!
//! # Across services
//!
//! [`HlcClock::recv`] is the other half. A service that receives a request
//! carrying an upstream timestamp calls `recv` before recording its own events,
//! and those events are then provably ordered after the upstream ones — without
//! the two hosts' clocks agreeing. See [`Logger::observe_hlc`](crate::Logger::observe_hlc).
//!
//! # Integrity
//!
//! The timestamp is part of the event's canonical form, so it is covered by
//! whatever [`AuditIntegrity`](crate::AuditIntegrity) is in use: with
//! [`HmacChainIntegrity`](crate::HmacChainIntegrity) the causal ordering cannot
//! be rewritten without detection. Events written without this feature carry no
//! `hlc` field at all, and their canonical bytes are unchanged, so logs and
//! chains produced by either build verify identically.

use serde::{Deserialize, Serialize};

pub use ash_time::{HlcClock, HlcError, HlcTimestamp};

/// An [`HlcTimestamp`] as it is stored on an event.
///
/// [`HlcTimestamp`] carries no serde derives, so this mirrors its two fields.
/// It serializes as `{"physical": <ns>, "logical": <n>}`, and orders exactly as
/// the underlying timestamp does: by wall-clock nanoseconds first, then by the
/// logical counter that breaks ties within the same nanosecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventClock {
    /// Wall-clock component: nanoseconds since the Unix epoch.
    pub physical: u64,
    /// Logical counter, distinguishing events within one nanosecond.
    pub logical: u32,
}

impl EventClock {
    /// Whether `self` was recorded before `other`.
    #[must_use]
    pub fn happened_before(self, other: Self) -> bool {
        self < other
    }
}

impl From<HlcTimestamp> for EventClock {
    fn from(ts: HlcTimestamp) -> Self {
        Self {
            physical: ts.physical,
            logical: ts.logical,
        }
    }
}

impl From<EventClock> for HlcTimestamp {
    fn from(clock: EventClock) -> Self {
        Self {
            physical: clock.physical,
            logical: clock.logical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trips_through_the_underlying_timestamp() {
        let clock = HlcClock::new();
        let ts = clock.now().expect("system clock is sane under test");

        let stored = EventClock::from(ts);
        assert_eq!(HlcTimestamp::from(stored), ts);
    }

    #[test]
    fn test_ordering_matches_the_underlying_timestamp() {
        let clock = HlcClock::new();
        let first = clock.now().unwrap();
        let second = clock.now().unwrap();

        assert!(first.happened_before(second));
        assert!(EventClock::from(first).happened_before(EventClock::from(second)));
        assert!(EventClock::from(first) < EventClock::from(second));
    }

    #[test]
    fn test_serializes_as_two_named_fields() {
        let clock = EventClock {
            physical: 1_700_000_000_000_000_000,
            logical: 7,
        };

        let json = serde_json::to_value(clock).unwrap();
        assert_eq!(json["physical"], 1_700_000_000_000_000_000_u64);
        assert_eq!(json["logical"], 7);

        let back: EventClock = serde_json::from_value(json).unwrap();
        assert_eq!(back, clock);
    }

    #[test]
    fn test_logical_counter_breaks_ties_within_a_nanosecond() {
        // Same physical component, different logical: the ordering must still
        // be total, or two events in the same nanosecond would be unorderable.
        let earlier = EventClock {
            physical: 42,
            logical: 0,
        };
        let later = EventClock {
            physical: 42,
            logical: 1,
        };

        assert!(earlier.happened_before(later));
        assert!(!later.happened_before(earlier));
    }
}
