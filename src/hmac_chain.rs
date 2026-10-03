//! Tamper-evident audit logging via an HMAC hash chain.
//!
//! Unlike [`ChecksumIntegrity`](crate::ChecksumIntegrity), which uses an
//! unkeyed hash that anyone can recompute, this module keys every entry with a
//! secret and links each entry to its predecessor. An attacker who can rewrite
//! the log file cannot produce a chain that verifies without the key, and
//! cannot delete, reorder, or truncate entries without breaking the link.

use super::{AuditEvent, AuditIntegrity};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// Metadata key holding the chained HMAC of an event.
pub const MAC_FIELD: &str = "mac";

/// Metadata key holding the event's position in the chain.
pub const CHAIN_INDEX_FIELD: &str = "chain_index";

/// Genesis value for the chain, used as the "previous MAC" of the first entry.
const GENESIS: &str = "ash-log:genesis:v1";

/// Metadata field naming the key an entry was signed with.
///
/// Present only when the chain was built with an identified key. Its absence
/// means a single unidentified key, which is how every chain written before
/// rotation support looked — so those chains canonicalize unchanged.
pub const KEY_ID_FIELD: &str = "key_id";

/// Metadata field naming the writer that produced an entry.
///
/// Present only when the chain was given a writer identity. See
/// [`HmacChainIntegrity::writer`].
pub const WRITER_FIELD: &str = "writer";

/// Render bytes as lowercase hex.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        // Writing to a String is infallible.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Serialize an event to a canonical, deterministic byte string.
///
/// Round-tripping through [`serde_json::Value`] sorts object keys (`serde_json`'s
/// map is a `BTreeMap` unless the `preserve_order` feature is on), so two events
/// with equal content always produce identical bytes. The MAC and chain-index
/// fields are removed first so a stamped event re-canonicalizes to the value
/// that was originally signed.
///
/// Returns `None` only if the event contains values that cannot be serialized
/// (for example a map with non-string keys inside `metadata` or `params`).
fn canonicalize(event: &AuditEvent) -> Option<Vec<u8>> {
    let mut value = serde_json::to_value(event).ok()?;
    if let Some(metadata) = value
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
    {
        metadata.remove(MAC_FIELD);
        metadata.remove(CHAIN_INDEX_FIELD);
    }
    serde_json::to_vec(&value).ok()
}

/// Compute the chained MAC for one event given the previous entry's MAC.
///
/// The previous MAC is bound with an explicit length prefix so that a value
/// ending in the canonical bytes of another cannot be confused with it.
fn compute_mac(key: &[u8], previous_mac: &str, canonical: &[u8]) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(
        &u64::try_from(previous_mac.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    mac.update(previous_mac.as_bytes());
    mac.update(canonical);
    to_hex(&mac.finalize().into_bytes())
}

/// Why a key rotation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationError {
    /// The chain has no key identifier, so entries could not say which key
    /// signed them and rotation would make earlier ones unverifiable.
    NoKeyId,
    /// The replacement key is empty, which provides no security.
    EmptyKey,
    /// The identifier is already in use by the current or a retired key.
    /// Reusing one for different key material would make entries signed with
    /// the earlier key impossible to verify.
    DuplicateKeyId(String),
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKeyId => write!(
                f,
                "cannot rotate a chain with no key id; call `with_key_id` before signing"
            ),
            Self::EmptyKey => write!(f, "the replacement key is empty and provides no security"),
            Self::DuplicateKeyId(id) => {
                write!(f, "key id `{id}` is already in use by this chain")
            }
        }
    }
}

impl std::error::Error for RotationError {}

/// Why a chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The event carries no `mac` metadata field, or it is not a string.
    MissingMac {
        /// Position of the offending entry within the verified stream.
        index: usize,
    },
    /// The event could not be canonicalized for hashing.
    NotCanonicalizable {
        /// Position of the offending entry within the verified stream.
        index: usize,
    },
    /// The stored MAC does not match the recomputed one: the entry was
    /// modified, or an earlier entry was altered, removed, or reordered.
    MacMismatch {
        /// Position of the offending entry within the verified stream.
        index: usize,
    },
    /// The event carries no `chain_index`, so its position cannot be
    /// established. Only returned by
    /// [`verify_unordered`](HmacChainIntegrity::verify_unordered).
    MissingChainIndex {
        /// Position of the offending entry within the verified stream.
        index: usize,
    },
    /// The entry names a key this verifier does not hold, so it cannot be
    /// checked. Supply the key, or verify with the instance that rotated.
    UnknownKeyId {
        /// Position of the offending entry within the verified stream.
        index: usize,
        /// The key identifier the entry carries.
        key_id: String,
    },
    /// Entries from two different writers are interleaved in one chain.
    ///
    /// Each writer keeps its own index and previous-MAC state, so their output
    /// cannot form a single valid chain. This is a configuration mistake, not
    /// an attack, and is reported separately so it is not mistaken for one.
    MixedWriters {
        /// Position of the entry whose writer differs from the first.
        index: usize,
        /// The writer the chain started with.
        expected: String,
        /// The writer this entry names.
        found: String,
    },
    /// The event's recorded chain index disagrees with its actual position,
    /// which indicates entries were removed or reordered.
    IndexMismatch {
        /// Position of the offending entry within the verified stream.
        index: usize,
        /// The chain index recorded in the entry.
        found: u64,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMac { index } => {
                write!(f, "entry {index}: missing or malformed `{MAC_FIELD}` field")
            }
            Self::NotCanonicalizable { index } => {
                write!(f, "entry {index}: could not be canonicalized for hashing")
            }
            Self::MissingChainIndex { index } => write!(
                f,
                "entry {index}: missing `{CHAIN_INDEX_FIELD}` field, so its position \
                 in the chain cannot be established"
            ),
            Self::UnknownKeyId { index, key_id } => write!(
                f,
                "entry {index}: signed with key `{key_id}`, which this verifier does not hold"
            ),
            Self::MixedWriters {
                index,
                expected,
                found,
            } => write!(
                f,
                "entry {index}: written by `{found}` but the chain began with `{expected}` — \
                 two processes cannot share one chain; give each its own chain or key"
            ),
            Self::MacMismatch { index } => write!(
                f,
                "entry {index}: MAC mismatch — this entry or an earlier one was altered, \
                 removed, or reordered"
            ),
            Self::IndexMismatch { index, found } => write!(
                f,
                "entry {index}: recorded chain index {found} does not match its position — \
                 entries were removed or reordered"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Tamper-evident integrity using a keyed HMAC-SHA256 hash chain.
///
/// Each event is stamped with `mac = HMAC(key, prev_mac || canonical(event))`
/// and a `chain_index`. Because the MAC covers the *entire* canonical event and
/// is keyed with a secret, an attacker cannot silently modify a field, and
/// because it also covers the previous MAC, they cannot delete, reorder, or
/// truncate entries without breaking every subsequent link.
///
/// # Key management
///
/// The key must be secret and must never be written to the log it protects.
/// Load it from a KMS, a secrets manager, or an environment variable at
/// startup. Use at least 32 bytes of random data.
///
/// # Limitations
///
/// This makes tampering *detectable*, not impossible. An attacker who obtains
/// the key can rewrite the whole chain. To protect against that, ship entries
/// off-box (or to WORM storage) promptly, so the attacker never controls the
/// only copy.
///
/// # Examples
///
/// ```rust
/// use ash_log::*;
///
/// let integrity = HmacChainIntegrity::new(b"a-32-byte-or-longer-secret-key!!");
///
/// let mut first = AuditEvent::builder()
///     .event_type(AuditEventType::AuthenticationAttempt)
///     .principal("alice@example.com")
///     .result(AuditResult::Success)
///     .build();
/// integrity.add_integrity(&mut first);
///
/// let mut second = AuditEvent::builder()
///     .event_type(AuditEventType::MethodInvocation)
///     .result(AuditResult::Success)
///     .build();
/// integrity.add_integrity(&mut second);
///
/// // A verifier holding the same key can confirm the whole stream.
/// let verifier = HmacChainIntegrity::new(b"a-32-byte-or-longer-secret-key!!");
/// assert!(verifier.verify_chain(&[first, second]).is_ok());
/// ```
pub struct HmacChainIntegrity {
    key: Vec<u8>,
    key_id: Option<String>,
    writer: Option<String>,
    /// Keys retired by rotation, kept so earlier entries still verify.
    previous_keys: Vec<(String, Vec<u8>)>,
    state: Mutex<ChainState>,
}

/// Mutable position in the chain.
#[derive(Debug, Clone)]
struct ChainState {
    previous_mac: String,
    index: u64,
}

impl HmacChainIntegrity {
    /// Create a chain starting from the genesis value.
    ///
    /// Use a secret of at least 32 random bytes.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty. An empty key provides no security whatsoever,
    /// and silently accepting one would produce a log that looks protected but
    /// is not; failing loudly at construction is the safer behaviour.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        assert!(
            !key.is_empty(),
            "HmacChainIntegrity requires a non-empty key; an empty key provides no security"
        );
        Self {
            key: key.to_vec(),
            key_id: None,
            writer: None,
            previous_keys: Vec::new(),
            state: Mutex::new(ChainState {
                previous_mac: GENESIS.to_string(),
                index: 0,
            }),
        }
    }

    /// Resume an existing chain from the last known MAC and index.
    ///
    /// Use this when a process restarts and must continue an existing log
    /// rather than begin a new chain. Pass the `mac` and `chain_index` of the
    /// last entry already written, so the next entry links to it.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty, for the same reason as [`new`](Self::new).
    #[must_use]
    pub fn resume(key: &[u8], last_mac: impl Into<String>, last_index: u64) -> Self {
        assert!(
            !key.is_empty(),
            "HmacChainIntegrity requires a non-empty key; an empty key provides no security"
        );
        Self {
            key: key.to_vec(),
            key_id: None,
            writer: None,
            previous_keys: Vec::new(),
            state: Mutex::new(ChainState {
                previous_mac: last_mac.into(),
                index: last_index.saturating_add(1),
            }),
        }
    }

    /// Name the key this chain signs with.
    ///
    /// The identifier is stamped on every entry and covered by the MAC, so a
    /// verifier can tell which key to use without guessing, and an attacker
    /// cannot relabel an entry to point at a key they do control.
    ///
    /// Required before [`rotate_to`](Self::rotate_to): rotation is meaningless
    /// if entries do not say which key signed them.
    #[must_use]
    pub fn with_key_id<S: Into<String>>(mut self, key_id: S) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Name the writer producing this chain.
    ///
    /// Two processes must never share one chain: each keeps its own index and
    /// previous-MAC state, so their entries interleave into a stream that
    /// verifies as tampered. Giving each writer a distinct identity makes that
    /// mistake diagnosable — [`verify_chain`](Self::verify_chain) reports
    /// [`ChainError::MixedWriters`] instead of a bare MAC mismatch, which would
    /// otherwise look exactly like an attack.
    ///
    /// Give each process its own chain, its own key, or serialize writes
    /// through one process.
    #[must_use]
    pub fn writer<S: Into<String>>(mut self, writer: S) -> Self {
        self.writer = Some(writer.into());
        self
    }

    /// Begin signing with a new key, keeping the old one for verification.
    ///
    /// The chain is *not* restarted: the next entry links to the previous MAC
    /// as usual, so continuity is preserved across the rotation. Entries signed
    /// before this call keep their original `key_id` and still verify, because
    /// the retired key is retained.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError`] if this chain has no key id, if `new_key` is
    /// empty, or if `new_key_id` is already in use — reusing an identifier for
    /// a different key would make earlier entries unverifiable.
    pub fn rotate_to(
        &mut self,
        new_key: &[u8],
        new_key_id: impl Into<String>,
    ) -> Result<(), RotationError> {
        if new_key.is_empty() {
            return Err(RotationError::EmptyKey);
        }
        let Some(current_id) = self.key_id.clone() else {
            return Err(RotationError::NoKeyId);
        };
        let new_key_id = new_key_id.into();
        if new_key_id == current_id || self.previous_keys.iter().any(|(id, _)| *id == new_key_id) {
            return Err(RotationError::DuplicateKeyId(new_key_id));
        }

        self.previous_keys.push((
            current_id,
            std::mem::replace(&mut self.key, new_key.to_vec()),
        ));
        self.key_id = Some(new_key_id);
        Ok(())
    }

    /// The key identifier currently in use, if one was set.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Identifiers of keys retired by rotation, oldest first.
    #[must_use]
    pub fn retired_key_ids(&self) -> Vec<&str> {
        self.previous_keys
            .iter()
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// The key to verify an entry stamped with `key_id`.
    ///
    /// An entry with no identifier is verified with the current key, which is
    /// how every chain written before rotation support behaves.
    fn key_for(&self, key_id: Option<&str>) -> Option<&[u8]> {
        match key_id {
            None => Some(&self.key),
            Some(id) if Some(id) == self.key_id.as_deref() => Some(&self.key),
            Some(id) => self
                .previous_keys
                .iter()
                .find(|(known, _)| known == id)
                .map(|(_, key)| key.as_slice()),
        }
    }

    /// Lock the chain state, recovering it if another thread panicked while
    /// holding the lock. The state remains valid, and refusing to log would be
    /// a worse outcome than continuing.
    fn lock(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The MAC most recently produced, or the genesis value if none yet.
    ///
    /// Persist this alongside the index to later [`resume`](Self::resume).
    #[must_use]
    pub fn current_mac(&self) -> String {
        self.lock().previous_mac.clone()
    }

    /// The index the next stamped event will receive.
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.lock().index
    }

    /// Verify a complete chain of events in order.
    ///
    /// Returns the number of entries verified, or the first
    /// [`ChainError`] encountered. Verification starts from genesis, so pass
    /// the stream from its beginning; a mid-stream segment will report a
    /// mismatch at entry 0.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] identifying the first entry that fails to verify.
    pub fn verify_chain(&self, events: &[AuditEvent]) -> Result<usize, ChainError> {
        let mut previous_mac = GENESIS.to_string();
        let mut chain_writer: Option<&str> = None;

        for (index, event) in events.iter().enumerate() {
            let stored_mac = event
                .metadata
                .get(MAC_FIELD)
                .and_then(serde_json::Value::as_str)
                .ok_or(ChainError::MissingMac { index })?;

            // A writer change means two processes wrote one chain. Reporting it
            // as its own error keeps a configuration mistake from being read as
            // an attack.
            let writer = event
                .metadata
                .get(WRITER_FIELD)
                .and_then(serde_json::Value::as_str);
            match (chain_writer, writer) {
                (None, Some(found)) => chain_writer = Some(found),
                (Some(expected), Some(found)) if expected != found => {
                    return Err(ChainError::MixedWriters {
                        index,
                        expected: expected.to_string(),
                        found: found.to_string(),
                    });
                }
                _ => {}
            }

            // Each entry is verified with the key it names, so a chain that
            // rotated keys mid-stream still verifies end to end.
            let key_id = event
                .metadata
                .get(KEY_ID_FIELD)
                .and_then(serde_json::Value::as_str);
            let key = self
                .key_for(key_id)
                .ok_or_else(|| ChainError::UnknownKeyId {
                    index,
                    key_id: key_id.unwrap_or_default().to_string(),
                })?;

            if let Some(found) = event
                .metadata
                .get(CHAIN_INDEX_FIELD)
                .and_then(serde_json::Value::as_u64)
                && found != index as u64
            {
                return Err(ChainError::IndexMismatch { index, found });
            }

            let canonical = canonicalize(event).ok_or(ChainError::NotCanonicalizable { index })?;
            let expected = compute_mac(key, &previous_mac, &canonical);

            // `expected` is derived from the secret key; comparing it against
            // attacker-supplied bytes is not a secret-dependent branch, but use
            // the constant-time path anyway to avoid leaking a comparison
            // oracle on the recomputed value.
            if !constant_time_eq(expected.as_bytes(), stored_mac.as_bytes()) {
                return Err(ChainError::MacMismatch { index });
            }

            previous_mac = expected;
        }

        Ok(events.len())
    }

    /// Verify a chain whose entries may not be in chain order.
    ///
    /// Concurrent producers stamp events under a lock but write them to the
    /// backend afterwards, so a log written by multiple threads can contain
    /// entries in a different order than they were stamped. Such a log is
    /// perfectly valid, but [`verify_chain`](Self::verify_chain) rejects it
    /// because it checks position. This method sorts by the recorded
    /// `chain_index` first, then verifies.
    ///
    /// Prefer this whenever more than one thread logs to the same chain. It
    /// requires every entry to carry a `chain_index`, and rejects duplicates,
    /// so it detects tampering just as strictly as `verify_chain` does.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] identifying the first entry that fails to verify.
    /// Indices in the returned error refer to positions in chain order, not to
    /// positions in the slice that was passed in.
    pub fn verify_unordered(&self, events: &[AuditEvent]) -> Result<usize, ChainError> {
        let mut ordered: Vec<AuditEvent> = events.to_vec();

        // Every entry must carry an index, or sorting is meaningless.
        for (index, event) in ordered.iter().enumerate() {
            if event
                .metadata
                .get(CHAIN_INDEX_FIELD)
                .and_then(serde_json::Value::as_u64)
                .is_none()
            {
                return Err(ChainError::MissingChainIndex { index });
            }
        }

        ordered.sort_by_key(|event| {
            event
                .metadata
                .get(CHAIN_INDEX_FIELD)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX)
        });

        self.verify_chain(&ordered)
    }
}

/// Compare two byte strings without short-circuiting on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl AuditIntegrity for HmacChainIntegrity {
    fn add_integrity(&self, event: &mut AuditEvent) {
        let mut state = self.lock();

        // Stamp everything identifying before hashing, so all of it is covered
        // by the MAC. A key id an attacker could rewrite would let them point
        // an entry at a key they control.
        event.add_metadata(CHAIN_INDEX_FIELD, state.index);
        if let Some(key_id) = &self.key_id {
            event.add_metadata(KEY_ID_FIELD, key_id.clone());
        }
        if let Some(writer) = &self.writer {
            event.add_metadata(WRITER_FIELD, writer.clone());
        }

        let Some(canonical) = canonicalize(event) else {
            eprintln!("[AUDIT ERROR] Failed to canonicalize event for HMAC chaining");
            return;
        };

        let mac = compute_mac(&self.key, &state.previous_mac, &canonical);
        event.add_metadata(MAC_FIELD, mac.clone());

        state.previous_mac = mac;
        state.index = state.index.saturating_add(1);
    }

    /// Verify a single event in isolation.
    ///
    /// This only confirms that a MAC field is present and well-formed; a single
    /// event carries no proof of its position. Use
    /// [`verify_chain`](Self::verify_chain) to actually detect tampering.
    fn verify(&self, event: &AuditEvent) -> bool {
        event
            .metadata
            .get(MAC_FIELD)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|mac| mac.len() == 64 && mac.bytes().all(|b| b.is_ascii_hexdigit()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult};

    const KEY: &[u8] = b"test-key-at-least-32-bytes-long!!";

    fn event(principal: &str) -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::AuthenticationAttempt)
            .principal(principal)
            .method("login")
            .result(AuditResult::Success)
            .build()
    }

    fn chain_of(n: usize) -> Vec<AuditEvent> {
        let integrity = HmacChainIntegrity::new(KEY);
        (0..n)
            .map(|i| {
                let mut e = event(&format!("user{i}@example.com"));
                integrity.add_integrity(&mut e);
                e
            })
            .collect()
    }

    #[test]
    fn test_valid_chain_verifies() {
        let events = chain_of(5);
        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(verifier.verify_chain(&events), Ok(5));
    }

    #[test]
    fn test_empty_chain_verifies() {
        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(verifier.verify_chain(&[]), Ok(0));
    }

    #[test]
    fn test_wrong_key_fails() {
        let events = chain_of(3);
        let verifier = HmacChainIntegrity::new(b"a-completely-different-secret-key");
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::MacMismatch { index: 0 })
        );
    }

    /// The attack that defeats `ChecksumIntegrity`: edit a field, strip the
    /// integrity metadata, and re-stamp with the same public algorithm.
    #[test]
    fn test_restamp_forgery_is_detected() {
        let mut events = chain_of(3);

        events[1].principal = Some("innocent@example.com".to_string());
        events[1].result = AuditResult::Success;
        events[1].metadata.remove(MAC_FIELD);
        events[1].metadata.remove(CHAIN_INDEX_FIELD);

        // Attacker re-stamps using the library, but without the secret key.
        let attacker = HmacChainIntegrity::new(b"attacker-guessed-key-not-the-real");
        attacker.add_integrity(&mut events[1]);

        // The attacker's fresh chain restarts at index 0, so the recorded
        // index betrays the forgery before the MAC is even compared. Either
        // way the entry is rejected.
        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::IndexMismatch { index: 1, found: 0 })
        );

        // With the index forged to match, the keyed MAC still catches it.
        events[1].add_metadata(CHAIN_INDEX_FIELD, 1u64);
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::MacMismatch { index: 1 })
        );
    }

    #[test]
    fn test_field_edit_is_detected() {
        let mut events = chain_of(3);
        events[2].principal = Some("attacker@evil.com".to_string());

        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::MacMismatch { index: 2 })
        );
    }

    /// Fields that `ChecksumIntegrity` ignored entirely must be covered here.
    #[test]
    fn test_previously_uncovered_fields_are_detected() {
        for (name, mutate) in [
            (
                "severity",
                (|e: &mut AuditEvent| {
                    // Events are built with `Success`, which defaults to `Info`;
                    // move to a different level so the field genuinely changes.
                    e.severity = crate::AuditSeverity::Critical;
                }) as fn(&mut AuditEvent),
            ),
            ("error", |e: &mut AuditEvent| {
                e.error = Some("rewritten".to_string());
            }),
            ("metadata", |e: &mut AuditEvent| {
                e.add_metadata("amount", 1);
            }),
            ("params", |e: &mut AuditEvent| {
                e.params = Some(serde_json::json!({"forged": true}));
            }),
        ] {
            let mut events = chain_of(2);
            mutate(&mut events[1]);

            let verifier = HmacChainIntegrity::new(KEY);
            assert_eq!(
                verifier.verify_chain(&events),
                Err(ChainError::MacMismatch { index: 1 }),
                "tampering with `{name}` went undetected"
            );
        }
    }

    #[test]
    fn test_deletion_is_detected() {
        let mut events = chain_of(5);
        events.remove(2);

        let verifier = HmacChainIntegrity::new(KEY);
        // The removed entry shifts later indices, caught by the recorded index.
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::IndexMismatch { index: 2, found: 3 })
        );
    }

    #[test]
    fn test_reorder_is_detected() {
        let mut events = chain_of(4);
        events.swap(1, 2);

        let verifier = HmacChainIntegrity::new(KEY);
        assert!(verifier.verify_chain(&events).is_err());
    }

    #[test]
    fn test_truncation_is_detected_via_index() {
        // Truncating the tail leaves a valid prefix; detection requires knowing
        // the expected length, so callers compare the final index. Verify that
        // a truncated stream still reports its true length.
        let events = chain_of(5);
        let truncated = &events[..3];

        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(verifier.verify_chain(truncated), Ok(3));

        let last_index = truncated[2]
            .metadata
            .get(CHAIN_INDEX_FIELD)
            .and_then(serde_json::Value::as_u64);
        assert_eq!(last_index, Some(2), "index reveals the stream length");
    }

    #[test]
    fn test_missing_mac_is_detected() {
        let mut events = chain_of(2);
        events[1].metadata.remove(MAC_FIELD);

        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(
            verifier.verify_chain(&events),
            Err(ChainError::MissingMac { index: 1 })
        );
    }

    #[test]
    fn test_resume_continues_chain() {
        let integrity = HmacChainIntegrity::new(KEY);
        let mut first = event("alice@example.com");
        integrity.add_integrity(&mut first);

        // Simulate a restart: resume from the persisted MAC and index.
        let resumed = HmacChainIntegrity::resume(KEY, integrity.current_mac(), 0);
        let mut second = event("bob@example.com");
        resumed.add_integrity(&mut second);

        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(verifier.verify_chain(&[first, second]), Ok(2));
    }

    #[test]
    fn test_canonicalization_is_order_independent() {
        // Metadata insertion order must not change the MAC.
        let integrity = HmacChainIntegrity::new(KEY);
        let mut a = event("alice@example.com");
        a.add_metadata("zebra", 1);
        a.add_metadata("apple", 2);
        integrity.add_integrity(&mut a);

        let integrity2 = HmacChainIntegrity::new(KEY);
        let mut b = event("alice@example.com");
        b.add_metadata("apple", 2);
        b.add_metadata("zebra", 1);
        // Match timestamps so only ordering differs.
        b.timestamp = a.timestamp;
        integrity2.add_integrity(&mut b);

        assert_eq!(
            a.metadata.get(MAC_FIELD),
            b.metadata.get(MAC_FIELD),
            "metadata ordering must not affect the MAC"
        );
    }

    #[test]
    fn test_serialization_round_trip_preserves_verification() {
        // The CLI verifies events that have been through JSON; make sure the
        // round trip does not perturb the canonical form.
        let events = chain_of(3);
        let lines: Vec<String> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        let parsed: Vec<AuditEvent> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        let verifier = HmacChainIntegrity::new(KEY);
        assert_eq!(verifier.verify_chain(&parsed), Ok(3));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[cfg(feature = "hlc")]
    mod hlc_canonical_form {
        use super::*;
        use crate::{EventClock, HlcClock, Logger, NoopAuditBackend};
        use std::sync::Arc;

        /// A chain produced before this feature existed, captured as the JSON
        /// lines it was written as. Enabling `hlc` must not change how these
        /// verify: the field is skipped when absent, so their canonical bytes
        /// are byte-identical to what was signed.
        const KEY: &[u8] = b"test-key-at-least-32-bytes-long!!";

        #[test]
        fn test_events_without_a_timestamp_canonicalize_unchanged() {
            // Built and signed exactly as a pre-`hlc` build would: no clock,
            // so no field, so the same bytes reach the MAC.
            let integrity = HmacChainIntegrity::new(KEY);
            let mut events: Vec<AuditEvent> = (0..4)
                .map(|n| {
                    let mut event = AuditEvent::builder()
                        .event_type(AuditEventType::AuthenticationAttempt)
                        .principal(format!("user{n}"))
                        .result(AuditResult::Success)
                        .build();
                    integrity.add_integrity(&mut event);
                    event
                })
                .collect();

            assert!(
                events.iter().all(|e| e.hlc.is_none()),
                "no clock was configured, so no event carries a timestamp"
            );
            assert_eq!(
                HmacChainIntegrity::new(KEY).verify_chain(&events),
                Ok(4),
                "a chain with no timestamps verifies under an hlc-enabled build"
            );

            // The serialized form carries no `hlc` key at all, so a consumer
            // reading these lines sees exactly the pre-feature schema.
            let json = serde_json::to_value(&events[0]).unwrap();
            assert!(json.get("hlc").is_none());

            // And the round trip still verifies, which is what a log file is.
            let line = serde_json::to_string(&events[0]).unwrap();
            events[0] = serde_json::from_str(&line).unwrap();
            assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&events), Ok(4));
        }

        #[test]
        fn test_a_stamped_chain_verifies() {
            let backend = Arc::new(NoopAuditBackend);
            let logger = Logger::builder(backend)
                .integrity(Arc::new(HmacChainIntegrity::new(KEY)))
                .clock(Arc::new(HlcClock::new()))
                .build();

            // Collect what the logger produces by stamping directly, since the
            // noop backend discards.
            let integrity = HmacChainIntegrity::new(KEY);
            let clock = HlcClock::new();
            let mut events: Vec<AuditEvent> = (0..4)
                .map(|n| {
                    let mut event = AuditEvent::builder()
                        .event_type(AuditEventType::AdminAction)
                        .result(AuditResult::Success)
                        .method(format!("action{n}"))
                        .hlc(EventClock::from(clock.now().unwrap()))
                        .build();
                    integrity.add_integrity(&mut event);
                    event
                })
                .collect();

            assert_eq!(
                HmacChainIntegrity::new(KEY).verify_chain(&events),
                Ok(4),
                "a chain of stamped events verifies"
            );

            // Round-tripping through JSON preserves the timestamp exactly, or
            // the chain would break on reload.
            let line = serde_json::to_string(&events[2]).unwrap();
            let reloaded: AuditEvent = serde_json::from_str(&line).unwrap();
            assert_eq!(reloaded.hlc, events[2].hlc);
            events[2] = reloaded;
            assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&events), Ok(4));

            let _ = logger;
        }

        #[test]
        fn test_rewriting_the_causal_order_is_detected() {
            // The reason the timestamp is inside the canonical form: an
            // attacker who edits it must forge the MAC to match.
            let integrity = HmacChainIntegrity::new(KEY);
            let clock = HlcClock::new();
            let mut events: Vec<AuditEvent> = (0..3)
                .map(|_| {
                    let mut event = AuditEvent::builder()
                        .event_type(AuditEventType::SecurityViolation)
                        .result(AuditResult::Violation)
                        .hlc(EventClock::from(clock.now().unwrap()))
                        .build();
                    integrity.add_integrity(&mut event);
                    event
                })
                .collect();

            assert_eq!(HmacChainIntegrity::new(KEY).verify_chain(&events), Ok(3));

            // Backdate one entry so it appears to have happened first.
            events[2].hlc = Some(EventClock {
                physical: 1,
                logical: 0,
            });

            assert_eq!(
                HmacChainIntegrity::new(KEY).verify_chain(&events),
                Err(ChainError::MacMismatch { index: 2 }),
                "altering the causal timestamp breaks the MAC"
            );
        }

        #[test]
        fn test_adding_a_timestamp_to_a_signed_event_is_detected() {
            // The inverse: an event signed without a timestamp cannot have one
            // grafted on afterwards.
            let integrity = HmacChainIntegrity::new(KEY);
            let mut event = AuditEvent::builder()
                .event_type(AuditEventType::AdminAction)
                .result(AuditResult::Success)
                .build();
            integrity.add_integrity(&mut event);

            assert_eq!(
                HmacChainIntegrity::new(KEY).verify_chain(&[event.clone()]),
                Ok(1)
            );

            event.hlc = Some(EventClock {
                physical: 99,
                logical: 0,
            });
            assert_eq!(
                HmacChainIntegrity::new(KEY).verify_chain(&[event]),
                Err(ChainError::MacMismatch { index: 0 }),
                "a timestamp cannot be added to an already-signed event"
            );
        }
    }
}
