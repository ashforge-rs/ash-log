//! Writing audit events to a file, with rotation.
//!
//! # Durability
//!
//! Each event is written and flushed to the OS before [`log_audit`] returns, so
//! a crashed process does not lose entries already accepted. It is *not*
//! `fsync`ed by default: a power loss can still lose recently written lines.
//! Enable [`FileBackendBuilder::sync_on_write`] where that matters, at a
//! substantial cost in throughput.
//!
//! # Rotation
//!
//! Rotation is driven by size, by age, or both, and is checked before each
//! write. The current file is renamed with a numeric suffix and a fresh one
//! opened, oldest files being removed once the retention limit is reached.
//!
//! Because rotation renames the *file*, a chain spanning several files is still
//! one chain: `chain_index` continues across the boundary and
//! [`HmacChainIntegrity::verify_chain`](crate::HmacChainIntegrity::verify_chain)
//! accepts the concatenation of the rotated files in order.
//!
//! Reassemble those files by sorting the *entries* on `chain_index`, not by
//! filename. Rotated names embed a timestamp, but two rotations within the same
//! second fall back to a numeric suffix that does not sort lexicographically
//! (`.10` orders before `.2`). The chain carries its own order; use it.
//!
//! # `logrotate` and other external rotators
//!
//! [`FileBackend::reopen`] closes and reopens the path, which is what an
//! external rotator needs after moving the file aside. Wire it to `SIGHUP`.
//! Without it the process keeps writing to the renamed inode and the new file
//! stays empty.
//!
//! [`log_audit`]: crate::AuditBackend::log_audit

use super::{AuditBackend, AuditEvent, ErrorSink, IgnoreErrors, WriteError};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// When to start a new file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RotationPolicy {
    /// Rotate once the file reaches this many bytes.
    pub max_bytes: Option<u64>,
    /// Rotate once the file has been open this long.
    pub max_age: Option<Duration>,
    /// How many rotated files to keep. `None` keeps every one.
    pub keep: Option<usize>,
}

impl RotationPolicy {
    /// Never rotate.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            max_bytes: None,
            max_age: None,
            keep: None,
        }
    }

    /// Rotate at `bytes`.
    #[must_use]
    pub const fn size(bytes: u64) -> Self {
        Self {
            max_bytes: Some(bytes),
            max_age: None,
            keep: None,
        }
    }

    /// Rotate at `age`.
    #[must_use]
    pub const fn age(age: Duration) -> Self {
        Self {
            max_bytes: None,
            max_age: Some(age),
            keep: None,
        }
    }

    /// Keep at most `n` rotated files, deleting the oldest beyond that.
    #[must_use]
    pub const fn keeping(mut self, n: usize) -> Self {
        self.keep = Some(n);
        self
    }

    /// Whether a file of `size` bytes opened at `opened_at` should rotate.
    fn should_rotate(self, size: u64, opened_at: SystemTime) -> bool {
        if self.max_bytes.is_some_and(|limit| size >= limit) {
            return true;
        }
        self.max_age
            .is_some_and(|limit| opened_at.elapsed().is_ok_and(|elapsed| elapsed >= limit))
    }
}

/// The open file and the state rotation decisions depend on.
struct OpenFile {
    writer: BufWriter<File>,
    bytes: u64,
    opened_at: SystemTime,
}

/// Appends audit events to a file as JSON lines.
///
/// # Examples
///
/// ```rust,no_run
/// use ash_log::*;
/// use std::sync::Arc;
///
/// let backend = FileBackend::builder("/var/log/audit.jsonl")
///     .rotation(RotationPolicy::size(64 * 1024 * 1024).keeping(10))
///     .errors(Arc::new(StderrErrorSink))
///     .build()
///     .expect("open the audit log");
///
/// let logger = Logger::builder(Arc::new(backend)).build();
/// logger.info("started");
/// ```
pub struct FileBackend {
    path: PathBuf,
    file: Mutex<OpenFile>,
    rotation: RotationPolicy,
    sync_on_write: bool,
    errors: Arc<dyn ErrorSink>,
}

impl FileBackend {
    /// Start building a backend writing to `path`.
    #[must_use]
    pub fn builder<P: Into<PathBuf>>(path: P) -> FileBackendBuilder {
        FileBackendBuilder {
            path: path.into(),
            rotation: RotationPolicy::never(),
            sync_on_write: false,
            errors: Arc::new(IgnoreErrors),
        }
    }

    /// Open `path` for appending with no rotation and no error reporting.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the file cannot be opened or created.
    pub fn new<P: Into<PathBuf>>(path: P) -> std::io::Result<Self> {
        Self::builder(path).build()
    }

    /// The path being written to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close and reopen the file at its original path.
    ///
    /// Call this from a `SIGHUP` handler when an external rotator such as
    /// `logrotate` moves the file aside. Without it the process keeps writing
    /// to the renamed inode.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the path cannot be reopened. The old
    /// handle is dropped either way, so a failure leaves the backend unable to
    /// write rather than writing to the wrong place.
    pub fn reopen(&self) -> std::io::Result<()> {
        let mut guard = self.lock();
        // Flush the outgoing handle first: buffered lines belong to the file
        // being rotated away, not the new one.
        drop(guard.writer.flush());
        *guard = open_at(&self.path)?;
        Ok(())
    }

    /// Number of bytes written to the current file.
    #[must_use]
    pub fn current_size(&self) -> u64 {
        self.lock().bytes
    }

    /// Rotate now, regardless of policy.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the rename or reopen fails.
    pub fn rotate(&self) -> std::io::Result<()> {
        let mut guard = self.lock();
        self.rotate_locked(&mut guard)
    }

    /// Lock the file, recovering from a poisoned mutex.
    ///
    /// A panic elsewhere must not stop the audit log: the file handle is still
    /// valid, and refusing to write because an unrelated thread panicked would
    /// be the worse failure.
    fn lock(&self) -> std::sync::MutexGuard<'_, OpenFile> {
        self.file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Rename the current file aside and open a fresh one.
    fn rotate_locked(&self, guard: &mut OpenFile) -> std::io::Result<()> {
        guard.writer.flush()?;

        let rotated = self.rotated_path();
        std::fs::rename(&self.path, &rotated)?;
        *guard = open_at(&self.path)?;

        if let Some(keep) = self.rotation.keep {
            self.prune(keep);
        }
        Ok(())
    }

    /// A free path to rename the current file to.
    ///
    /// Uses a timestamp so rotated names sort chronologically and no rename can
    /// clobber an earlier archive, with a counter to break ties when two
    /// rotations land in the same second.
    fn rotated_path(&self) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let base = self.path.as_os_str().to_string_lossy().into_owned();
        for counter in 0..u32::MAX {
            let candidate = if counter == 0 {
                PathBuf::from(format!("{base}.{stamp}"))
            } else {
                PathBuf::from(format!("{base}.{stamp}.{counter}"))
            };
            if !candidate.exists() {
                return candidate;
            }
        }
        PathBuf::from(format!("{base}.{stamp}.overflow"))
    }

    /// Delete the oldest rotated files beyond `keep`.
    ///
    /// Failures are ignored: being unable to delete an old file is not a reason
    /// to stop recording new events.
    fn prune(&self, keep: usize) {
        let Some(dir) = self.path.parent() else {
            return;
        };
        let Some(name) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let prefix = format!("{name}.");

        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut rotated: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .collect();

        if rotated.len() <= keep {
            return;
        }
        // Names embed a sortable timestamp, so lexicographic order is
        // chronological and the oldest are at the front.
        rotated.sort();
        let excess = rotated.len() - keep;
        for path in rotated.into_iter().take(excess) {
            drop(std::fs::remove_file(path));
        }
    }

    /// Write one serialized line, rotating first if the policy calls for it.
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut guard = self.lock();

        if self.rotation.should_rotate(guard.bytes, guard.opened_at) {
            self.rotate_locked(&mut guard)?;
        }

        guard.writer.write_all(line.as_bytes())?;
        guard.writer.write_all(b"\n")?;
        // Flush every line: an audit event still sitting in a userspace buffer
        // is an event that a crash loses.
        guard.writer.flush()?;

        if self.sync_on_write {
            guard.writer.get_ref().sync_data()?;
        }

        guard.bytes += line.len() as u64 + 1;
        Ok(())
    }

    /// Serialize and write, reporting any failure to the error sink.
    fn write_value<T: serde::Serialize>(&self, value: &T) {
        let line = match serde_json::to_string(value) {
            Ok(line) => line,
            Err(e) => {
                self.errors.on_error(&WriteError {
                    backend: "FileBackend",
                    source: std::io::Error::other(e),
                    events_lost: 1,
                });
                return;
            }
        };

        if let Err(source) = self.write_line(&line) {
            self.errors.on_error(&WriteError {
                backend: "FileBackend",
                source,
                events_lost: 1,
            });
        }
    }
}

/// Open `path` for appending, creating it if absent.
fn open_at(path: &Path) -> std::io::Result<OpenFile> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let bytes = file.metadata().map_or(0, |m| m.len());

    Ok(OpenFile {
        writer: BufWriter::new(file),
        bytes,
        opened_at: SystemTime::now(),
    })
}

impl AuditBackend for FileBackend {
    fn log_audit(&self, event: &AuditEvent) {
        self.write_value(event);
    }

    fn security_log(&self, event: &serde_json::Value) {
        self.write_value(event);
    }

    fn flush(&self) {
        let mut guard = self.lock();
        if let Err(source) = guard.writer.flush() {
            self.errors.on_error(&WriteError {
                backend: "FileBackend",
                source,
                events_lost: 0,
            });
        }
    }
}

impl std::fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackend")
            .field("path", &self.path)
            .field("rotation", &self.rotation)
            .field("sync_on_write", &self.sync_on_write)
            .finish_non_exhaustive()
    }
}

/// Builder for [`FileBackend`].
pub struct FileBackendBuilder {
    path: PathBuf,
    rotation: RotationPolicy,
    sync_on_write: bool,
    errors: Arc<dyn ErrorSink>,
}

impl FileBackendBuilder {
    /// Set when to rotate. Defaults to never.
    #[must_use]
    pub const fn rotation(mut self, rotation: RotationPolicy) -> Self {
        self.rotation = rotation;
        self
    }

    /// `fsync` after every event.
    ///
    /// Without this an event survives a process crash but not a power loss.
    /// With it, throughput drops by roughly an order of magnitude.
    #[must_use]
    pub const fn sync_on_write(mut self, sync: bool) -> Self {
        self.sync_on_write = sync;
        self
    }

    /// Where to report writes that fail. Defaults to discarding them.
    #[must_use]
    pub fn errors(mut self, errors: Arc<dyn ErrorSink>) -> Self {
        self.errors = errors;
        self
    }

    /// Open the file.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the path cannot be created or opened for
    /// appending.
    pub fn build(self) -> std::io::Result<FileBackend> {
        Ok(FileBackend {
            file: Mutex::new(open_at(&self.path)?),
            path: self.path,
            rotation: self.rotation,
            sync_on_write: self.sync_on_write,
            errors: self.errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEventType, AuditResult, CountingErrorSink};

    /// A scratch directory removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("ash-log-test-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&path));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    fn event(n: usize) -> AuditEvent {
        AuditEvent::builder()
            .event_type(AuditEventType::AdminAction)
            .method(format!("action{n}"))
            .result(AuditResult::Success)
            .build()
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn test_events_are_written_as_json_lines() {
        let dir = TempDir::new("write");
        let path = dir.join("audit.jsonl");
        let backend = FileBackend::new(&path).expect("open");

        backend.log_audit(&event(0));
        backend.log_audit(&event(1));

        let written = lines(&path);
        assert_eq!(written.len(), 2, "one line per event");
        for line in &written {
            let parsed: AuditEvent = serde_json::from_str(line).expect("each line parses");
            assert_eq!(parsed.event_type, AuditEventType::AdminAction);
        }
    }

    #[test]
    fn test_reopening_appends_rather_than_truncating() {
        // Truncating on open would silently destroy the audit record on every
        // restart, which is the worst possible failure mode here.
        let dir = TempDir::new("append");
        let path = dir.join("audit.jsonl");

        {
            let backend = FileBackend::new(&path).expect("open");
            backend.log_audit(&event(0));
        }
        {
            let backend = FileBackend::new(&path).expect("reopen");
            backend.log_audit(&event(1));
        }

        assert_eq!(
            lines(&path).len(),
            2,
            "the earlier event survives a restart"
        );
    }

    #[test]
    fn test_size_rotation_starts_a_new_file() {
        let dir = TempDir::new("rotate-size");
        let path = dir.join("audit.jsonl");
        let backend = FileBackend::builder(&path)
            .rotation(RotationPolicy::size(200))
            .build()
            .expect("open");

        for n in 0..10 {
            backend.log_audit(&event(n));
        }

        assert!(
            backend.current_size() < 400,
            "the live file stays near the limit rather than growing without bound"
        );

        let rotated: Vec<_> = std::fs::read_dir(&dir.0)
            .expect("read dir")
            .flatten()
            .filter(|e| e.file_name() != "audit.jsonl")
            .collect();
        assert!(!rotated.is_empty(), "at least one file was rotated aside");
    }

    #[test]
    fn test_no_events_are_lost_across_rotation() {
        // The property that matters: rotation moves lines between files, it
        // never drops them.
        let dir = TempDir::new("rotate-complete");
        let path = dir.join("audit.jsonl");
        let backend = FileBackend::builder(&path)
            .rotation(RotationPolicy::size(150))
            .build()
            .expect("open");

        for n in 0..20 {
            backend.log_audit(&event(n));
        }
        backend.flush();

        let mut total = 0;
        for entry in std::fs::read_dir(&dir.0).expect("read dir").flatten() {
            total += lines(&entry.path()).len();
        }
        assert_eq!(total, 20, "every event is in one file or another");
    }

    #[test]
    fn test_keep_prunes_the_oldest_files() {
        let dir = TempDir::new("prune");
        let path = dir.join("audit.jsonl");
        let backend = FileBackend::builder(&path)
            .rotation(RotationPolicy::size(120).keeping(2))
            .build()
            .expect("open");

        for n in 0..30 {
            backend.log_audit(&event(n));
        }

        let rotated = std::fs::read_dir(&dir.0)
            .expect("read dir")
            .flatten()
            .filter(|e| e.file_name() != "audit.jsonl")
            .count();
        assert!(
            rotated <= 2,
            "retention keeps at most 2 rotated files, found {rotated}"
        );
    }

    #[test]
    fn test_explicit_rotate_renames_the_current_file() {
        let dir = TempDir::new("manual");
        let path = dir.join("audit.jsonl");
        let backend = FileBackend::new(&path).expect("open");

        backend.log_audit(&event(0));
        backend.rotate().expect("rotate");
        backend.log_audit(&event(1));

        assert_eq!(
            lines(&path).len(),
            1,
            "the live file holds only what followed"
        );
        assert_eq!(backend.current_size(), lines(&path)[0].len() as u64 + 1);
    }

    #[test]
    fn test_reopen_recreates_a_file_moved_aside() {
        // The logrotate case: an external tool renames the file, and `reopen`
        // is what makes the process write to the new one.
        let dir = TempDir::new("reopen");
        let path = dir.join("audit.jsonl");
        let moved = dir.join("audit.jsonl.1");
        let backend = FileBackend::new(&path).expect("open");

        backend.log_audit(&event(0));
        std::fs::rename(&path, &moved).expect("external rotation");

        backend.reopen().expect("reopen");
        backend.log_audit(&event(1));

        assert_eq!(lines(&moved).len(), 1, "the archived file keeps its event");
        assert_eq!(
            lines(&path).len(),
            1,
            "the new file receives the next event"
        );
    }

    #[test]
    fn test_write_failures_reach_the_error_sink() {
        // A rotation into a directory that has been made read-only fails at the
        // rename, which is a real OS-reported error rather than a simulated one.
        let dir = TempDir::new("errors");
        let path = dir.join("audit.jsonl");
        let sink = Arc::new(CountingErrorSink::new());
        let backend = FileBackend::builder(&path)
            .rotation(RotationPolicy::size(1))
            .errors(sink.clone())
            .build()
            .expect("open");

        // The first write rotates (size limit 1), which needs to rename inside
        // the directory. Make that impossible.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dir.0).expect("stat").permissions();
            perms.set_mode(0o500); // r-x: no creation or rename
            std::fs::set_permissions(&dir.0, perms).expect("chmod");
        }

        backend.log_audit(&event(0));
        backend.log_audit(&event(1));

        // Restore permissions so the scratch directory can be cleaned up.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dir.0).expect("stat").permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&dir.0, perms).expect("chmod");
        }

        #[cfg(unix)]
        {
            assert!(
                sink.had_failures(),
                "a failed write is reported rather than silently dropped"
            );
            assert!(sink.events_lost() >= 1, "lost events are counted");
        }
    }

    #[test]
    fn test_a_deleted_file_does_not_look_like_a_write_failure() {
        // Documents the Unix behaviour above so it is not mistaken for a bug:
        // writes to an unlinked handle succeed silently. `reopen` is the fix,
        // which is exactly why external rotators need SIGHUP wired to it.
        let dir = TempDir::new("unlinked");
        let path = dir.join("audit.jsonl");
        let sink = Arc::new(CountingErrorSink::new());
        let backend = FileBackend::builder(&path)
            .errors(sink.clone())
            .build()
            .expect("open");

        std::fs::remove_file(&path).expect("unlink");
        backend.log_audit(&event(0));

        assert!(
            !sink.had_failures(),
            "the OS accepts the write, so no error is reported"
        );
        assert!(!path.exists(), "but the event is not in the log");

        backend.reopen().expect("reopen recreates the path");
        backend.log_audit(&event(1));
        assert_eq!(lines(&path).len(), 1, "events land again after reopen");
    }

    #[test]
    fn test_concurrent_writers_produce_intact_lines() {
        // Interleaved partial writes would corrupt the log irrecoverably, so
        // every line must arrive whole.
        let dir = TempDir::new("concurrent");
        let path = dir.join("audit.jsonl");
        let backend = Arc::new(FileBackend::new(&path).expect("open"));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let backend = backend.clone();
            handles.push(std::thread::spawn(move || {
                for n in 0..25 {
                    backend.log_audit(&event(n));
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker panicked");
        }
        backend.flush();

        let written = lines(&path);
        assert_eq!(written.len(), 200);
        for line in &written {
            serde_json::from_str::<AuditEvent>(line).expect("no interleaved line");
        }
    }

    #[test]
    fn test_rotation_policy_predicates() {
        let now = SystemTime::now();
        assert!(!RotationPolicy::never().should_rotate(u64::MAX, now));
        assert!(RotationPolicy::size(100).should_rotate(100, now));
        assert!(!RotationPolicy::size(100).should_rotate(99, now));

        let old = now - Duration::from_secs(120);
        assert!(RotationPolicy::age(Duration::from_secs(60)).should_rotate(0, old));
        assert!(!RotationPolicy::age(Duration::from_secs(600)).should_rotate(0, old));
    }
}
