//! A writer of report lines that never holds up the code that reports (`run --explain`).
//!
//! A thread of its own writes the lines from a queue of `QUEUED_LINES`, each with one write, so
//! that a line stays whole next to other output on the same stream. A line that finds the queue
//! full is dropped, and the next write says how many were: a standard error that nobody reads
//! fills its pipe and then blocks every write, and the code that reports must keep going.
//! `finish` lets the writer write what is queued, for at most `FINAL_WRITE`.
//!
//! It lives here because both its users depend on this crate: the egress broker and the Linux
//! backend's path report.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

/// The most lines that wait for the writer.
pub const QUEUED_LINES: usize = 256;

/// How long `finish` waits for the writer to write what is queued.
pub const FINAL_WRITE: Duration = Duration::from_secs(1);

/// The stack of the writer thread, which keeps nothing large on it.
const STACK: usize = 256 * 1024;

pub struct Lines {
    /// The queue to the writer, until `finish` closes it.
    queue: Mutex<Option<SyncSender<String>>>,
    dropped: Arc<AtomicUsize>,
    written: Mutex<Option<Receiver<()>>>,
}

impl std::fmt::Debug for Lines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lines").finish_non_exhaustive()
    }
}

impl Lines {
    /// Starts the writer on `out`, standard error for every caller. The caller starts each line
    /// with `prefix`; the note of dropped lines starts with it too and names them as `what`
    /// lines. When no thread can start, one line on standard error says so, and every line is
    /// dropped.
    pub fn start(
        mut out: impl Write + Send + 'static,
        prefix: &'static str,
        what: &'static str,
    ) -> Lines {
        let (queue, lines) = mpsc::sync_channel::<String>(QUEUED_LINES);
        let (done, written) = mpsc::channel();
        let dropped = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&dropped);
        let started = thread::Builder::new()
            .name("report".into())
            .stack_size(STACK)
            .spawn(move || {
                let note_dropped = |out: &mut dyn Write| {
                    let lost = counted.swap(0, Ordering::AcqRel);
                    if lost > 0 {
                        let note = format!(
                            "{prefix}{lost} {what} lines dropped: standard error took no more \
                             for a while\n"
                        );
                        let _ = out.write_all(note.as_bytes());
                    }
                };
                for line in lines {
                    let _ = out.write_all(line.as_bytes());
                    note_dropped(&mut out);
                }
                // A send that found the queue full counts its line a moment later, by when the
                // writer may have written every queued line.
                note_dropped(&mut out);
                let _ = done.send(());
            });
        let (queue, written) = match started {
            Ok(_) => (Some(queue), Some(written)),
            Err(error) => {
                let line = format!("{prefix}the {what} report cannot start: {error}\n");
                let _ = std::io::stderr().write_all(line.as_bytes());
                (None, None)
            }
        };
        Lines {
            queue: Mutex::new(queue),
            dropped,
            written: Mutex::new(written),
        }
    }

    /// Queues `line`, which ends with its newline, or counts it as dropped when the queue is
    /// full. Never waits for the writer.
    pub fn send(&self, line: String) {
        let queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(queue) = queue.as_ref()
            && let Err(TrySendError::Full(_)) = queue.try_send(line)
        {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// How many lines were dropped and not reported yet.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Acquire)
    }

    /// Ends the report: the writer writes what is queued, for at most `FINAL_WRITE`, so that a
    /// standard error that nobody reads keeps no process from ending. Later lines are dropped.
    pub fn finish(&self) {
        drop(
            self.queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let written = self
            .written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(written) = written {
            let _ = written.recv_timeout(FINAL_WRITE);
        }
    }
}

impl Drop for Lines {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct Collected(Arc<Mutex<Vec<u8>>>);

    impl Write for Collected {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Every queued line arrives once `finish` returns, each whole.
    #[test]
    fn finish_writes_what_is_queued() {
        let out = Collected::default();
        let lines = Lines::start(out.clone(), "p: ", "test");
        for n in 0..10 {
            lines.send(format!("p: line {n}\n"));
        }
        lines.finish();
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 10, "{text}");
    }

    /// A stream that takes nothing holds up neither `send` nor `finish` beyond `FINAL_WRITE`.
    #[test]
    fn a_stalled_stream_holds_up_neither_send_nor_finish() {
        struct Stalled(Mutex<mpsc::Receiver<()>>);
        impl Write for Stalled {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.0.lock().unwrap().recv();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release, stalled) = mpsc::channel::<()>();
        let lines = Lines::start(Stalled(Mutex::new(stalled)), "p: ", "test");
        let started = Instant::now();
        for n in 0..QUEUED_LINES * 4 {
            lines.send(format!("p: line {n}\n"));
        }
        // A send that waited for the writer would never return; the bound leaves room for a
        // slow host.
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(lines.dropped() > 0);
        let ending = Instant::now();
        lines.finish();
        assert!(ending.elapsed() < FINAL_WRITE + Duration::from_secs(1));
        drop(release);
    }
}
