//! Bounded, batched SQLite writer thread.
//!
//! The ring-buffer callback never blocks on disk I/O. It hands events to a
//! bounded channel; this thread owns a separate SQLite connection and commits
//! batches in transactions.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use syscall_core::Event;
use syscall_storage::{Storage, StorageError};

const BATCH_SIZE: usize = 256;
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Default, Clone, Copy)]
pub struct WriterStats {
    pub persisted: u64,
}

/// Writer completion. The stats remain available when a later batch fails, so
/// the collector can report what was committed instead of discarding it.
#[derive(Debug)]
pub struct WriterOutcome {
    pub stats: WriterStats,
    pub error: Option<StorageError>,
}

pub fn spawn(
    database_path: PathBuf,
    session_id: String,
    receiver: Receiver<Event>,
) -> JoinHandle<WriterOutcome> {
    thread::Builder::new()
        .name("syscall-writer".to_owned())
        .spawn(move || run(&database_path, &session_id, receiver))
        .expect("failed to spawn writer thread")
}

fn run(database_path: &PathBuf, session_id: &str, receiver: Receiver<Event>) -> WriterOutcome {
    let mut stats = WriterStats::default();
    let mut storage = match Storage::open(database_path) {
        Ok(storage) => storage,
        Err(error) => {
            return WriterOutcome {
                stats,
                error: Some(error),
            }
        }
    };
    let mut batch = Vec::with_capacity(BATCH_SIZE);

    loop {
        match receiver.recv_timeout(FLUSH_INTERVAL) {
            Ok(event) => {
                batch.push(event);
                if batch.len() >= BATCH_SIZE {
                    match flush(&mut storage, session_id, &mut batch) {
                        Ok(inserted) => stats.persisted += inserted as u64,
                        Err(error) => {
                            return WriterOutcome {
                                stats,
                                error: Some(error),
                            }
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    match flush(&mut storage, session_id, &mut batch) {
                        Ok(inserted) => stats.persisted += inserted as u64,
                        Err(error) => {
                            return WriterOutcome {
                                stats,
                                error: Some(error),
                            }
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                if !batch.is_empty() {
                    match flush(&mut storage, session_id, &mut batch) {
                        Ok(inserted) => stats.persisted += inserted as u64,
                        Err(error) => {
                            return WriterOutcome {
                                stats,
                                error: Some(error),
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    WriterOutcome { stats, error: None }
}

fn flush(
    storage: &mut Storage,
    session_id: &str,
    batch: &mut Vec<Event>,
) -> Result<usize, StorageError> {
    let inserted = storage.insert_events(session_id, batch)?;
    batch.clear();
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;
    use syscall_core::{EventPayload, EventType, ProcessMetadata, SCHEMA_VERSION};

    fn event(session: &str, pid: i32, timestamp: i64) -> Event {
        Event {
            id: None,
            session_id: session.to_owned(),
            schema_version: SCHEMA_VERSION,
            event_type: EventType::ProcessExec,
            timestamp_ns: timestamp,
            monotonic_ns: timestamp as u64,
            pid,
            tid: pid,
            uid: 1000,
            gid: 1000,
            ppid: Some(1),
            comm: "test".to_owned(),
            process_instance_id: format!("boot:{pid}:1"),
            payload: EventPayload::ProcessExec {
                filename: "/bin/test".to_owned(),
                process: ProcessMetadata {
                    ppid: Some(1),
                    start_time_ticks: Some(1),
                },
                old_pid: Some(1),
            },
            provenance: None,
        }
    }

    #[test]
    fn writer_persists_until_disconnect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writer.db");
        {
            let storage = Storage::open(&path).unwrap();
            storage
                .create_session(&syscall_storage::NewSession {
                    id: "s-writer".to_owned(),
                    schema_version: SCHEMA_VERSION,
                    started_at_ns: 1,
                    command: "/bin/test".to_owned(),
                    arguments: vec![],
                    recording_scope: syscall_core::RecordingScope::TargetTree,
                    boot_id: Some("boot".to_owned()),
                    kernel_release: Some("test".to_owned()),
                    collector_version: Some("test".to_owned()),
                })
                .unwrap();
        }

        let (tx, rx) = sync_channel(16);
        let handle = spawn(path.clone(), "s-writer".to_owned(), rx);
        tx.send(event("s-writer", 10, 1)).unwrap();
        tx.send(event("s-writer", 11, 2)).unwrap();
        drop(tx);

        let outcome = handle.join().unwrap();
        assert!(outcome.error.is_none());
        assert_eq!(outcome.stats.persisted, 2);

        let storage = Storage::open_read_only(&path).unwrap();
        assert_eq!(storage.count_events("s-writer").unwrap(), 2);
    }
}
