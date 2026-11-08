//! Strict decoder for the BPF ring-buffer wire format.
//!
//! The decoder never trusts lengths or strings from the kernel side. Every
//! field is bounds-checked; malformed samples are counted by the collector and
//! discarded without terminating the session.

use syscall_core::{EventType, COMM_LEN, MAX_FILENAME_LEN};
use thiserror::Error;
use tracing;

pub const EVENT_MAGIC: u32 = 0x5343_594c;
pub const WIRE_SCHEMA_VERSION: u16 = 2;

pub const HEADER_LEN: usize = 56;
const PID_OFFSET: usize = 16;
const TGID_OFFSET: usize = 20;
const UID_OFFSET: usize = 24;
const GID_OFFSET: usize = 28;
const COMM_OFFSET: usize = 32;
const DATA_LEN_OFFSET: usize = 48;
const NS_TGID_OFFSET: usize = 52;

const EXEC_OLD_PID_OFFSET: usize = 56;
const EXEC_FILENAME_OFFSET: usize = 60;
const EXEC_MIN_LEN: usize = EXEC_FILENAME_OFFSET + MAX_FILENAME_LEN;

const FORK_PARENT_PID_OFFSET: usize = 56;
const FORK_CHILD_PID_OFFSET: usize = 60;
const FORK_PARENT_COMM_OFFSET: usize = 64;
const FORK_CHILD_COMM_OFFSET: usize = 80;
const FORK_MIN_LEN: usize = FORK_CHILD_COMM_OFFSET + COMM_LEN;

const EXIT_PRIORITY_OFFSET: usize = 56;
const EXIT_MIN_LEN: usize = EXIT_PRIORITY_OFFSET + 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("event is too short: {actual} bytes, need at least {minimum} for {kind}")]
    TooShort {
        kind: &'static str,
        actual: usize,
        minimum: usize,
    },

    #[error("bad event magic: 0x{0:08x}")]
    BadMagic(u32),

    #[error("unsupported wire schema version {0}")]
    UnsupportedSchemaVersion(u16),

    #[error("unsupported wire event type {0}")]
    UnsupportedEventType(u16),

    #[error("invalid {field} value: {value}")]
    InvalidField { field: &'static str, value: i64 },

    #[error("{field} is not NUL-terminated within the sample")]
    MissingNul { field: &'static str },

    #[error("payload length {length} exceeds the {limit}-byte limit")]
    PayloadTooLong { length: usize, limit: usize },

    #[error("payload extends past the end of the sample")]
    PayloadPastEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload {
    Exec {
        old_pid: i32,
        filename: String,
    },
    Fork {
        parent_pid: i32,
        child_pid: i32,
        parent_comm: String,
        child_comm: String,
    },
    Exit {
        exit_priority: i32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvent {
    pub event_type: EventType,
    pub monotonic_ns: u64,
    pub pid: i32,
    pub tgid: i32,
    /// TGID in the observer/collector PID namespace when provided by BPF
    /// (schema v2+); 0 means unavailable.
    pub ns_tgid: i32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub payload: DecodedPayload,
}

/// Decode one ring-buffer sample. All reads are bounds-checked.
pub fn decode(bytes: &[u8]) -> Result<DecodedEvent, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            kind: "header",
            actual: bytes.len(),
            minimum: HEADER_LEN,
        });
    }

    let magic = u32_at(bytes, 0);
    if magic != EVENT_MAGIC {
        return Err(DecodeError::BadMagic(magic));
    }
    let schema_version = u16_at(bytes, 4);
    if schema_version != 1 && schema_version != WIRE_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedSchemaVersion(schema_version));
    }
    let event_type = EventType::from_wire_id(u16_at(bytes, 6))
        .ok_or_else(|| DecodeError::UnsupportedEventType(u16_at(bytes, 6)))?;

    let monotonic_ns = u64_at(bytes, 8);
    if monotonic_ns == 0 {
        return Err(DecodeError::InvalidField {
            field: "monotonic_ns",
            value: 0,
        });
    }
    let pid = i32_at(bytes, PID_OFFSET);
    if pid <= 0 {
        return Err(DecodeError::InvalidField {
            field: "pid",
            value: i64::from(pid),
        });
    }
    let tgid = i32_at(bytes, TGID_OFFSET);
    if tgid <= 0 {
        return Err(DecodeError::InvalidField {
            field: "tgid",
            value: i64::from(tgid),
        });
    }
    let uid = u32_at(bytes, UID_OFFSET);
    let gid = u32_at(bytes, GID_OFFSET);
    let comm = decode_comm(&bytes[COMM_OFFSET..COMM_OFFSET + COMM_LEN], "comm")?;
    let data_len = usize::try_from(u32_at(bytes, DATA_LEN_OFFSET)).unwrap_or(usize::MAX);
    let ns_tgid = i32_at(bytes, NS_TGID_OFFSET);

    let payload = match event_type {
        EventType::ProcessExec => {
            if bytes.len() < EXEC_MIN_LEN {
                return Err(DecodeError::TooShort {
                    kind: "process_exec",
                    actual: bytes.len(),
                    minimum: EXEC_MIN_LEN,
                });
            }
            if data_len > MAX_FILENAME_LEN {
                return Err(DecodeError::PayloadTooLong {
                    length: data_len,
                    limit: MAX_FILENAME_LEN,
                });
            }
            let end = EXEC_FILENAME_OFFSET
                .checked_add(data_len)
                .ok_or(DecodeError::PayloadPastEnd)?;
            if end > bytes.len() {
                return Err(DecodeError::PayloadPastEnd);
            }
            // The BPF side sets data_len to strlen (excluding NUL), so the byte
            // at `end` must be the terminator when data_len > 0.
            if data_len > 0 {
                let nul = *bytes.get(end).ok_or(DecodeError::PayloadPastEnd)?;
                if nul != 0 {
                    return Err(DecodeError::MissingNul { field: "filename" });
                }
            }
            let filename = String::from_utf8_lossy(&bytes[EXEC_FILENAME_OFFSET..end]).into_owned();
            DecodedPayload::Exec {
                old_pid: i32_at(bytes, EXEC_OLD_PID_OFFSET),
                filename,
            }
        }
        EventType::ProcessFork => {
            if bytes.len() < FORK_MIN_LEN {
                return Err(DecodeError::TooShort {
                    kind: "process_fork",
                    actual: bytes.len(),
                    minimum: FORK_MIN_LEN,
                });
            }
            DecodedPayload::Fork {
                parent_pid: i32_at(bytes, FORK_PARENT_PID_OFFSET),
                child_pid: i32_at(bytes, FORK_CHILD_PID_OFFSET),
                parent_comm: decode_comm(
                    &bytes[FORK_PARENT_COMM_OFFSET..FORK_PARENT_COMM_OFFSET + COMM_LEN],
                    "parent_comm",
                )?,
                child_comm: decode_comm(
                    &bytes[FORK_CHILD_COMM_OFFSET..FORK_CHILD_COMM_OFFSET + COMM_LEN],
                    "child_comm",
                )?,
            }
        }
        EventType::ProcessExit => {
            if bytes.len() < EXIT_MIN_LEN {
                return Err(DecodeError::TooShort {
                    kind: "process_exit",
                    actual: bytes.len(),
                    minimum: EXIT_MIN_LEN,
                });
            }
            DecodedPayload::Exit {
                exit_priority: i32_at(bytes, EXIT_PRIORITY_OFFSET),
            }
        }
        EventType::FileOpen | EventType::NetworkConnect => {
            return Err(DecodeError::UnsupportedEventType(event_type.wire_id()));
        }
    };

    tracing::debug!(
        phase = "decode",
        wire_schema_version = schema_version,
        event_type = ?event_type,
        hdr_pid = pid,
        hdr_tgid = tgid,
        hdr_ns_tgid = ns_tgid,
        ns_tgid_offset = NS_TGID_OFFSET,
        header_len = HEADER_LEN,
        "decoded ring-buffer event"
    );
    Ok(DecodedEvent {
        event_type,
        monotonic_ns,
        pid,
        tgid,
        ns_tgid,
        uid,
        gid,
        comm,
        payload,
    })
}

fn decode_comm(bytes: &[u8], field: &'static str) -> Result<String, DecodeError> {
    debug_assert_eq!(bytes.len(), COMM_LEN);
    match bytes.iter().position(|byte| *byte == 0) {
        Some(end) => Ok(String::from_utf8_lossy(&bytes[..end]).into_owned()),
        None => Err(DecodeError::MissingNul { field }),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    let array: [u8; 2] = bytes[offset..offset + 2]
        .try_into()
        .expect("bounds checked by caller");
    u16::from_ne_bytes(array)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let array: [u8; 4] = bytes[offset..offset + 4]
        .try_into()
        .expect("bounds checked by caller");
    u32::from_ne_bytes(array)
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    let array: [u8; 4] = bytes[offset..offset + 4]
        .try_into()
        .expect("bounds checked by caller");
    i32::from_ne_bytes(array)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let array: [u8; 8] = bytes[offset..offset + 8]
        .try_into()
        .expect("bounds checked by caller");
    u64::from_ne_bytes(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }
    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    fn put_comm(bytes: &mut [u8], offset: usize, value: &str) {
        let raw = value.as_bytes();
        bytes[offset..offset + raw.len()].copy_from_slice(raw);
        bytes[offset + raw.len()] = 0;
    }

    fn header(bytes: &mut [u8], event_type: u16) {
        put_u32(bytes, 0, EVENT_MAGIC);
        put_u16(bytes, 4, WIRE_SCHEMA_VERSION);
        put_u16(bytes, 6, event_type);
        put_u64(bytes, 8, 123_456);
        put_i32(bytes, PID_OFFSET, 42);
        put_i32(bytes, TGID_OFFSET, 42);
        put_u32(bytes, UID_OFFSET, 1000);
        put_u32(bytes, GID_OFFSET, 1000);
        put_comm(bytes, COMM_OFFSET, "sleep");
    }

    #[test]
    fn decodes_exec() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 1);
        put_i32(&mut bytes, EXEC_OLD_PID_OFFSET, 41);
        let filename = b"/usr/bin/sleep";
        bytes[EXEC_FILENAME_OFFSET..EXEC_FILENAME_OFFSET + filename.len()]
            .copy_from_slice(filename);
        put_u32(&mut bytes, DATA_LEN_OFFSET, filename.len() as u32);

        let event = decode(&bytes).unwrap();
        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(
            event.payload,
            DecodedPayload::Exec {
                old_pid: 41,
                filename: "/usr/bin/sleep".to_owned()
            }
        );
    }

    #[test]
    fn decodes_fork() {
        let mut bytes = vec![0u8; 96];
        header(&mut bytes, 2);
        put_i32(&mut bytes, FORK_PARENT_PID_OFFSET, 100);
        put_i32(&mut bytes, FORK_CHILD_PID_OFFSET, 101);
        put_comm(&mut bytes, FORK_PARENT_COMM_OFFSET, "parent");
        put_comm(&mut bytes, FORK_CHILD_COMM_OFFSET, "child");
        let event = decode(&bytes).unwrap();
        assert_eq!(
            event.payload,
            DecodedPayload::Fork {
                parent_pid: 100,
                child_pid: 101,
                parent_comm: "parent".to_owned(),
                child_comm: "child".to_owned()
            }
        );
    }

    #[test]
    fn decodes_exit() {
        let mut bytes = vec![0u8; 64];
        header(&mut bytes, 3);
        put_i32(&mut bytes, EXIT_PRIORITY_OFFSET, 120);
        let event = decode(&bytes).unwrap();
        assert_eq!(event.payload, DecodedPayload::Exit { exit_priority: 120 });
    }

    #[test]
    fn rejects_short_sample() {
        assert!(matches!(
            decode(&[0u8; 10]),
            Err(DecodeError::TooShort { .. })
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 1);
        put_u32(&mut bytes, 0, 0);
        assert!(matches!(decode(&bytes), Err(DecodeError::BadMagic(0))));
    }

    #[test]
    fn rejects_unknown_schema() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 1);
        put_u16(&mut bytes, 4, 99);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::UnsupportedSchemaVersion(99))
        ));
    }

    #[test]
    fn rejects_unknown_event_type() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 99);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::UnsupportedEventType(99))
        ));
    }

    #[test]
    fn rejects_oversized_filename_length() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 1);
        put_u32(&mut bytes, DATA_LEN_OFFSET, (MAX_FILENAME_LEN + 1) as u32);
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::PayloadTooLong { .. })
        ));
    }

    #[test]
    fn rejects_unterminated_comm() {
        let mut bytes = vec![0u8; 320];
        header(&mut bytes, 1);
        bytes[COMM_OFFSET..COMM_OFFSET + COMM_LEN].fill(b'x');
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::MissingNul { .. })
        ));
    }
}
