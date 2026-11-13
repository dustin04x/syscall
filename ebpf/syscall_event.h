/* SPDX-License-Identifier: MIT */
#ifndef SYSCALL_EVENT_H
#define SYSCALL_EVENT_H

/*
 * Wire format shared by the BPF programs and the Rust decoder.
 *
 * These structures are deliberately fixed-size and local-host only. The
 * timestamp is the raw bpf_ktime_get_ns() value; userspace adds a captured
 * realtime/monotonic offset to produce the wall-clock timestamp.
 *
 * Layout notes:
 *   - All fields are naturally aligned and the enclosing structures are
 *     aligned to 8 bytes, matching the Rust decoder's explicit offsets.
 *   - `data_len` counts payload bytes excluding a trailing NUL.
 *   - Tracepoint context structures are verified against the running kernel's
 *     BTF by the development workflow; see docs/DEVELOPMENT.md.
 *
 * Wire v3 adds file-open and network-connect payloads. Process-lifecycle
 * layouts are unchanged from v2 so v1/v2 decoders remain compatible with the
 * first three event types.
 */

#define SYSCALL_EVENT_MAGIC 0x5343594cU /* "SYCL" as a native u32 */
#define SYSCALL_EVENT_VERSION 3
#define SYSCALL_COMM_LEN 16
#define SYSCALL_PATH_LEN 256

enum syscall_event_type {
    SYSCALL_EVENT_PROCESS_EXEC = 1,
    SYSCALL_EVENT_PROCESS_FORK = 2,
    SYSCALL_EVENT_PROCESS_EXIT = 3,
    SYSCALL_EVENT_FILE_OPEN = 4,
    SYSCALL_EVENT_NETWORK_CONNECT = 5,
};

struct syscall_event_hdr {
    __u32 magic;
    __u16 schema_version;
    __u16 event_type;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[SYSCALL_COMM_LEN];
    __u32 data_len;
    /* TGID in the collector/observer PID namespace when known (0 if
     * unavailable). Emitted via bpf_get_ns_current_pid_tgid using the
     * namespace configured by userspace; allows correlation when BPF and
     * userspace observe different PID namespace ID spaces. */
    __u32 ns_tgid;
} __attribute__((aligned(8)));

struct syscall_event_exec {
    struct syscall_event_hdr hdr;
    __s32 old_pid;
    char filename[SYSCALL_PATH_LEN];
} __attribute__((aligned(8)));

struct syscall_event_fork {
    struct syscall_event_hdr hdr;
    __u32 parent_pid;
    __u32 child_pid;
    char parent_comm[SYSCALL_COMM_LEN];
    char child_comm[SYSCALL_COMM_LEN];
} __attribute__((aligned(8)));

struct syscall_event_exit {
    struct syscall_event_hdr hdr;
    __s32 exit_priority;
} __attribute__((aligned(8)));

/*
 * File-open activity, emitted at sys_exit_openat after the matching
 * sys_enter_openat.
 *
 * `result` is the raw kernel return value: a non-negative file descriptor on
 * success, or a negative errno on failure. `path` is the path string supplied
 * to openat(2) exactly as read from userspace. It may be relative and is NOT
 * resolved by the collector: `dirfd` identifies the directory base
 * (AT_FDCWD == -100 for the process cwd), and `path_is_absolute` records
 * whether the path began with '/'. `path_truncated` records that the path was
 * longer than SYSCALL_PATH_LEN and was cut (the stored string is still
 * NUL-terminated). The hook proves an openat attempt and its result, not that
 * the file contents were read.
 */
struct syscall_event_file_open {
    struct syscall_event_hdr hdr;
    __s64 result;
    __s32 dirfd;
    __u32 flags;
    __u8 path_is_absolute;
    __u8 path_truncated;
    __u8 _pad[6];
    char path[SYSCALL_PATH_LEN];
} __attribute__((aligned(8)));

/*
 * Network-connect activity, emitted at sys_exit_connect after the matching
 * sys_enter_connect for AF_INET and AF_INET6 sockaddr values.
 *
 * This hook observes connect(2) attempts for IPv4/IPv6 addresses. It does not
 * observe packet payloads and cannot distinguish TCP from UDP at the syscall
 * tracepoint, so the event is an "IP connect attempt", not proof of an
 * established connection. `source_address`/`source_port` are normally
 * unavailable at this hook (`source_available == 0`). Ports are stored in
 * network byte order; the decoder converts them.
 */
struct syscall_event_network_connect {
    struct syscall_event_hdr hdr;
    __s64 result;
    __u16 family;
    __u16 destination_port;
    __u16 source_port;
    __u8 address_len;
    __u8 source_available;
    __u8 destination_address[16];
    __u8 source_address[16];
} __attribute__((aligned(8)));

#endif /* SYSCALL_EVENT_H */
