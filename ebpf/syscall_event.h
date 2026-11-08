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
 */

#define SYSCALL_EVENT_MAGIC 0x5343594cU /* "SYCL" as a native u32 */
#define SYSCALL_EVENT_VERSION 2
#define SYSCALL_COMM_LEN 16
#define SYSCALL_PATH_LEN 256

enum syscall_event_type {
    SYSCALL_EVENT_PROCESS_EXEC = 1,
    SYSCALL_EVENT_PROCESS_FORK = 2,
    SYSCALL_EVENT_PROCESS_EXIT = 3,
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

#endif /* SYSCALL_EVENT_H */
