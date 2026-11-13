// SPDX-License-Identifier: MIT
//
// SYSCALL kernel-side collector.
//
// Process lifecycle uses three scheduler tracepoints. File-open and network
// connect activity use the syscall entry/exit tracepoints, paired in a bounded
// LRU map keyed by pid/tgid. The eBPF side stays deliberately small: copy
// bounded data into a fixed-size event at syscall exit and send it through a
// ring buffer. It never resolves paths, performs DNS, or inspects payloads.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "syscall_event.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

/* Number of ring-buffer output failures, read by userspace at session end. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_lost_events SEC(".maps");

/* Observer/collector PID namespace, set by userspace before load/attach.
 * When set, handlers emit hdr.ns_tgid as the TGID in this namespace via
 * bpf_get_ns_current_pid_tgid, enabling correlation across PID namespaces. */
struct observer_pidns {
    __u64 dev;
    __u64 ino;
    __u32 configured;
    __u32 _pad;
};

struct observer_ns_stats {
    __u64 configured_calls;
    __u64 resolved;
    __u64 helper_error;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct observer_pidns);
} observer_pidns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct observer_ns_stats);
} observer_ns_stats SEC(".maps");

/*
 * Tracepoint context layouts, verified against this kernel's BTF:
 *   trace_event_raw_sched_process_exec   size 20
 *   trace_event_raw_sched_process_fork   size 48
 *   trace_event_raw_sched_process_template (exit) size 32
 */
struct syscall_tp_common {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

struct syscall_tp_exec {
    struct syscall_tp_common common;
    __u32 data_loc_filename;
    __s32 pid;
    __s32 old_pid;
};

struct syscall_tp_fork {
    struct syscall_tp_common common;
    char parent_comm[SYSCALL_COMM_LEN];
    __s32 parent_pid;
    char child_comm[SYSCALL_COMM_LEN];
    __s32 child_pid;
};

struct syscall_tp_exit {
    struct syscall_tp_common common;
    char comm[SYSCALL_COMM_LEN];
    __s32 pid;
    __s32 prio;
};

/* Generic raw syscall tracepoint contexts (x86_64/arm64 long == 8 bytes). */
struct syscall_tp_sys_enter {
    struct syscall_tp_common common;
    long id;
    unsigned long args[6];
};

struct syscall_tp_sys_exit {
    struct syscall_tp_common common;
    long id;
    long ret;
};

_Static_assert(sizeof(struct syscall_tp_exec) == 20, "exec tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_fork) == 48, "fork tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_exit) == 32, "exit tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_sys_enter) == 64, "sys_enter tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_sys_exit) == 24, "sys_exit tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_event_hdr) == 56, "event header layout drift");
_Static_assert(sizeof(struct syscall_event_exec) == 320, "exec event layout drift");
_Static_assert(sizeof(struct syscall_event_fork) == 96, "fork event layout drift");
_Static_assert(sizeof(struct syscall_event_exit) == 64, "exit event layout drift");
_Static_assert(sizeof(struct syscall_event_file_open) == 336, "file-open event layout drift");
_Static_assert(sizeof(struct syscall_event_network_connect) == 104,
               "network-connect event layout drift");

static __always_inline void count_lost_event(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ringbuf_lost_events, &key);

    /* Atomic add is safe for a shared ARRAY value. */
    if (value)
        __sync_fetch_and_add(value, 1);
}

struct bpf_pidns_info_local {
    __u32 pid;
    __u32 tgid;
};

static __always_inline __u32 current_ns_tgid(void)
{
    __u32 key = 0;
    struct observer_pidns *ns = bpf_map_lookup_elem(&observer_pidns, &key);
    struct observer_ns_stats *stats = bpf_map_lookup_elem(&observer_ns_stats, &key);
    struct bpf_pidns_info_local nsdata = {};

    if (!ns || !ns->configured)
        return 0;
    if (stats)
        __sync_fetch_and_add(&stats->configured_calls, 1);
    if (bpf_get_ns_current_pid_tgid(ns->dev, ns->ino, (void *)&nsdata, sizeof(nsdata))) {
        if (stats)
            __sync_fetch_and_add(&stats->helper_error, 1);
        return 0;
    }
    if (stats)
        __sync_fetch_and_add(&stats->resolved, 1);
    return nsdata.tgid;
}

static __always_inline void fill_header(struct syscall_event_hdr *hdr,
                                        __u16 event_type,
                                        __u64 timestamp_ns,
                                        __u32 pid,
                                        __u32 tgid)
{
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->magic = SYSCALL_EVENT_MAGIC;
    hdr->schema_version = SYSCALL_EVENT_VERSION;
    hdr->event_type = event_type;
    hdr->timestamp_ns = timestamp_ns;
    hdr->pid = pid;
    hdr->tgid = tgid;
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->data_len = 0;
    hdr->ns_tgid = current_ns_tgid();
    bpf_get_current_comm(hdr->comm, sizeof(hdr->comm));
}

static __always_inline void copy_comm(char dst[SYSCALL_COMM_LEN],
                                      const char src[SYSCALL_COMM_LEN])
{
    __builtin_memcpy(dst, src, SYSCALL_COMM_LEN - 1);
    dst[SYSCALL_COMM_LEN - 1] = '\0';
}

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct syscall_tp_exec *ctx)
{
    struct syscall_event_exec event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 data_loc = ctx->data_loc_filename;
    __u32 filename_offset = data_loc & 0xffff;
    long copied;

    fill_header(&event.hdr, SYSCALL_EVENT_PROCESS_EXEC,
                bpf_ktime_get_ns(), pid, tgid);

    event.old_pid = ctx->old_pid;

    /*
     * The tracepoint stores the filename as a __data_loc string: the low 16
     * bits are the byte offset from the start of the tracepoint context.
     * bpf_probe_read_kernel_str is bounded by sizeof(event.filename) and
     * always NUL-terminates on success.
     */
    copied = bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
                                       (void *)ctx + filename_offset);
    if (copied > 0)
        event.hdr.data_len = (__u32)(copied - 1);
    else
        event.hdr.data_len = 0;

    if (bpf_ringbuf_output(&events, &event, sizeof(event), 0) < 0)
        count_lost_event();

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct syscall_tp_fork *ctx)
{
    struct syscall_event_fork event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = (__u32)pid_tgid;

    /*
     * The tracepoint gives task PIDs, not TGIDs. For an ordinary fork the
     * child is a process leader and child_pid == child_tgid. Userspace
     * verifies this through /proc and drops thread-creation events.
     */
    fill_header(&event.hdr, SYSCALL_EVENT_PROCESS_FORK,
                bpf_ktime_get_ns(), (__u32)ctx->child_pid,
                (__u32)ctx->child_pid);
    /* fill_header() set ns_tgid from the current (parent) task; for fork the
     * subject is the child and its observer-ns TGID is not available from the
     * tracepoint context without a task pointer. Leave ns_tgid unset so
     * userspace does not misattribute the child. */
    event.hdr.ns_tgid = 0;

    event.parent_pid = (__u32)ctx->parent_pid;
    event.child_pid = (__u32)ctx->child_pid;

    copy_comm(event.parent_comm, ctx->parent_comm);
    copy_comm(event.child_comm, ctx->child_comm);
    copy_comm(event.hdr.comm, ctx->child_comm);

    if (bpf_ringbuf_output(&events, &event, sizeof(event), 0) < 0)
        count_lost_event();

    (void)parent_pid;
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct syscall_tp_exit *ctx)
{
    struct syscall_event_exit event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);

    fill_header(&event.hdr, SYSCALL_EVENT_PROCESS_EXIT,
                bpf_ktime_get_ns(), pid, tgid);

    copy_comm(event.hdr.comm, ctx->comm);
    event.exit_priority = ctx->prio;

    if (bpf_ringbuf_output(&events, &event, sizeof(event), 0) < 0)
        count_lost_event();

    return 0;
}

/* ------------------------------------------------------------------------- */
/* File-open activity: pair sys_enter_openat with sys_exit_openat.            */
/* ------------------------------------------------------------------------- */

struct syscall_open_args {
    __u32 flags;
    __s32 dirfd;
    __u32 path_len;
    __u8 path_is_absolute;
    __u8 path_truncated;
    __u8 _pad[2];
    char path[SYSCALL_PATH_LEN];
};

/*
 * Bounded LRU to avoid unbounded kernel memory. Entries are keyed by the
 * full pid/tgid so thread-level syscalls pair correctly. If an entry is
 * evicted before sys_exit_openat, no event is emitted (userspace never sees
 * a fabricated path/result); ring-buffer loss counters remain authoritative
 * only for ring-buffer output failures.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct syscall_open_args);
} open_args SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct syscall_tp_sys_enter *ctx)
{
    struct syscall_open_args args = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long copied;

    args.dirfd = (__s32)ctx->args[0];
    args.flags = (__u32)ctx->args[2];

    copied = bpf_probe_read_user_str(args.path, sizeof(args.path),
                                     (void *)ctx->args[1]);
    if (copied > 0) {
        if (copied >= (long)sizeof(args.path)) {
            /*
             * The string was longer than the buffer. Force termination and
             * record explicit truncation; never pretend the captured path is
             * complete.
             */
            args.path[sizeof(args.path) - 1] = '\0';
            args.path_len = sizeof(args.path) - 1;
            args.path_truncated = 1;
        } else {
            args.path_len = (__u32)(copied - 1);
        }
        args.path_is_absolute = args.path[0] == '/' ? 1 : 0;
    } else {
        args.path[0] = '\0';
        args.path_len = 0;
    }

    bpf_map_update_elem(&open_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_sys_exit_openat(struct syscall_tp_sys_exit *ctx)
{
    struct syscall_event_file_open *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);
    struct syscall_open_args *captured;

    captured = bpf_map_lookup_elem(&open_args, &pid_tgid);
    if (!captured)
        return 0;

    /*
     * Build the 336-byte event in a ring-buffer reservation instead of on the
     * stack (BPF stack is limited to 512 bytes). Read the captured arguments
     * directly from the map value; do not copy the 272-byte struct onto the
     * stack.
     */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&open_args, &pid_tgid);
        count_lost_event();
        return 0;
    }

    fill_header(&event->hdr, SYSCALL_EVENT_FILE_OPEN,
                bpf_ktime_get_ns(), pid, tgid);
    event->hdr.data_len = captured->path_len;
    event->result = (__s64)ctx->ret;
    event->dirfd = captured->dirfd;
    event->flags = captured->flags;
    event->path_is_absolute = captured->path_is_absolute;
    event->path_truncated = captured->path_truncated;
    __builtin_memcpy(event->path, captured->path, sizeof(event->path));
    event->path[sizeof(event->path) - 1] = '\0';

    bpf_map_delete_elem(&open_args, &pid_tgid);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Network-connect activity: pair sys_enter_connect with sys_exit_connect.    */
/* ------------------------------------------------------------------------- */

struct sockaddr_in_local {
    __u16 family;
    __u16 port;
    __u32 addr;
};

struct sockaddr_in6_local {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u8 addr[16];
    __u32 scope;
};

struct syscall_connect_args {
    __u16 family;
    __u16 destination_port;
    __u8 address_len;
    __u8 source_available;
    __u8 _pad[2];
    __u8 destination_address[16];
    __u8 source_address[16];
};

/* Bounded LRU for connect(2) attempts; same non-fabrication rule as openat. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct syscall_connect_args);
} connect_args SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct syscall_tp_sys_enter *ctx)
{
    struct syscall_connect_args args = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u16 family = 0;
    void *sockaddr = (void *)ctx->args[1];

    if (bpf_probe_read_user(&family, sizeof(family), sockaddr))
        return 0;

    if (family == 2) {
        struct sockaddr_in_local in = {};
        if (bpf_probe_read_user(&in, sizeof(in), sockaddr))
            return 0;
        args.family = 2;
        args.destination_port = in.port; /* network byte order */
        args.destination_address[0] = (__u8)(in.addr & 0xff);
        args.destination_address[1] = (__u8)((in.addr >> 8) & 0xff);
        args.destination_address[2] = (__u8)((in.addr >> 16) & 0xff);
        args.destination_address[3] = (__u8)((in.addr >> 24) & 0xff);
        args.address_len = 4;
    } else if (family == 10) {
        struct sockaddr_in6_local in6 = {};
        if (bpf_probe_read_user(&in6, sizeof(in6), sockaddr))
            return 0;
        args.family = 10;
        args.destination_port = in6.port; /* network byte order */
        __builtin_memcpy(args.destination_address, in6.addr,
                         sizeof(args.destination_address));
        args.address_len = 16;
    } else {
        /* AF_UNIX/other families are outside Phase 5 network scope. */
        return 0;
    }

    /*
     * Source address/port are not reliably available from the connect(2)
     * tracepoint context (the socket fd, not a sock pointer, is the argument).
     * Mark them explicitly unavailable instead of guessing.
     */
    args.source_available = 0;

    bpf_map_update_elem(&connect_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_sys_exit_connect(struct syscall_tp_sys_exit *ctx)
{
    struct syscall_connect_args args = {};
    struct syscall_event_network_connect event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);
    struct syscall_connect_args *captured;

    captured = bpf_map_lookup_elem(&connect_args, &pid_tgid);
    if (!captured)
        return 0;

    __builtin_memcpy(&args, captured, sizeof(args));
    bpf_map_delete_elem(&connect_args, &pid_tgid);

    fill_header(&event.hdr, SYSCALL_EVENT_NETWORK_CONNECT,
                bpf_ktime_get_ns(), pid, tgid);
    event.result = (__s64)ctx->ret;
    event.family = args.family;
    event.destination_port = args.destination_port;
    event.source_available = args.source_available;
    event.address_len = args.address_len;
    __builtin_memcpy(event.destination_address, args.destination_address,
                     sizeof(event.destination_address));
    __builtin_memcpy(event.source_address, args.source_address,
                     sizeof(event.source_address));

    if (bpf_ringbuf_output(&events, &event, sizeof(event), 0) < 0)
        count_lost_event();

    return 0;
}
