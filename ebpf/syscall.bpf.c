// SPDX-License-Identifier: MIT
//
// SYSCALL Mission 01 kernel-side collector.
//
// Only three scheduler tracepoints are observed. They are system-wide, stable
// tracepoint ABIs; userspace performs target-tree attribution. The eBPF side
// stays deliberately small: copy bounded data into a fixed-size event and send
// it through a ring buffer.

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

_Static_assert(sizeof(struct syscall_tp_exec) == 20, "exec tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_fork) == 48, "fork tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_tp_exit) == 32, "exit tracepoint ABI drift");
_Static_assert(sizeof(struct syscall_event_hdr) == 56, "event header layout drift");
_Static_assert(sizeof(struct syscall_event_exec) == 320, "exec event layout drift");
_Static_assert(sizeof(struct syscall_event_fork) == 96, "fork event layout drift");
_Static_assert(sizeof(struct syscall_event_exit) == 64, "exit event layout drift");

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
