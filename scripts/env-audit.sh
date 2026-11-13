#!/usr/bin/env bash
# Read-only environment audit. This script never invokes sudo, never loads BPF,
# and never writes outside /tmp. Statuses are deliberately conservative:
# anything that cannot be proven as an unprivileged user is BLOCKED, not PASS.

set -u

status() {
    local label="$1"
    local value="$2"
    printf '%-52s %s\n' "$label" "$value"
}

section() {
    printf '\n== %s ==\n' "$1"
}

section "Platform"
status "Date (UTC)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
status "Kernel" "$(uname -srmo 2>/dev/null || uname -a)"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    status "Distribution" "${PRETTY_NAME:-unknown}"
else
    status "Distribution" "unknown"
fi
if grep -qi microsoft /proc/version 2>/dev/null; then
    status "WSL2" "PASS (Microsoft kernel detected)"
else
    status "WSL2" "no (native kernel)"
fi

section "Toolchain"
for tool in rustc cargo clang llvm-objdump make pkg-config python3; do
    if command -v "$tool" >/dev/null 2>&1; then
        status "$tool" "PASS ($(command -v "$tool"))"
    else
        status "$tool" "FAIL (not installed)"
    fi
done
if command -v rustc >/dev/null 2>&1; then
    status "rustc version" "$(rustc --version)"
fi
if command -v cargo >/dev/null 2>&1; then
    status "cargo version" "$(cargo --version)"
fi
if command -v clang >/dev/null 2>&1; then
    status "clang version" "$(clang --version | head -n1)"
fi

section "libbpf"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
    status "pkg-config libbpf" "PASS (version $(pkg-config --modversion libbpf))"
else
    status "pkg-config libbpf" "FAIL (libbpf.pc not found)"
fi
if ldconfig -p 2>/dev/null | grep -q 'libbpf\.so'; then
    status "shared libbpf" "PASS"
else
    status "shared libbpf" "FAIL"
fi
if command -v bpftool >/dev/null 2>&1; then
    status "bpftool" "present ($(command -v bpftool))"
else
    status "bpftool" "absent (not required; libbpf-cargo generates skeletons)"
fi

section "Kernel interfaces"
if [ -r /sys/kernel/btf/vmlinux ]; then
    status "BTF /sys/kernel/btf/vmlinux" "PASS (readable)"
else
    status "BTF /sys/kernel/btf/vmlinux" "FAIL (not readable)"
fi

tracefs=""
for candidate in /sys/kernel/tracing /sys/kernel/debug/tracing; do
    if [ -d "$candidate" ]; then
        tracefs="$candidate"
        break
    fi
done
if [ -n "$tracefs" ]; then
    status "tracefs mount" "PASS ($tracefs)"
    status "tracefs permissions" "$(ls -ld "$tracefs" 2>/dev/null)"
    if [ -r "$tracefs/events/sched/sched_process_exec/id" ]; then
        for tp in sched_process_exec sched_process_fork sched_process_exit; do
            if [ -d "$tracefs/events/sched/$tp" ]; then
                status "tracepoint $tp" "PASS (available)"
            else
                status "tracepoint $tp" "FAIL (missing)"
            fi
        done
    else
        for tp in sched_process_exec sched_process_fork sched_process_exit; do
            status "tracepoint $tp" "BLOCKED (tracefs not readable without root)"
        done
    fi
else
    status "tracefs mount" "FAIL (not mounted)"
fi

if [ -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    status "unprivileged_bpf_disabled" "$(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
else
    status "unprivileged_bpf_disabled" "unknown"
fi
if [ -r /proc/sys/kernel/perf_event_paranoid ]; then
    status "perf_event_paranoid" "$(cat /proc/sys/kernel/perf_event_paranoid)"
fi

section "Privilege"
status "Current identity" "$(id)"
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"
status "CapEff" "${cap_eff:-unknown}"
status "BPF load/attach" "BLOCKED (requires root or CAP_BPF+CAP_PERFMON; this script does not use sudo)"
status "sudo" "NOT TESTED (this script never invokes sudo)"

section "Project"
if [ -f Cargo.toml ]; then
    status "workspace manifest" "PASS ($(pwd)/Cargo.toml)"
else
    status "workspace manifest" "FAIL (run from the repository root)"
fi
if [ -f ebpf/syscall.bpf.c ]; then
    status "eBPF source" "PASS (ebpf/syscall.bpf.c)"
else
    status "eBPF source" "FAIL"
fi

printf '\nSummary: unprivileged checks completed. Kernel tracepoint visibility and BPF\n'
printf 'load/attach are BLOCKED until an operator explicitly runs a privileged test.\n'
