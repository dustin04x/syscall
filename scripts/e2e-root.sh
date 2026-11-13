#!/usr/bin/env bash
# Privileged end-to-end test. The operator must invoke this script explicitly:
#
#   sudo scripts/e2e-root.sh
#
# The script itself never asks for a password. It requires an existing binary:
#
#   cargo build -p syscall-cli
#
# It records a target tree, verifies the persist/inspect path as the invoking
# user, then tests Ctrl+C handling and exit status 130. The database is left in
# the invoking user's data directory for manual inspection.

set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "Refusing to run: invoke explicitly with 'sudo scripts/e2e-root.sh'." >&2
    exit 2
fi
if [ -z "${SUDO_USER:-}" ] || [ -z "${SUDO_UID:-}" ] || [ -z "${SUDO_GID:-}" ]; then
    echo "Run this script through sudo from a normal user account." >&2
    exit 2
fi
if [ "${SUDO_UID}" -eq 0 ]; then
    echo "Refusing to run for the root account; use a normal invoking user." >&2
    exit 2
fi
if ! command -v runuser >/dev/null 2>&1; then
    echo "runuser is required to verify user-owned inspection." >&2
    exit 2
fi
if ! command -v mktemp >/dev/null 2>&1; then
    echo "mktemp is required." >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${SYSCALL_BIN:-$root/target/debug/syscall}"
if [ ! -e "$binary" ]; then
    echo "Binary not found: $binary" >&2
    echo "Build it first with: cargo build -p syscall-cli" >&2
    exit 2
fi
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
if [ ! -x "$binary" ]; then
    echo "Binary is not executable: $binary" >&2
    exit 2
fi

user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
    echo "Could not resolve home directory for $SUDO_USER" >&2
    exit 2
fi
data_dir="$user_home/.local/share/syscall"
if [ ! -d "$data_dir" ]; then
    install -d -m 0700 -o "$SUDO_UID" -g "$SUDO_GID" "$data_dir"
fi
if [ "$(stat -c %u "$data_dir")" != "$SUDO_UID" ]; then
    echo "Refusing to use data directory not owned by $SUDO_USER: $data_dir" >&2
    exit 2
fi

stamp="$(date +%s%N)"
db="$data_dir/e2e-$stamp.db"
normal_session="e2e-normal-$stamp"
interrupt_session="e2e-interrupt-$stamp"
info_tmp="$(mktemp "${TMPDIR:-/tmp}/syscall-e2e-info.XXXXXX")"
record_pid=""

cleanup() {
    local status=$?
    if [ -n "${record_pid:-}" ] && kill -0 "$record_pid" 2>/dev/null; then
        kill -TERM "$record_pid" 2>/dev/null || true
        wait "$record_pid" 2>/dev/null || true
    fi
    rm -f -- "$info_tmp"
    return "$status"
}
trap cleanup EXIT

run_as_user() {
    runuser -u "$SUDO_USER" -- env HOME="$user_home" USER="$SUDO_USER" LOGNAME="$SUDO_USER" "$@"
}

echo "== 0. root capability report =="
"$binary" info --db "$db" | tee "$info_tmp"
grep -q 'Can load eBPF:.*yes' "$info_tmp"
grep -q 'sched_process_exec.*available' "$info_tmp"
grep -q 'sched_process_fork.*available' "$info_tmp"
grep -q 'sched_process_exit.*available' "$info_tmp"
echo "PASS: root can load BPF and all three tracepoints are visible"

echo
echo "== 1. normal target-tree recording =="
"$binary" record \
    --db "$db" \
    --session-id "$normal_session" \
    -- /bin/sh -c '/bin/sleep 0.2 & /bin/true; wait'

normal_output="$(run_as_user "$binary" inspect "$normal_session" --db "$db")"
printf '%s\n' "$normal_output"
grep -q 'Status:.*completed' <<<"$normal_output"
grep -q 'process_exec' <<<"$normal_output"
grep -q 'process_fork' <<<"$normal_output"
grep -q 'process_exit' <<<"$normal_output"
echo "PASS: session is inspectable as $SUDO_USER and contains all lifecycle types"

echo
echo "== 2. Ctrl+C handling =="
"$binary" record \
    --db "$db" \
    --session-id "$interrupt_session" \
    -- /bin/sleep 30 &
record_pid=$!

# The collector installs its signal handlers after privileged BPF setup.
# Poll until the session is recording so SIGINT is handled as an interruption.
ready=0
for _ in $(seq 1 60); do
    if inspect_out="$(run_as_user "$binary" inspect "$interrupt_session" --db "$db" 2>/dev/null)"; then
        if grep -q 'Status:.*recording' <<<"$inspect_out"; then
            ready=1
            break
        fi
        # If it already reached a terminal state, break and report below.
        if grep -Eq 'Status:.*(completed|interrupted|failed)' <<<"$inspect_out"; then
            echo "Recording reached a terminal state before SIGINT was sent:" >&2
            printf '%s\n' "$inspect_out" >&2
            break
        fi
    fi
    if ! kill -0 "$record_pid" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
if [ "$ready" -ne 1 ]; then
    echo "Timed out waiting for interrupt test session to reach recording state." >&2
fi

# Signal the actual recorder process (not a wrapper). The recorder was started
# directly as $binary above, so $record_pid is the intended target.
if ! kill -0 "$record_pid" 2>/dev/null; then
    echo "FAIL: recorder exited before SIGINT could be delivered" >&2
    exit 1
fi
kill -INT "$record_pid"
record_status=0
wait "$record_pid" || record_status=$?
record_pid=""
echo "record exit status: $record_status (expected 130)"
if [ "$record_status" -ne 130 ]; then
    echo "FAIL: interrupted recording did not exit 130" >&2
    # Best-effort diagnostics
    run_as_user "$binary" inspect "$interrupt_session" --db "$db" 2>&1 || true
    exit 1
fi
interrupt_output="$(run_as_user "$binary" inspect "$interrupt_session" --db "$db")"
printf '%s\n' "$interrupt_output"
grep -q 'Status:.*interrupted' <<<"$interrupt_output"
# The long-running target (sleep 30) must not be orphaned.
sleep 1
if pgrep -u "$SUDO_UID" -f "^/bin/sleep 30$" >/dev/null 2>&1; then
    echo "FAIL: interrupted recording left target process running" >&2
    pgrep -au "$SUDO_UID" -f "^/bin/sleep 30$" >&2 || true
    pkill -u "$SUDO_UID" -f "^/bin/sleep 30$" 2>/dev/null || true
    exit 1
fi
echo "PASS: Ctrl+C marked the session interrupted, exited 130, and cleaned up target"

echo
echo "== 3. database ownership and permissions =="
owner="$(stat -c %u "$db")"
mode="$(stat -c %a "$db")"
dir_mode="$(stat -c %a "$data_dir")"
echo "database: $db"
echo "owner uid: $owner (expected $SUDO_UID)"
echo "mode: $mode (expected 600)"
echo "data dir mode: $dir_mode (expected 700)"
if [ "$owner" -ne "$SUDO_UID" ]; then
    echo "FAIL: database is not owned by the invoking user" >&2
    exit 1
fi
if [ "$mode" != "600" ]; then
    echo "FAIL: database mode is not 600" >&2
    exit 1
fi
if [ "$dir_mode" != "700" ]; then
    echo "FAIL: data directory mode is not 700" >&2
    exit 1
fi

echo
echo "E2E PASS"
echo "Inspect manually with:"
echo "  syscall sessions --db '$db'"
echo "  syscall inspect '$normal_session' --db '$db'"
echo "  syscall events '$normal_session' --db '$db'"
