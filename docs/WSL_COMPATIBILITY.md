# WSL2 Compatibility Report

Date of audit: **2026-11-08** (UTC).
Host: WSL2 on Windows, Ubuntu 24.04.4 LTS.
Kernel: `6.6.87.2-microsoft-standard-WSL2` (x86_64).

This document records only observed results. Capabilities that could not be
exercised without root are marked **BLOCKED**, never PASS.

## Environment evidence

| Item | Observed value | Status |
| --- | --- | --- |
| WSL detection | `/proc/version` contains Microsoft kernel marker | PASS |
| Distribution | Ubuntu 24.04.4 LTS | PASS |
| Kernel | `6.6.87.2-microsoft-standard-WSL2` | PASS |
| Rust | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` | PASS |
| Cargo | `cargo 1.99.1 (5f94df478 2026-08-27)` | PASS |
| clang | Ubuntu clang 18.1.3 | PASS |
| llvm-objdump | present | PASS |
| BTF | `/sys/kernel/btf/vmlinux` readable | PASS |
| tracefs mount | `/sys/kernel/tracing` exists | PASS |
| tracefs permissions | `drwx------ 6 root root` | FAIL for unprivileged read |
| BTF tracepoint layouts | exec 20, fork 48, exit 32 members verified | PASS |
| `unprivileged_bpf_disabled` | `2` | FAIL for unprivileged BPF |
| `perf_event_paranoid` | `2` | INFO |
| `bpftool` | not installed | INFO; not required |
| system libbpf (pkg-config) | 1.3.0 | PASS |
| `libbpf-sys` crate | 1.7.0+v1.7.0 | PASS |
| sudo | requires an interactive password | BLOCKED for automated runs |

Raw audit command:

```bash
./scripts/env-audit.sh
```

Representative output:

```
== Kernel interfaces ==
BTF /sys/kernel/btf/vmlinux                  PASS (readable)
tracefs mount                                PASS (/sys/kernel/tracing)
tracefs permissions                          drwx------ 6 root root 0 Nov  8 19:17 /sys/kernel/tracing
tracepoint sched_process_exec                BLOCKED (tracefs not readable without root)
tracepoint sched_process_fork                BLOCKED (tracefs not readable without root)
tracepoint sched_process_exit                BLOCKED (tracefs not readable without root)
unprivileged_bpf_disabled                    2
perf_event_paranoid                          2

== Privilege ==
Current identity                             uid=1000(dustin) ...
CapEff                                       0000000000000000
BPF load/attach                              BLOCKED (requires root or CAP_BPF+CAP_PERFMON; this script does not use sudo)
sudo                                         NOT TESTED (this script never invokes sudo)
```

## Capability matrix

| Capability | Status | Evidence |
| --- | --- | --- |
| Workspace build | PASS | `cargo check --workspace --all-targets` |
| Formatting | PASS | `cargo fmt --all --check` |
| Lints | PASS | `cargo clippy --workspace --all-targets -- -D warnings` |
| Unit/integration tests | PASS | `cargo test --workspace`: 99 passed, 0 failed |
| eBPF object compile | PASS | `make -C ebpf clean check`; three tracepoint sections |
| libbpf skeleton generation | PASS | `libbpf-cargo` produced `syscall.skel.rs` |
| Tracepoint ABI vs BTF | PASS | `scripts/check-btf-layout.sh` |
| `syscall info` as user | PASS | Reports WSL, BTF, root-only tracefs, missing capability |
| Unprivileged `record` refusal | PASS | Exit 1: `insufficient privileges: BPF loading requires effective UID 0 or CAP_BPF+CAP_PERFMON` |
| SQLite sessions/event queries | PASS | Storage integration tests; seeded fixture inspection |
| CLI text/JSON output | PASS | `sessions`, `inspect`, `events`, `--json` |
| BPF program load | **BLOCKED** | Requires root/capabilities; not run by agent |
| Tracepoint attach | **BLOCKED** | Same |
| Ring-buffer kernel events | **BLOCKED** | Same |
| Real exec/fork/exit capture | **BLOCKED** | Same |
| Ctrl+C against real capture | **BLOCKED** | Same |
| User-owned DB after sudo | **BLOCKED** | Requires the privileged run |
| WSL2 end-to-end verdict | **BLOCKED** | One privileged operator run remains |

## Why blocking is the correct result

The host sets `unprivileged_bpf_disabled=2`, which permanently disables
unprivileged BPF loading. The current user has an empty `CapEff`, and tracefs is
readable only by root. Under these conditions an unprivileged load **must** fail.
Reporting a PASS would require either fabricating output or silently changing
kernel hardening settings, both of which are unacceptable.

The userspace path has been exercised against a SQLite fixture to validate
queries and rendering, but that fixture is not kernel telemetry and is not
presented as such.

## Exact command to complete the proof

Build first:

```bash
cargo build -p syscall-cli
```

Then, as the operator, run:

```bash
sudo scripts/e2e-root.sh
```

The script is intentionally not run automatically. It:

1. Refuses to run unless invoked through sudo for a non-root user.
2. Checks root capability and visibility of all three tracepoints.
3. Records `/bin/sh -c '/bin/sleep 0.2 & /bin/true; wait'`.
4. Inspects the session as the invoking user and requires exec, fork, and exit
   events.
5. Starts `/bin/sleep 30`, sends Ctrl+C (SIGINT), and requires exit status 130
   plus `interrupted` status.
6. Requires the database to be owned by the invoking user with mode `600`.

Promotion criteria:

- All three tracepoints report `available` under root.
- The normal session is `completed` and contains all three event types.
- The interrupt session is `interrupted` and the target is terminated.
- Database owner equals `SUDO_UID` and mode is `600`.
- No fake or borrowed output is used.

After the run, preserve the command output and replace the BLOCKED rows above
with the observed PASS/FAIL result, including any exact libbpf error if load
fails.

## WSL2-specific notes

- WSL2 exposes a real Linux kernel and real tracepoints; this is not an emulated
  eBPF environment. The blocker is privilege and tracefs access, not missing
  kernel features.
- `unprivileged_bpf_disabled=2` is a host hardening setting, not a SYSCALL
  defect. Operators who cannot use sudo must grant `CAP_BPF` + `CAP_PERFMON` to
  the binary or run in a differently provisioned environment.
- Do not weaken `unprivileged_bpf_disabled` or tracefs permissions merely to make
  a test pass.
- If the privileged run loads but attach fails, record the exact
  `CollectorError::Attach` message. BTF layout checks already rule out the three
  context-struct sizes on this kernel.
- Ring-buffer support is present by kernel version (`>= 5.8`), but this is a
  version check, not proof of a successful ring-buffer read. That remains
  BLOCKED until the privileged run.
