# WSL2 Compatibility Report

Date of audit: **2026-11-10** (UTC).
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
| sudo | authenticated operator session used for validation | PASS (not automated; `check.sh` never invokes sudo) |

Unprivileged audit command (before the operator run):

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
| Unit/integration tests | PASS | `cargo test --workspace`: 180 passed, 0 failed |
| eBPF object compile | PASS | `make -C ebpf clean check`; seven tracepoint sections (3 scheduler + 4 syscall) |
| Syscall tracepoints present | PASS (runtime confirmed) | All four syscall sections attached and captured activity in the privileged run |
| Live file-open capture | **PASS** | Operator run 2026-11-10: 64 `file_open` rows, including `/etc/hostname` success |
| Live IPv4/IPv6 connect capture | **PASS** | IPv4 `127.0.0.1:1` and IPv6 `::1:1`, both result `-111` (ECONNREFUSED) |
| libbpf skeleton generation | PASS | `libbpf-cargo` produced `syscall.skel.rs` |
| Tracepoint ABI vs BTF | PASS | `scripts/check-btf-layout.sh` |
| `syscall info` as user | PASS | Reports WSL, BTF, root-only tracefs, missing capability |
| Unprivileged `record` refusal | PASS | Exit 1: `insufficient privileges: BPF loading requires effective UID 0 or CAP_BPF+CAP_PERFMON` |
| SQLite sessions/event queries | PASS | Storage integration tests; seeded fixture inspection |
| CLI text/JSON output | PASS | `sessions`, `inspect`, `events`, `--json` |
| BPF program load | **PASS** | Privileged lifecycle and Phase 5 runs loaded the skeleton |
| Tracepoint attach | **PASS** | All seven programs attached and produced events |
| Ring-buffer kernel events | **PASS** | Events decoded and persisted; `ringbuf_lost=0` in validated sessions |
| Real exec/fork/exit capture | **PASS** | Lifecycle e2e completed with exec/fork/exit rows |
| Ctrl+C against real capture | **PASS** | Exit `130`, session `interrupted`, target terminated |
| User-owned DB after sudo | **PASS** | Database uid `1000`, mode `600`; data directory mode `700` |
| WSL2 end-to-end verdict | **PASS** | `scripts/e2e-root.sh`: `E2E PASS` |
| Phase 5 activity e2e | **PASS** | Two sessions: 72 events (IPv4) and 315 events (IPv4+IPv6); both `valid`, 0 findings |

## Privileged validation results

Validated on 2026-11-10 with an operator-authenticated sudo session. The
unprivileged audit above still reports BLOCKED and remains the correct result
without privilege; it is not evidence of kernel failure.

- `sudo scripts/e2e-root.sh`: **E2E PASS**. All seven tracepoints attached; the
  normal lifecycle session completed and was inspectable as the invoking user;
  SIGINT exited `130` with `interrupted`; the database was uid 1000, mode 600.
- Phase 5 manual capture: **PASS**. First session: 72 events (64 `file_open`,
  1 IPv4 `network_connect`). Second session: 315 events, including IPv4
  `127.0.0.1:1` and IPv6 `::1:1`, both `-111`. `/etc/hostname` opened
  successfully; both sessions verified `valid` with zero findings.
- Workspace gate: fmt, clippy, 180 tests, build, and `scripts/check.sh` passed.

Two defects were exposed and fixed during validation:

- The collector's own `/proc` enrichment generated recursive `openat` events.
  Self-originated samples are now filtered before enrichment, so `ring.poll`
  cannot be trapped in a feedback loop.
- The session lock directory was created as root before dropping privileges,
  causing the unprivileged writer to fail with `EACCES` and drop every event.
  The lock is now acquired after privilege drop and is user-owned.

## Reproduce the privileged validation

Build first:

```bash
cargo build -p syscall-cli
```

Then run as the operator:

```bash
sudo scripts/e2e-root.sh

sudo target/debug/syscall record --db /tmp/syscall-phase5.db -- \
  /bin/bash -c 'cat /etc/hostname >/dev/null; (exec 3<>/dev/tcp/127.0.0.1/1) || true'
SID=$(target/debug/syscall --db /tmp/syscall-phase5.db sessions --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
target/debug/syscall --db /tmp/syscall-phase5.db files "$SID"
target/debug/syscall --db /tmp/syscall-phase5.db connections "$SID"
target/debug/syscall --db /tmp/syscall-phase5.db verify "$SID"
```

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
- Ring-buffer support was exercised by the privileged run; both validated
  sessions reported `ringbuf_lost=0`.
- The syscall tracepoints used for Phase 5 exist in the WSL2 6.6 kernel ABI and
  were attached successfully under root. The Phase 5 runs captured 64 file opens
  and IPv4 plus IPv6 connect attempts.
- WSL2 localhost networking may refuse a connection to an unused port. That is
  still a valid failed-connect attempt and is useful evidence. A successful
  local connect is also valid but does not prove TCP versus UDP or application
  establishment.

### Phase 5 manual validation

The following operator run was completed on 2026-11-10 and passed:

```bash
cargo build -p syscall-cli
sudo target/debug/syscall record --db /tmp/syscall-phase5.db -- /bin/bash -c 'cat /etc/hostname >/dev/null; (exec 3<>/dev/tcp/127.0.0.1/1) || true'
SID=$(target/debug/syscall --db /tmp/syscall-phase5.db sessions --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
target/debug/syscall --db /tmp/syscall-phase5.db files "$SID"
target/debug/syscall --db /tmp/syscall-phase5.db connections "$SID"
target/debug/syscall --db /tmp/syscall-phase5.db verify "$SID"
```

Observed: a successful `/etc/hostname` `file_open`, `network_connect` rows for
`127.0.0.1:1` and `::1:1` with result `-111`, matching process instances against
exec events, and `syscall verify` `valid` with zero findings. If a future run produces no
rows, record `bpftool`/debug output and treat capture as unproven.
