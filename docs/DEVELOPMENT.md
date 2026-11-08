# Development Guide

## Prerequisites

The checked environment:

- Ubuntu 24.04.4 on WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`, x86_64.
- Rust 1.99.1 (`rustup` toolchain).
- clang/LLVM 18.1.3, `llvm-objdump`, `make`, `pkg-config`.
- libbpf 1.3.0 development package and shared library.
- Readable `/sys/kernel/btf/vmlinux`.

Typical Debian/Ubuntu packages (installed by the operator, not by SYSCALL):

```bash
sudo apt-get install build-essential clang llvm libbpf-dev pkg-config
```

`bpftool` is not required. The Rust build uses `libbpf-cargo`, which invokes
clang and generates `syscall.skel.rs` in `OUT_DIR`.

## Build and test

```bash
cargo build --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace denies `unsafe_op_in_unsafe_fn`; every unsafe block must have a
safety comment.

The expected test count on this revision is 100: 19 CLI, 37 collector, 27 core,
4 storage unit, 13 storage integration.

## eBPF development

Compile the standalone object without Rust:

```bash
make -C ebpf clean check
```

Expected output includes three tracepoint sections:

```
tracepoint/sched/sched_process_exec
tracepoint/sched/sched_process_fork
tracepoint/sched/sched_process_exit
license
.maps
```

The `_Static_assert`s in `ebpf/syscall.bpf.c` enforce context and event sizes at
compile time. If the kernel's tracepoint layout changes, compilation fails rather
than emitting a silently truncated sample.

Generating the libbpf skeleton happens automatically:

```bash
cargo build -p syscall-collector
find target -path '*syscall-collector*/out/syscall.skel.rs'
```

`build.rs` passes `-D__TARGET_ARCH_x86` and explicit x86_64/libc include paths.
Supporting another architecture requires updating both the Makefile and
`build.rs`.

## Verifying tracepoint layouts against BTF

`scripts/check-btf-layout.sh` compiles `scripts/btf-layout.c` against libbpf and
checks the running kernel's BTF for:

| Struct | Expected size | Checked members |
| --- | ---: | --- |
| `trace_event_raw_sched_process_exec` | 20 | `ent@0`, `__data_loc_filename@8`, `pid@12`, `old_pid@16` |
| `trace_event_raw_sched_process_fork` | 48 | `ent@0`, `parent_comm@8`, `parent_pid@24`, `child_comm@28`, `child_pid@44` |
| `trace_event_raw_sched_process_template` | 32 | `ent@0`, `comm@8`, `pid@24`, `prio@28` |

The offsets in the C helper are **bit** offsets as returned by BTF; divide by 8
for byte offsets. The helper is read-only and works without root if
`/sys/kernel/btf/vmlinux` is readable.

Expected output:

```
PASS trace_event_raw_sched_process_exec             size=20 members verified
PASS trace_event_raw_sched_process_fork             size=48 members verified
PASS trace_event_raw_sched_process_template         size=32 members verified

All tracepoint context layouts match the running kernel BTF.
```

If this fails, do not load the program. Update the context structs, payload
offsets, and decoder together, and bump the wire schema if the wire format
changes.

## Running the collector

```bash
# Non-privileged readiness report.
target/debug/syscall info

# Privileged capture (operator-run).
sudo target/debug/syscall record -- /usr/bin/sleep 5

# Inspect as the normal user.
target/debug/syscall sessions
target/debug/syscall inspect SESSION_ID
target/debug/syscall events SESSION_ID
```

Use `RUST_LOG=debug` for decoder and collector diagnostics:

```bash
RUST_LOG=syscall_collector=debug,syscall_storage=debug \
    target/debug/syscall record -- /usr/bin/sleep 1
```

Diagnostics go to stderr; JSON data goes to stdout.

## Privileged testing policy

Unit and integration tests never load BPF and never require root. This is
deliberate: CI must not fake a kernel PASS.

The privileged path is an explicit operator action:

```bash
cargo build -p syscall-cli
sudo scripts/e2e-root.sh
```

`scripts/e2e-root.sh`:

1. Refuses to run unless invoked through sudo for a non-root user.
2. Verifies `syscall info` reports BPF-capable and that all three tracepoints are
   visible.
3. Records a small target tree and inspects it as the invoking user.
4. Sends SIGINT to a second recording and verifies exit 130 and `interrupted`.
5. Verifies the database is owned by the user and mode `600`.

Never run privileged tests automatically from an agent or CI job without an
explicit provisioning decision. Never put a password in a script, environment
variable, or command line.

## Diagnosing WSL2 failures

- `unprivileged_bpf_disabled=2` means an unprivileged load must fail. Run through
  sudo.
- Tracefs is often `drwx------ root root`; `syscall info` reports tracepoint
  availability as `unknown (tracefs not readable)` rather than guessing.
- `/sys/kernel/btf/vmlinux` must be readable for BTF verification. BTF is present
  on the checked WSL2 kernel.
- If skeleton generation fails, verify `clang` and libbpf headers, then run
  `make -C ebpf clean check` to isolate the compiler from Cargo.
- If load fails under root, capture the exact libbpf error. Do not report it as a
  pass. Update `docs/WSL_COMPATIBILITY.md` with the real failure.

## Adding a schema migration

1. Add `crates/syscall-storage/migrations/00N_name.sql`.
2. Add a `Migration` entry and bump `LATEST_SCHEMA_VERSION` in `migrations.rs`.
3. Add a migration test that opens version N-1 and verifies version N.
4. Add read-only rejection tests for future versions.
5. Update `docs/EVENT_SCHEMA.md`.

## Adding a collected event type

Adding `file_open` or `network_connect` requires all of:

1. A real eBPF program with bounded capture.
2. Wire structs, decoder offsets, and BTF/layout checks.
3. Payload construction and validation.
4. Storage/index review and CLI rendering.
5. Root-run e2e evidence.

Do not mark a placeholder as collected until the kernel path exists. The domain
validator intentionally rejects schema-only variants.
