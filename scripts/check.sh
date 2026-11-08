#!/usr/bin/env bash
# Non-privileged quality gate. No sudo, no BPF loading, no network access.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "== cargo fmt --all --check =="
cargo fmt --all --check

echo "== cargo clippy --workspace --all-targets -- -D warnings =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== cargo test --workspace =="
cargo test --workspace

echo "== cargo build -p syscall-collector (generates skeleton) =="
cargo build -p syscall-collector

skeleton_count="$(find target -path '*syscall-collector*/out/syscall.skel.rs' -type f | wc -l)"
if [ "$skeleton_count" -lt 1 ]; then
    echo "FAIL: libbpf-cargo did not generate syscall.skel.rs" >&2
    exit 1
fi
echo "PASS: libbpf skeleton generated ($skeleton_count copy/copies in target/)"

echo "== make -C ebpf clean check =="
make -C ebpf clean check

echo "== tracepoint context layout vs kernel BTF =="
scripts/check-btf-layout.sh

echo
echo "All non-privileged checks passed."
echo "Kernel load/attach/e2e tests remain BLOCKED until an operator runs:"
echo "  sudo scripts/e2e-root.sh"
