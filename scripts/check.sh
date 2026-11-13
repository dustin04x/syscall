#!/usr/bin/env bash
# Non-privileged quality gate. No sudo, no BPF loading, no network access.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "== cargo fmt --all --check =="
cargo fmt --all --check

if pkg-config --exists webkit2gtk-4.1 gtk+-3.0; then
    echo "== cargo clippy --workspace --all-targets -- -D warnings =="
    cargo clippy --workspace --all-targets -- -D warnings

    echo "== cargo test --workspace =="
    cargo test --workspace
else
    echo "== desktop GTK/WebKit development packages not found =="
    echo "   Running the command-independent desktop service layer headlessly."
    echo "   Install the desktop prerequisites (docs/DESKTOP.md) to compile the GUI."

    echo "== cargo clippy (workspace excluding syscall-desktop) =="
    cargo clippy --workspace --exclude syscall-desktop --all-targets -- -D warnings

    echo "== cargo clippy -p syscall-desktop (headless service layer) =="
    cargo clippy -p syscall-desktop --no-default-features --all-targets -- -D warnings

    echo "== cargo test (workspace excluding syscall-desktop) =="
    cargo test --workspace --exclude syscall-desktop

    echo "== cargo test -p syscall-desktop (headless service layer) =="
    cargo test -p syscall-desktop --no-default-features
fi

echo "== cargo build -p syscall-cli =="
cargo build -p syscall-cli

echo "== cargo build -p syscall-collector (generates skeleton) =="
cargo build -p syscall-collector

if [ -d "$root/desktop/node_modules" ]; then
    echo "== desktop frontend: strict TypeScript + production build =="
    npm --prefix "$root/desktop" run build

    echo "== desktop frontend: component and IPC tests =="
    npm --prefix "$root/desktop" test
else
    echo "== desktop frontend dependencies not installed; run npm --prefix desktop install =="
fi

skeleton_count="$(find target -path '*syscall-collector*/out/syscall.skel.rs' -type f | wc -l)"
if [ "$skeleton_count" -lt 1 ]; then
    echo "FAIL: libbpf-cargo did not generate syscall.skel.rs" >&2
    exit 1
fi
echo "PASS: libbpf skeleton generated ($skeleton_count copy/copies in target/)"

echo "== make -C ebpf clean check =="
make -C ebpf clean check

echo "== tracepoint context layout vs kernel BTF =="
if [ "${SYSCALL_SKIP_BTF_LAYOUT:-0}" = "1" ]; then
    echo "SKIP: SYSCALL_SKIP_BTF_LAYOUT=1 (kernel layout is environment-specific)"
else
    scripts/check-btf-layout.sh
fi

echo
echo "All non-privileged checks passed."
echo "Kernel load/attach/e2e are intentionally not run by this gate."
echo "To reproduce the operator validation:"
echo "  sudo scripts/e2e-root.sh"
