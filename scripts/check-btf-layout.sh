#!/usr/bin/env bash
# Compile and run the read-only BTF layout verifier. No root required.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${TMPDIR:-/tmp}/syscall-btf-layout"

if ! pkg-config --exists libbpf; then
    echo "FAIL: pkg-config libbpf is required" >&2
    exit 1
fi

# shellcheck disable=SC2046
cc -O2 -Wall -Wextra -o "$out" "$root/scripts/btf-layout.c" \
    $(pkg-config --cflags --libs libbpf)

"$out" "${1:-/sys/kernel/btf/vmlinux}"
