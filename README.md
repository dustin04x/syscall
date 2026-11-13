<h1 align="center">SYSCALL</h1>

<p align="center"><strong>Runtime forensics for Linux, built on real kernel telemetry.</strong></p>

<p align="center">
  <a href="https://github.com/dustin04x/syscall/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dustin04x/syscall/actions/workflows/ci.yml/badge.svg?branch=master"></a>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2f6f4e?style=flat-square&labelColor=1b1b19">
  <img alt="Rust 1.82+" src="https://img.shields.io/badge/rust-1.82%2B-b03a2e?style=flat-square&labelColor=1b1b19">
  <img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-2f6f4e?style=flat-square&labelColor=1b1b19">
  <img alt="Read-only workbench" src="https://img.shields.io/badge/workbench-read--only-b03a2e?style=flat-square&labelColor=1b1b19">
</p>

<p align="center">
  Record process lifecycle, file-open, and network-connect activity with eBPF.<br>
  Persist it as attributable evidence. Investigate it from the CLI or a read-only desktop workbench.
</p>

<p align="center">
  <a href="https://syscall.mintlify.site/"><strong>Documentation</strong></a> ·
  <a href="https://syscall.mintlify.site/quickstart">Quickstart</a> ·
  <a href="https://syscall.mintlify.site/reference/cli">CLI reference</a> ·
  <a href="https://syscall.mintlify.site/operations/security">Security</a>
</p>

<p align="center">
  <img src="docs/screenshots/overview.png" alt="SYSCALL evidence overview in the workbench" width="100%">
</p>

> **Scope:** SYSCALL records real kernel telemetry. Collection covers process lifecycle, `openat(2)` attempts, and IPv4/IPv6 `connect(2)` attempts. File contents, packet payloads, DNS names, and environment variables are not captured. A successful `connect` proves an attempt, not an established session. Missing or incomplete data is reported, not fabricated.

## Quick start

**Requirements:** Linux x86_64 with BPF/BTF/tracefs/ring-buffer support, Rust 1.82+, `clang`, libbpf, and `pkg-config`. `record` needs root or `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels); inspection, analysis, verification, export, and the workbench do not.

```bash
# Build
cargo build --release -p syscall-cli

# Check environment (no privilege)
./target/release/syscall info

# Record a target tree
sudo ./target/release/syscall record -- /usr/bin/sleep 5

# Inspect, analyze, verify, export
./target/release/syscall sessions
./target/release/syscall inspect <SESSION_ID>
./target/release/syscall analyze <SESSION_ID>
./target/release/syscall verify <SESSION_ID>
./target/release/syscall export <SESSION_ID> --format json --output ./evidence-<SESSION_ID>.json
```

Desktop workbench (read-only):

```bash
cd desktop && npm install && npm run tauri:build -- --no-bundle
./target/release/syscall-workbench --db="$HOME/.local/share/syscall/<session>.db"
```

See the [installation guide](https://syscall.mintlify.site/installation) and [workbench guide](https://syscall.mintlify.site/guides/workbench) for prerequisites and details.

### Docker

Launch the web UI preview and a `syscall` CLI container with one command (Docker Desktop / Docker Compose):

```bash
docker compose up --build -d
```

- **UI preview:** [http://localhost:8080](http://localhost:8080) (serves the standalone mock workbench in `ui/`).
- **CLI container:** `docker compose exec syscall syscall --help` (the project is mounted at `/work`, so you can inspect/verify/analyze/export mounted SQLite session databases).

> Live eBPF recording requires Linux kernel BPF/BTF support and elevated privileges on the host kernel; running `record` inside Docker Desktop's Linux VM is environment-dependent and may not work the same as a native Linux host. Use the CLI on a supported host for capture, then inspect the resulting database here.

## Documentation

Full documentation is hosted at **[syscall.mintlify.site](https://syscall.mintlify.site/)**, covering:

- **Concepts:** [how it works](https://syscall.mintlify.site/concepts/how-it-works), [identity and scope](https://syscall.mintlify.site/concepts/identity-and-scope), [evidence model](https://syscall.mintlify.site/concepts/evidence-model)
- **Guides:** [record](https://syscall.mintlify.site/guides/record), [investigate](https://syscall.mintlify.site/guides/investigate), [analyze](https://syscall.mintlify.site/guides/analyze), [verify](https://syscall.mintlify.site/guides/verify), [export](https://syscall.mintlify.site/guides/export), [workbench](https://syscall.mintlify.site/guides/workbench)
- **Reference:** [CLI](https://syscall.mintlify.site/reference/cli), [schemas](https://syscall.mintlify.site/reference/schemas), [analysis rules](https://syscall.mintlify.site/reference/analysis-rules), [export format](https://syscall.mintlify.site/reference/export-format)
- **Operations & project:** [security](https://syscall.mintlify.site/operations/security), [limitations](https://syscall.mintlify.site/operations/limitations), [WSL2](https://syscall.mintlify.site/operations/wsl), [troubleshooting](https://syscall.mintlify.site/operations/troubleshooting), [architecture](https://syscall.mintlify.site/project/architecture), [development](https://syscall.mintlify.site/project/development), [testing](https://syscall.mintlify.site/project/testing), [roadmap](https://syscall.mintlify.site/project/roadmap)

Source for the docs site lives in [`docs/`](docs/).

## Development

```bash
./scripts/check.sh
# or: cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Privileged validation is manual; see [development docs](https://syscall.mintlify.site/project/development) and [testing](https://syscall.mintlify.site/project/testing).

## License

MIT. See [LICENSE](LICENSE).
