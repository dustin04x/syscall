# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libelf-dev \
    pkg-config \
    zlib1g-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY desktop ./desktop
COPY ebpf ./ebpf

# Build the CLI binary. Live eBPF recording in containers depends on host kernel,
# privileges, and BTF access; inspection/analysis/verify/export work on mounted DBs.
RUN cargo build --release -p syscall-cli --locked

FROM debian:bookworm-slim AS runtime
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/syscall /usr/local/bin/syscall

ENTRYPOINT ["syscall"]
CMD ["--help"]
