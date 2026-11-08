# Standalone build for the BPF object. The Rust build generates the libbpf
# skeleton through libbpf-cargo; this Makefile is for focused compiler checks.

CLANG ?= clang
ARCH ?= x86
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
ARCH_INCLUDES := $(shell uname -m)-linux-gnu

.PHONY: all clean check

all: syscall.bpf.o

syscall.bpf.o: syscall.bpf.c syscall_event.h
	$(CLANG) $(BPF_CFLAGS) -I/usr/include/$(ARCH_INCLUDES) -I/usr/include -c $< -o $@

check: syscall.bpf.o
	@file syscall.bpf.o
	@llvm-objdump -h syscall.bpf.o | grep -E '\.maps|tracepoint|license' || true

clean:
	rm -f syscall.bpf.o
