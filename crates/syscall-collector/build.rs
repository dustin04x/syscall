use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let source = manifest_dir.join("../../ebpf/syscall.bpf.c");
    let header = manifest_dir.join("../../ebpf/syscall_event.h");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"))
        .join("syscall.skel.rs");

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", header.display());

    // The BPF object is compiled by libbpf-cargo. Keep the arch include paths
    // explicit so the build works on Ubuntu without a vmlinux.h dependency.
    SkeletonBuilder::new()
        .source(&source)
        .clang("clang")
        .clang_args([
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include",
        ])
        .build_and_generate(&out)
        .expect("failed to compile eBPF program and generate libbpf skeleton");
}
