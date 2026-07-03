//! Build script.
//!
//! When the `ebpf` feature is enabled, compile the sibling `mcpfz-probe-ebpf`
//! crate to BPF bytecode (target `bpfel-unknown-none`, nightly + build-std) and
//! stage the resulting object in `OUT_DIR` for `include_bytes_aligned!`. When the
//! feature is off (the default — e.g. on macOS/CI), this is a no-op so the
//! portable build needs no nightly, no bpf-linker, and no LLVM.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let ebpf_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("mcpfz-probe-ebpf");
    let ebpf_target_dir = out_dir.join("ebpf-target");

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .current_dir(&ebpf_dir)
        .env("CARGO_TARGET_DIR", &ebpf_target_dir)
        // Cargo runs build scripts with its toolchain pinned via these vars;
        // clear them so the child `cargo +nightly` actually uses nightly (the BPF
        // target needs nightly + build-std) instead of the parent's toolchain.
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to invoke cargo for the eBPF crate");
    assert!(status.success(), "eBPF crate build failed");

    let object = ebpf_target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("mcpfz-probe-ebpf");
    let staged = out_dir.join("mcpfz-probe-ebpf.bpf.o");
    std::fs::copy(&object, &staged)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", object.display(), staged.display()));

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );
    println!("cargo:rerun-if-changed=../mcpfz-probe-ebpf-common/src/lib.rs");
}
