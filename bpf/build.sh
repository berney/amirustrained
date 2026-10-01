#!/usr/bin/env bash
# Reproduce the committed eBPF object embedded by src/probes/ebpf_load.rs.
#
# Why the artifact is checked in: the main crate builds on STABLE with the
# repo-wide musl target (.cargo/config.toml). The BPF object needs nightly
# (-Z build-std for the Tier-3 bpfel-unknown-none target) + bpf-linker; baking
# that into every contributor/CI build would poison the default toolchain.
# So `prebuilt/hello.bpf.o` is committed, and this script is the audit path:
# run it, then `git diff prebuilt/` — an empty diff means the object matches
# its source (the CI `eBPF-object` job in ci.yml does exactly this).
#
# Prerequisites: rustup nightly (`rustup toolchain install nightly
# --component rust-src`) and bpf-linker (`cargo install bpf-linker`, or grab
# a release binary from https://github.com/aya-rs/bpf-linker/releases).
#
# bpf/.cargo/config.toml pins target bpfel-unknown-none, the bpf-linker
# linker, and `-Z build-std = core` — nightly-only, and scoped to this
# directory so the main workspace never sees them.
set -euo pipefail
cd "$(dirname "$0")"

cargo +nightly build --release

# The bin target links to an extension-less ELF relocatable object named
# after the crate: `target/bpfel-unknown-none/release/hello-bpf`.
obj=target/bpfel-unknown-none/release/hello-bpf
[ -f "$obj" ] || { echo "no object at $obj" >&2; exit 1; }
mkdir -p prebuilt
cp "$obj" prebuilt/hello.bpf.o
echo "wrote prebuilt/hello.bpf.o from $obj"
