# Kernel-Mode Execution Attack Surface & UX Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement passive kernel config parsing (with pure-Rust gzip decompression and dual SHA-256), passive kernel attack surface inspection (modules, kexec, memory/IO, USMH, ACPI), active non-destructive boundary execution probing (`--probe-kernel-execution`, alias `--probe-kernel`), rules `AMR-023..029` (including chained kexec bypass and opt-in feedback guarantee), and an output UX overhaul (silencing probe noise, high-density identity/capability-hex header, `--compact`/`--terse` diff mode, CPU arch and `/etc/os-release` capture, and `AGENTS.md`).

**Architecture:** Split into modular passive probes (`kernel_config.rs`, `kernel_surface.rs`) running in the default pipeline and an active probe (`kernel_exec.rs`) running inside an isolated forked worker process under a 5-second deadline when opt-in flags are passed. Rule evaluation handles discrete findings and composite suppression logic in `rules.rs`. Output rendering in `render/text.rs` replaces probe execution noise with an identity/sandbox context header and provides a single-line compact format for fast diffing across privilege boundaries.

**Tech Stack:** Rust edition 2024, `flate2` (with pure-Rust `miniz_oxide` backend, zero C toolchain dependencies), `rustix`, `libc`, `sha2`, `clap` (derive), `serde`/`serde_json`.

**Spec:** `docs/superpowers/specs/2026-10-05-kernel-execution-and-ux-design.md`

## Global Constraints
- Target static musl platforms: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `riscv64gc-unknown-linux-musl`. Zero dynamic C library linkages.
- Non-destructive probing: active syscall tests must ONLY use kernel-validated boundary arguments (`finit_module(-1)`, `init_module(NULL)`, `kexec_file_load(-1)`, `kexec_load(ULONG_MAX)`, `iopl(3)`) that fail deterministically before mutating state.
- Isolation: active probe MUST run in a forked worker child with a 5-second timeout; stalls must be killed via `SIGKILL` and recorded as timeouts without hanging the main scan.
- Output contract: human mode is concise and avoids noise; machine formats (JSON/YAML/SARIF) are exhaustive and always include full hashes, option dictionaries, and syscall diagnostics.
- Opt-in expressiveness: opt-in flags (`--probe-*`) must always emit visible human feedback explaining the outcome of the tested surface, even when the verdict is negative/closed (`AMR-029`).

---

### Task 1: Pure-Rust Gzip Decompression & Dependency Setup

**Files:**
- Modify: `Cargo.toml:8-25`
- Create: `src/sys/gz.rs`
- Modify: `src/sys.rs:1-10`
- Test: `src/sys/gz.rs` (inline unit tests)

**Interfaces:**
- Produces: `pub fn decompress_gz(bytes: &[u8]) -> std::io::Result<Vec<u8>>`

- [ ] **Step 1: Write failing unit test for `decompress_gz`**
Create `src/sys/gz.rs` with a unit test that compresses bytes using `flate2::write::GzEncoder` and verifies `decompress_gz` round-trips correctly, as well as rejecting truncated/malformed inputs.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn roundtrip_gzip_decompression() {
        let input = b"CONFIG_MODULES=y\nCONFIG_KEXEC=y\n";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gz(&compressed).expect("decompression succeeds");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn malformed_gzip_fails_gracefully() {
        let bad = b"\x1f\x8b\x08garbage";
        assert!(decompress_gz(bad).is_err());
    }
}
```

- [ ] **Step 2: Add `flate2` and `sha2` dependencies to `Cargo.toml`**
Edit `Cargo.toml` to add `flate2` (pure Rust `rust_backend`) and `sha2` (pure Rust SHA-256):
```toml
flate2 = { version = "1.0", default-features = false, features = ["rust_backend"] }
sha2 = { version = "0.10", default-features = false }
```

- [ ] **Step 3: Implement `decompress_gz`**
Implement in `src/sys/gz.rs`:
```rust
use std::io::{self, Read};
use flate2::read::GzDecoder;

pub fn decompress_gz(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}
```
Expose `pub mod gz;` in `src/sys.rs`.

- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test sys::gz::tests`
Expected: PASS

- [ ] **Step 5: Verify static musl build and clippy**
Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS with 0 warnings.

- [ ] **Step 6: Commit**
```bash
git add Cargo.toml Cargo.lock src/sys.rs src/sys/gz.rs
git commit -m "feat(sys): add pure-Rust gzip decompression via flate2"
```

---

### Task 2: Kernel Config Discovery, Parsing & Dual SHA-256 (`src/probes/kernel_config.rs`)

**Files:**
- Create: `src/probes/kernel_config.rs`
- Modify: `src/probes/mod.rs`
- Modify: `src/pipeline.rs`

**Interfaces:**
- Produces: `pub struct KernelConfig;` implementing `Probe`.
- Exports facts:
  - `kernel.config.path`: string (e.g. `"/proc/config.gz"` or `"/boot/config-6.8.0"`)
  - `kernel.config.raw_sha256`: hex string (hash of file bytes)
  - `kernel.config.uncompressed_sha256`: hex string (hash of normalized text)
  - `kernel.config.options`: `serde_json::Value` (map of curated `CONFIG_*` values)

- [ ] **Step 1: Write unit tests for config parsing, option extraction, and hashing**
In `src/probes/kernel_config.rs`, write tests covering:
1. Parsing `# CONFIG_MODULE_UNLOAD is not set` $\to$ `"n"`.
2. Parsing `CONFIG_MODULES=y` $\to$ `"y"`.
3. Parsing `CONFIG_DEFAULT_HOSTNAME="box"` $\to$ `"box"`.
4. Whitelist filtering (unrelated `CONFIG_SND_*` discarded).
5. Dual SHA-256 computation on raw vs decompressed bytes.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test probes::kernel_config::tests`
Expected: FAIL (unimplemented).

- [ ] **Step 3: Implement `KernelConfig` probe**
Implement in `src/probes/kernel_config.rs`:
- Search candidates in order: `/proc/config.gz`, `/boot/config-<release>`, `/proc/config`.
- Read bytes using `fs.read_to_end(...)`. If gzip, decompress via `sys::gz::decompress_gz`.
- Compute raw SHA-256 and uncompressed SHA-256 using `sha2::Sha256`.
- Parse lines into key-value pairs matching the curated security whitelist (modules, kexec, memory/IO, lockdown, livepatch, acpi, bpf, userns).
- Record facts with `Fact::ok("kernel.config.path", ...)` etc.
Register in `src/probes/mod.rs` and `src/pipeline.rs`.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test probes::kernel_config::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/probes/kernel_config.rs src/probes/mod.rs src/pipeline.rs
git commit -m "feat(probes): add kernel config discovery, dual hashing, and whitelist parser"
```

---

### Task 3: Passive Kernel Attack Surface Probe (`src/probes/kernel_surface.rs`)

**Files:**
- Create: `src/probes/kernel_surface.rs`
- Modify: `src/probes/mod.rs`
- Modify: `src/pipeline.rs`

**Interfaces:**
- Produces: `pub struct KernelSurface;` implementing `Probe`.
- Exports facts:
  - `kernel.surface.modules_disabled`: `Option<bool>` (from `/proc/sys/kernel/modules_disabled`)
  - `kernel.surface.kexec_load_disabled`: `Option<bool>` (from `/proc/sys/kernel/kexec_load_disabled`)
  - `kernel.surface.kexec_loaded`: `Option<bool>` (from `/sys/kernel/kexec_loaded`)
  - `kernel.surface.lockdown`: `Option<String>` (`"none"`, `"integrity"`, `"confidentiality"`)
  - `kernel.surface.dev_mem`: `Option<String>` (`"accessible"`, `"denied"`, `"absent"`)
  - `kernel.surface.dev_kmem`: `Option<String>`
  - `kernel.surface.dev_port`: `Option<String>`
  - `kernel.surface.core_pattern`: `Option<String>` (and `writable: bool`)
  - `kernel.surface.modprobe`: `Option<String>` (and `writable: bool`)
  - `kernel.surface.livepatch_present`: `bool`
  - `kernel.surface.acpi_table_writable`: `bool`

- [ ] **Step 1: Write unit tests with synthetic procfs/sysfs/dev directories**
In `src/probes/kernel_surface.rs`, write unit tests utilizing temp directories verifying:
1. `modules_disabled` set to `"1\n"` parses to `Some(true)`.
2. `lockdown` string `"[none] integrity confidentiality\n"` parses to `Some("none")`.
3. Read-only `/proc/sys/kernel/core_pattern` reports `writable: false`.
4. Character device presence and permission tests.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test probes::kernel_surface::tests`
Expected: FAIL.

- [ ] **Step 3: Implement `KernelSurface` probe**
Implement the passive inspections in `src/probes/kernel_surface.rs`.
Register `KernelSurface` in `src/probes/mod.rs` and the default probe list in `src/pipeline.rs`.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test probes::kernel_surface::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/probes/kernel_surface.rs src/probes/mod.rs src/pipeline.rs
git commit -m "feat(probes): add passive kernel attack surface inspection probe"
```

---

### Task 4: CLI Flags `--probe-kernel-execution` & `--compact` / `--terse`

**Files:**
- Modify: `src/opts.rs:40-90`
- Modify: `tests/cli.rs`

**Interfaces:**
- Produces:
  - `opts.probe_kernel_execution: bool` (flag `--probe-kernel-execution`, alias `--probe-kernel`)
  - `opts.compact: bool` (flag `--compact`, alias `--terse`)

- [ ] **Step 1: Write CLI argument parsing tests in `tests/cli.rs`**
Add tests asserting:
1. `amirustrained --probe-kernel-execution` and `amirustrained --probe-kernel` both enable the kernel exec probe flag.
2. `amirustrained --compact` and `amirustrained --terse` both enable the compact format flag.
3. Help text displays both options and their aliases.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test cli flag_probe_kernel`
Expected: FAIL (unrecognized flag).

- [ ] **Step 3: Update `src/opts.rs` with flags and aliases**
In `src/opts.rs`, add to `Cli`:
```rust
    /// Probe kernel-mode execution boundaries (finit_module, kexec, raw memory/IO).
    #[arg(long = "probe-kernel-execution", alias = "probe-kernel")]
    pub probe_kernel_execution: bool,

    /// Render concise single-line findings (ideal for diffing privilege states).
    #[arg(long = "compact", alias = "terse")]
    pub compact: bool,
```
Update `Opts::from_cli`.

- [ ] **Step 4: Run CLI tests to verify they pass**
Run: `cargo test --test cli`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/opts.rs tests/cli.rs
git commit -m "feat(cli): add --probe-kernel-execution and --compact with aliases"
```

---

### Task 5: Active Kernel Execution Probe (`src/probes/kernel_exec.rs`)

**Files:**
- Create: `src/probes/kernel_exec.rs`
- Modify: `src/probes/mod.rs`
- Modify: `src/pipeline.rs`

**Interfaces:**
- Produces: `pub struct KernelExec;` implementing `Probe`.
- Exports facts under `kernel.exec`:
  - `finit_module`: status (`"permitted"`, `"denied"`, `"unsupported"`, `"error"`), errno, error_name
  - `init_module`: status, errno, error_name
  - `kexec_file_load`: status, errno, error_name
  - `kexec_load`: status, errno, error_name
  - `iopl`: status (`"permitted"`, `"denied"`, `"unsupported_arch"`, `"error"`), errno, error_name

- [ ] **Step 1: Write tests for active syscall outcome decoder**
In `src/probes/kernel_exec.rs`, write unit tests verifying that:
- `Err(EBADF)` from `finit_module` maps to `Status::Permitted`.
- `Err(EPERM)` maps to `Status::Denied`.
- `Err(ENOSYS)` maps to `Status::Unsupported`.
- `iopl` maps to `Status::UnsupportedArch` on non-x86_64.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test probes::kernel_exec::tests`
Expected: FAIL.

- [ ] **Step 3: Implement forked worker execution harness in `src/probes/kernel_exec.rs`**
Implement worker harness:
- Check `opts.probe_kernel_execution`; if false, return empty results immediately.
- Fork worker child with `libc::fork()`.
- Inside worker: invoke the non-destructive boundary syscalls:
  - `libc::syscall(SYS_finit_module, -1, c"", 0)`
  - `libc::syscall(SYS_init_module, std::ptr::null::<u8>(), 0, c"")`
  - `libc::syscall(SYS_kexec_file_load, -1, -1, 0, std::ptr::null::<u8>(), 0)`
  - `libc::syscall(SYS_kexec_load, 0, usize::MAX, std::ptr::null::<u8>(), 0)`
  - `#[cfg(any(target_arch = "x86", target_arch = "x86_64"))] libc::iopl(3)`
- Encode results to JSON over pipe.
- Parent reads with a 5-second `poll`/timeout. Kills worker with `SIGKILL` on timeout.
Register in `src/pipeline.rs` (conditional on `opts.probe_kernel_execution`).

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test probes::kernel_exec::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/probes/kernel_exec.rs src/probes/mod.rs src/pipeline.rs
git commit -m "feat(probes): add active isolated kernel execution boundary probe"
```

---

### Task 6: Rule Evaluation: `AMR-023` through `AMR-029` (`src/model/rules.rs`)

**Files:**
- Modify: `src/model/rules.rs`
- Modify: `src/model/finding.rs`

**Interfaces:**
- Produces:
  - `AMR-023`: `kernel-module-loading-permitted` (High)
  - `AMR-024`: `kexec-kernel-replacement-permitted` (High)
  - `AMR-025`: `raw-memory-access-permitted` (Critical)
  - `AMR-026`: `user-mode-helper-writable` (High)
  - `AMR-027`: `acpi-table-injection-writable` (High)
  - `AMR-028`: `kexec-module-lockdown-bypass` (High, chained, suppressed if `AMR-023` fires)
  - `AMR-029`: `kernel-execution-probe-report` (Info, fires when opt-in probe confirms all closed)

- [ ] **Step 1: Write rule engine unit tests in `src/model/rules.rs`**
Write tests covering:
1. `AMR-023` fires when `finit_module` is permitted or `CAP_SYS_MODULE` + config allows modules.
2. `AMR-028` fires when modules are blocked AND kexec is permitted.
3. `AMR-028` is SUPPRESSED when direct module loading is open (`AMR-023` fires).
4. `AMR-029` fires under `--probe-kernel-execution` when all pathways are denied/unsupported.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test model::rules::tests::kernel_execution_rules`
Expected: FAIL.

- [ ] **Step 3: Implement rules `AMR-023` through `AMR-029` in `src/model/rules.rs`**
Add rule definitions and evaluations according to spec §4.
Wire `AMR-028` chain suppression logic.
Wire `AMR-029` opt-in report generation when `opts.probe_kernel_execution` is active and none of `AMR-023..027` fired.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test model::rules::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/model/rules.rs src/model/finding.rs
git commit -m "feat(rules): add AMR-023..AMR-029 for kernel execution and chained bypass"
```

---

### Task 7: Report Metadata: CPU Architecture & OS Release Capture

**Files:**
- Modify: `src/model/report.rs:20-50`
- Modify: `src/pipeline.rs:130-160`
- Modify: `src/sys/os.rs`

**Interfaces:**
- Produces:
  - `ReportMeta.arch: String` (from `rustix::system::uname().machine()`)
  - `ReportMeta.distro: Option<String>` (from `/etc/os-release` `PRETTY_NAME`)
  - Machine serialization includes `scan.arch` and `scan.distro`.

- [ ] **Step 1: Write unit test for `/etc/os-release` parsing**
In `src/sys/os.rs`, write a parser test handling standard `PRETTY_NAME="Ubuntu 22.04.4 LTS"`, quotes stripping, fallback to `NAME` + `VERSION_ID`, and missing files.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test sys::os::tests::os_release`
Expected: FAIL.

- [ ] **Step 3: Implement `parse_os_release` and update `ReportMeta`**
Implement parser in `src/sys/os.rs`.
Update `ReportMeta` in `src/model/report.rs`:
```rust
pub struct ReportMeta {
    ...
    pub kernel: String,
    pub arch: String,
    pub distro: Option<String>,
}
```
Populate in `src/pipeline.rs` using `rustix::system::uname().machine()` and `parse_os_release(&fs)`.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/model/report.rs src/pipeline.rs src/sys/os.rs
git commit -m "feat(report): capture CPU arch and os-release distro in report metadata"
```

---

### Task 8: UX Overhaul: Identity Header & Silence Probe Noise

**Files:**
- Modify: `src/render/text.rs`
- Modify: `src/render/markdown.rs`
- Modify: `src/probes/capabilities.rs` (export raw 64-bit hex mask)
- Modify: `src/probes/uidmap.rs` (parse supplemental groups and `/etc/group`)
- Modify: `src/probes/namespaces.rs` (export visible PID count, PID 1 cmdline, hidepid)

**Interfaces:**
- Produces:
  - Suppresses `probe <name>: ok` in default human output (keeps on `--verbose`).
  - Formats Environment & Identity Header:
    ```text
    Host:       Linux <release> (<arch>) | distro: <distro> | runtime: <runtime>
    Identity:   uid=<uid>(<user>) gid=<gid>(<group>) groups=<groups>
    Caps:       <hex> (<count> caps) [eff=<hex> bnd=<hex> inh=<hex>]
    Sandboxing: no_new_privs=<bool> seccomp=<mode> lockdown=<mode>
    Visibility: pid_ns=<status> (<N> procs visible, pid 1="<cmd>", procfs hidepid=<val>)
    ```

- [ ] **Step 1: Write render tests for the Identity & Environment Header**
In `src/render/text.rs`, write tests asserting the exact format and color styling of the 5-line header across root vs unprivileged identities.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test render::text::tests::identity_header`
Expected: FAIL.

- [ ] **Step 3: Implement header rendering and silence probe progress**
In `src/render/text.rs`:
- Remove unconditional printing of `probe <name>: ok`.
- If `--verbose` is true, print probe execution logs.
- If probe is degraded, print single-line warning to stderr.
- Render the 5-line Identity & Environment Header at top of report.
Update `capabilities.rs`, `uidmap.rs`, and `namespaces.rs` to expose the required hex masks, groups, and PID visibility facts.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test render::text::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/render/text.rs src/render/markdown.rs src/probes/capabilities.rs src/probes/uidmap.rs src/probes/namespaces.rs
git commit -m "feat(render): add high-density identity context header and silence probe noise"
```

---

### Task 9: Compact Diffable Output Mode (`--compact` / `--terse`)

**Files:**
- Modify: `src/render/text.rs`
- Modify: `tests/cli.rs`

**Interfaces:**
- Produces:
  - Single-line finding format when `opts.compact` is true:
    `SEVERITY AMR-XXX identifier: summary evidence`

- [ ] **Step 1: Write CLI test for `--compact` and `--terse` output**
In `tests/cli.rs`, add a test asserting that running with `--compact` or `--terse` produces single-line findings without `why:` or `fix:` multi-line blocks.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test cli compact_output`
Expected: FAIL.

- [ ] **Step 3: Implement compact rendering in `src/render/text.rs`**
In `src/render/text.rs`, when `opts.compact` is true:
- Render each finding on exactly one line:
  `format!("{severity} {id} {name}: {evidence_or_summary}")`
- Retain the Identity Header for diffability.

- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test cli`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/render/text.rs tests/cli.rs
git commit -m "feat(render): add --compact and --terse single-line diffable finding mode"
```

---

### Task 10: Scenario Corpus & Fixture Testing

**Files:**
- Create: `tests/fixtures/monolithic-kernel/...`
- Create: `tests/fixtures/locked-down-kernel/...`
- Create: `tests/fixtures/hardened-microvm/...`
- Modify: `tests/scenarios.rs`

**Interfaces:**
- Tests all 9 original scenarios + 3 new kernel execution scenarios.

- [ ] **Step 1: Create fixture trees for the 3 new kernel scenarios**
Create simulated `/proc`, `/sys`, `/boot` files for:
1. `monolithic-kernel`: `CONFIG_MODULES=n` in `/proc/config.gz`, `/sys/kernel/kexec_loaded=0`, `CAP_SYS_BOOT` present.
2. `locked-down-kernel`: `/sys/kernel/security/lockdown` = `[integrity]`, `/dev/mem` unopenable.
3. `hardened-microvm`: `modules_disabled=1`, `kexec_load_disabled=1`, unprivileged.

- [ ] **Step 2: Write scenario assertions in `tests/scenarios.rs`**
Assert:
- `monolithic-kernel`: `AMR-028` fires; `AMR-023` does not fire.
- `locked-down-kernel`: `AMR-024` and `AMR-025` do not fire.
- `hardened-microvm`: `AMR-029` fires under `--probe-kernel-execution`.

- [ ] **Step 3: Run scenario suite to verify it passes**
Run: `cargo test --test scenarios`
Expected: PASS.

- [ ] **Step 4: Commit**
```bash
git add tests/fixtures/ tests/scenarios.rs
git commit -m "test(scenarios): add fixture test cases for kernel execution and chained bypass"
```

---

### Task 11: Architectural Contracts & Documentation (`AGENTS.md`, `README.md`)

**Files:**
- Create: `AGENTS.md`
- Modify: `README.md`

- [ ] **Step 1: Create `AGENTS.md`**
Document the repository tenets:
- Tenet 1: Human Output is Opinionated and Concise (silence noise, keep hashes in `--verbose`).
- Tenet 2: Machine Formats are Exhaustive (always include dual SHA-256 and full options).
- Tenet 3: Opt-in Expressiveness Guarantee (opt-in probes must always report outcomes).
- Tenet 4: Non-Destructive Boundary Probing (kernel-validated boundaries only).

- [ ] **Step 2: Update `README.md`**
Document:
- New CLI options: `--probe-kernel-execution` (alias `--probe-kernel`), `--compact` (alias `--terse`).
- New rules: `AMR-023` through `AMR-029`.
- Updated terminal output examples showing the Identity Header.

- [ ] **Step 3: Run full quality gates**
Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: 100% PASS with 0 warnings.

- [ ] **Step 4: Commit**
```bash
git add AGENTS.md README.md
git commit -m "docs: add AGENTS.md architecture tenets and update README for v0.2.0"
```
