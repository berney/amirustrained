# Architecture Contracts & Agent Guidelines (`AGENTS.md`)

This document defines the architectural invariants, core tenets, execution models, and output contracts of `amirustrained`. All contributors and automated agents extending or modifying this codebase must adhere strictly to these principles.

---

## The Four Core Repository Tenets

### Tenet 1: Human Output is Opinionated and Concise
- **Signal-to-Noise Ratio:** Default human text output (`--format text`) prioritizes actionable security findings and immediate situational context.
- **Probe Heartbeat Silencing:** Routine probe progress lines (`probe <name>: ok`) are silenced by default in human output. Only degraded probes emit a concise single-line warning to `stderr`. Full probe progress is deferred to `--verbose` (`-v`).
- **Verbose-Only Informational Suppression (`Rule.verbose_only`):** Low-priority informational findings (e.g. `AMR-030` at `Info` on bare hosts) are silenced in default human terminal output (`--format text` and `--compact`) to prevent alert fatigue. Findings above `Info` are never silenced. The summary line alerts the user with `[N verbose notices hidden — run with -v]`, running with `-v` renders them in full, and machine formats (`json`, `yaml`, `sarif`, `jsonl`) always export 100% of findings regardless of flag.
- **Deferred Metadata:** Large data structures—such as full kernel configuration option dictionaries and cryptographic SHA-256 hashes—are suppressed from default human terminal output and displayed only when `--verbose` is enabled.
- **Identity & Environment Header:** Every human scan begins with a high-density, 5-line context header (`Host:`, `Identity:`, `Caps:`, `Sandboxing:`, `Visibility:`) establishing the execution baseline (UID/GID, supplemental groups, 64-bit hexadecimal capabilities bitmask, seccomp/lockdown sandboxing state, PID namespace isolation, and PID 1).
- **Compact Diffable Mode:** The `--compact` flag (alias `--terse`) provides single-line finding summaries (`<SEVERITY> <RULE_ID> <SLUG>: <SUMMARY>`), retaining the Identity Header for diffability across privilege boundaries (e.g. `diff -u before.txt after.txt`).

### Tenet 2: Machine Formats are Exhaustive
- **Exhaustive Telemetry:** Machine output streams (`json`, `yaml`, `sarif`, `jsonl`) must **never** truncate, elide, or summarize data for human convenience.
- **Dual Cryptographic Hashes:** When kernel configuration artifacts are discovered (`/proc/config.gz`, `/boot/config-*`, `/proc/config`), machine streams must capture both:
  - `raw_sha256`: SHA-256 hash of the exact binary/compressed artifact on disk or procfs.
  - `uncompressed_sha256`: SHA-256 hash of the canonical uncompressed text normalized with LF newlines.
- **Complete Dictionaries & Diagnostics:** Machine streams always include full parsed configuration option key-value maps (`kernel.config.options`), per-syscall execution statuses and errno mappings (`kernel.exec.*`), and precise chain dependency evaluations.
- **Strict Backward Compatibility:** Fact keys, probe names, and JSON/YAML schemas are append-only. Automated tooling must be able to rely on stable fact structures without lossy format conversions.

### Tenet 3: Opt-in Expressiveness Guarantee
- **Observable Outcomes:** Probes requiring active, privilege-sensitive operations or syscall invocations (`--probe-syscalls`, `--probe-ebpf`, `--probe-kernel-execution`) require explicit opt-in CLI flags.
- **Affirmative Reporting on Negatives:** Opt-in probes must **always** emit visible human feedback explaining the outcome of the tested surface, even when the verdict is negative, locked down, or closed.
- **Zero Silent Opt-in Runs:** An opt-in scan that tests an execution boundary and finds all pathways closed must never exit with empty findings. In `--probe-kernel-execution`, when all tested Ring 0 pathways are confirmed blocked or restricted, rule `AMR-029` (`kernel-execution-probe-report`) fires at `info` severity to affirmatively report that the boundary was actively audited and verified closed.

### Tenet 4: Non-Destructive Boundary Probing
- **Zero State Mutation:** Active probes touch real kernel interfaces but must **never** modify kernel state, insert modules, boot kernels, or trigger kernel panics.
- **Kernel-Validated Boundary Arguments:** Syscall probes strictly pass boundary arguments that fail deterministically before state mutation:
  - `finit_module(-1, "", 0)`: triggers `EBADF` on success (authorizing caller and verifying subsystem before file descriptor resolution).
  - `init_module(NULL, 0, "")`: triggers `EFAULT` or `ENOEXEC` on authorized kernels without loading code.
  - `kexec_file_load(-1, -1, 0, NULL, 0)`: triggers `EBADF` when permitted by caps and lockdown.
  - `kexec_load(0, ULONG_MAX, NULL, 0)`: triggers `EINVAL` when permitted.
  - `iopl(3)`: returns `Ok(0)` on granted raw port I/O; restricted or unsupported on non-x86 architectures.
- **Forked Process Isolation & Deadlines:** All active boundary probing must execute in an isolated forked worker process monitored across an IPC channel. Probes run under a strict 5-second deadline; any hanging, stalled, or unresponsive child process is killed via `SIGKILL` and recorded as a timeout or error without hanging or crashing the parent auditor.

---

## Repository Architecture & Pipeline

### Pipeline Model
The scan pipeline executes probes sequentially in deterministic order:
1. `namespaces` — Namespace isolation, PID visibility, hidepid mount options.
2. `uidmap` — UID/GID mappings, supplemental groups, `/etc/group` resolution.
3. `capabilities` — Effective, bounding, inheritable capability bitmasks and NoNewPrivs.
4. `seccomp` — Seccomp mode, filter counts, and action availability.
5. `syscall-probe` — *(Opt-in: `--probe-syscalls`)* Audited zero-arg syscall sweep.
6. `lsm` — AppArmor, SELinux, Landlock ABI, and kernel lockdown state.
7. `ebpf` — Passive eBPF knobs and reachability evaluation.
8. `ebpf-load`, `ebpf-btf`, `ebpf-types` — *(Opt-in: `--probe-ebpf`)* Real `bpf()` probes.
9. `vmm` — CPUID, DMI tables, vsock, and hypervisor detection.
10. `sockets` — Container runtime UDS inspection.
11. `cgroup` — Cgroup hierarchy, controllers, and resource limits.
12. `mounts` — `/proc/self/mountinfo` parsing, staging mount detection, sensitive proc/sys masking, propagation tags, and host leaks.
13. `k8s` — Kubernetes service account and environment detection.
14. `kernel-config` — Passive config discovery, pure-Rust decompression, dual SHA-256, whitelist extraction.
15. `kernel-surface` — Passive attack surface checks (modules, kexec, `/dev/mem`, USMH, ACPI).
16. `kernel-exec` — *(Opt-in: `--probe-kernel-execution`)* Isolated boundary execution probe.
17. `runtime` — Composite container/host runtime verdict fusion.

### Rule Evaluation Model
- **Append-Only ID Space:** Rule IDs (`AMR-001` through `AMR-033`) are immutable and append-only.
- **Container Gating:** Container-specific rules (e.g., `AMR-002`, `AMR-005`, `AMR-019`, `AMR-031`, `AMR-032`, `AMR-033`) fire only when running inside a shared-kernel container. They stay silent under `Host` or VM-isolated verdicts (`firecracker`, `gVisor`, `kata`).
- **Path-Agnostic Capability & DAC Staging Invariants:** `AMR-030` (`staging-mount-unhardened`) does not rely on fragile directory name lists or path heuristics. It evaluates filesystem and mount security invariants:
  - Mount options: filesystem is writable (`rw`) and execution is permitted (`!noexec`).
  - $O(1)$ DAC writability: `fs.writable` confirms current process credentials can write to the mount target.
  - Severity ladder: bare host environments degrade to `Info` (and are suppressed under `verbose_only`), container environments report `Medium`, and containers combining missing `nodev` with `CAP_MKNOD` elevate to `High` (device node creation primitive).
- **Chained Bypass Suppression:** Composite rules prevent notification fatigue:
  - `AMR-028` (`kexec-module-lockdown-bypass`) fires when kexec replacement is open while direct module loading is blocked.
  - If direct module loading is **also** open (`AMR-023` fires), `AMR-028` is **strictly suppressed** because full Ring 0 access is already directly reported.
- **Honest Privilege Degradation:** Probes never guess state when privileges are lacking. Missing root or capability access degrades findings honestly to `info` with explanatory rationale.
---

## Toolchain & Platform Invariants

- **Language & Edition:** Rust edition 2024.
- **Static Musl Binaries:** Targets `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and `riscv64gc-unknown-linux-musl`.
- **Zero Dynamic C Dependencies:** Decompression is pure Rust (`flate2` with `miniz_oxide`/`rust_backend`). Hashing is pure Rust (`sha2`). System calls use `rustix` and `libc`.
- **Per-Architecture Syscall ABIs:** Syscall numbers are treated as arch ABIs, strictly maintaining per-architecture committed tables without dynamic assumptions.
