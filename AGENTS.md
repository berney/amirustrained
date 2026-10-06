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
- **Observable Outcomes:** Probes requiring active, privilege-sensitive operations or syscall invocations (`--probe-syscalls`, `--probe-ebpf`, `--probe-kernel-execution`, `--probe-device-open`) require explicit opt-in CLI flags; `--yolo` turns every opt-in on at once (an explicit `--probe-ebpf` subset stays authoritative).
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
16. `device-open` — *(Opt-in: `--probe-device-open`)* Empirical `open()` test of the raw memory/port devices (`/dev/mem`, `/dev/kmem`, `/dev/port`) in an isolated forked worker; off by default because the `open(2)` itself trips HIDS rules (Falco alerts on `/dev/mem` opens).
17. `kernel-exec` — *(Opt-in: `--probe-kernel-execution`)* Isolated boundary execution probe.
18. `runtime` — Composite container/host runtime verdict fusion.

### Rule Evaluation Model
- **Append-Only ID Space:** Rule IDs (`AMR-001` through `AMR-033`) are immutable and append-only.
- **Container Gating:** Container-specific rules (e.g., `AMR-002`, `AMR-005`, `AMR-019`, `AMR-031`, `AMR-032`, `AMR-033`) fire only when running inside a shared-kernel container. They stay silent under `Host` or VM-isolated verdicts (`firecracker`, `gVisor`, `kata`).
- **Raw-Memory Ground Truth (`AMR-025`):** The claim is about the kernel *behind* the device node, and it never goes silent: raw memory is a finding wherever it is real, because readable raw *guest* memory is kernel-equivalent access to the platform the hypervisor must defend (the fallback primitive when module loading and kexec are closed). What VM-isolated verdicts (`firecracker`, `gVisor`, `kata`) change is trust in the *passive* leg: `access(2)` cannot distinguish a genuinely openable guest device (Firecracker hands root guest RAM) from a driverless pseudo-node (gVisor answers `open()` with `ENXIO` - the reproduced false-positive class), so an unverified passive reading under such a verdict is honestly degraded to `Info`. An empirically permitted `--probe-device-open` open - or granted `iopl(2)` - is Critical under every verdict, and `permitted` fires even where DAC read denied; `denied`/`absent`/`unsupported` close even where DAC read accessible; only `error` (worker timeout/IPC failure) is inconclusive and defers to the passive verdict.
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

---

## Live Runtime Verification

Run the real binary inside real isolation runtimes. Everything lives in `scripts/live/` (one leaf script per runtime plus shared `lib.sh`), `scripts/live-matrix.sh`, `scripts/live-matrix-summary.py`, and `tests/live_matrix.rs`; you do not need to read them to use them.

### Running one runtime
```sh
scripts/live/<env>.sh [AMIRUSTRAINED ARGS...]   # e.g. scripts/live/gvisor.sh --compact
scripts/live/<env>.sh check                     # "available" (exit 0) | "unavailable: <why>" (exit 3)
scripts/live/<env>.sh setup [--system]          # fetch assets to ~/.cache/amirustrained/live-matrix; --system = sudo host prep (CI)
scripts/live/<env>.sh label                     # human label
scripts/live/<env>.sh shell                     # interactive shell in the env, binary staged as usual
scripts/live/<env>.sh shell -- CMD [ARGS...]    # run CMD in the env instead (non-interactive; agents use this)
```
- Args pass straight to amirustrained; stdout, stderr and exit code are amirustrained's own (e.g. `scripts/live/firecracker.sh --format json | jq .verdict`). Exit `3` = runtime unavailable here: "not testable", never a pass.
- `shell` uses the same staging, then runs a shell or `CMD` instead of amirustrained. `$AMR` is the in-env binary path and its directory is first on `PATH`, so `amirustrained --compact` works inside. Exit codes pass through (e.g. `scripts/live/gvisor.sh shell -- sh -c 'uname -r; amirustrained --format json'`). The interactive shell skips rc files and prompts `[live/<env>]`. In Firecracker it runs on the guest serial console and the VM reboots when you exit.
- `BIN` unset: the leaf runs `cargo build` first (sub-second no-op), so it always tests the working tree. `BIN=path` tests a given binary. `PROFILE=release` switches the build. Other knobs: `CONTAINER_ENGINE` (docker|podman), `IMAGE` (default `alpine:latest`), `AMR_LIVE_CACHE`, `FC_TIMEOUT` (default 120s), `AMR_FC_CONSOLE=1` (dump the guest console to stderr).

| env | runs the binary via | expected verdict |
| :--- | :--- | :--- |
| `host` | directly | `host` |
| `docker-default` / `docker-privileged` | `docker run --rm [--privileged]` (podman when `docker` is podman) | `docker` or `podman` |
| `bubblewrap` | `bwrap --ro-bind / / --unshare-all ...` | `host` |
| `unshare` | `unshare --user --pid --mount --fork --map-root-user` | `host` |
| `gvisor` | container engine with `--runtime=runsc` | `gvisor` |
| `gvisor-privileged` | container engine with `--privileged --runtime=runsc`. Unavailable under rootless podman: its `--privileged` bind-mounts every host device and runsc fails with "FD 253 is already in use" | `gvisor` |
| `gvisor-rootless` | `runsc --rootless --network=none do` | `gvisor` |
| `gvisor-sudo` | `sudo -n runsc --network=none do` (needs passwordless sudo) | `gvisor` |
| `firecracker` | rootless microVM (needs read/writable `/dev/kvm`) | `firecracker` |

### Matrix, cargo tests, CI
- `scripts/live-matrix.sh list` prints env, status, label and reason: aligned columns on a terminal, TSV when stdout is piped (parse the piped form). `run [--skip-unavailable] <env>...|all` writes `target/live-matrix/<env>/` with a `status` file (`ok` | `skipped: <why>` | `failed: <why>`), seven human views (`standard.txt`, `compact.txt`, `verbose.txt`, `active.txt` = `--compact --probe-kernel-execution --probe-syscalls`, `report.md`, `report.yaml`, `yolo.txt` = `--compact --yolo`, each with a `.stderr`), and `result.json`. The views come from `MODES` in `scripts/live-matrix.sh`, which local runs and CI share. Only `result.json` must succeed and parse. `all` implies skipping unavailable envs. `summary [DIR]` prints the markdown comparison tables.
- `cargo test --test live_matrix -- --ignored [name]` runs one `#[ignore]` test per env. Each test asserts `schemaVersion`, `scan.complete`, the expected verdict, the container-only rules silent under host/gVisor/Firecracker, and `AMR-014` under gVisor/Firecracker. Unavailable envs are skipped with a stderr note; `AMR_LIVE_REQUIRE=1` turns skips into failures. Plain `cargo test` never starts runtimes.
- `.github/workflows/live-matrix.yml` legs run `setup --system <envs>` (apt bwrap, AppArmor userns sysctl, install runsc and `runsc install` for docker, `chmod /dev/kvm`), then `BIN=bin/amirustrained scripts/live-matrix.sh run <envs>`, and upload `target/live-matrix/`. The summary job merges the uploads and calls `summary`. The gVisor leg covers `gvisor`, `gvisor-privileged`, `gvisor-sudo` and `gvisor-rootless`. Firecracker uses `--skip-unavailable` and records a skip when the runner lacks KVM; never fabricate a result.
- For detection or rule-gating changes, run the cargo live tests (filter to the affected env) and quote the observed verdicts.

### Extending and gotchas
- New runtime = new `scripts/live/<env>.sh` (set `LABEL`, define `env_check` (print the reason when unavailable), `env_launch` (run `"$BIN" "$@"`), optional `env_setup`, end with `leaf_main "$@"`) + `ENVS` entry in `scripts/live-matrix.sh` (order = summary column order) + `live!` row in `tests/live_matrix.rs` + a CI matrix leg. Keep `shellcheck -x scripts/live-matrix.sh scripts/live/*.sh` and `actionlint` clean.
- SELinux plus rootless podman cannot read a bind-mounted binary from `target/`, and the process dies with SIGSEGV (exit 139), which looks like a product crash. `container_run` in `lib.sh` copies the binary to a temp dir and mounts it `:z`. Reuse that helper rather than mounting `$BIN` directly. Do not use `label=disable` except for the runsc-under-podman case, which requires it.
- Firecracker: the cached Ubuntu rootfs is attached read-only and never mutated. The guest init script, the binary and a result tarball travel over raw drives `vdb`/`vdc`/`vdd`; init is `/bin/sh /dev/vdb`, so the scan reports that as PID 1. One boot per invocation, about 2s.
