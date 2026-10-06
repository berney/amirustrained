# amirustrained

**Runtime introspection & LPE-posture reporter.** A modern Rust container-runtime
posture auditor from the local-privilege-escalation / hardening point of view: it
fuses kernel-interface, configuration, and execution-boundary probes (namespaces,
uidmap, capabilities, seccomp, LSM, eBPF, VMM, cgroup, sockets, k8s, kernel-config,
kernel-surface, runtime, and opt-in kernel-exec) into a single verdict:
what an attacker already inside your environment gains from it. The fingerprint is
evidence-scored, not socket-guessing: a `host` verdict means **not contained even
when podman/docker sockets are present** — a reachable runtime socket only proves a
daemon lives on this machine (an `environment:` note), never that we run inside it.
Read-only against the system, no root required (privilege-sensitive assessments
downgrade honestly to `info` instead of guessing), single static binary.
## Install

Prebuilt tarballs (one per supported CPU arch — each a static-pie musl ELF,
independent of the host libc):

```sh
tar -xzf amirustrained-0.3.0-x86_64-unknown-linux-musl.tar.gz   # CI "Release (musl)" artifact for your triple
./amirustrained --format markdown
```

From source:

```sh
cargo install --path .
# or just `cargo build` — .cargo/config.toml defaults the target to
# x86_64-unknown-linux-musl, so plain builds are already static musl ELFs under
# target/x86_64-unknown-linux-musl/{debug,release}/amirustrained. A debug build
# (opt-level z applies to release only) is fine for smokes; release is fat-LTO,
# single-codegen, stripped (~900 KiB).
```

> One-time prerequisite: `rustup target add x86_64-unknown-linux-musl` —
> `.cargo/config.toml` sets the musl target repo-wide, and a fresh toolchain
> without the target installed fails with E0463. Cross-building the other
> release arches additionally needs
> `rustup target add aarch64-unknown-linux-musl riscv64gc-unknown-linux-musl`
> (no system cross-gcc: those legs link with the toolchain's self-contained
> rust-lld, configured per-target in `.cargo/config.toml`).

## Supported CPU architectures

| target triple | `--probe-syscalls` sweep | CI |
|---|---|---|
| `x86_64-unknown-linux-musl` | ✔ audited 289-call sweep (native x86_64 table) | release + static check + artifact; all test gates |
| `aarch64-unknown-linux-musl` | ✔ 239-call sweep (asm-generic table) | release + static check + artifact |
| `riscv64gc-unknown-linux-musl` | ✔ 238-call sweep (asm-generic table) | release + static check + artifact |
| any other target | ✘ probe reports `Degraded("unsupported arch")`; the rest of the scan runs normally | out of matrix |

Every arch ships its own committed syscall-number table, generated per arch
from the libc crate's unistd constants (regeneration recipe documented beside
the tables in `src/probes/syscall_probe.rs`). Numbers are arch ABIs, not
constants — `mount` is 165 on x86_64 but 40 on asm-generic aarch64/riscv64 —
so an arch without a committed table gets the honest degraded probe instead
of a guessed sweep.

Emulated hosts: a qemu-user aarch64 smoke of the *plain* scan passes, but
`--probe-syscalls` must run on a real kernel — qemu-user (observed: 10.2.2)
crashes **inside the emulator** on the sweep's `reboot(0,0,0,0)` call
(EINVAL on any real kernel, magic-guarded by design), so it is not a
substitute for native testing of the sweep.

## Usage

```sh
amirustrained                                     # human-readable text report with 5-line identity header
amirustrained --compact                           # concise single-line findings (diffable mode, alias --terse)
amirustrained --probe-kernel-execution            # opt-in: audit ring 0 boundaries (finit_module, kexec, dev_mem; alias --probe-kernel)
amirustrained --verbose                           # show probe heartbeats, full config options, and hashes
amirustrained --format yaml                       # full report as block YAML
amirustrained --format json | jq '.findings[] | {rule, severity}'
amirustrained --fail-on high                      # CI gate: exit 1 at High+ (any|info|low|medium|high|critical)
amirustrained --probe-syscalls                    # opt-in: enumerate syscalls blocked by seccomp
amirustrained --probe-ebpf                        # opt-in: real bpf() probes — load + BTF/fentry + type sweep (see note)
amirustrained --probe-ebpf types                  # opt-in: sweep the 32 prog-type existence matrix only
amirustrained --probe-device-open                 # opt-in: empirically open() /dev/mem, /dev/kmem, /dev/port (see note)
amirustrained --yolo                              # maximum-info: every opt-in probe at once (expect HIDS alerts)
amirustrained -o report.sarif --format sarif      # for code-scanning pipelines
amirustrained --format markdown --no-color        # plain bytes even on a terminal
```

Six formats: `text` (default), `markdown`, `json`, `yaml`, `sarif`, `jsonl`.
`--format yaml` is the complete report model as strict block YAML (2-space
indent, PyYAML dash alignment; strings quoted only where a plain scalar could
change meaning) — piped output round-trips through `yaml.safe_load`.

### Terminal output & Identity Header

Default text scans begin with a 5-line Environment & Identity context header establishing
the host kernel, CPU architecture, OS distribution, user/group IDs, 64-bit capability bitmask,
sandboxing mitigations, and PID namespace visibility:

```text
Host:       Linux 6.8.0-142-generic (x86_64) | distro: Ubuntu 22.04.4 LTS | runtime: docker (confidence high)
Identity:   uid=0(root) gid=0(root) groups=0(root),10(wheel),998(docker)
Caps:       000001ffffffffff (all 41 caps) [eff=000001ffffffffff bnd=000001ffffffffff inh=0000000000000000]
Sandboxing: no_new_privs=0 seccomp=0(disabled) lockdown=none
Visibility: pid_ns=isolated (59 procs visible, pid 1="/sbin/fireworks-init", procfs hidepid=0)

CRIT AMR-001 container-socket-exposed: Container runtime API socket is reachable and writable
  why: The Docker/Podman API is served by the runtime daemon as root: whoever can write to the socket can create a container that mounts the entire host filesystem with full privileges — one API call from contained user to host root (the docker.sock exposure class, cf. CVE-2019-5736-era runtime escapes).
  fix: Remove the socket mount from the workload; if the API is genuinely needed, broker it through a least-privilege proxy (docker-socket-proxy) exposing only the required endpoints, and restrict which users may reach it.
    - sockets.found = [{"path":"/run/docker.sock","writable":true,"kind":"docker","info":null}] (known runtime socket paths)

HIGH AMR-002 privileged-container: Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement
  why: This is the `--privileged` signature: CAP_SYS_ADMIN plus no seccomp filter plus nothing confining the task with mandatory access control...
  fix: Drop `--privileged` and CAP_SYS_ADMIN; keep the runtime's default seccomp and AppArmor profiles...
    - capabilities.effective = ["cap_chown", ...] (/proc/<pid>/status)
    - seccomp.mode = "disabled" (/proc/<pid>/status)

12 findings (c1 h2 m5 l3 i1)
scan complete
```

In diffable mode (`--compact` or `--terse`), findings are collapsed to single lines while preserving
the Identity Header for clean diffs (`diff -u before.txt after.txt`):

```text
Host:       Linux 6.8.0-142-generic (x86_64) | distro: Ubuntu 22.04.4 LTS | runtime: docker (confidence high)
Identity:   uid=0(root) gid=0(root) groups=0(root),10(wheel),998(docker)
Caps:       000001ffffffffff (all 41 caps) [eff=000001ffffffffff bnd=000001ffffffffff inh=0000000000000000]
Sandboxing: no_new_privs=0 seccomp=0(disabled) lockdown=none
Visibility: pid_ns=isolated (59 procs visible, pid 1="/sbin/fireworks-init", procfs hidepid=0)

CRIT AMR-001 container-socket-exposed: Container runtime API socket is reachable and writable
HIGH AMR-002 privileged-container: Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement
HIGH AMR-023 kernel-module-loading-permitted: Kernel module loading is permitted: ring 0 execution accessible via finit_module/init_module or unconstrained modules

3 findings (c1 h2 m0 l0 i0)
```
## Colour

`text`, `markdown`, `json` and `yaml` paint their output with the OMP
**titanium** palette (severity ladder critical→red/high→amber/medium→gold/
low+info→dim aluminium; verdict host→bright aluminium, container→electric
blue, VM/sandbox→readout green; keys blue, quoted strings gold, scalars amber,
bool/null green). `--format text` fact lines from `--probe-ebpf` /
`--probe-syscalls` ride the same JSON tokeniser, and `--help`/parse errors
are styled too (blue section headers, green flags, gold placeholders,
red errors) — but colour appears only when **all** of:

- stdout is a terminal (piping to `jq`, a pager, or a file yields byte-identical plain bytes; `CLICOLOR_FORCE=1` forces the clap help/error stream),
- `--no-color` is not given (it silences the help/error stream as well),
- `NO_COLOR` is **absent** (mere presence counts, even `NO_COLOR=` — no-color.org),
- `TERM` is not `dumb`.

`jsonl` and `sarif` are machine streams and never paint. `-o FILE` never
paints. Truecolor (`38;2;r;g;b`) is the only emission mode. Colour changes
presentation only: exit codes and document semantics are identical on and off.

`--probe-syscalls` risk note: it *executes* ~289 zero-argument syscalls on
x86_64 (239 on aarch64, 238 on riscv64 — per-arch committed tables; other
arches execute nothing) to see which return `EPERM`/`EACCES`. The list is
audited and hang/EPERM-safe, but the binary must
**not** be installed setuid-root or with file capabilities: under such a launch the
zero-arg credential syscalls would succeed and convert the process's real/saved ids
to root. Nothing in this project packages those bits.

`--probe-ebpf` risk & cleanup note: targets are `load`, `btf`, `types` (comma list;
a bare flag means `all`). The `load` verdict rests on one real `bpf(BPF_PROG_LOAD)`
with a tracepoint program embedded in the binary (`bpf/prebuilt/hello.bpf.o`: zero maps,
zero helpers, never attached — it can never execute); aya's lazy, once-per-process
kernel feature detection additionally issues a handful of transient bpf() calls (up to
nine BTF loads, five trivial probe prog-loads, three map creates, one link-create
attempt) whose fds all close inside the call. `types` sweeps all 32 `BPF_PROG_TYPE_*`
ids with the same two-instruction program — existence evidence only, no attach. `btf`
loads a minimal in-memory BTF object, then `/sys/kernel/btf/vmlinux` verbatim, then
resolves `vfs_read` offline and attempts a real fentry load (`BPF_PROG_TYPE_TRACING` +
`BPF_TRACE_FENTRY` + `attach_btf_id`) — never attached, fd closed immediately, no BTF
object outlives the process.
A load **succeeds** only if this
process may load programs: CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN, i.e. effectively root;
every refusal is decoded into `ebpf.load` (`eperm-no-caps`, `eperm-unpriv-disabled`,
`eacces-lsm`, `eopnotsupp`, `verifier-reject`, …) instead of a bare error. Nothing is
ever pinned under `/sys/fs/bpf`: the program fd closes on drop right after the verdict,
and even a crash closes it at process exit, so the kernel frees the program — no
leftover state is structurally possible and no unload CLI exists. Rebuilding the
embedded object is a nightly-only contributor path (`bash bpf/build.sh`); the normal
stable/musl build just embeds the committed artifact.

`--probe-kernel-execution` (alias `--probe-kernel`) risk & isolation note: actively tests
kernel-mode execution boundaries (`finit_module`, `init_module`, `kexec_file_load`, `kexec_load`,
and on x86 `iopl`). All tests strictly invoke kernel-validated boundary arguments (`finit_module(-1)`,
`init_module(NULL)`, `kexec_file_load(-1)`, `kexec_load(ULONG_MAX)`, `iopl(3)`) that fail
deterministically before mutating kernel state. The probe executes inside an isolated forked worker
process under a 5-second deadline; any hanging worker is terminated via `SIGKILL` without affecting
the main scan. When all tested entry points are confirmed closed or restricted, rule AMR-029
affirmatively reports the verified boundary status.

`--probe-device-open` risk note: the probe issues a real `open(2)` against `/dev/mem`,
`/dev/kmem`, and `/dev/port` (`O_RDONLY`; the fd closes immediately - nothing is read,
written, or mapped) inside an isolated forked worker under a 5-second deadline. The
syscall mutates no state, but the open itself is HIDS/EDR bait: Falco ships rules that
alert on `/dev/mem` opens regardless of any read. That is why it is off by default. When
it does run, its empirical verdict (`permitted`/`denied`/`absent`/`unsupported`) outranks
the passive `access(2)`-derived `kernel.surface.dev_*` facts in AMR-025 in both directions:
a node with no driver behind it (gVisor answers `open()` with `ENXIO`) is no raw-memory
pathway, and a node that opens while its DAC bits read denied is one. In VM-family
verdicts (firecracker, gVisor, kata) AMR-025 never mints a Critical from the passive
`access(2)` leg alone: an identical DAC reading comes either from a genuinely openable
guest device (a Firecracker guest really does hand root guest RAM) or from a driverless
pseudo-node, so unverified findings surface at `Info` until `--probe-device-open`
settles them - a verified permitted open is Critical anywhere, because raw *guest*
memory is kernel-equivalent access to the platform the hypervisor must defend.

`--yolo` is the maximum-info switch: it turns on `--probe-syscalls`,
`--probe-kernel-execution`, `--probe-device-open`, and every `--probe-ebpf` target (an
explicit `--probe-ebpf` subset stays authoritative). It will trip runtime monitoring by
design; run it only where active reconnaissance is authorized.

`--fixture-root <DIR>` (hidden, for tests) relocates every pseudo-file read under
`<DIR>/proc`, `<DIR>/sys`, … — the whole fixture corpus (11 scenarios, golden tests)
runs on it.

## Probes & privilege

| probe | unprivileged | root | degrades when |
|---|---|---|---|
| `namespaces` | own `/proc/self/ns/*`, container markers | + pid-1 ns comparison | hardened host with unreadable pid-1 namespaces ⇒ `degraded` (comparison skipped, scan stays complete) |
| `uidmap` | own `uid_map`/`gid_map`/`setgroups` | — | files absent (no userns support) |
| `capabilities` | own all 6 cap sets, NoNewPrivs, Yama scope | + other `--pid` targets | Yama knob absent |
| `seccomp` | mode, filter count, action matrix | + raw BPF filter dump (`SECCOMP_GET_FILTER`) | pre-4.14 kernel ⇒ mode-only |
| `lsm` | LSM list, AppArmor/SELinux state, lockdown, Landlock ABI | — | each knob reported present/absent independently |
| `ebpf` | `unprivileged_bpf_disabled` + lockdown knobs; computed bpf() reachability (zero syscalls — the real load probe is the opt-in `--probe-ebpf`) | — | capabilities facts absent ⇒ `reachability` degraded (knobs still reported) |
| `vmm` | CPUID, DMI (public fields), clocksource, vsock | — | restricted DMI ⇒ fewer signatures |
| `cgroup` | own cgroup path, controllers, limits | — | v1 or v2, both handled |
| `mounts` | `/proc/self/mountinfo` parsing, staging mount detection, sensitive proc/sys masking, propagation tags, host leaks | — | unreadable mountinfo ⇒ legacy `/proc/mounts` fallback |
| `sockets` | candidate socket probe + `GET /info` over UDS | — | socket absent/unwritable ⇒ quiet (environment-only evidence) |
| `k8s` | env vars, serviceaccount dir | — | outside a pod ⇒ silent |
| `runtime` | composite fusion of all the above | — | low-confidence verdict ⇒ AMR-015 tells you to audit manually |
| `kernel-config` | discover `/proc/config.gz`, `/boot/config-*`, `/proc/config` | — | no config found ⇒ `degraded` (pure-Rust decompression + dual SHA-256) |
| `kernel-surface` | sysctl (`modules_disabled`, `kexec_load_disabled`), lockdown, `/dev/mem`, USMH, ACPI | + test open | unreadable paths ⇒ reported independently |
| `device-open` | *(opt-in: `--probe-device-open`)* real `open()` test of `/dev/mem`, `/dev/kmem`, `/dev/port` in an isolated worker (`O_RDONLY`, immediate close, never read/mapped) | - | worker timeout (5s) => `degraded`; verdicts are never inferred |
| `kernel-exec` | *(opt-in: `--probe-kernel-execution`)* isolated worker testing `finit_module`, `init_module`, `kexec_file_load`, `kexec_load`, `iopl` | + elevated capabilities | worker timeout (5s) ⇒ `degraded` |

`--probe-syscalls` adds the `syscall-probe` event to the stream (see risk note above).
`--probe-ebpf` adds the selected `ebpf-load`, `ebpf-btf` and/or `ebpf-types` events
(fact namespaces `ebpf.load`, `ebpf.btf`, `ebpf.types`); all touch `bpf(2)`, and only
`load` success arms AMR-021. `btf` reports the `btfSyscall`/`vmlinuxBtf`/`fentry`
layering; `types` reports `loadable`/`absent`/`denied`/`rejected` per prog type.
`--probe-kernel-execution` adds the `kernel-exec` event (fact namespace `kernel.exec`)
evaluating Ring 0 execution pathways; safe closure triggers AMR-029.
`--probe-device-open` adds the `device-open` event (fact namespace `kernel.device_open`)
carrying the `permitted`/`denied`/`absent`/`unsupported` verdicts that AMR-025 prefers over
the passive DAC facts; `--yolo` fans all of the above opt-ins on at once.


## Exit codes

| code | meaning |
|---|---|
| 0 | scan completed — findings alone never change the exit code |
| 1 | `--fail-on <LEVEL>` threshold tripped |
| 2 | CLI misuse (bad `--format`/`--fail-on`) or output-IO failure |
| 3 | internal error (a bug; probes must never produce this) |

`scan.complete` is `true` only when the scan reaches its summary with no probe
timed out: a per-probe timeout (`--probe-timeout`) yields a `timed_out` probe and
`complete: false` while the scan continues (spec §5). Degraded or unavailable
probe facts (e.g. `namespaces` on a hardened host) stay visible in each probe's
`availability` and never flip the scan to incomplete.

## Rule catalog (v0.3.0)
Severity = how much closer to host root the state puts an attacker already inside
the environment. Container-gated rules stay silent unless the verdict is a
shared-kernel containment — i.e. at a `host` verdict and at VM-family verdicts
(firecracker, gVisor, kata), where the guest kernel/identity makes the
finding's rationale false (spec §6 erratum 2026-10-01). Rules needing root
report `info` + "insufficient privilege to assess" when run unprivileged.

| id | slug | severity | summary |
|---|---|---|---|
| AMR-001 | `container-socket-exposed` | critical | Container runtime API socket is reachable and writable (root peer; unknown peer is treated as root — a confirmed-rootless peer is AMR-022) |
| AMR-002 | `privileged-container` | high | Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement — AppArmor `complain` mode counts as unconfining (log-only; only `enforce`/`kill` veto the combo) |
| AMR-003 | `cap-sys-module` | high | CAP_SYS_MODULE in the effective capability set (contained process; module load ⇒ host root on unlocked kernels) |
| AMR-004 | `host-pid-ns-ptraceable` | high | Host PID namespace with ptrace access to host processes |
| AMR-005 | `seccomp-disabled-in-container` | medium | Seccomp filter disabled inside a container |
| AMR-006 | `apparmor-unconfined-in-container` | medium | AppArmor mandatory access control not applied inside a container |
| AMR-007 | `selinux-permissive-in-container` | medium | SELinux context present while the policy runs permissive |
| AMR-008 | `identity-uidmap` | medium | User namespace keeps no identity isolation: uid_map is the full identity mapping |
| AMR-009 | `cgroup-v1-container` | low | Container runs on the legacy cgroup v1 hierarchy |
| AMR-010 | `no-pids-limit` | low | pids controller present but unlimited (pids.max = max) |
| AMR-011 | `gid-map-includes-0` | medium | gid_map maps host gid 0 while setgroups is not denied |
| AMR-012 | `landlock-abi-available` | info | Landlock LSM available in this kernel (ABI version reported) — presence-only, "unused" is never claimed |
| AMR-013 | `virtualized` | info | Running on a hypervisor (VMM boundary detected) |
| AMR-014 | `strong-isolation-runtime` | info | Running inside a strong-isolation runtime (firecracker, gVisor, or kata) |
| AMR-015 | `unrecognized-runtime` | info | Runtime verdict is low-confidence: identify the environment manually |
| AMR-016 | `cap-sys-admin-no-combo` | medium | CAP_SYS_ADMIN held while some runtime restraints remain active (complement of AMR-002's amended combo — a `complain` profile is never counted as a restraint) |
| AMR-017 | `cgroupns-host` | info | Container shares the host cgroup namespace |
| AMR-018 | `no-new-privs-unset` | low | NoNewPrivs unset: execve can still gain privileges |
| AMR-019 | `bpf-unpriv-open` | medium | Inside a shared-kernel container and unprivileged_bpf_disabled is 0 (or absent pre-5.13): any local uid can reach bpf() from a weak foothold — shares the container gate, so VM-family verdicts are exempt (guest bpf() is guest-kernel-local; spec §6 erratum 2026-10-01) |
| AMR-020 | `cap-bpf-or-perfmon` | low | CapEff includes CAP_BPF or CAP_PERFMON: program load / map read possible without full root |
| AMR-021 | `ebpf-load-succeeded` | high | `--probe-ebpf` only: trivial program load succeeded while in a shared-kernel container — `bpf()` reachable past seccomp/LSM/cap drops; kernel attack surface confirmed open *(same container gate: silent at Host verdicts — root loading is ordinary there — and at VM-family verdicts — the program lands in the guest kernel; spec §6 erratum 2026-10-01)* |
| AMR-022 | `rootless-socket-exposed` | high | Rootless container runtime API socket is reachable and writable (escape to an unprivileged host uid — not a host-root promise) |
| AMR-023 | `kernel-module-loading-permitted` | high | Kernel module loading is permitted: ring 0 execution accessible via finit_module/init_module or unconstrained modules |
| AMR-024 | `kexec-kernel-replacement-permitted` | high | Kexec kernel replacement is permitted: new kernel image can be loaded and booted directly into ring 0 |
| AMR-025 | `raw-memory-access-permitted` | critical / info | Raw physical memory or port I/O access is permitted via /dev/mem, /dev/kmem, or iopl (under VM-family verdicts the claim is raw *guest* memory - an empirically permitted `--probe-device-open` open or granted iopl is Critical, an unverified passive DAC reading degrades to Info because the node may be driverless; spec §6 erratum lineage) |
| AMR-026 | `user-mode-helper-writable` | high | Kernel user-mode helper path (core_pattern or modprobe) is writable |
| AMR-027 | `acpi-table-injection-writable` | high | ACPI table customization interface (/sys/kernel/config/acpi/table) is writable |
| AMR-028 | `kexec-module-lockdown-bypass` | high | Kexec kernel replacement is permitted while kernel module loading is blocked (lockdown bypass; suppressed when AMR-023 fires) |
| AMR-029 | `kernel-execution-probe-report` | info | Active kernel execution probe confirmed all tested ring 0 pathways are closed or restricted |
| AMR-030 | `staging-mount-unhardened` | medium / info | Writable mount allows code execution and device creation (Info on bare host; High with CAP_MKNOD in container) |
| AMR-031 | `sensitive-proc-sys-unmasked` | high | Sensitive /proc or /sys pseudo-filesystem paths are unmasked or writable inside container |
| AMR-032 | `shared-mount-propagation` | medium | Container mount carries shared or master mount propagation flags |
| AMR-033 | `host-filesystem-exposed` | critical | Host root filesystem or system control directories are mounted directly inside container |

*Notes:* the 33-id catalog (v0.3.0) is complete; the id-space is append-only. AMR-021
and AMR-029 are rules whose evidence requires opt-in probes (`--probe-ebpf` and
`--probe-kernel-execution` respectively): without the corresponding flag the fact never
exists and the rule can never fire. AMR-028 is a chained bypass rule that triggers when
kexec kernel replacement is open while module loading is blocked, but is suppressed when
direct module loading (AMR-023) is already open to avoid redundant alerts. AMR-030 through
AMR-033 audit mount sandboxing and filesystem isolation: AMR-030 detects staging mounts
(rw + !noexec + fs.writable), silenced in default human terminal output on bare hosts via
`Rule.verbose_only`; AMR-031 flags unmasked/writable sensitive pseudo-filesystem paths in
containers; AMR-032 flags shared/master propagation; and AMR-033 flags host root or host
control directory leaks into containers.

## Development
```sh
cargo test --all          # unit + CLI + 9-scenario fixture corpus (musl default target)
cargo build --release --target aarch64-unknown-linux-musl    # cross-free (self-contained rust-lld)
cargo build --release --target riscv64gc-unknown-linux-musl  # ditto; CI builds all three
scripts/live-smoke.sh                       # smoke the debug binary
PROFILE=release scripts/live-smoke.sh       # …or the release binary
```

The smoke script builds on demand, runs the json/jsonl/sarif/markdown formats
plus `--probe-syscalls`, and asserts the JSON contract (`schemaVersion 1`,
`scan.complete`, all twelve default probes with `runtime` emitting the verdict,
SARIF 2.1.0). Its `--fail-on high ⇒ 1 / critical ⇒ 0` exit-code asserts are
**this-host** posture claims, so it is a local smoke, not portable CI.

### Live runtime matrix

Run the latest working-tree binary inside a real isolation runtime. Each
`scripts/live/<env>.sh` leaf rebuilds (unless `BIN` is set), then forwards its
arguments to amirustrained, passing stdout, stderr and the exit code straight through:

```sh
scripts/live/gvisor.sh --compact                # one env, any amirustrained args
scripts/live/firecracker.sh --format json | jq .verdict
scripts/live/firecracker.sh check               # "available" (0) | "unavailable: <why>" (3)
scripts/live/firecracker.sh setup               # fetch assets into ~/.cache/amirustrained/live-matrix
scripts/live/gvisor.sh shell                    # poke around: interactive shell, $AMR / `amirustrained` on PATH
scripts/live/gvisor.sh shell -- cat /proc/self/status   # or one command, exit code passed through
scripts/live-matrix.sh list                     # every env + availability (aligned; TSV when piped)
scripts/live-matrix.sh run all                  # full 7-view sweep -> target/live-matrix/<env>/
scripts/live-matrix.sh summary                  # markdown comparison tables
cargo test --test live_matrix -- --ignored      # verdict + container-gating asserts per env
```

Envs: `host`, `docker-default`, `docker-privileged`, `bubblewrap`, `unshare`,
`gvisor` (engine `--runtime=runsc`), `gvisor-rootless`, `gvisor-sudo`, `firecracker`.
`docker-*` use `docker` or podman (`CONTAINER_ENGINE` overrides). Firecracker runs
rootless with a writable `/dev/kvm`: the rootfs is attached read-only and the binary
and result travel over raw scratch drives. Unavailable envs exit 3 and are skipped by
`run all` and the cargo tests (`AMR_LIVE_REQUIRE=1` makes them fail).
`.github/workflows/live-matrix.yml` runs the same scripts after `setup --system`
(sudo host prep: apt, sysctl, `runsc install`, `/dev/kvm` perms).

## Security notes

The binary is read-only with respect to the system: it never writes files (except
`-o`), never changes kernel state. The only syscalls with any effect are the opt-in
`--probe-syscalls` null-arg probes, `seccomp(GET_ACTION_AVAIL)` (inert),
`--probe-ebpf` `bpf(BPF_PROG_LOAD)` attempts (plus aya's one-time feature
detection: a few transient bpf() calls, all fds closed immediately; `btf` additionally
loads BTF objects into the kernel's in-memory table, freed at process exit), and
`kexec_file_load(-1)`, `kexec_load(ULONG_MAX)`, `iopl(3)`), and
`--probe-device-open` `open(2)`+`close()` round-trips on the raw memory/port devices
(`O_RDONLY`, fd dropped inside the worker; never read, written, or mapped).

Boundary execution probing runs inside an isolated forked worker child with a 5-second
deadline; any hung or unresponsive child is forcefully killed with `SIGKILL`. The boundary
arguments ensure the kernel performs privilege checks and fails deterministically before
any state can mutate. Programs are never pinned, never attached, and fd-dropped before
the process exits.
Findings are evidence-cited facts, and anything the tool cannot assess at the
current privilege level says so instead of overclaiming. Architectural contracts and
core tenets are permanently codified in `AGENTS.md`.
