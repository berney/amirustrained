# amirustrained

**Runtime introspection & LPE-posture reporter.** A modern Rust container-runtime
posture auditor from the local-privilege-escalation / hardening point of view: it
fuses eleven kernel-interface probes (namespaces, uidmap,
capabilities, seccomp, LSM, eBPF, VMM, cgroup, sockets, k8s, runtime) into a single verdict:
what an attacker already inside your environment gains from it. The fingerprint is
evidence-scored, not socket-guessing: a `host` verdict means **not contained even
when podman/docker sockets are present** — a reachable runtime socket only proves a
daemon lives on this machine (an `environment:` note), never that we run inside it.
Read-only against the system, no root required (privilege-sensitive assessments
downgrade honestly to `info` instead of guessing), single static binary.

## Install

Prebuilt tarball (any x86_64 Linux host — the binary is a static-pie musl ELF,
independent of the host libc):

```sh
tar -xzf amirustrained-0.1.0-x86_64-musl.tar.gz   # from the CI "Release (musl)" artifact
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
> without the target installed fails with E0463.

## Usage

```sh
amirustrained                                  # human-readable text report
amirustrained --format json | jq '.findings[] | {rule, severity}'
amirustrained --fail-on high                   # CI gate: exit 1 at High+ (any|info|low|medium|high|critical)
amirustrained --probe-syscalls                 # opt-in: enumerate syscalls blocked by seccomp
amirustrained -o report.sarif --format sarif   # for code-scanning pipelines
```

`--probe-syscalls` risk note: it *executes* ~289 zero-argument syscalls to see which
return `EPERM`/`EACCES`. The list is audited and hang/EPERM-safe, but the binary must
**not** be installed setuid-root or with file capabilities: under such a launch the
zero-arg credential syscalls would succeed and convert the process's real/saved ids
to root. Nothing in this project packages those bits.

`--fixture-root <DIR>` (hidden, for tests) relocates every pseudo-file read under
`<DIR>/proc`, `<DIR>/sys`, … — the whole fixture corpus (9 scenarios, golden tests)
runs on it.

## Probes & privilege

| probe | unprivileged | root | degrades when |
|---|---|---|---|
| `namespaces` | own `/proc/self/ns/*`, container markers | + pid-1 ns comparison | hardened host with unreadable pid-1 namespaces ⇒ `degraded` (comparison skipped, scan stays complete) |
| `uidmap` | own `uid_map`/`gid_map`/`setgroups` | — | files absent (no userns support) |
| `capabilities` | own all 6 cap sets, NoNewPrivs, Yama scope | + other `--pid` targets | Yama knob absent |
| `seccomp` | mode, filter count, action matrix | + raw BPF filter dump (`SECCOMP_GET_FILTER`) | pre-4.14 kernel ⇒ mode-only |
| `lsm` | LSM list, AppArmor/SELinux state, lockdown, Landlock ABI | — | each knob reported present/absent independently |
| `ebpf` | `unprivileged_bpf_disabled` + lockdown knobs; computed bpf() reachability (zero syscalls — the real load probe is the future `--probe-ebpf`) | — | capabilities facts absent ⇒ `reachability` degraded (knobs still reported) |
| `vmm` | CPUID, DMI (public fields), clocksource, vsock | — | restricted DMI ⇒ fewer signatures |
| `cgroup` | own cgroup path, controllers, limits | — | v1 or v2, both handled |
| `sockets` | candidate socket probe + `GET /info` over UDS | — | socket absent/unwritable ⇒ quiet (environment-only evidence) |
| `k8s` | env vars, serviceaccount dir | — | outside a pod ⇒ silent |
| `runtime` | composite fusion of all the above | — | low-confidence verdict ⇒ AMR-015 tells you to audit manually |

`--probe-syscalls` adds the `syscall-probe` event to the stream (see risk note above).

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

## Rule catalog (v1)

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
| AMR-022 | `rootless-socket-exposed` | high | Rootless container runtime API socket is reachable and writable (escape to an unprivileged host uid — not a host-root promise) |

*Notes:* the one remaining planned id is AMR-021 (eBPF program load), which will
fire only when the opt-in `--probe-ebpf` load probe succeeds; the id-space is
append-only.

## Development

```sh
cargo test --all          # unit + CLI + 9-scenario fixture corpus (musl default target)
scripts/live-smoke.sh                       # smoke the debug binary
PROFILE=release scripts/live-smoke.sh       # …or the release binary
```

The smoke script builds on demand, runs all five formats plus
`--probe-syscalls`, and asserts the JSON contract (`schemaVersion 1`,
`scan.complete`, all eleven default probes with `runtime` emitting the verdict, SARIF
2.1.0). Its `--fail-on high ⇒ 1 / critical ⇒ 0` exit-code asserts are
**this-host** posture claims, so it is a local smoke, not portable CI.

## Security notes

The binary is read-only with respect to the system: it never writes files (except
`-o`), never changes kernel state. The only syscalls with any effect are the opt-in
`--probe-syscalls` null-arg probes and `seccomp(GET_ACTION_AVAIL)`, which is inert.
Findings are evidence-cited facts, and anything the tool cannot assess at the
current privilege level says so instead of overclaiming.
