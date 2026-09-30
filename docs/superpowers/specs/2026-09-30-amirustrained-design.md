# amirustrained — Design Specification

Date: 2026-09-30
Status: draft for review
Author: bdawg + omp (brainstorming session)

## 1. Overview

`amirustrained` (pun: *restrained* / *Rust*) is a modern Rust rewrite in the spirit of
`amicontained`: a single static binary that introspects the **runtime environment it is
running in** and reports how locked-down (or not) that environment is, from a Linux
local-privilege-escalation (LPE) perspective.

It answers, for security audits, pentests, and red-team engagements:

- What runtime am I inside? (docker, podman rootless, Kubernetes pod, containerd/CRI-O,
  LXC, systemd-nspawn, firecracker, gVisor, kata, plain host…)
- How is it restrained? (namespaces, uid/gid maps, capabilities, seccomp, AppArmor /
  SELinux / Landlock, cgroup context, VMM layer, management sockets)
- What does that mean? (derived findings with stable rule IDs and severities, plus raw
  facts so consumers can re-derive their own verdicts)

It is **runtime state only**. It does not hunt for distro-level LPEs, CVEs, SUID
binaries, or vulnerable packages. It observes; it never remediates.

## 2. Decisions from brainstorming

| Topic | Decision |
|---|---|
| Deployment | Capability-aware drop-binary: one static musl binary (amd64 + arm64); every probe degrades gracefully when unprivileged, enriches under root. |
| Scope | "Parity+" — amicontained parity plus VMM detection, modern runtimes (podman/CRI-O/k8s/firecracker/gVisor/kata), own-cgroup context, LSM matrix. |
| Syscall enumeration | Safe introspection by default; amicontained-style null-arg brute-force only behind explicit `--probe-syscalls`. |
| eBPF audit | Exposure knobs read always; a real program load only behind `--probe-ebpf`. `aya` + embedded object (compiled with `bpf-linker` in the release build); ships as the same single static binary. |
| Output | Facts + findings, two layers; formats `text` (default), `markdown`, `json`, `sarif` (findings-only), `jsonl` (streaming). |
| Streaming | Event-stream pipeline so partial results survive probe hangs and mid-scan SIGKILL. |

### Non-goals (v1)

- Full runtime sysctl hardening audit (`kptr_restrict`, `dmesg_restrict`, …) — deferred
  tier. Exception: single-knob reads a specific rule needs (Yama `ptrace_scope`) are
  in scope; they are rule inputs, not an audit.
- Mount/rootfs analysis (overlayfs, masked paths, ro-root) — deferred tier.
- Whole-host cgroup tree (only own cgroup in v1).
- Recursive filesystem socket hunt (amicontained walks `/`; we probe known paths only).
- Escape proof-of-concepts / exploitation of any kind.
- Non-Linux platforms; other init systems; config-file auditing.

## 3. CLI surface

```
amirustrained [OPTIONS]

      --format <FORMAT>     text (default) | markdown | json | sarif | jsonl
      --probe-syscalls      enable execution-based seccomp syscall enumeration (opt-in)
      --probe-ebpf          attempt a real trivial eBPF program load (opt-in; needs privileges)
  -o, --output <FILE>       write to file instead of stdout
      --pid <PID>           inspect another process (root required; default: self)
      --probe-timeout <S>   per-probe timeout in seconds (default: none)
      --fail-on <LEVEL>     exit 1 if a finding at LEVEL or above exists: any|medium|high|critical
                            ("any" = any severity, including info)
      --no-color            disable color in text output
  -v, --verbose             per-probe progress lines (text only)
      --fixture-root <DIR>  hidden; relocates all pseudo-file reads for testing
  -h, --help, -V, --version
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Scan completed (findings alone never change the exit code) |
| 1 | `--fail-on` threshold tripped |
| 2 | CLI misuse or output-IO failure |
| 3 | Internal error (a bug; probes must never produce this) |

## 4. Architecture

Single crate (chosen over workspace split and over a data-driven check engine), four
modules, event-stream pipeline:

```
cli ──> Context ──> probe workers (thread each) ──mpsc──> Event<T> ──> sink
                                                          ├─ text / jsonl: pass-through, flush per line
                                                          └─ markdown / json / sarif: collect, render at end
```

- **`cli`** — argument parsing (`clap`), exit-code policy, sink selection.
- **`sys`** — thin seam over OS interfaces: procfs/sysfs file access (rooted at
  `--fixture-root` when set), `prctl`/`ptrace`-free process reads, CPUID, socket
  connect, `landlock(ABI)`, `seccomp(2)`. Exposed as small adapter traits so every
  probe's logic is injectable/testable without a live kernel.
- **`probes`** — one module per probe (§5). Each probe:
  1. runs on its own worker thread,
  2. returns `ProbeOutcome { name, availability, facts: Vec<Fact>, candidate_signals }`,
  3. never returns `Err` upward — its own failures become `Unavailable` facts,
  4. never touches stdout (all output flows through the channel, so a hung/abandoned
     worker cannot deadlock rendering).
- **`model`** — `Fact`, `Finding`, `Rule` registry, `Report`, fingerprinting logic, and
  the aggregation step that evaluates rules over collected facts and dedupes findings.
- **`render`** — five serializers over the event stream / `Report` (§7).

Pipeline details:

- Events: `Meta` (tool/kernel/target, first), `ProbeDone { name, outcome }`,
  `Summary { verdict, findings, counts, complete }`.
- `--probe-timeout`: the main thread emits `ProbeDone { timed_out: true }` and
  continues; the worker thread is abandoned and reaped at process exit. Known caveat:
  a thread wedged in uninterruptible kernel sleep can delay reaping (zombie) — output,
  exit code, and stream have already been flushed.
- Sequential probe scheduling (µs-scale file reads; determinism beats parallelism), but
  threaded execution per probe for hang isolation.
- `runtime` and `k8s` probes run **after** their inputs (cgroup, vmm, sockets, uidmap)
  and consume collected signals; the sink tolerates this ordering because ordering is
  static.
- Dependencies (pinned small): `rustix`, `clap`, `serde`, `serde_json`. No async
  runtime. Edition 2024.

## 5. Probe catalog

| probe | sources | emits (facts) |
|---|---|---|
| `namespaces` | `/proc/<pid>/ns/*`, pid-1 ns (root), `/.dockerenv`, `container=` env var | per-type isolation for all 8 ns types; `degraded` when pid-1 unreadable; cgroup-ns inode comparison; container membership markers (`containerMarkers`: dockerenv bool + container-env value) |
| `uidmap` | `/proc/<pid>/uid_map`, `gid_map`, `setgroups` | full mapping rows; single-line range-1 ⇒ rootless **environment note** (never scores into the verdict) |
| `capabilities` | `/proc/<pid>/status` `CapEff/Prm/Inh/Bnd/Amb/LastEff`, `NoNewPrivs`, securebits, `/proc/sys/kernel/yama/ptrace_scope` | all 6 sets decoded to names (incl. `CAP_BPF`, `CAP_PERFMON`, `CAP_CHECKPOINT_RESTORE`); `NoNewPrivs` state; Yama ptrace scope (scoped single-knob read, see non-goals) |
| `seccomp` | `/proc/<pid>/status` `Seccomp`, `Seccomp_filters` (kernel ≥ 4.14; degrade to mode-only when absent), `seccomp(2)` `GET_ACTION_AVAIL`, `SECCOMP_GET_FILTER` (root) | mode 0/1/2, filter count, supported actions matrix; raw BPF program dump when root. Template matching against known profile templates (docker/runc defaults) is **deferred to v1.1** — it requires disassembling the filter program, and reporting a matched template name as fact would overclaim |
| `syscall-probe` | execution of null-arg syscalls `0..RSEQ`, EPERM/EACCES classified as blocked | blocked-syscall list. **Only with `--probe-syscalls`.** Canonical SKIP list (security review 2026-10-01, supersedes amicontained's hang list): hang-class (rt_sigreturn, select, pause, pselect6, ppoll), exit-class (exit, exit_group, clone, fork, vfork), self-modifying (seccomp, ptrace, umask, setsid, setpgid, setgroups), NULL-arg acts-on-root (swapoff, delete_module, vhangup, acct, sethostname, setdomainname), fd-0-relative (fchmod, fchown, ftruncate, finit_module), conditional-block (wait4, waitid, msgrcv, accept, accept4). Rationale: the null-arg safety premise fails exactly where the capability check precedes arg validation and the NULL branch is a documented *action* (swapoff-ALL, rmmod -a, accounting off), where state lives behind fd 0, or where a wake-up-less wait exists. When `--probe-syscalls` is set and `--probe-timeout` is not, a 30 s timeout is forced — a sweep hang must never wedge the scan by default |
| `ebpf` | always: `/proc/sys/kernel/unprivileged_bpf_disabled`, `/sys/kernel/security/lockdown`, capabilities facts; with `--probe-ebpf`: trivial program load of the embedded object via `aya` | knob states (`unprivileged_bpf_disabled` 0/1/2, lockdown mode), which privilege path to `bpf()` is open (cap-based vs unprivileged); opt-in load result: ok, or denial decoded (EPERM caps / EPERM unpriv-disabled / EACCES-LSM / EOPNOTSUPP lockdown). Objects are never pinned: kernel frees them when the process exits, so crashes leave nothing behind |
| `lsm` | `/proc/<pid>/attr/current`, `/sys/kernel/security/lsm`, `/sys/kernel/security/lockdown`, `/sys/kernel/security/apparmor/`, `landlock(ABI)` query | active LSM list verbatim (may include `lockdown`, `bpf`, `ipe`, `ima`); AppArmor profile + mode; SELinux context + enforce/permissive; Kernel Lockdown state; Landlock ABI level or absent |
| `vmm` | CPUID hypervisor bit + vendor leaf (x86; best-effort aarch64), `/sys/class/dmi/id/*` (public fields unprivileged), `clocksource0`, `/dev/vsock` presence, `/proc/cpuinfo` `hypervisor` flag | hypervisor vendor/product; confidence per signature; composite signals for firecracker (no DMI + `kvm-clock` + vsock) and gVisor (characteristic kernel/ptrace quirks reported conservatively) |
| `cgroup` | `/proc/<pid>/cgroup`, own `memory.max`, `pids.max`, `cpu.max`, cpuset, controllers list | v1/v2, controllers, own limits, normalized path pattern (`kubepods-…pod<uid>`, `libpod-…`, `docker-<hex>`, `lxc-…`) |
| `sockets` | fixed candidate list: `/var/run/docker.sock`, `/run/docker.sock`, `/run/docker/*.sock`, `/run/containerd/containerd.sock`, `/run/crio/crio.sock`, `/run/podman/podman.sock`, `$XDG_RUNTIME_DIR/podman/podman.sock` | path, type, writable?; for docker/podman endpoints a hand-rolled `GET /info` over the UDS (no HTTP dep; 1 s timeout) reporting `SecurityOptions` (userns-remap, apparmor/seccomp defaults), version, rootless flag. **Environment-only evidence**: presence of a socket means a runtime is reachable here, not that we run inside it; contributes verdict evidence notes, never score |
| `k8s` | env `KUBERNETES_SERVICE_HOST/PORT`, `/var/run/secrets/kubernetes.io/serviceaccount/`, downward-API dir | in-pod?, namespace name, QoS class (cross-referenced with cgroup path) |
| `runtime` | composite of all above | self-containment fingerprint: primary verdict + alternatives, each citing evidence facts; environment-only signals become `environment:` notes |

### Fingerprinting algorithm

Scored evidence, not a single string. Each probe contributes weighted signals; the
`runtime` probe sums them into candidates.

**Verdict semantics (amendment 2026-10-01): the verdict names *self-containment*.**
`verdict.runtime` identifies the containment the scanning process is itself running
inside (`host` when it is not contained). Evidence that a runtime is *installed or
reachable on the machine* — a writable control socket (`sockets.found`), a user's
rootless uidmap layout (`uidmap.rootless`) — is an **environment-only** signal: it
never scores into the verdict. Environment-only signals are reported as evidence
notes (`environment: <kind> present (<probe>.<key>)`) so "this is a podman system"
stays visible while the verdict stays honest. Only self-containment evidence scores:

- own-cgroup classification (`/proc/<pid>/cgroup` path patterns via `cgroup.pattern`)
- container membership markers visible from inside: `/.dockerenv`, `container=` env
  var (`container=docker` / `container=podman`, image-set; weight below cgroup proof).
  **Precedence:** a named `container=` value out-ranks the `/.dockerenv`-derived
  Docker inference for the *inner* runtime — with `container=podman` and `/.dockerenv`
  both present, only Podman scores; `/.dockerenv` still lands in the `containerMarkers`
  fact and becomes the outer layer via the variant rule below. Two same-family markers
  (dockerenv + `container=docker`) count once.
- in-pod evidence (SA token dir, `KUBERNETES_SERVICE_HOST`) — existing k8s branch
- hypervisor presence (VM containment: kvm/qemu/firecracker/gVisor/kata)

Per-kind scored evidence after the gate:

- docker: `docker-<64hex>`/`/docker/` cgroup (0.8) + `/.dockerenv` or
  `container=docker` marker + docker.sock SecurityOptions (environment note)
- podman: `libpod-` cgroup (0.7) + `container=podman` marker; uidmap single-line and
  the XDG podman socket are environment notes
- containerd/CRI-O: cgroup path identity (socket = environment note)
- Kubernetes pod: `kubepods` cgroup path or `KUBERNETES_SERVICE_HOST` + SA token dir
  (underlying runtime reported separately, e.g. "k8s pod on containerd")
- LXC / systemd-nspawn: cgroup path patterns + container-env vars
- firecracker: hypervisor present + empty DMI + `kvm-clock` + vsock, no PCI-visible BIOS
- gVisor / kata: vmm signatures + kernel-version/name mismatches (conservative, labeled)
- bare host: no self-containment signals, host cgroup path, no hypervisor

**Nesting:** the innermost identifiable containment is the verdict (own cgroup scope
sees it first). When outer-layer markers coexist with an inner containment verdict
that they do not explain (e.g. verdict `podman` from a `libpod-` scope while
`/.dockerenv` is present), the verdict gains `variant: "nested-in-docker"` and an
evidence note. A nested container whose runtime leaves no inner marker degrades to
the outer layer's evidence — stated at that evidence's confidence, never guessed.

Output always includes the evidence list per candidate; low-confidence outcomes say so.

## 6. Rule registry & findings

Rules are **code**: `static RULES: &[Rule]`, each
`{ id, slug, severity, summary, why, remediation, references[] }`. A rule is a pure
predicate over collected facts. Findings reference the rule id and attach the evidence
facts. Evaluated once after aggregation; combination rules are first-class.

Severity vocabulary: `info | low | medium | high | critical`, judged by *how much closer
to host root this state puts an attacker already inside the environment*.

Seed catalog (v1; registry is append-only in id-space):

| id | slug | sev | condition (sketch) |
|---|---|---|---|
| AMR-001 | container-socket-exposed | critical | reachable, writable docker/podman socket (API peer is root); evidence includes SecurityOptions |
| AMR-002 | privileged-container | high | CAP_SYS_ADMIN ∈ CapEff ∧ seccomp mode 0 ∧ AppArmor unconfined ∧ runtime detected |
| AMR-003 | cap-sys-module | high | CAP_SYS_MODULE ∈ CapEff (module load ⇒ host root on unlocked kernels) |
| AMR-004 | host-pid-ns-ptraceable | high | host PID ns ∧ (Yama ptrace_scope == 0 ∨ CAP_SYS_PTRACE ∈ CapEff) |
| AMR-005 | seccomp-disabled-in-container | medium | runtime detected ∧ seccomp mode 0 |
| AMR-006 | apparmor-unconfined-in-container | medium | runtime detected ∧ AppArmor unconfined (or absent while LSMs active) |
| AMR-007 | selinux-permissive-in-container | medium | SELinux context present ∧ permissive |
| AMR-008 | identity-uidmap | medium | container detected ∧ uid_map is full identity (no userns isolation; DAC root == host root) |
| AMR-009 | cgroup-v1-container | low | cgroup v1 in effect inside container (release_agent-class vectors; host-side) |
| AMR-010 | no-pids-limit | low | container detected ∧ pids controller present but unlimited |
| AMR-011 | gid-map-includes-0 | medium | gid_map maps host gid 0 without `setgroups: deny` |
| AMR-012 | landlock-abi-available | info | kernel exposes Landlock ABI ≥ 1 (`/sys/kernel/security/landlock` present) — presence-only: a process's Landlock domain state is not observable through procfs, so "unused" is never claimed |
| AMR-013 | virtualized | info | hypervisor detected (context for VMM-boundary claims) |
| AMR-014 | strong-isolation-runtime | info | firecracker/gVisor/kata detected (positive note) |
| AMR-015 | unrecognized-runtime | info | no candidate scored above threshold (audit manually) |
| AMR-016 | cap-sys-admin-no-combo | medium | CAP_SYS_ADMIN present but some restraints active (weaker sibling of AMR-002) |
| AMR-017 | cgroupns-host | info | own cgroup-ns inode equals pid-1's (container sees host cgroup tree) |
| AMR-018 | no-new-privs-unset | low | NoNewPrivs = 0 (execve can gain privs via setuid/exec-caps) |
| AMR-019 | bpf-unpriv-open | medium | verdict != host and `unprivileged_bpf_disabled` is 0 (or absent pre-5.13 knob): any local uid can reach `bpf()` from a weak foothold |
| AMR-020 | cap-bpf-or-perfmon | low | `CapEff` includes `CAP_BPF` or `CAP_PERFMON`: program load / map read possible without full root |
| AMR-021 | ebpf-load-succeeded | high | `--probe-ebpf` only: trivial program load succeeded while contained — `bpf()` reachable past seccomp/LSM/cap drops; kernel attack surface confirmed open |

Rules downgraded by privilege: where the assessment needs data an unprivileged run
cannot read, the rule reports `info` with "insufficient privilege to assess" rather
than firing or staying silent.

## 7. Output formats

All formats derive from the same `Report` / event stream. `Fact` shape:
`{ probe, key, value, source, status: "ok" | "unavailable" | "degraded" }`
(`Unavailable` carries `{path, errno}`).

### `json` (bulk)

```json
{
  "schemaVersion": 1,
  "tool": {"name": "amirustrained", "version": "0.1.0"},
  "scan": {"targetPid": 1234, "uid": 1000, "timestamp": "...", "kernel": "6.x", "complete": true, "probeTimeoutS": null},
  "verdict": {"runtime": "podman", "variant": null, "confidence": "high",
               "alternatives": [{"runtime": "docker", "score": 0.2}],
               "evidence": ["podman cgroup.pattern 0.7", "podman namespaces.containerMarkers 0.6",
                             "environment: podman present (sockets.found)",
                             "environment: podman present (uidmap.rootless)"]},
  "probes": [{"name": "namespaces", "availability": "ok", "facts": []}, …],
  "findings": [{"rule": "AMR-011", "severity": "medium", "summary": "…", "why": "…",
                 "evidence": [ …facts… ], "remediation": "…", "references": [ … ]}],
  "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 4}
}
```

### `jsonl` (streaming)

One JSON object per line, each carrying `"schemaVersion": 1` and a `type`:

- `{"type":"meta", …}` — first line, flushed before probes start.
- `{"type":"probe","name":"seccomp","availability":"ok","facts":[…],"findings":[…]}` —
  flushed immediately on completion; consumers can act mid-scan.
- `{"type":"summary","verdict":…,"findings":[…]` (deduped aggregate incl. combination
  rules that need multiple probes)`,"counts":…,"complete":true}` — last line.

Probe-level findings are provisional for cross-probe rules; the summary is canonical.

### `text` / `markdown`

Same template data: verdict first, then per-probe sections, then findings grouped by
severity. Markdown uses headings/tables for agent consumption; color in text only,
`--no-color` and non-TTY both disable it.

### `sarif`

SARIF 2.1.0, **findings only** (facts have no SARIF concept). Mapping: rule registry →
`runs[0].tool.driver.rules[]` (fullRule, help=remediation); finding → `result`
(ruleId, level: critical/high→error, medium→warning, low/info→note, message,
`partialFingerprints` from rule id + evidence keys; no `locations` — runtime state;
process context in `properties`). Validated against the official schema in tests.

## 8. Error handling & degradation

- Probes never fail the run; denials/misses are typed facts
  (`Unavailable {path, errno}`) and trigger the privilege-downgrade path in §6.
- Per-probe timeout (when set) yields a `timed_out` ProbeDone; report marked
  `"complete": false`; scan continues.
- `--probe-syscalls` is documented as best-effort against unknown kernels; the skip
  list (§5) is a hard-coded constant with the rationale in comments.
- Unprivileged degradations: pid-1 ns unreadable ⇒ `degraded` namespace comparison;
  restricted DMI ⇒ public fields; no root ⇒ no `SECCOMP_GET_FILTER`, no `--pid`.
- Output failures (unwritable `-o` path) ⇒ stderr + exit 2.
- The binary is read-only w.r.t. the system: it never writes files, never changes
  kernel state (the only syscalls with any effect are the opt-in `--probe-syscalls`
  null-arg probes and `GET_ACTION_AVAIL`, which is inert).

## 9. Testing

- **Fixtures + `--fixture-root`**: hand-authored pseudo-fs trees per scenario —
  `bare-host`, `docker-default`, `docker-privileged`, `rootless-podman`, `k8s-pod`,
  `firecracker`, `gvisor`, `lxc`, `hardened-host`. All classification logic is pure
  over injected content; OS effects (CPUID, socket handshake, prctl) go through
  adapter traits and are stubbed in tests.
- **Unit tests**: uid_map/gid_map parser, cgroup-path classifier, capability decoder,
  DMI/CPUID matcher, each rule predicate against synthetic fact sets (fire + no-fire).
- **Golden tests**: all five renderers against each fixture scenario; SARIF validated
  against the official JSON schema in-test. Scenario table MUST include the
  containment-vs-environment cases: *host with writable podman/docker sockets* ⇒
  verdict `host` with `environment:` notes (no socket score); *inside docker with
  cgroupns-hidden path* ⇒ `/.dockerenv` marker carries docker over the primary bar;
  *podman-in-docker* (libpod scope + dockerenv) ⇒ verdict `podman`,
  `variant: "nested-in-docker"`.
- **Live smoke harness** (scripted, manual/nightly, never shared CI hosts): run the
  same binary in docker default, docker `--privileged`, rootless podman, kind pod,
  systemd-nspawn; assert the fingerprint verdict table. `--probe-syscalls` exercised
  only inside containers; `--probe-ebpf` real load exercised here with root, never on
  shared CI hosts (fixtures cannot fake `BPF_PROG_LOAD`; knob reading is fixture-tested).

## 10. Build & distribution

- Targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (static, no
  runtime deps), plus native builds for dev.
- Edition 2024; deps: `rustix`, `clap`, `serde`, `serde_json`; `aya` for the eBPF load
  (pure Rust, musl-safe); release profile `opt-level="z"`, `lto=true`, `strip=true`,
  panic=abort (abandon-worker design still works: hangs are stalls, not unwinds).
- eBPF object: minimal probe program in `bpf/`, built with `bpf-linker` (nightly) in a
  dedicated CI job; the main crate embeds the artifact via `include_bytes!` (aya's
  recommended layout) — the shipped binary stays a single static file.
- GitHub Actions: `cargo fmt --check`, `clippy -D warnings`, unit+golden tests on
  native, cross-compile release artifacts, eBPF-object build job (nightly + bpf-linker).

## 11. Future tiers (explicitly out of v1)

Sysctl hardening audit; mount/rootfs analysis; whole-host cgroup tree; recursive socket
hunt; workspace split if embedding demand appears; config-driven checks if the rule
registry outgrows code; additional runtimes (runv, sysbox, wsl2 nuances).