//! Task 26 — the nine-environment fixture corpus.
//!
//! Each `tests/fixtures/<scenario>/` tree is a complete pseudo-filesystem for
//! one deployment shape. Every fact the pipeline reads arrives through the two
//! seams it already has in production:
//!
//! - **files** through [`PseudoFs`] rooted at the tree. `PseudoFs` relocates
//!   `/proc/<pid>/…` onto the tree's `proc/self/…` subtree, so one corpus works
//!   whatever pid the harness runs under (`/proc/1/…` deliberately does NOT
//!   relocate: that is the init-namespace baseline the namespaces probe
//!   compares against, and collapsing both sides would fabricate the facts).
//! - **syscalls/env/privilege** through [`FixtureOs`], the [`OsApi`] impl below.
//!
//! Scans run through the real `pipeline::scan_with_probes` and the real
//! `probes::registry(&opts)` — the same dispatch the CLI performs, opt-in
//! syscall probe excluded exactly as an unflagged CLI excludes it (Task 28-29's
//! eBPF probe is not landed, so it is absent here too). Nothing is stubbed at
//! the rule or fusion layer: a scenario's verdict, confidence and finding set
//! are computed by shipped code from shipped fixtures.
//!
//! A tree carries only the files that decide something, plus the process/
//! namespace baseline its environment implies. `proc/self/ns/*` is present
//! exactly where the cgroup-namespace comparison is a container signal: in a
//! microVM guest the equality is the guest's own init-ns constant, so
//! `firecracker`/`gvisor` carry no ns files and `namespaces.cgroupNsSameAsInit`
//! stays unknown (AMR-017 fails closed rather than claiming a container shares
//! a host cgroup tree it cannot see).
//!
//! The machine contributes nothing: assertions are exact on
//! `verdict.runtime`, the `high|medium|low` confidence ladder, and the sorted
//! list of fired rule ids.

// The crate under test is a binary with no lib target, so the shipped modules
// are spliced in verbatim rather than reimplemented: `include!` of the crate
// root leaves `mod model; … mod sys;` resolving inside `src/`, exactly as the
// binary compiles them, and the harness keeps its own entry point (the
// spliced `fn main` is dead code here).
//
// The splice brings `main.rs`'s own imports with it (`Arc`, `clap::Parser`), so
// this file must not re-import them.

// Because the splice compiles the crate as a test target, the src modules' own
// `#[cfg(test)]` unit tests ride along in this harness — they are the same
// tests the bin target runs, not a second copy to maintain.
#![allow(dead_code)]
include!("../src/main.rs");

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use model::{Report, RuntimeKind};
use opts::{Format, Opts};
use sys::fs::PseudoFs;
use sys::os::{HypervisorInfo, OsApi, SeccompActions, UdsReply};

/// One environment: its fixture tree plus the syscall-seam answers that tree
/// cannot express, and the exact outcome the shipped rules must produce.
struct Scenario {
    /// Directory name under `tests/fixtures/`.
    name: &'static str,
    runtime: RuntimeKind,
    /// The string ladder (`Verdict::confidence`), never a float.
    confidence: &'static str,
    /// Sorted rule ids of every fired finding, including the AMR-004
    /// insufficient-privilege note where the scenario runs unprivileged.
    ids: &'static [&'static str],
    /// `geteuid() == 0` inside the environment.
    root: bool,
    /// `SYS_landlock_create_ruleset` ABI level, `None` ⇒ unsupported.
    landlock: Option<u64>,
    /// CPUID leaf 1 ECX bit 31 plus the vendor string.
    hypervisor: bool,
    /// Environment variables visible to the scanned process.
    env: &'static [(&'static str, &'static str)],
}

/// The corpus. Each entry's expectations were derived from the predicates as
/// landed in `src/model/rules.rs`, then cross-checked against the spec §6 rows;
/// the notes record where that differs from the Task 26 plan sketch.
const SCENARIOS: &[Scenario] = &[
    Scenario {
        // systemd user session on physical hardware: no self-containment
        // signal at all, so the host fallback plus the hypervisor-ruled-out
        // confidence. Every container-gated rule is silent here, which is the
        // point of the scenario: the identity uid_map, `NoNewPrivs 0` and the
        // init-ns cgroup equality are host constants, not findings. Knob
        // posture `unprivileged_bpf_disabled 1` + lockdown `[none]`: read
        // silently — the host gate silences AMR-019 and an empty CapEff holds
        // no CAP_BPF/CAP_PERFMON for AMR-020.
        name: "bare-host",
        runtime: RuntimeKind::Host,
        confidence: "high",
        ids: &[],
        root: false,
        landlock: None,
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // `/docker/<64 hex>` (0.8) + `/.dockerenv` (0.6) = 1.4 → high.
        // Default seccomp filter and the `docker-default` enforce profile keep
        // AMR-002/005/006/016 silent; the identity id mappings, the unlimited
        // pids controller and the writable docker.sock are the exposure. The
        // classic-host eBPF posture (`unprivileged_bpf_disabled 0`, lockdown
        // not exposed to the container) opens bpf() to any uid → AMR-019; the
        // docker-default cap set has no CAP_BPF/CAP_PERFMON, so AMR-020
        // stays silent.
        name: "docker-default",
        runtime: RuntimeKind::Docker,
        confidence: "high",
        ids: &[
            "AMR-001", "AMR-008", "AMR-010", "AMR-011", "AMR-012", "AMR-018", "AMR-019",
        ],
        root: true,
        landlock: Some(1),
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // Same tree, `--privileged`: seccomp mode 0 + `unconfined` + full caps
        // is the AMR-002 signature, so AMR-016 (its weaker sibling) goes quiet
        // and CAP_SYS_MODULE joins the list. AppArmor absence is not the MAC
        // witness here: the profile literally says unconfined. The knob stays
        // open (0) → AMR-019, and the full 41-bit CapEff includes
        // CAP_BPF/CAP_PERFMON → AMR-020.
        name: "docker-privileged",
        runtime: RuntimeKind::Docker,
        confidence: "high",
        ids: &[
            "AMR-001", "AMR-002", "AMR-003", "AMR-005", "AMR-006", "AMR-008", "AMR-010", "AMR-011",
            "AMR-012", "AMR-018", "AMR-019", "AMR-020",
        ],
        root: true,
        landlock: Some(1),
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // `libpod-` scope (0.7) scores alone — no `container=podman` marker in
        // this tree, so 0.7 stays `medium`, and the socket only adds an
        // `environment:` note (env-only signals never rank). The handshake
        // fails against a fixture stand-in, so AMR-001's fail-loud branch is
        // what fires: AMR-022 needs a live reply saying `rootless: true`.
        // `setgroups deny` silences AMR-011 while the sub-range uid_map
        // silences AMR-008 — rootless isolation working as intended. The host
        // knob is 2 (immutable until reboot), so the unprivileged bpf() path
        // is closed and neither eBPF rule fires.
        name: "rootless-podman",
        runtime: RuntimeKind::Podman,
        confidence: "medium",
        ids: &[
            "AMR-001", "AMR-004", "AMR-005", "AMR-010", "AMR-012", "AMR-018",
        ],
        root: false,
        landlock: Some(1),
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // kubepods path (0.7) → medium, no underlying containerd/docker signal
        // in the tree, so `variant` stays empty and the k8s evidence line is
        // appended by the fusion layer. Seccomp is off (no runtime-default
        // profile), the service account is mounted. Default k8s pods use no
        // user namespace, so the tree carries the identity uid_map/gid_map
        // with `setgroups: allow` like the docker-default twin: a real scan
        // containment. Knob 2 (hardened node) closes unprivileged bpf(), and
        // the default-cap pod set carries no CAP_BPF → neither eBPF rule.
        name: "k8s-pod",
        runtime: RuntimeKind::Kubernetes,
        confidence: "medium",
        ids: &[
            "AMR-005", "AMR-008", "AMR-010", "AMR-011", "AMR-012", "AMR-018",
        ],
        root: true,
        landlock: Some(1),
        hypervisor: false,
        env: &[("KUBERNETES_SERVICE_HOST", "10.96.0.1")],
    },
    Scenario {
        // Firecracker guest: hypervisor + empty DMI + /dev/vsock + kvm-clock
        // is a single 0.8 signal, and `confidence_of` reserves `high` for a
        // 0.9+ top score — so the composite reads `medium`, not the plan
        // sketch's "high". The ladder is landed probe behaviour; a fixture
        // must not buy its way up it, so the expectation follows the probe.
        // The tree carries the real root-in-guest baseline — Seccomp 0, full
        // guest-root caps, NoNewPrivs 0, identity id mappings — and no
        // container-gated rule fires because a VM verdict is not a
        // shared-kernel containment (spec §6 erratum 2026-10-01, ReviewT26
        // F3), not because the facts are unknown. The tree's own 5.10.195
        // banner predates Landlock (merged in 5.13), so the probe reports
        // unsupported: the virtualization note and the sandbox note are the
        // whole reportable set. The erratum's fixture proof: the guest knob
        // is open (0), so the posture alone would hand AMR-019 its conjunct
        // — VM verdicts are exempt (guest bpf() is guest-kernel-local); and
        // the guest-root CapEff is the legacy 38-bit pre-5.8 mask, which
        // decodes WITHOUT CAP_BPF/CAP_PERFMON, so AMR-020 stays quiet on
        // fact, not on gate.
        name: "firecracker",
        runtime: RuntimeKind::Firecracker,
        confidence: "medium",
        ids: &["AMR-013", "AMR-014"],
        root: true,
        landlock: None,
        hypervisor: true,
        env: &[],
    },
    Scenario {
        // gVisor: `/proc/version` carrying the Sentry banner (0.9) → high. No
        // hypervisor bit (the sandbox is a kernel, not a VM), no Landlock in
        // the 4.4-parity Sentry kernel. The guest carries the same realistic
        // root baseline as the firecracker twin (Seccomp 0, full guest-root
        // caps, identity id mappings) and still reports only the
        // strong-isolation note: the container-gated exposure is exempt at a
        // VM verdict (spec §6 erratum 2026-10-01, ReviewT26 F3), not unknown
        // — the corpus's "clean sandbox" case, open knob (0) and all: the
        // same VM-exemption + legacy-38-bit-CapEff reasoning as firecracker.
        name: "gvisor",
        runtime: RuntimeKind::Gvisor,
        confidence: "high",
        ids: &["AMR-014"],
        root: true,
        landlock: None,
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // `/lxc/<name>` (0.7) → medium. A privileged LXC hands its payload the
        // full kernel capability set, so CAP_SYS_MODULE is reportable here even
        // though the plan sketch listed only 005/018 — the fixture keeps the
        // realistic caps and the assertion follows them. Like k8s-pod it runs
        // no user namespace: the identity uid_map/gid_map with `setgroups:
        // allow` is what a real root scan reads, so AMR-008/011 belong in the
        // pinned set. No LSM files at all in the tree: with nothing
        // observable, AMR-002's MAC branch cannot cite an unconfined profile,
        // AMR-006's absence branch cannot cite an LSM list, and AMR-016
        // refuses to claim a restraint it cannot evidence, so all three fail
        // closed — the corpus's fail-closed-on-unknown case. The shared-kernel
        // knob is open (0) → AMR-019 fires here; the legacy 38-bit caps mask
        // predates CAP_BPF/CAP_PERFMON, so AMR-020 stays silent.
        name: "lxc",
        runtime: RuntimeKind::Lxc,
        confidence: "medium",
        ids: &[
            "AMR-003", "AMR-005", "AMR-008", "AMR-011", "AMR-018", "AMR-019",
        ],
        root: true,
        landlock: None,
        hypervisor: false,
        env: &[],
    },
    Scenario {
        // Hardened physical host: seccomp filter, AppArmor enforce, lockdown
        // integrity, NoNewPrivs, empty capability set, Landlock present. No
        // container markers → Host verdict; AMR-004/017/018 are gated off
        // rather than reported as a bare-host tautology, AMR-007 needs a
        // permissive SELinux this stack does not have, and the one thing left
        // to say is the ungated Landlock-availability note. eBPF knobs 2 +
        // lockdown integrity: unprivileged bpf() closed outright, the host
        // gate silences AMR-019 anyway, empty CapEff silences AMR-020.
        name: "hardened-host",
        runtime: RuntimeKind::Host,
        confidence: "high",
        ids: &["AMR-012"],
        root: false,
        landlock: Some(1),
        hypervisor: false,
        env: &[],
    },
];

fn scenario(name: &str) -> &'static Scenario {
    SCENARIOS
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no such scenario: {name}"))
}

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// The `OsApi` half of a fixture: every non-filesystem fact an environment
/// could answer, answered from the scenario table. Nothing here consults the
/// machine running the test.
struct FixtureOs {
    hypervisor: HypervisorInfo,
    landlock: Option<u64>,
    env: HashMap<String, String>,
    root: bool,
}

impl FixtureOs {
    fn new(s: &Scenario) -> Self {
        Self {
            hypervisor: HypervisorInfo {
                present: s.hypervisor,
                vendor: s.hypervisor.then(|| "KVMKVMKVM".to_string()),
            },
            landlock: s.landlock,
            env: s
                .env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            root: s.root,
        }
    }
}

impl OsApi for FixtureOs {
    fn hypervisor(&self) -> HypervisorInfo {
        self.hypervisor.clone()
    }

    fn landlock_abi(&self) -> Option<u64> {
        self.landlock
    }

    /// A current kernel: every `SECCOMP_RET_*` action available, and the probe
    /// succeeded. No landed rule reads these bits; the value is fixed so a
    /// report rendered from a fixture can never depend on the host CPU.
    fn seccomp_actions(&self) -> SeccompActions {
        SeccompActions {
            kill_process: true,
            kill_thread: true,
            trap: true,
            errno: true,
            log: true,
            trace: true,
            user_notif: true,
            probed_ok: true,
        }
    }

    /// Filter programs are a root-only ptrace interface; no scenario in the
    /// corpus dumps filters (`--dump-filters` is a CLI concern).
    fn seccomp_filter_dump(&self, _pid: u32) -> Result<Vec<u64>, sys::fs::ProbeIo> {
        Err(sys::fs::ProbeIo::Other(
            "fixture: filter dump not modelled".into(),
        ))
    }

    /// Only the opt-in `--probe-syscalls` sweep calls this, and the registry
    /// under test never registers that probe. `ENOSYS` keeps any accidental
    /// use honest instead of pretending a syscall ran.
    fn syscall0(&self, _id: u32) -> Result<(), i32> {
        Err(libc::ENOSYS)
    }

    /// A fixture socket is a regular-file stand-in: no daemon answers, so the
    /// handshake fails the way a connection refused does. That is what keeps
    /// AMR-001's "peer not confirmed rootless ⇒ treat as root" branch, and
    /// AMR-022's `rootless: true` requirement, testable from a tree on disk.
    fn uds_probe(&self, _path: &Path, _timeout: Duration) -> std::io::Result<UdsReply> {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }

    fn env(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }

    fn is_root(&self) -> bool {
        self.root
    }
}

/// Runs the scenario through the shipped pipeline and registry.
fn scan(s: &Scenario) -> Report {
    let opts = Opts {
        pid: None,
        probe_syscalls: false,
        probe_ebpf: Vec::new(),
        probe_timeout: None,
        fail_on: None,
        dump_filters: false,
    };
    pipeline::scan_with_probes(
        Arc::new(PseudoFs::new(fixture_root(s.name))),
        Arc::new(FixtureOs::new(s)),
        &opts,
        probes::registry(&opts),
        &mut |_| {},
    )
}

/// Failure message that makes an adjudication possible without a debugger:
/// verdict (with variant/evidence) plus every fired id and summary.
fn observed(r: &Report) -> String {
    let v = r.verdict.as_ref();
    let mut s = match v {
        Some(v) => format!(
            "verdict {} variant {:?} confidence {}\n  evidence:\n    {}\n",
            v.runtime.as_str(),
            v.variant,
            v.confidence,
            v.evidence.join("\n    ")
        ),
        None => "verdict <none>\n".to_string(),
    };
    for f in &r.findings {
        s.push_str(&format!("  {} {}\n", f.rule, f.summary));
    }
    let degraded: Vec<String> = r
        .probes
        .iter()
        .filter(|p| !matches!(p.availability, model::Availability::Ok))
        .map(|p| format!("{}: {:?}", p.name, p.availability))
        .collect();
    if !degraded.is_empty() {
        s.push_str(&format!("  non-Ok probes: {}\n", degraded.join(", ")));
    }
    s
}

fn assert_scenario(s: &Scenario) {
    let r = scan(s);
    let context = format!("scenario `{}`\n{}", s.name, observed(&r));
    let verdict = r.verdict.as_ref().expect("runtime probe always answers");
    assert_eq!(verdict.runtime, s.runtime, "{context}");
    assert_eq!(verdict.confidence, s.confidence, "{context}");
    let mut ids: Vec<&str> = r.findings.iter().map(|f| f.rule).collect();
    ids.sort_unstable();
    assert_eq!(ids, s.ids, "{context}");
}

#[test]
fn bare_host_is_a_plain_host_with_no_findings() {
    assert_scenario(scenario("bare-host"));
}

#[test]
fn docker_default_reports_socket_and_identity_isolation_gaps() {
    assert_scenario(scenario("docker-default"));
}

#[test]
fn docker_privileged_reports_the_full_privileged_signature() {
    assert_scenario(scenario("docker-privileged"));
}

#[test]
fn rootless_podman_scores_alone_and_notes_the_runtime_presence() {
    assert_scenario(scenario("rootless-podman"));
}

#[test]
fn k8s_pod_overlays_the_orchestrator_verdict() {
    assert_scenario(scenario("k8s-pod"));
}

#[test]
fn firecracker_reports_the_microvm_composite() {
    assert_scenario(scenario("firecracker"));
}

#[test]
fn gvisor_reports_only_the_strong_isolation_note() {
    assert_scenario(scenario("gvisor"));
}

#[test]
fn lxc_fails_closed_where_no_lsm_is_observable() {
    assert_scenario(scenario("lxc"));
}

#[test]
fn hardened_host_reports_nothing() {
    assert_scenario(scenario("hardened-host"));
}

/// The corpus and the table are one contract: each of the nine trees is
/// claimed by exactly one scenario and each scenario names a tree that exists.
/// A mistyped name would otherwise scan an empty root — which reads as an
/// ordinary bare host rather than an error — and an unclaimed tree would drift
/// without a single assertion noticing.
#[test]
fn corpus_and_scenario_table_name_the_same_trees() {
    let mut table: Vec<&str> = SCENARIOS.iter().map(|s| s.name).collect();
    table.sort_unstable();
    let mut on_disk: Vec<String> = std::fs::read_dir(fixture_root(""))
        .expect("tests/fixtures exists")
        .map(|e| {
            e.expect("readable corpus entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    on_disk.sort();
    assert_eq!(table, on_disk, "scenario table vs `tests/fixtures/`");
}

// ── end-to-end: the shipped CLI over a corpus tree ──────────────────────────

/// Ids the CLI's *real* `OsApi` can add or remove, whatever the tree says:
/// the live `/info` handshake on the literal host socket path (AMR-001 vs
/// AMR-022), the real Landlock syscall (AMR-012), the real CPUID hypervisor bit
/// (AMR-013), and the real uid (AMR-004's insufficient-privilege note). These
/// are excluded from the exact set and pinned by shape instead.
const MACHINE_DEPENDENT: [&str; 5] = ["AMR-001", "AMR-004", "AMR-012", "AMR-013", "AMR-022"];

#[test]
fn docker_defaults_cli_json_matches_the_corpus_scenario() {
    let out = assert_cmd::Command::new(env!("CARGO_BIN_EXE_amirustrained"))
        .arg("--fixture-root")
        .arg(fixture_root("docker-default"))
        .args(["--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("--format json emits one document");
    assert_eq!(v["verdict"]["runtime"], "docker");
    assert_eq!(v["verdict"]["confidence"], "high");

    let mut ids: Vec<&str> = v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| f["rule"].as_str().expect("every finding carries a rule id"))
        .collect();
    ids.sort_unstable();
    let fixture_decided: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| !MACHINE_DEPENDENT.contains(id))
        .collect();
    assert_eq!(
        fixture_decided,
        ["AMR-008", "AMR-010", "AMR-011", "AMR-018", "AMR-019"],
        "fixture-decided findings over CLI: {ids:?}"
    );
    // Exactly one of the socket pair, whichever way the live handshake went:
    // the fixture socket is present and writable, so one of the two exposures
    // must be reported and never both (one entry, one rootless answer).
    let reported_001 = ids.contains(&"AMR-001");
    let reported_022 = ids.contains(&"AMR-022");
    assert_ne!(
        reported_001, reported_022,
        "docker.sock exposure must be exactly one of AMR-001/AMR-022: {ids:?}"
    );
}

// ── golden text output ──────────────────────────────────────────────────────

/// Evidence sources name the scanned process by pid, and the harness' pid is
/// whatever the test runner got — the slot is normalized so the snapshot pins
/// the report, not the process id.
fn normalize_pids(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("/proc/") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "/proc/".len()..];
        let digits = after.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0 && after.as_bytes().get(digits) == Some(&b'/') {
            out.push_str("/proc/<pid>/");
            rest = &after[digits + 1..];
        } else {
            out.push_str("/proc/");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// docker-privileged through the shipped text renderer, colourless and
/// non-verbose (which only suppresses the scan header, not the per-probe
/// status lines): probe status, verdict line, the whole finding set with its
/// evidence, the counts footer and the completion line.
#[test]
fn docker_privileged_text_output_snapshot() {
    let mut renderer = render::make(
        Format::Text,
        false,
        render::style::ColorSupport::Off,
        vec![],
    );
    let mut buf: Vec<u8> = Vec::new();
    let s = scenario("docker-privileged");
    let opts = Opts {
        pid: None,
        probe_syscalls: false,
        probe_ebpf: Vec::new(),
        probe_timeout: None,
        fail_on: None,
        dump_filters: false,
    };
    pipeline::scan_with_probes(
        Arc::new(PseudoFs::new(fixture_root(s.name))),
        Arc::new(FixtureOs::new(s)),
        &opts,
        probes::registry(&opts),
        &mut |ev| {
            renderer
                .on_event(&mut buf, ev)
                .expect("text renderer writes to a Vec");
        },
    );
    renderer.finish(&mut buf).expect("text renderer flushes");
    let text = String::from_utf8(buf).expect("renderer output is utf-8");
    insta::assert_snapshot!(normalize_pids(&text));
}

/// The scan-meta block names the machine and the moment, none of it the
/// fixture: timestamp, kernel, uid and targetPid are placeholdered so the
/// snapshot pins the document shape and every fixture-derived fact. The
/// two-space anchor is deliberate — deeper indents are evidence keys (a
/// `uid=0` style fact would sit further in), only the scan block puts these
/// four directly under `scan:`.
fn normalize_scan_meta(text: &str) -> String {
    let mut out = text.to_string();
    for key in ["timestamp", "kernel", "uid", "targetPid"] {
        let pat = format!("\n  {key}: ");
        if let Some(s) = out.find(&pat) {
            let v = s + pat.len();
            let e = out[v..].find('\n').map_or(out.len(), |n| v + n);
            out.replace_range(v..e, &format!("<{key}>"));
        }
    }
    out
}

/// docker-default through the shipped YAML renderer, colourless (piped
/// contract): the whole report as strict block YAML, loadable verbatim by
/// PyYAML (verified out-of-band; the snapshot is the byte-for-byte pin).
#[test]
fn docker_default_yaml_output_snapshot() {
    let mut renderer = render::make(
        Format::Yaml,
        false,
        render::style::ColorSupport::Off,
        vec![],
    );
    let mut buf: Vec<u8> = Vec::new();
    let s = scenario("docker-default");
    let opts = Opts {
        pid: None,
        probe_syscalls: false,
        probe_ebpf: Vec::new(),
        probe_timeout: None,
        fail_on: None,
        dump_filters: false,
    };
    pipeline::scan_with_probes(
        Arc::new(PseudoFs::new(fixture_root(s.name))),
        Arc::new(FixtureOs::new(s)),
        &opts,
        probes::registry(&opts),
        &mut |ev| {
            renderer
                .on_event(&mut buf, ev)
                .expect("yaml renderer writes to a Vec");
        },
    );
    renderer.finish(&mut buf).expect("yaml renderer flushes");
    let text = String::from_utf8(buf).expect("renderer output is utf-8");
    assert!(!text.contains('\x1b'), "colourless output has no escapes");
    let text = normalize_scan_meta(&normalize_pids(&text));
    insta::assert_snapshot!(text);
}
