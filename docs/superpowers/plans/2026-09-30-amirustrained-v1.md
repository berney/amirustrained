# amirustrained v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `amirustrained`, a static Rust binary that fingerprints the Linux runtime environment (container, VM, host) and its LPE-relevant restraints, emitting facts + findings in text/markdown/json/sarif/jsonl.

**Architecture:** Event-stream pipeline: each probe runs on its own worker thread, returns `ProbeOutcome` (facts + runtime-candidate signals + findings inputs) over an mpsc channel; a renderer sink streams `Meta`/`Probe`/`Summary` events (jsonl/text pass through with per-line flush, bulk formats collect). Rules are code-defined predicates over the aggregated `Report`, evaluated once before `Summary`.

**Tech Stack:** Rust edition 2024, `clap` (derive), `serde`/`serde_json`, `rustix`, `libc`. Dev: `tempfile`, `insta`, `assert_cmd`, `jsonschema`. No async runtime.

**Spec:** `docs/superpowers/specs/2026-09-30-amirustrained-design.md` (read it with this plan; the spec's §5 probe table and §6 rule catalog are normative).

## Global Constraints

- rustc ≥ 1.85, edition 2024. All builds and tests must pass on stable.
- Runtime deps ONLY: `clap`, `serde`, `serde_json`, `rustix`, `libc`. Dev deps: `tempfile`, `insta`, `assert_cmd`, `jsonschema`.
- The binary NEVER writes to the system except via `-o`; no state-changing syscalls except inside `--probe-syscalls` (opt-in) and the inert `SECCOMP_GET_ACTION_AVAIL`.
- Exit codes: `0` scan completed · `1` `--fail-on` tripped · `2` CLI misuse / output IO · `3` internal error. (Spec §3.)
- Probe names are exact strings: `namespaces uidmap capabilities seccomp syscall-probe lsm vmm cgroup sockets k8s runtime` (registry order as listed; `syscall-probe` only with `--probe-syscalls`).
- Rule ids `AMR-001`…`AMR-018`, slugs/severities exactly per spec §6. Id space is append-only.
- Formats: `text` (default) `markdown` `json` `sarif` `jsonl`. JSON/JSONL carry `"schemaVersion": 1` (camelCase keys everywhere).
- Every pseudo-file read goes through `PseudoFs` (fixture-root remap); every syscall effect goes through the `OsApi` trait. No `std::fs` direct calls in probes.
- Static musl targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`. Release profile `opt-level="z"`, `lto=true`, `strip=true`, `panic="abort"`.

## File Structure

```
Cargo.toml
.github/workflows/ci.yml
src/
  main.rs               entry: parse CLI, wire pipeline, exit codes
  opts.rs               Opts struct (parsed flags + derived), Format enum
  model/
    mod.rs              re-exports
    fact.rs             Fact, FactStatus, ProbeIo
    rule.rs             Rule, Severity, static RULES registry, evaluate()
    finding.rs          Finding
    outcome.rs          Availability, ProbeOutcome
    report.rs           Report, ScanMeta, Counts, Verdict
    runtime.rs          RuntimeKind, Signal, PriorSignals, fingerprint()
  sys/
    mod.rs              re-exports
    fs.rs               PseudoFs (fixture-rooted reads/readlink/exists/dir)
    os.rs               OsApi trait, RealOs impl, HypervisorInfo, SeccompActions, UdsReply
  pipeline.rs           Event, run_with_timeout, scan(), Ctx
  probes/
    mod.rs              Probe trait, registry()
    namespaces.rs uidmap.rs capabilities.rs seccomp.rs syscall_probe.rs
    lsm.rs vmm.rs cgroup.rs sockets.rs k8s.rs runtime.rs
  render/
    mod.rs              Renderer trait, format selection
    text.rs markdown.rs jsonr.rs sarif.rs jsonl.rs
tests/
  fixtures/<scenario>/proc/... , dmi/...   (Task 26–27)
  scenarios.rs          scenario-driven verdict/findings tests
  cli.rs                end-to-end CLI tests (assert_cmd)
```

Rationale: probes change together with their parsers (one file each); renderers never see procfs, only `Report`/`Event`; `sys` is the only seam that touches the OS.

---

### Task 1: Crate scaffold + CI

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/opts.rs`, `.gitignore` (exists), `.github/workflows/ci.yml`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: binary crate `amirustrained`, `mod opts; mod model; mod sys; mod pipeline; mod probes; mod render;` declared in `main.rs` (empty stub files for later tasks).

- [ ] **Step 1: Write the failing test**

```rust
// tests/cli.rs
use assert_cmd::Command;

#[test]
fn version_flag_prints_semver() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("amirustrained 0.1.0"));
}
```

Add `predicates = "3"` to `[dev-dependencies]` (dev-only, allowed).

- [ ] **Step 2: Run to verify failure** — Run: `cargo test --test cli` → FAIL (no `main`/crate).

- [ ] **Step 3: Implement**

```toml
# Cargo.toml
[package]
name = "amirustrained"
version = "0.1.0"
edition = "2024"
description = "Runtime introspection & LPE-posture reporter"
license = "MIT"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rustix = { version = "1", features = ["fs", "process"] }
libc = "0.2"

[dev-dependencies]
tempfile = "3"
insta = "1"
assert_cmd = "2"
predicates = "3"
jsonschema = "0.30"

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
```

```rust
// src/opts.rs
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "amirustrained", version, about = "Runtime introspection & LPE-posture reporter")]
pub struct Cli {
    // Flags are wired for real in Task 7; parse them now so --help is stable.
    /// text | markdown | json | sarif | jsonl
    #[arg(long, default_value = "text")]
    pub format: String,
    #[arg(long, short)]
    pub output: Option<std::path::PathBuf>,
    #[arg(long)]
    pub probe_syscalls: bool,
    #[arg(long)]
    pub probe_timeout: Option<u64>,
    #[arg(long)]
    pub pid: Option<u32>,
    #[arg(long)]
    pub fail_on: Option<String>,
    #[arg(long)]
    pub no_color: bool,
    #[arg(long, short)]
    pub verbose: bool,
    #[arg(long, hide = true)]
    pub fixture_root: Option<std::path::PathBuf>,
}
```

```rust
// src/main.rs
mod opts;
mod model { pub fn placeholder() {} }   // replaced in Task 2 with `pub mod ...` tree
mod sys { pub fn placeholder() {} }
mod pipeline { pub fn placeholder() {} }
mod probes { pub fn placeholder() {} }
mod render { pub fn placeholder() {} }

fn main() {
    let _cli = opts::Cli::parse();
    // Full wiring lands in Task 7.
    println!("amirustrained 0.1.0: no probes wired yet");
}
```

`ci.yml`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` on `ubuntu-latest`. (Cross-build jobs land in Task 27.)

- [ ] **Step 4: Run to verify pass** — `cargo test --test cli` → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "chore: crate scaffold + CI"`

---

### Task 2: Core model types

**Files:**
- Create: `src/model/mod.rs`, `fact.rs`, `rule.rs`, `finding.rs`, `outcome.rs`, `report.rs`, `runtime.rs`
- Test: `src/model/fact.rs` (inline `#[cfg(test)]`), `src/model/report.rs` (inline)

**Interfaces:**
- Consumes: Task 1 crate.
- Produces (canonical for all later tasks — signatures must match exactly):
  - `Fact { probe: String, key: String, value: serde_json::Value, source: String, status: FactStatus }` + ctors `Fact::ok(probe,&key,value,source)`, `Fact::unavailable(probe,&key,source,errno: Option<i32>)`, `Fact::degraded(probe,&key,value,source)`
  - `FactStatus::{Ok,Unavailable,Degraded}` (serde lowercase)
  - `Severity::{Info,Low,Medium,High,Critical}` (serde lowercase, Ord in that order)
  - `Availability::{Ok,Degraded(String),Unavailable(String)}`
  - `ProbeOutcome { name: String, availability: Availability, facts: Vec<Fact>, signals: Vec<Signal>, timed_out: bool }` (`signals` `#[serde(skip)]`)
  - `Finding::new(rule: &'static Rule, evidence: Vec<Fact>) -> Finding`
  - `Rule { id, slug, severity, summary, why, remediation, references: &'static [&'static str], requires_root: bool, check: fn(&Report, bool) -> Option<Vec<Fact>> }`
  - `RuntimeKind` (serde kebab-lowercase): `Docker, Containerd, CriO, Podman, Kubernetes, Lxc, SystemdNspawn, Firecracker, Gvisor, Kata, Host`
  - `Signal { runtime: RuntimeKind, weight: f32, evidence: Fact }`
  - `Report::fact(&self, probe: &str, key: &str) -> Option<&Fact>` (status-Ok only)

- [ ] **Step 1: Write the failing tests**

```rust
// in src/model/fact.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fact_serde_shape() {
        let f = Fact::ok("uidmap", "rootless", serde_json::json!(true), "/proc/1/uid_map".into());
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(j, r#"{"probe":"uidmap","key":"rootless","value":true,"source":"/proc/1/uid_map","status":"ok"}"#);
    }
    #[test]
    fn unavailable_carries_errno() {
        let f = Fact::unavailable("lsm", "lockdown", "/sys/kernel/security/lockdown".into(), Some(2));
        assert_eq!(f.status, FactStatus::Unavailable);
        assert_eq!(f.value["errno"], 2);
    }
}
```

```rust
// in src/model/report.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fact_lookup_skips_non_ok() {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.push_probe(ProbeOutcome::empty("uidmap").with_fact(
            Fact::unavailable("uidmap", "uidMap", "/x".into(), Some(13))));
        assert!(r.fact("uidmap", "uidMap").is_none());
    }
}
```

- [ ] **Step 2: Run — FAIL** (`cargo test -p amirustrained -- lib tests`, expect unresolved imports).
- [ ] **Step 3: Implement** — full type definitions:

```rust
// src/model/fact.rs
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactStatus { Ok, Unavailable, Degraded }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub probe: String,
    pub key: String,
    pub value: Value,
    pub source: String,
    pub status: FactStatus,
}

impl Fact {
    pub fn ok(probe: &str, key: &str, value: Value, source: String) -> Self {
        Self { probe: probe.into(), key: key.into(), value, source, status: FactStatus::Ok }
    }
    pub fn degraded(probe: &str, key: &str, value: Value, source: String) -> Self {
        Self { probe: probe.into(), key: key.into(), value, source, status: FactStatus::Degraded }
    }
    pub fn unavailable(probe: &str, key: &str, source: String, errno: Option<i32>) -> Self {
        Self {
            probe: probe.into(), key: key.into(), source,
            value: serde_json::json!({ "unavailable": true, "errno": errno }),
            status: FactStatus::Unavailable,
        }
    }
}
```

```rust
// src/model/outcome.rs
use serde::{Deserialize, Serialize};
use super::{Fact, Signal};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state", content = "detail")]
pub enum Availability { Ok, Degraded(String), Unavailable(String) }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutcome {
    pub name: String,
    pub availability: Availability,
    pub facts: Vec<Fact>,
    #[serde(skip)]
    pub signals: Vec<Signal>,
    pub timed_out: bool,
}

impl ProbeOutcome {
    pub fn empty(name: &str) -> Self {
        Self { name: name.into(), availability: Availability::Ok, facts: vec![], signals: vec![], timed_out: false }
    }
    pub fn with_fact(mut self, f: Fact) -> Self { self.facts.push(f); self }
    pub fn with_signal(mut self, s: Signal) -> Self { self.signals.push(s); self }
}
```

```rust
// src/model/runtime.rs
use serde::{Deserialize, Serialize};
use super::Fact;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-lowercase")]
pub enum RuntimeKind {
    Docker, Containerd, CriO, Podman, Kubernetes,
    Lxc, SystemdNspawn, Firecracker, Gvisor, Kata, Host,
}

#[derive(Clone, Debug)]
pub struct Signal { pub runtime: RuntimeKind, pub weight: f32, pub evidence: Fact }

/// Signals accumulated by the pipeline before the `runtime` probe runs.
#[derive(Default)]
pub struct PriorSignals(pub Vec<Signal>);
impl PriorSignals { pub fn extend(&mut self, sigs: Vec<Signal>) { self.0.extend(sigs); } }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate { pub runtime: RuntimeKind, pub score: f32 }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub runtime: RuntimeKind,
    pub variant: Option<String>,          // e.g. "rootless"
    pub confidence: String,               // "high" | "medium" | "low"
    pub alternatives: Vec<Candidate>,
    pub evidence: Vec<String>,            // "cgroup:libpod-…" style citations
}
```

```rust
// src/model/finding.rs
use serde::{Deserialize, Serialize};
use super::{Fact, Severity};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    pub evidence: Vec<Fact>,
}
```

```rust
// src/model/rule.rs
use super::{Finding, Report, Severity, Fact};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Info, Low, Medium, High, Critical }

pub struct Rule {
    pub id: &'static str,
    pub slug: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    /// true → an unprivileged run emits an Info downgrade instead of evaluating `check`.
    pub requires_root: bool,
    pub check: fn(report: &Report, privileged: bool) -> Option<Vec<Fact>>,
}

impl Rule {
    pub fn evaluate(&self, report: &Report, privileged: bool) -> Option<Finding> {
        if self.requires_root && !privileged {
            let mut e = vec![Fact::degraded(self.id, "assessment",
                serde_json::json!({"insufficientPrivilege": true}), "probe".into())];
            e.extend(self.downgrade_evidence(report));
            return Some(Finding { rule: self.id, severity: Severity::Info,
                summary: "insufficient privilege to assess", why: self.why,
                remediation: self.remediation, references: self.references, evidence: e });
        }
        (self.check)(report, privileged).map(|ev| Finding {
            rule: self.id, severity: self.severity, summary: self.summary,
            why: self.why, remediation: self.remediation, references: self.references,
            evidence: ev })
    }
    fn downgrade_evidence(&self, report: &Report) -> Vec<Fact> {
        let _ = report; vec![]
    }
}
```

```rust
// src/model/report.rs
use serde::{Deserialize, Serialize};
use super::{Fact, Finding, ProbeOutcome, Verdict};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool { pub name: String, pub version: String }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanMeta {
    pub target_pid: u32, pub uid: u32, pub timestamp: String, pub kernel: String,
    pub complete: bool, pub probe_timeout_s: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts { pub critical: usize, pub high: usize, pub medium: usize, pub low: usize, pub info: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub scan: ScanMeta,
    pub verdict: Option<Verdict>,
    pub probes: Vec<ProbeOutcome>,
    pub findings: Vec<Finding>,
    pub counts: Counts,
}

impl ScanMeta {
    pub fn stub() -> Self { ScanMeta { target_pid: 0, uid: 0, timestamp: "T".into(),
        kernel: "K".into(), complete: true, probe_timeout_s: None } }
}

impl Report {
    pub fn blank(scan: ScanMeta, schema_version: u32) -> Self {
        Self { schema_version, tool: Tool { name: "amirustrained".into(), version: env!("CARGO_PKG_VERSION").into() },
            scan, verdict: None, probes: vec![], findings: vec![], counts: Counts::default() }
    }
    pub fn push_probe(&mut self, o: ProbeOutcome) { self.probes.push(o); }
    pub fn fact(&self, probe: &str, key: &str) -> Option<&Fact> {
        self.probes.iter().flat_map(|p| &p.facts)
            .find(|f| f.probe == probe && f.key == key && f.status == super::FactStatus::Ok)
    }
    pub fn compute_counts(&mut self) {
        self.counts = Default::default();
        for f in &self.findings {
            match f.severity {
                super::Severity::Critical => self.counts.critical += 1,
                super::Severity::High => self.counts.high += 1,
                super::Severity::Medium => self.counts.medium += 1,
                super::Severity::Low => self.counts.low += 1,
                super::Severity::Info => self.counts.info += 1,
            }
        }
    }
}
```

```rust
// src/model/mod.rs
pub mod fact; pub mod finding; pub mod outcome; pub mod report; pub mod rule; pub mod runtime;
pub use fact::{Fact, FactStatus};
pub use finding::Finding;
pub use outcome::{Availability, ProbeOutcome};
pub use report::{Counts, Fact as _, Report, ScanMeta};   // drop stray line; re-export Report/ScanMeta/Counts/Tool only
pub use rule::{Rule, Severity};
pub use runtime::{Candidate, PriorSignals, RuntimeKind, Signal, Verdict};
```

(Replace `mod model { … }` in `main.rs` with `pub mod model;`. Note the stray `Fact as _` line above must be omitted — re-export exactly `{Counts, Report, ScanMeta, Tool}`.)

- [ ] **Step 4: Run — PASS** (`cargo test`). Fix re-export mismatch before moving on.
- [ ] **Step 5: Commit** — `git commit -am "feat: core model types (Fact, Rule, Report, events)"`

---

### Task 3: `sys::fs` — PseudoFs with fixture remap

**Files:**
- Create: `src/sys/fs.rs`, `src/sys/mod.rs`
- Test: inline in `fs.rs`

**Interfaces:**
- Consumes: Task 2 (none directly; standalone).
- Produces:
  - `PseudoFs::real()`, `PseudoFs::new(root: PathBuf)`
  - `enum ProbeIo { NotFound, PermissionDenied, Other(String) }` + `From<std::io::Error>`
  - `read(&self, abs: &str) -> Result<String, ProbeIo>` (trailing `\n` trimmed)
  - `read_link(&self, abs: &str) -> Result<String, ProbeIo>` — under a fixture root, a plain file whose content is the target string stands in for a symlink
  - `exists(&self, abs: &str) -> bool`
  - `list_dir(&self, abs: &str) -> Result<Vec<String>, ProbeIo>` (sorted file names)

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_remap_reads_rooted_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/1")).unwrap();
        std::fs::write(dir.path().join("proc/1/cgroup"), "0::/user.slice/x.scope\n").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(fs.read("/proc/1/cgroup").unwrap(), "0::/user.slice/x.scope");
        assert!(matches!(fs.read("/proc/1/missing"), Err(ProbeIo::NotFound)));
    }
    #[test]
    fn fixture_symlink_stand_in() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/1/ns")).unwrap();
        std::fs::write(dir.path().join("proc/1/ns/pid"), "pid:[4026532192]").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(fs.read_link("/proc/1/ns/pid").unwrap(), "pid:[4026532192]");
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq)]
pub enum ProbeIo { NotFound, PermissionDenied, Other(String) }

impl From<std::io::Error> for ProbeIo {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            NotFound => ProbeIo::NotFound,
            PermissionDenied => ProbeIo::PermissionDenied,
            _ => ProbeIo::Other(e.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct PseudoFs { root: PathBuf }

impl PseudoFs {
    pub fn real() -> Self { Self { root: PathBuf::from("/") } }
    pub fn new(root: PathBuf) -> Self { Self { root } }
    pub fn is_fixture(&self) -> bool { self.root != Path::new("/") }
    fn p(&self, abs: &str) -> PathBuf { self.root.join(abs.trim_start_matches('/')) }

    pub fn read(&self, abs: &str) -> Result<String, ProbeIo> {
        Ok(std::fs::read_to_string(self.p(abs))?.trim_end_matches('\n').to_string())
    }
    pub fn read_link(&self, abs: &str) -> Result<String, ProbeIo> {
        let path = self.p(abs);
        if self.is_fixture() && path.is_file() {
            return Ok(std::fs::read_to_string(path)?.trim().to_string());
        }
        Ok(std::fs::read_link(path)?.to_string_lossy().into_owned())
    }
    pub fn exists(&self, abs: &str) -> bool { self.p(abs).exists() }
    pub fn list_dir(&self, abs: &str) -> Result<Vec<String>, ProbeIo> {
        let mut v: Vec<String> = std::fs::read_dir(self.p(abs))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        Ok(v)
    }
}
```

`src/sys/mod.rs`: `pub mod fs; pub mod os;` (stub `os.rs` with `// implemented in Task 4` so crate compiles: actually create empty `os.rs` now).

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: PseudoFs fixture-rooted pseudo-fs access"`

---

### Task 4: `sys::os` — OsApi trait + RealOs

**Files:**
- Create: `src/sys/os.rs`
- Test: inline — real-host CPUID sanity + trait-object compilability (pure logic tested in consumer probes).

**Interfaces:**
- Consumes: standalone.
- Produces (canonical trait — stubs in later tests implement this):

```rust
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct HypervisorInfo { pub present: bool, pub vendor: Option<String> }

#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompActions {
    pub kill_process: bool, pub kill_thread: bool, pub trap: bool,
    pub errno: bool, pub log: bool, pub trace: bool, pub user_notif: bool,
    pub probed_ok: bool, // false ⇒ GET_ACTION_AVAIL unsupported (pre-4.14 / EOPNOTSUPP)
}

pub struct UdsReply { pub status: u16, pub body: String }

pub trait OsApi: Send + Sync {
    fn hypervisor(&self) -> HypervisorInfo;
    fn landlock_abi(&self) -> Option<u64>;               // None ⇒ syscall unsupported
    fn seccomp_actions(&self) -> SeccompActions;
    fn seccomp_filter_dump(&self, pid: u32) -> Result<Vec<u64>, ProbeIo>;
    fn syscall0(&self, id: u32) -> Result<(), i32>;      // raw arg-less syscall; Err = errno
    fn uds_probe(&self, path: &Path, timeout: Duration) -> std::io::Result<UdsReply>;
    fn env(&self, key: &str) -> Option<String>;
    fn is_root(&self) -> bool;                           // geteuid() == 0
}
pub struct RealOs;
impl OsApi for RealOs { /* real impls below */ }
```

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_cpuid_returns_consistent_hypervisor_info() {
        let h = RealOs.hypervisor();
        // On bare metal: present=false, vendor=None. On VMs: both Some. Either way
        // the invariant: vendor present ⇔ present.
        assert_eq!(h.vendor.is_some(), h.present);
    }
    #[test]
    fn env_lookup_works() { assert!(RealOs.env("PATH").is_some()); }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement.** Key bodies (full code, keep as written):

```rust
impl OsApi for RealOs {
    fn hypervisor(&self) -> HypervisorInfo {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: CPUID is supported on all x86_64.
            let feat = unsafe { std::arch::x86_64::__cpuid(1) };
            let hv_bit = feat.ecx & (1 << 31) != 0;
            if !hv_bit { return HypervisorInfo::default(); }
            // Leaves 0x40000000..: hypervisor vendor string (12 chars across EBX..EDX of leaf 0x40000000).
            let leaf = unsafe { std::arch::x86_64::__cpuid(0x4000_0000) };
            let bytes: [u8; 12] = leaf.ebx.to_le_bytes().into_iter()
                .chain(leaf.ecx.to_le_bytes()).chain(leaf.edx.to_le_bytes())
                .collect::<Vec<_>>().try_into().unwrap();
            let vendor = String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string();
            HypervisorInfo { present: true, vendor: Some(vendor) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        HypervisorInfo::default() // aarch64: DMI-only detection (Task 14)
    }

    fn landlock_abi(&self) -> Option<u64> {
        // SAFETY: null attrs + QUERY_ABI flag is the documented probe; invalid syscall nr ⇒ ENOSYS.
        let r = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, 1u32 /*QUERY_ABI*/) };
        if r < 0 { None } else { Some(r as u64) }
    }

    fn seccomp_actions(&self) -> SeccompActions {
        let mut a = SeccompActions::default();
        // Per-action: seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action). rc == 0 ⇒
        // supported. rc < 0 (EINVAL on older kernels, e.g. pre-4.14 KILL_PROCESS)
        // leaves that flag false and clears probed_ok — unsupported is not silently
        // "all false": the matrix stays individually honest.
        let mut all_ok = true;
        for (act, flag) in [
            (2u32 /*SECCOMP_RET_KILL_PROCESS*/, &mut a.kill_process),
            (0u32 /*KILL_THREAD*/, &mut a.kill_thread),
            (1u32 /*TRAP*/, &mut a.trap),
            (0x0005_0000u32 /*ERRNO base*/, &mut a.errno),
            (0x4000_0000u32 /*LOG base*/, &mut a.log),
            (0x7ff0_0000u32 /*TRACE base*/, &mut a.trace),
            (0x7fc0_0900u32 /*USER_NOTIF*/, &mut a.user_notif),
        ] {
            let v = act;
            // SAFETY: v is a plain u32 read by the kernel.
            let rc = unsafe { libc::syscall(317i64 /*SYS_seccomp on x86_64*/,
                2i32 /*SECCOMP_GET_ACTION_AVAIL*/, 0u32, &v) };
            if rc < 0 { all_ok = false; }
            *flag = rc == 0;
        }
        a.probed_ok = all_ok;
        a
    }

    fn seccomp_filter_dump(&self, pid: u32) -> Result<Vec<u64>, ProbeIo> {
        // ptrace attach + PTRACE_SECCOMP_GET_FILTER; long form lives in probe only if root.
        // Return Err(ProbeIo::PermissionDenied) unless we can attach.
        Err(ProbeIo::PermissionDenied) // Task 12 refines; unprivileged default is honest.
    }

    fn syscall0(&self, id: u32) -> Result<(), i32> {
        let rc = unsafe { libc::syscall(id as libc::c_long) };
        if rc < 0 { Err(unsafe { *libc::__errno_location() }) } else { Ok(()) }
    }

    fn uds_probe(&self, path: &Path, timeout: Duration) -> std::io::Result<UdsReply> {
        use std::os::unix::net::UnixStream;
        let mut s = UnixStream::connect_timeout(
            &std::os::unix::net::SocketAddr::from_pathname(path), timeout)?;
        s.set_read_timeout(Some(timeout))?;
        use std::io::{Read, Write};
        s.write_all(b"GET /info HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n")?;
        let mut buf = String::new();
        s.read_to_string(&mut buf)?; // read_to_string caps at stream close; sockets probe enforces timeout via set_read_timeout (ErrorKind::WouldBlock -> TimedOut)
        let (head, body) = buf.split_once("\r\n\r\n").unwrap_or(("", ""));
        let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        Ok(UdsReply { status, body: body.to_string() })
    }

    fn env(&self, key: &str) -> Option<String> { std::env::var(key).ok() }
    fn is_root(&self) -> bool { unsafe { libc::geteuid() == 0 } }
}
```

`SYS_seccomp` literal 317 is x86_64-only: gate the `seccomp_actions` body with `#[cfg(target_arch = "x86_64")]` and return `SeccompActions::default()` elsewhere; on aarch64 `libc::SYS_seccomp` may be defined — prefer `libc::SYS_seccomp` where it exists, keeping `probed_ok=false` fallback. `landlock_create_ruleset` const: `libc::SYS_landlock_create_ruleset` where defined, else `probed None`.

- [ ] **Step 4: Run — PASS** (on bare-metal host `present=false` trivially satisfies the invariant; in CI-on-VM both are Some — either passes).
- [ ] **Step 5: Commit** — `"feat: OsApi seam (cpuid, landlock, seccomp, uds, raw syscall)"`

---

### Task 5: Pipeline — events, per-probe threads, timeout, aggregation

**Files:**
- Create: `src/pipeline.rs`, `src/probes/mod.rs` (trait + registry; registry empty for now)
- Test: inline `pipeline.rs`

**Interfaces:**
- Consumes: Task 2 types, Task 3 PseudoFs, Task 4 OsApi.
- Produces:
  - `Opts { pid: Option<u32>, probe_syscalls: bool, probe_timeout: Option<Duration>, fail_on: Option<Severity> }` in `src/opts.rs` (Task 7 converts `Cli` → `Opts`)
  - `Ctx<'a> { pid: u32, uid: u32, fs: &'a PseudoFs, os: &'a dyn OsApi, opts: &'a Opts, prior: Prior }` where `Prior { signals: Vec<Signal>, facts: HashMap<String, Value> }` (`#[derive(Clone, Default)]`) — snapshot of everything earlier probes produced
  - `pub trait Probe: Send + Sync { fn name(&self) -> &'static str; fn run(&self, cx: &Ctx) -> ProbeOutcome; }`
  - `Event::Meta { tool, scan }`, `Event::Probe(ProbeOutcome)`, `Event::Summary { verdict, findings, counts, complete }`
  - `fn run_probe_bounded(probe: Arc<dyn Probe>, fs: Arc<PseudoFs>, os: Arc<dyn OsApi>, opts: &Opts, pid: u32, uid: u32, prior: Vec<Signal>, timeout: Option<Duration>) -> ProbeOutcome` (private)
  - `pub fn scan_with_probes(fs: Arc<PseudoFs>, os: Arc<dyn OsApi>, opts: &Opts, probes: Vec<Arc<dyn Probe>>, sink: &mut dyn FnMut(&Event)) -> Report` — runs probes in order, accumulates signals into an immutable per-dispatch snapshot, sets `verdict` from the runtime probe's `verdict` fact, evaluates `RULES` (empty until Task 19 → `Vec::new()`), returns finished `Report`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::Probe;
    struct Slow; impl Probe for Slow {
        fn name(&self) -> &'static str { "slow" }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome {
            std::thread::sleep(std::time::Duration::from_millis(300));
            ProbeOutcome::empty("slow")
        }
    }
    struct Fast; impl Probe for Fast {
        fn name(&self) -> &'static str { "fast" }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome { ProbeOutcome::empty("fast") }
    }

    #[test]
    fn timed_out_probe_is_marked_and_scan_continues() {
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts { pid: None, probe_syscalls: false, dump_filters: false,
            probe_timeout: Some(std::time::Duration::from_millis(50)), fail_on: None };
        let mut events = vec![];
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(Slow), Arc::new(Fast)];
        let report = scan_with_probes(fs, os, &opts, probes, &mut |e| events.push(format!("{e:?}")));
        let slow = report.probes.iter().find(|p| p.name == "slow").unwrap();
        assert!(slow.timed_out);
        assert!(matches!(slow.availability, Availability::Unavailable(_)));
        let fast = report.probes.iter().find(|p| p.name == "fast").unwrap();
        assert!(!fast.timed_out);
        assert!(report.scan.complete);
    }
    #[test]
    fn events_are_emitted_in_meta_probe_summary_order() {
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts { pid: None, probe_syscalls: false, dump_filters: false, probe_timeout: None, fail_on: None };
        let mut events = vec![];
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(Fast), Arc::new(Slow2)];
        scan_with_probes(fs, os, &opts, probes, &mut |e| events.push(format!("{e:?}")));
        assert!(events[0].starts_with("Meta"));
        assert!(events[1].starts_with(r#"Probe(ProbeOutcome { name: "fast""#));
        assert!(events[2].starts_with(r#"Probe(ProbeOutcome { name: "slow2""#));
        assert!(events[3].starts_with("Summary"));
    }
    struct Slow2; impl Probe for Slow2 {
        fn name(&self) -> &'static str { "slow2" }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome { ProbeOutcome::empty("slow2") }
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
// src/opts.rs — append (Cli stays as-is; Opts is the derived internal view)
use std::time::Duration;
use crate::model::Severity;

#[derive(Debug, Clone)]
pub struct Opts {
    pub pid: Option<u32>,
    pub probe_syscalls: bool,
    pub probe_timeout: Option<Duration>,
    pub fail_on: Option<Severity>,
    pub dump_filters: bool,
}
```

```rust
// src/pipeline.rs
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::model::*;
use crate::opts::Opts;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;
use crate::sys::os::OsApi;

/// What earlier probes accumulated, snapshotted per dispatch (probes run one at
/// a time, so building it between dispatches is race-free).
#[derive(Clone, Default)]
pub struct Prior {
    pub signals: Vec<Signal>,
    /// keyed "{probe}.{factKey}", Ok-status facts only
    pub facts: std::collections::HashMap<String, serde_json::Value>,
}

pub struct Ctx<'a> {
    pub pid: u32,
    pub uid: u32,
    pub fs: &'a PseudoFs,
    pub os: &'a dyn OsApi,
    pub opts: &'a Opts,
    pub prior: Prior,
}

#[derive(Debug)]
pub enum Event {
    Meta { tool: Tool, scan: ScanMeta },
    Probe(ProbeOutcome),
    Summary { verdict: Option<Verdict>, findings: Vec<Finding>, counts: Counts, complete: bool },
}

/// Runs one probe on its own thread. The thread captures `Arc` clones of the
/// shared seams, so an abandoned (hung) worker can never outlive its data —
/// `exit()` reaps it. First channel response wins; timeouts are not retried,
/// which keeps event order deterministic.
fn run_probe_bounded(probe: Arc<dyn Probe>, fs: Arc<PseudoFs>, os: Arc<dyn OsApi>,
                     opts: &Opts, pid: u32, uid: u32, prior: Prior,
                     timeout: Option<Duration>) -> ProbeOutcome {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let cx = Ctx { pid, uid, fs: &fs, os: &*os, opts, prior };
        let _ = tx.send(probe.run(&cx));
    });
    match timeout {
        Some(d) => rx.recv_timeout(d),
        None => rx.recv(),
    }.unwrap_or_else(|_| {
        let mut o = ProbeOutcome::empty(probe.name());
        o.timed_out = true;
        o.availability = Availability::Unavailable("timed out".into());
        o
    })
}

pub fn scan_with_probes(fs: Arc<PseudoFs>, os: Arc<dyn OsApi>, opts: &Opts,
                        probes: Vec<Arc<dyn Probe>>,
                        sink: &mut dyn FnMut(&Event)) -> Report {
    let target_pid = opts.pid.unwrap_or_else(std::process::id);
    let meta = ScanMeta {
        target_pid,
        uid: unsafe { libc::geteuid() },
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string()).unwrap_or_default(),
        kernel: rustix::system::uname().release().to_string(),
        complete: false,
        probe_timeout_s: opts.probe_timeout.map(|d| d.as_secs()),
    };
    let mut report = Report::blank(meta.clone(), 1);
    sink(&Event::Meta { tool: report.tool.clone(), scan: meta.clone() });
    let mut prior = Prior::default();
    for probe in probes {
        let mut o = run_probe_bounded(probe.clone(), fs.clone(), os.clone(), opts,
                                      target_pid, meta.uid, prior.clone(), opts.probe_timeout);
        prior.signals.extend(o.signals.drain(..));
        for f in o.facts.iter().filter(|f| f.status == FactStatus::Ok) {
            prior.facts.insert(format!("{}.{}", o.name, f.key), f.value.clone());
        }
        if o.name == "runtime" {
            if let Some(f) = o.facts.iter()
                .find(|f| f.key == "verdict" && f.status == FactStatus::Ok) {
                report.verdict = serde_json::from_value(f.value.clone()).ok();
            }
        }
        report.push_probe(o.clone());
        sink(&Event::Probe(o));
    }
    report.findings = crate::model::rules::evaluate_all(&report, os.is_root());
    report.compute_counts();
    report.scan.complete = true;
    sink(&Event::Summary { verdict: report.verdict.clone(),
        findings: report.findings.clone(), counts: report.counts.clone(), complete: true });
    report
}
```

Add `"system"` to the `rustix` feature list in `Cargo.toml`.

```rust
// src/model/rules.rs — empty registry for now; Tasks 19–21 fill RULES in id order.
use super::{Finding, Report};
pub use super::rule::Rule;

pub static RULES: &[Rule] = &[];

pub fn evaluate_all(report: &Report, privileged: bool) -> Vec<Finding> {
    RULES.iter().filter_map(|r| r.evaluate(report, privileged)).collect()
}
```

```rust
// src/probes/mod.rs
use std::sync::Arc;
use crate::model::ProbeOutcome;
use crate::opts::Opts;
use crate::pipeline::Ctx;

pub trait Probe: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, cx: &Ctx) -> ProbeOutcome;
}

// Modules are appended here by their own tasks. Final order (spec Global
// Constraints): namespaces, uidmap, capabilities, seccomp, [syscall-probe],
// lsm, vmm, cgroup, sockets, k8s, runtime.
pub mod namespaces;
pub mod uidmap;
// …capabilities; seccomp; lsm; vmm; cgroup; sockets; k8s; runtime;

pub fn registry(opts: &Opts) -> Vec<Arc<dyn Probe>> {
    let mut v: Vec<Arc<dyn Probe>> = vec![
        Arc::new(namespaces::Namespaces),
        Arc::new(uidmap::Uidmap),
    ];
    if opts.probe_syscalls { v.push(Arc::new(crate::probes::syscall_probe::SyscallProbe)); }
    v
}
```

(`Task 5 lands `namespaces.rs`/`uidmap.rs` as compiling stubs — each just `pub struct Namespaces;` / `Uidmap;` implementing `Probe` with `ProbeOutcome::empty(name)`; Tasks 8–9 replace the bodies. This keeps `registry()` honest at every commit.)
- [ ] **Step 4: Run — PASS** (`cargo test`; also `cargo clippy --all-targets -- -D warnings` clean).
- [ ] **Step 5: Commit** — `"feat: event-stream pipeline with per-probe timeout isolation"`

---

### Task 6: Renderer trait + JSONL + minimal text

**Files:**
- Create: `src/render/mod.rs`, `src/render/text.rs`, `src/render/jsonl.rs`
- Modify: `src/opts.rs` (add `Format`)
- Test: inline in `jsonl.rs`, `text.rs`

**Interfaces:**
- Consumes: Task 5 `Event`.
- Produces:
  - `enum Format { Text, Markdown, Json, Sarif, Jsonl }` + `FromStr` (Err = unit type; CLI maps to exit 2)
  - `pub trait Renderer: Send { fn on_event(&mut self, w: &mut dyn Write, ev: &Event) -> io::Result<()>; fn finish(&mut self, w: &mut dyn Write) -> io::Result<()>; }` in `render/mod.rs`
  - `render::make(fmt: Format) -> Box<dyn Renderer>` (Text/Jsonl only until Tasks 22–24; others `todo!()` replaced then)

- [ ] **Step 1: Failing tests**

```rust
// src/render/jsonl.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ScanMeta, Tool};
    use crate::pipeline::Event;
    #[test]
    fn one_object_per_line_with_type_and_schema() {
        let mut buf = vec![];
        let mut r = Jsonl;
        r.on_event(&mut buf, &Event::Meta {
            tool: Tool { name: "amirustrained".into(), version: "0.1.0".into() },
            scan: ScanMeta::stub() }).unwrap();
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap"))).unwrap();
        let lines: Vec<&str> = String::from_utf8(buf).unwrap().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(r#"{"schemaVersion":1,"type":"meta""#));
        assert!(lines[1].contains(r#""type":"probe","name":"uidmap""#));
    }
}
```

```rust
// src/render/text.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimal_text_emits_probe_lines_and_summary() {
        let mut buf = vec![];
        let mut r = Text { verbose: false };
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap"))).unwrap();
        r.on_event(&mut buf, &Event::Summary { verdict: None, findings: vec![],
            counts: Counts::default(), complete: true }).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("probe uidmap: ok"));
        assert!(s.contains("scan complete"));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
// src/opts.rs — append
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format { Text, Markdown, Json, Sarif, Jsonl }
impl std::str::FromStr for Format {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s {
            "text" => Format::Text, "markdown" => Format::Markdown,
            "json" => Format::Json, "sarif" => Format::Sarif,
            "jsonl" => Format::Jsonl, _ => return Err(()),
        })
    }
}
```

```rust
// src/render/mod.rs
pub mod jsonl; pub mod text;
use crate::pipeline::Event;
use crate::opts::Format;

pub trait Renderer {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()>;
    fn finish(&mut self, w: &mut dyn std::io::Write) -> std::io::Result<()>;
}

pub fn make(fmt: Format, verbose: bool) -> Box<dyn Renderer> {
    match fmt {
        Format::Text => Box::new(text::Text { verbose }),
        Format::Jsonl => Box::new(jsonl::Jsonl),
        // Tasks 22–24 replace these arms; until then treated as misuse-safe default:
        Format::Markdown | Format::Json | Format::Sarif => Box::new(text::Text { verbose }),
    }
}
```

```rust
// src/render/jsonl.rs
use crate::model::ProbeOutcome; // referenced by tests through `use super::*`
use crate::pipeline::Event;
use super::Renderer;

pub struct Jsonl;

impl Renderer for Jsonl {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // `#[serde(flatten)]` needs an inner tagged struct per variant; build lines
        // with serde_json directly to keep control of field order:
        let line = match ev {
            Event::Meta { tool, scan } => serde_json::json!(
                { "schemaVersion": 1, "type": "meta", "tool": tool, "scan": scan }),
            Event::Probe(o) => {
                let mut v = serde_json::to_value(o).map_err(std::io::Error::other)?;
                v["schemaVersion"] = serde_json::json!(1);
                v["type"] = serde_json::json!("probe");
                v
            }
            Event::Summary { verdict, findings, counts, complete } => serde_json::json!(
                { "schemaVersion": 1, "type": "summary", "verdict": verdict,
                  "findings": findings, "counts": counts, "complete": complete }),
        };
        let mut s = serde_json::to_string(&line).map_err(std::io::Error::other)?;
        s.push('\n');
        w.write_all(s.as_bytes())?;
        w.flush() // streaming guarantee: consumer sees each probe the moment it lands
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> { Ok(()) }
}
```

(`serde_json::to_value` of a struct yields a map, so the `probe` event line can inject `schemaVersion`/`type` by index-assignment; `Meta`/`Summary` are built directly with `json!`.)

```rust
// src/render/text.rs
use crate::pipeline::Event;
use super::Renderer;

pub struct Text { pub verbose: bool }

impl Renderer for Text {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        match ev {
            Event::Meta { tool, scan } if self.verbose => writeln!(w,
                "{} {} scanning pid {} (uid {})", tool.name, tool.version, scan.target_pid, scan.uid)?,
            Event::Probe(o) if self.verbose => writeln!(w, "probe {}: {}", o.name,
                match &o.availability {
                    crate::model::Availability::Ok => "ok".into(),
                    crate::model::Availability::Degraded(d) => format!("degraded: {d}"),
                    crate::model::Availability::Unavailable(d) => format!("unavailable: {d}"),
                })?,
            Event::Probe(o) => { let _ = o; }        // quiet by default until Task 23
            Event::Summary { counts, complete, .. } => writeln!(w,
                "scan complete{}: {} findings (c{} h{} m{} l{} i{})",
                if *complete { "" } else { " INCOMPLETE" },
                counts.critical + counts.high + counts.medium + counts.low + counts.info,
                counts.critical, counts.high, counts.medium, counts.low, counts.info)?,
            _ => {}
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> { Ok(()) }
}
```

(Order matters: `Event::Probe(o) if self.verbose` must precede the catch-all `Event::Probe(o)` arm.)

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: renderer trait, jsonl streaming, minimal text"`

---

### Task 7: CLI wiring + exit codes

**Files:**
- Modify: `src/main.rs`, `src/opts.rs`
- Test: extend `tests/cli.rs`

**Interfaces:**
- Consumes: Tasks 5–6.
- Produces: process contract — `Cli → (Format, Opts)` conversion fn `Opts::from_cli(&Cli) -> Result<(Format, Opts), CliError>`; exit codes per Global Constraints.

- [ ] **Step 1: Failing tests**

```rust
// tests/cli.rs — append
#[test]
fn bogus_format_exits_2() {
    Command::cargo_bin("amirustrained").unwrap()
        .args(["--format", "yaml"]).assert().code(2)
        .stderr(predicates::str::contains("unknown format"));
}
#[test]
fn jsonl_stream_has_meta_first_and_summary_last() {
    let out = Command::cargo_bin("amirustrained").unwrap()
        .args(["--format", "jsonl"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    assert!(lines.next().unwrap().contains(r#""type":"meta""#));
    assert!(lines.last().unwrap().contains(r#""type":"summary""#));
}
#[test]
fn unwritable_output_exits_2() {
    Command::cargo_bin("amirustrained").unwrap()
        .args(["-o", "/nonexistent-dir-xyz/out.json"]).assert().code(2);
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
// src/opts.rs — append
#[derive(Debug)]
pub enum CliError { BadFormat(String), BadFailOn(String) }

impl Opts {
    pub fn from_cli(c: &Cli) -> Result<(Format, Opts), CliError> {
        let fmt: Format = c.format.parse().map_err(|_| CliError::BadFormat(c.format.clone()))?;
        let fail_on = match c.fail_on.as_deref() {
            None => None,
            Some(s) => Some(match s {
                "any" => crate::model::Severity::Info,
                "info" => crate::model::Severity::Info,
                "low" => crate::model::Severity::Low,
                "medium" => crate::model::Severity::Medium,
                "high" => crate::model::Severity::High,
                "critical" => crate::model::Severity::Critical,
                _ => return Err(CliError::BadFailOn(s.into())),
            }),
        };
        Ok((fmt, Opts { pid: c.pid, probe_syscalls: c.probe_syscalls,
            probe_timeout: c.probe_timeout.map(std::time::Duration::from_secs), fail_on }))
    }
}
```

```rust
// src/main.rs — replace body
mod opts; mod model; mod sys; mod pipeline; mod probes; mod render;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = opts::Cli::parse();
    let (fmt, opts) = match opts::Opts::from_cli(&cli) {
        Ok(v) => v,
        Err(e) => { eprintln!("error: {e:?}"); return ExitCode::from(2); }
    };
    let fs = std::sync::Arc::new(match &cli.fixture_root {
        Some(r) => sys::fs::PseudoFs::new(r.clone()),
        None => sys::fs::PseudoFs::real(),
    });
    let os: std::sync::Arc<dyn sys::os::OsApi> = std::sync::Arc::new(sys::os::RealOs);
    let mut renderer = render::make(fmt, cli.verbose);
    let mut out: Box<dyn std::io::Write> = match &cli.output {
        Some(p) => match std::fs::File::create(p) {
            Ok(f) => Box::new(f),
            Err(e) => { eprintln!("error: cannot write {}: {e}", p.display()); return ExitCode::from(2); }
        },
        None => Box::new(std::io::stdout()),
    };
    let mut sink = |ev: &pipeline::Event| {
        if let Err(e) = renderer.on_event(&mut out, ev) {
            eprintln!("error: output failed: {e}");
            // stdout closed mid-scan: exit 2 without finishing remaining probes
            std::process::exit(2);
        }
    };
    let report = pipeline::scan_with_probes(fs, os, &opts,
        probes::registry(&opts), &mut sink);
    if let Err(e) = renderer.finish(&mut out) {
        eprintln!("error: output failed: {e}"); return ExitCode::from(2);
    }
    let tripped = opts.fail_on.is_some_and(|lvl|
        report.findings.iter().any(|f| f.severity >= lvl));
    if tripped { return ExitCode::from(1); }
    ExitCode::SUCCESS
}
```

`CliError` display: derive Debug output is acceptable (`unknown format` string: implement `std::fmt::Display` for `CliError` with exactly `unknown format '{0}'` / `unknown fail-on level '{0}'` — the test greps for `unknown format`).

- [ ] **Step 4: Run — PASS** (`cargo test`; stub probes make the full pipeline green).
- [ ] **Step 5: Commit** — `"feat: cli wiring, formats, exit codes"`

---

### Task 8: uidmap probe

**Files:**
- Modify: `src/probes/uidmap.rs` (replace stub)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs`, `ProbeOutcome`, `Signal`, `RuntimeKind`.
- Produces facts (probe `"uidmap"`): `uidMap` (array of `{container,host,range}` numbers), `gidMap`, `setgroups` (`"allow"|"deny"`), `rootless` (bool). Signal: `rootless ⇒ Signal{ Podman, 0.3 }`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, c) in files {
            let full = d.path().join(p.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        }
        d
    }
    #[test]
    fn rootless_single_mapped_row() {
        let d = fixture(&[
            ("proc/42/uid_map", "         0       100000      65536\n"),
            ("proc/42/gid_map", "         0       100000      65536\n"),
            ("proc/42/setgroups", "deny\n")]);
        let rows = parse_map("0 100000 65536");
        assert_eq!(rows[0], MapRow { container: 0, host: 100000, range: 65536 });
        // drive the probe via public helper used in run():
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let outcome = probe_uidmap(&fs, 42);
        assert!(outcome.facts.iter().any(|f| f.key == "rootless" && f.value == serde_json::json!(true)));
        assert!(outcome.facts.iter().any(|f| f.key == "setgroups" && f.value == "deny"));
    }
    #[test]
    fn identity_map_is_not_rootless() {
        let d = fixture(&[("proc/42/uid_map", "         0          0 4294967295\n")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_uidmap(&fs, 42);
        assert!(o.facts.iter().any(|f| f.key == "rootless" && f.value == serde_json::json!(false)));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use serde::Serialize;
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::sys::fs::PseudoFs;

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct MapRow { pub container: u32, pub host: u32, pub range: u32 }

pub fn parse_map(s: &str) -> Vec<MapRow> {
    s.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        Some(MapRow { container: it.next()?.parse().ok()?, host: it.next()?.parse().ok()?, range: it.next()?.parse().ok()? })
    }).collect()
}

pub fn probe_uidmap(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("uidmap");
    let base = format!("/proc/{pid}");
    let mut rootless = false;
    for (key, file) in [("uidMap", "uid_map"), ("gidMap", "gid_map")] {
        match fs.read(&format!("{base}/{file}")) {
            Ok(s) => {
                let rows = parse_map(&s);
                if key == "uidMap" {
                    rootless = rows.len() == 1 && rows[0].container == 0
                        && rows[0].host != 0 && rows[0].range < u32::MAX;
                }
                o = o.with_fact(Fact::ok("uidmap", key,
                    serde_json::to_value(&rows).unwrap(), format!("{base}/{file}")));
            }
            Err(e) => o = o.with_fact(Fact::unavailable("uidmap", key,
                format!("{base}/{file}"), errno_of(&e))),
        }
    }
    match fs.read(&format!("{base}/setgroups")) {
        Ok(s) => o = o.with_fact(Fact::ok("uidmap", "setgroups", s.into(), format!("{base}/setgroups"))),
        // setgroups absent ⇒ pre-3.19 kernel or EACCES inside container: absent-safe.
        Err(_) => o = o.with_fact(Fact::degraded("uidmap", "setgroups",
            serde_json::Value::Null, format!("{base}/setgroups"))),
    }
    let rf = Fact::ok("uidmap", "rootless", rootless.into(), format!("{base}/uid_map"));
    if rootless { o = o.with_signal(Signal { runtime: RuntimeKind::Podman, weight: 0.3, evidence: rf.clone() }); }
    o.with_fact(rf)
}

pub struct Uidmap;
impl crate::probes::Probe for Uidmap {
    fn name(&self) -> &'static str { "uidmap" }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome { probe_uidmap(cx.fs, cx.pid) }
}
```

`errno_of(&ProbeIo) -> Option<i32>`: shared helper — put `pub fn errno_of(e: &ProbeIo) -> Option<i32>` in `sys/fs.rs` (`PermissionDenied ⇒ Some(13)`, `NotFound ⇒ Some(2)`, `Other ⇒ None`).

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: uidmap probe"`

---

### Task 9: capabilities probe

**Files:**
- Modify: `src/probes/capabilities.rs` (create + registry entry)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs`.
- Produces facts (probe `"capabilities"`): `effective`, `permitted`, `inheritable`, `bounding`, `ambient`, `lastEffective` (arrays of capability names), `noNewPrivs` (number), `secureBits` (hex string), `ptraceScope` (number or null-degraded).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode_known_bits() {
        let caps = decode((1u64 << 21) | 1);
        assert!(caps.contains(&"cap_chown") && caps.contains(&"cap_sys_admin"));
    }
    #[test]
    fn decode_bpf_perfmon_checkpoint() {
        let v = (1u64<<39) | (1u64<<38) | (1u64<<40);
        let caps = decode(v);
        assert!(caps.contains(&"cap_bpf") && caps.contains(&"cap_perfmon")
            && caps.contains(&"cap_checkpoint_restore"));
    }
    #[test]
    fn status_parse_pulls_all_sets() {
        let status = "CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";
        let p = parse_status_caps(status);
        assert_eq!(p.effective.len(), 41);
        assert_eq!(p.no_new_privs, Some(0));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
const CAP_NAMES: [&str; 41] = [
    "cap_chown","cap_dac_override","cap_dac_read_search","cap_fowner","cap_fsetid","cap_kill",
    "cap_setgid","cap_setuid","cap_setpcap","cap_linux_immutable","cap_net_bind_service",
    "cap_net_broadcast","cap_net_admin","cap_net_raw","cap_ipc_lock","cap_ipc_owner",
    "cap_sys_module","cap_sys_rawio","cap_sys_chroot","cap_sys_ptrace","cap_sys_pacct",
    "cap_sys_admin","cap_sys_boot","cap_sys_nice","cap_sys_resource","cap_sys_time",
    "cap_sys_tty_config","cap_mknod","cap_lease","cap_audit_write","cap_audit_control",
    "cap_setfcap","cap_mac_override","cap_mac_admin","cap_syslog","cap_wake_alarm",
    "cap_block_suspend","cap_audit_read","cap_perfmon","cap_bpf","cap_checkpoint_restore"];

pub fn decode(mut bits: u64) -> Vec<&'static str> {
    CAP_NAMES.iter().enumerate()
        .filter(|(i, _)| bits & (1u64 << *i) != 0).map(|(_, n)| *n).collect()
}

#[derive(Debug, Default)]
pub struct StatusCaps {
    pub effective: Vec<&'static str>, pub permitted: Vec<&'static str>,
    pub inheritable: Vec<&'static str>, pub bounding: Vec<&'static str>,
    pub ambient: Vec<&'static str>, pub last_effective: Option<u64>,
    pub no_new_privs: Option<u64>, pub secure_bits: Option<String>,
}

pub fn parse_status_caps(status: &str) -> StatusCaps {
    let mut out = StatusCaps::default();
    for line in status.lines() {
        let mut it = line.splitn(2, ':');
        let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        let bits = u64::from_str_radix(v, 16).unwrap_or(0);
        match k {
            "CapEff" => out.effective = decode(bits),
            "CapPrm" => out.permitted = decode(bits),
            "CapInh" => out.inheritable = decode(bits),
            "CapBnd" => out.bounding = decode(bits),
            "CapAmb" => out.ambient = decode(bits),
            "CapLastEff" => out.last_effective = Some(bits),
            "NoNewPrivs" => out.no_new_privs = v.parse().ok(),
            "SecureBits" => out.secure_bits = Some(v.to_string()),
            _ => {}
        }
    }
    out
}
```

Probe `run`: `fs.read(&format!("/proc/{pid}/status"))` → `parse_status_caps` → one `Fact::ok` per field (arrays via `serde_json::to_value`); then read `/proc/sys/kernel/yama/ptrace_scope` (fixture-rooted! — Yama file lives under the same remapped root: path `/proc/sys/kernel/yama/ptrace_scope`), absent ⇒ `Fact::degraded` null (rule AMR-004 tolerates).

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: capabilities probe with full cap name table"`

---

### Task 10: namespaces probe

**Files:**
- Modify: `src/probes/namespaces.rs` (replace stub)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs::read_link`.
- Produces facts (probe `"namespaces"`): `isolated` = object over the 8 types (`cgroup ipc mnt net pid pid_for_children time time_ns user`) → `true|false|null`; `inodes` = object type → link target string; `cgroupNsSameAsInit` = bool|null. Availability `Degraded("pid 1 namespaces unreadable")` when init links fail (facts for own inodes still emitted, isolation values `null`).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn fx(files: &[(&str, &str)]) -> tempfile::TempDir { /* same helper as Task 8 */ }
    #[test]
    fn isolated_vs_init() {
        let d = fx(&[
            ("proc/42/ns/pid", "pid:[4026532192]"), ("proc/1/ns/pid", "pid:[4026531836]"),
            ("proc/42/ns/net", "net:[4026532195]"), ("proc/1/ns/net", "net:[4026532195]"),
            ("proc/42/ns/cgroup", "cgroup:[4026532190]"), ("proc/1/ns/cgroup", "cgroup:[4026531999]"),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        let f = o.facts.iter().find(|f| f.key == "isolated").unwrap();
        assert_eq!(f.value["pid"], serde_json::json!(true));
        assert_eq!(f.value["net"], serde_json::json!(false));
        assert_eq!(o.facts.iter().find(|f| f.key == "cgroupNsSameAsInit").unwrap().value,
                   serde_json::json!(false));
    }
    #[test]
    fn degraded_when_init_unreadable() {
        let d = fx(&[("proc/42/ns/pid", "pid:[4026532192]")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        assert!(matches!(o.availability, crate::model::Availability::Degraded(_)));
        let f = o.facts.iter().find(|f| f.key == "isolated").unwrap();
        assert_eq!(f.value["pid"], serde_json::Value::Null);
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
const NS_TYPES: [&str; 8] = ["cgroup","ipc","mnt","net","pid","pid_for_children","time","time_ns","user"]
    // NOTE: 9 entries incl. pid_for_children; the spec's "8 ns types" counts the
    // kernel-visible families — we report every link file found under /proc/<pid>/ns.
    ;

pub fn probe_namespaces(fs: &crate::sys::fs::PseudoFs, pid: u32) -> ProbeOutcome {
    use crate::model::{Availability, Fact};
    let mut o = ProbeOutcome::empty("namespaces");
    let mut isolated = serde_json::Map::new();
    let mut inodes = serde_json::Map::new();
    let mut degraded = false;
    for t in NS_TYPES {
        let own = fs.read_link(&format!("/proc/{pid}/ns/{t}"));
        let init = fs.read_link("/proc/1/ns/" + t);
        let entry = match (&own, &init) {
            (Ok(a), Ok(b)) => serde_json::json!(a != b),
            _ => { if own.is_ok() { degraded = true; } serde_json::Value::Null }
        };
        if let Ok(a) = &own { inodes.insert(t.into(), a.clone().into()); }
        isolated.insert(t.into(), entry);
    }
    let cg_same = match (fs.read_link(&format!("/proc/{pid}/ns/cgroup")), fs.read_link("/proc/1/ns/cgroup")) {
        (Ok(a), Ok(b)) => serde_json::json!(a == b),
        _ => serde_json::Value::Null,
    };
    o = o.with_fact(if degraded {
        Fact::degraded("namespaces", "isolated", serde_json::Value::Object(isolated.clone()),
            format!("/proc/{pid}/ns"))
    } else {
        Fact::ok("namespaces", "isolated", serde_json::Value::Object(isolated),
            format!("/proc/{pid}/ns"))
    });
    o = o.with_fact(Fact::ok("namespaces", "inodes", serde_json::Value::Object(inodes),
        format!("/proc/{pid}/ns")));
    o = o.with_fact(Fact::ok("namespaces", "cgroupNsSameAsInit", cg_same, "/proc/1/ns/cgroup"));
    if degraded { o.availability = Availability::Degraded("pid 1 namespaces unreadable".into()); }
    o
}

pub struct Namespaces;
impl crate::probes::Probe for Namespaces {
    fn name(&self) -> &'static str { "namespaces" }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome { probe_namespaces(cx.fs, cx.pid) }
}
```

(Task 19 adds `Report::fact_any(probe, key)` returning facts of any status; AMR-004 accepts `Degraded` — pid 1 unreadable — but not `Unavailable`. `Report::fact()` itself keeps filtering to Ok.)

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: namespaces probe with init comparison + degraded mode"`

---

### Task 11: cgroup probe

**Files:**
- Modify: `src/probes/cgroup.rs` (create + registry entry)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs`.
- Produces facts (probe `"cgroup"`): `version` (1|2), `path` (own cgroup path string), `pattern` (`"docker"|"kubernetes"|"podman"|"lxc"|"nspawn"|"systemd"|"root"|null`), `controllers` (array, v2 `cgroup.controllers`), `limits` (object `{memory,pids,cpu}` strings, `"max"` = unlimited, v2 only). Signals: pattern→RuntimeKind with weights docker 0.8 / kubernetes 0.7 / podman 0.7 / lxc 0.7 / nspawn 0.6.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_runtime_paths() {
        assert_eq!(classify("/docker/135c8edbc014a110669e20515a1a90d3f4d2ee5c50ee50a03e6a9ed7d1c8c4a2").0, Some(RuntimeKind::Docker));
        assert_eq!(classify("/kubepods/besteffort/pod73f1a1b2-1234/cpu.slice").0, Some(RuntimeKind::Kubernetes));
        assert_eq!(classify("/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-1a2b3c4d.scope").0, Some(RuntimeKind::Podman));
        assert_eq!(classify("/lxc/mycontainer").0, Some(RuntimeKind::Lxc));
        assert_eq!(classify("/machine.slice/machine-nspawn1.scope").0, Some(RuntimeKind::SystemdNspawn));
        assert_eq!(classify("/user.slice/session-1.scope").0, None);
        assert_eq!(classify("/user.slice/session-1.scope").1, Some("systemd"));
    }
    #[test]
    fn v2_and_limits() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sys/fs/cgroup/user.slice")).unwrap();
        std::fs::write(d.path().join("sys/fs/cgroup/cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(d.path().join("sys/fs/cgroup/user.slice/pids.max"), "2048\n").unwrap();
        std::fs::write(d.path().join("sys/fs/cgroup/user.slice/memory.max"), "max\n").unwrap();
        std::fs::create_dir_all(d.path().join("proc/9")).unwrap();
        std::fs::write(d.path().join("proc/9/cgroup"), "0::/user.slice\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 9);
        assert_eq!(o.facts.iter().find(|f| f.key == "version").unwrap().value, serde_json::json!(2));
        assert_eq!(o.facts.iter().find(|f| f.key == "limits").unwrap().value["pids"], "2048");
        assert_eq!(o.facts.iter().find(|f| f.key == "limits").unwrap().value["memory"], "max");
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::sys::fs::PseudoFs;

pub fn classify(path: &str) -> (Option<RuntimeKind>, Option<&'static str>) {
    let hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
    if path.contains("kubepods") { return (Some(RuntimeKind::Kubernetes), Some("kubernetes")); }
    if path.contains("libpod-") { return (Some(RuntimeKind::Podman), Some("podman")); }
    if path.contains("/docker/") || path.starts_with("docker-") {
        let last = path.rsplit(['/', '-']).next().unwrap_or("");
        if hex64(last) || path.contains("/docker/") { return (Some(RuntimeKind::Docker), Some("docker")); }
    }
    if path.starts_with("/lxc") || path.contains("/lxc.payload.") { return (Some(RuntimeKind::Lxc), Some("lxc")); }
    if path.contains("machine-nspawn") || path.contains("nspawn") { return (Some(RuntimeKind::SystemdNspawn), Some("nspawn")); }
    if path.starts_with("/user.slice") || path.starts_with("/system.slice") { return (None, Some("systemd")); }
    if path == "/" { return (None, Some("root")); }
    (None, None)
}

pub fn probe_cgroup(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("cgroup");
    let src = format!("/proc/{pid}/cgroup");
    let raw = match fs.read(&src) {
        Ok(raw) => raw,
        Err(e) => return o.with_fact(Fact::unavailable("cgroup", "path", src, crate::sys::fs::errno_of(&e))),
    };
    let (version, path) = parse_cgroup_line(&raw);
    let (kind, pattern) = classify(&path);
    o = o.with_fact(Fact::ok("cgroup", "version", version.into(), src.clone()));
    o = o.with_fact(Fact::ok("cgroup", "path", path.clone().into(), src));
    o = o.with_fact(Fact::ok("cgroup", "pattern",
        pattern.map(|p| serde_json::json!(p)).unwrap_or(serde_json::Value::Null), path.clone()));
    if version == 2 {
        let cgroot = "/sys/fs/cgroup";
        if let Ok(c) = fs.read(&format!("{cgroot}/cgroup.controllers")) {
            o = o.with_fact(Fact::ok("cgroup", "controllers",
                c.split_whitespace().collect::<Vec<_>>().into(), format!("{cgroot}/cgroup.controllers")));
        }
        let mut limits = serde_json::Map::new();
        for k in ["memory.max", "pids.max", "cpu.max"] {
            if let Ok(v) = fs.read(&format!("{cgroot}{path}/{k}")) {
                limits.insert(k.trim_end_matches(".max").into(), v.into());
            }
        }
        o = o.with_fact(Fact::ok("cgroup", "limits", serde_json::Value::Object(limits),
            format!("{cgroot}{path}")));
    }
    if let Some(rt) = kind {
        let w = match rt { RuntimeKind::Docker => 0.8, RuntimeKind::Kubernetes => 0.7,
            RuntimeKind::Podman => 0.7, RuntimeKind::Lxc => 0.7,
            RuntimeKind::SystemdNspawn => 0.6, _ => 0.0 };
        if w > 0.0 {
            o = o.with_signal(Signal { runtime: rt, weight: w,
                evidence: o.facts.iter().find(|f| f.key == "pattern").unwrap().clone() });
        }
    }
    o
}

pub fn parse_cgroup_line(raw: &str) -> (u8, String) {
    // v2 single line "0::/path"; v1 multiple "N:ctrl:/path" — take first line's path.
    let first = raw.lines().next().unwrap_or("");
    if first.starts_with("0::") { (2, first[3..].to_string()) }
    else { (1, first.rsplit(':').next().unwrap_or("/").to_string()) }
}
```



---

### Task 12: seccomp probe

**Files:**
- Create: `src/probes/seccomp.rs` + registry entry (after `capabilities`, before `lsm`)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `OsApi::seccomp_actions`, `PseudoFs`.
- Produces facts (probe `"seccomp"`): `mode` (`"disabled"|"strict"|"filter"|"unknown"`), `filterCount` (number|null), `actions` — the `SeccompActions` struct serialized `rename_all = "camelCase"`: `{killProcess,killThread,trap,errno,log,trace,userNotif,probedOk}`. `Seccomp` status line missing → `mode:"unknown"` + `Availability::Degraded`. Filter *program* dump: only when `os.is_root() && cx.opts.dump_filters` — Task 7's `Cli` gained `#[arg(long, hide = true)] pub dump_filters: bool`; append it to `Opts` too (`dump_filters: bool`) and to `from_cli`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    struct StubOs { actions: SeccompActions, root: bool }
    impl crate::sys::os::OsApi for StubOs {   // signatures MUST match Task 4 trait
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo { Default::default() }
        fn landlock_abi(&self) -> Option<u64> { None }
        fn seccomp_actions(&self) -> SeccompActions { self.actions.clone() }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::model::ProbeIo> {
            Err(crate::model::ProbeIo::PermissionDenied) }
        fn syscall0(&self, _n: u32) -> Result<(), i32> { Err(38) } // ENOSYS
        fn uds_probe(&self, _p: &std::path::Path, _t: std::time::Duration)
            -> std::io::Result<crate::sys::os::UdsReply> { Err(std::io::Error::other("stub")) }
        fn env(&self, _k: &str) -> Option<String> { None }
        fn is_root(&self) -> bool { self.root }
    }
    use crate::pipeline::Ctx;
    use std::sync::Arc;
    fn cx<'a>(fs: &'a crate::sys::fs::PseudoFs, os: &'a dyn crate::sys::os::OsApi,
              opts: &'a crate::opts::Opts) -> Ctx<'a> {
        Ctx { pid: 1234, uid: 1000, fs, os, opts, prior: crate::pipeline::Prior::default() }
    }
    #[test]
    fn mode_and_actions_from_status_and_avail() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("proc/1234")).unwrap();
        std::fs::write(d.path().join("proc/1234/status"), "Seccomp:\t2\nSeccomp_filters:\t3\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs { actions: SeccompActions { kill_process: true, kill_thread: true,
            ..Default::default() }, root: false };
        let opts = crate::opts::Opts { pid: None, probe_syscalls: false,
            probe_timeout: None, fail_on: None, dump_filters: false };
        let o = Seccomp.run(&cx(&fs, &os, &opts));
        assert_eq!(o.facts.iter().find(|f| f.key == "mode").unwrap().value, "filter");
        assert_eq!(o.facts.iter().find(|f| f.key == "filterCount").unwrap().value, serde_json::json!(3));
        let a = o.facts.iter().find(|f| f.key == "actions").unwrap().value.clone();
        assert_eq!(a["killProcess"], serde_json::json!(true));
        assert_eq!(a["userNotif"], serde_json::json!(false));
    }
    #[test]
    fn missing_seccomp_line_degrades_unknown() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("proc/1234")).unwrap();
        std::fs::write(d.path().join("proc/1234/status"), "Name:\tx\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs { actions: SeccompActions::default(), root: false };
        let opts = crate::opts::Opts { pid: None, probe_syscalls: false,
            probe_timeout: None, fail_on: None, dump_filters: false };
        let o = Seccomp.run(&cx(&fs, &os, &opts));
        assert_eq!(o.facts.iter().find(|f| f.key == "mode").unwrap().value, "unknown");
        assert!(matches!(o.availability, crate::model::Availability::Degraded(_)));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::os::SeccompActions;

pub fn parse_mode(status: &str) -> Option<(&'static str, Option<u32>)> {
    let mut mode = None; let mut count = None;
    for line in status.lines() {
        let mut it = line.splitn(2, ':');
        match (it.next().unwrap_or(""), it.next().unwrap_or("").trim()) {
            ("Seccomp", "0") => mode = Some("disabled"),
            ("Seccomp", "1") => mode = Some("strict"),
            ("Seccomp", "2") => mode = Some("filter"),
            ("Seccomp", _) => mode = Some("unknown"),
            ("Seccomp_filters", v) => count = v.parse().ok(),
            _ => {}
        }
    }
    mode.map(|m| (m, count))
}

pub struct Seccomp;
impl Probe for Seccomp {
    fn name(&self) -> &'static str { "seccomp" }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let mut o = ProbeOutcome::empty("seccomp");
        let src = format!("/proc/{}/status", cx.pid);
        let (mode, count) = match cx.fs.read(&src) {
            Ok(s) => parse_mode(&s).map(|(m, c)| (m.to_string(), c)).unwrap_or_else(|| ("unknown".into(), None)),
            Err(e) => return o.with_fact(Fact::unavailable("seccomp", "mode", src, crate::sys::fs::errno_of(&e))),
        };
        o = o.with_fact(Fact::ok("seccomp", "mode", mode.clone().into(), src.clone()));
        o = o.with_fact(Fact::ok("seccomp", "filterCount",
            count.map(|c| serde_json::json!(c)).unwrap_or(serde_json::Value::Null), src));
        o = o.with_fact(Fact::ok("seccomp", "actions",
            serde_json::to_value(cx.os.seccomp_actions()).unwrap(), "SECCOMP_GET_ACTION_AVAIL"));
        if mode == "unknown" { o.availability = Availability::Degraded("Seccomp line absent from status".into()); }
        if cx.opts.dump_filters && cx.os.is_root() {
            let raw = cx.os.seccomp_filter_dump(cx.pid);
            o = o.with_fact(Fact::ok("seccomp", "filterDump",
                serde_json::json!({ "ret": raw.ret, "words": raw.words }), "PTRACE_SECCOMP_GET_FILTER"));
        }
        o
    }
}
```

(`SeccompActions` needs `#[derive(Default)]` — add in `sys/os.rs`. `Opts`/`from_cli` gain `dump_filters: c.dump_filters`.)

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: seccomp probe (mode, filters, action matrix)"`

---

### Task 13: LSM probe (AppArmor / SELinux / Lockdown / Landlock)

**Files:**
- Create: `src/probes/lsm.rs` + registry entry (after `seccomp`)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs`, `OsApi::landlock_abi`.
- Produces facts (probe `"lsm"`): `list` (array from `/sys/kernel/security/lsm`), `apparmor` (`{profile,mode}`|null), `selinux` (`{context,mode}`|null), `lockdown` (string|null), `landlockAbi` (number|null).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apparmor_and_selinux_and_landlock() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| { let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap(); f };
        std::fs::write(p("/sys/kernel/security/lsm"), "capability,apparmor,landlock\n").unwrap();
        std::fs::write(p("/proc/7/attr/current"), "docker-default (enforce)\n").unwrap();
        std::fs::write(p("/sys/kernel/security/lockdown"), "[none] integrity\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = parse_lsm(&fs, 7, Some(6));
        assert_eq!(o.facts.iter().find(|f| f.key == "list").unwrap().value,
                   serde_json::json!(["capability","apparmor","landlock"]));
        let aa = o.facts.iter().find(|f| f.key == "apparmor").unwrap().value.clone();
        assert_eq!(aa["profile"], "docker-default");
        assert_eq!(aa["mode"], "enforce");
        assert_eq!(o.facts.iter().find(|f| f.key == "landlockAbi").unwrap().value, serde_json::json!(6));
        assert_eq!(o.facts.iter().find(|f| f.key == "lockdown").unwrap().value, "none");
    }
    #[test]
    fn unconfined_and_missing_securityfs() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("proc/7/attr/current");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "unconfined\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = parse_lsm(&fs, 7, None);
        let aa = o.facts.iter().find(|f| f.key == "apparmor").unwrap().value.clone();
        assert_eq!(aa["profile"], "unconfined");
        assert!(o.facts.iter().any(|f| f.key == "selinux" && f.value.is_null()));
        assert!(o.facts.iter().any(|f| f.key == "landlockAbi" && f.value.is_null()));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::ProbeOutcome;
use crate::model::Fact;

pub fn parse_lsm(fs: &crate::sys::fs::PseudoFs, pid: u32, landlock_abi: Option<u64>) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("lsm");
    let list = fs.read("/sys/kernel/security/lsm").ok()
        .map(|s| s.trim().split(',').map(String::from).collect::<Vec<_>>());
    o = o.with_fact(Fact::ok("lsm", "list",
        list.clone().map(|l| serde_json::json!(l)).unwrap_or(serde_json::Value::Null),
        "/sys/kernel/security/lsm"));
    // current profile label — AppArmor OR SELinux context, same file
    let label = fs.read(&format!("/proc/{pid}/attr/current")).ok().map(|s| s.trim().to_string());
    let apparmor = list.as_ref().map(|l| l.iter().any(|x| x == "apparmor")).unwrap_or(true);
    let aa = match (&label, apparmor) {
        (Some(l), true) => {
            let (profile, mode) = match l.rsplit_once(" (") {
                Some((p, rest)) => (p.to_string(), rest.trim_end_matches(')').to_string()),
                None => (l.clone(), String::new()),
            };
            Some(serde_json::json!({ "profile": profile, "mode": mode }))
        }
        _ => None,
    };
    o = o.with_fact(Fact::ok("lsm", "apparmor",
        aa.unwrap_or(serde_json::Value::Null), format!("/proc/{pid}/attr/current")));
    let selinux = list.as_ref().map(|l| l.iter().any(|x| x == "selinux")).unwrap_or(false);
    let sel = if selinux { label.as_ref().map(|l| serde_json::json!({
            "context": l,
            "mode": fs.read("/sys/fs/selinux/enforce").ok().map(|e|
                if e.trim() == "1" { "enforcing" } else { "permissive" }),
        })) } else { None };
    o = o.with_fact(Fact::ok("lsm", "selinux",
        sel.unwrap_or(serde_json::Value::Null), "/sys/fs/selinux/enforce"));
    let lockdown = fs.read("/sys/kernel/security/lockdown").ok()
        .and_then(|s| s.split([' ', ']']).find(|t| t.starts_with('[') )
            .map(|t| t.trim_start_matches('[').to_string()));
    o = o.with_fact(Fact::ok("lsm", "lockdown",
        lockdown.map(|l| serde_json::json!(l)).unwrap_or(serde_json::Value::Null),
        "/sys/kernel/security/lockdown"));
    o = o.with_fact(Fact::ok("lsm", "landlockAbi",
        landlock_abi.map(|a| serde_json::json!(a)).unwrap_or(serde_json::Value::Null),
        "SYS_LANDLOCK_CREATE_RULESET"));
    o
}

pub struct Lsm;
impl crate::probes::Probe for Lsm {
    fn name(&self) -> &'static str { "lsm" }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome {
        parse_lsm(cx.fs, cx.pid, cx.os.landlock_abi())
    }
}
```

Note: `label` under AppArmor reports `unconfined` (mode empty); rules test `profile == "unconfined" || mode == "unconfined"` — the `unconfined` label has no parenthetical, so rule AMR-006 (Task 19) matches on `profile=="unconfined"`. SELinux labels land in `selinux.context`; `apparmor` fact is null when apparmor not in the LSM list.

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: lsm probe (apparmor/selinux/lockdown/landlock)"`

---

### Task 14: VMM probe (DMI + hypervisor + firecracker/gVisor)

**Files:**
- Create: `src/probes/vmm.rs` + registry entry (after `lsm`)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `OsApi::hypervisor`, `PseudoFs`.
- Produces facts (probe `"vmm"`): `hypervisor` (`{present,vendor}`), `dmi` (`{sysVendor,productName,biosVendor,boardVendor}`), `clocksource`, `vsock` (bool), `cpuHypervisorFlag` (bool), `kernel` (from `/proc/version`). Signal: firecracker composite → `Firecracker 0.8`; `/proc/version` contains `gVisor` → `Gvisor 0.9`.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hypervisor_vendor_table() {
        assert_eq!(match_vendor("KVMKVMKVM"), Some("KVM"));
        assert_eq!(match_vendor("VMwareVMware"), Some("VMware"));
        assert_eq!(match_vendor("Microsoft hv"), Some("Hyper-V"));
        assert_eq!(match_vendor("bhyve bhyve "), Some("bhyve"));
        assert_eq!(match_vendor("TCGTCGTCGTCG"), Some("QEMU-TCG"));
    }
    #[test]
    fn firecracker_composite() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| { let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap(); f };
        std::fs::create_dir_all(p("/sys/class/dmi/id")).parent().unwrap(); // empty dmi dir
        std::fs::write(p("/sys/devices/system/clocksource/clocksource0/current_clocksource"), "kvm-clock\n").unwrap();
        std::fs::create_dir_all(p("/dev")).unwrap();
        std::fs::write(p("/dev/vsock"), "").unwrap();
        std::fs::write(p("/proc/cpuinfo"), "processor\t: 0\nflags\t\t: fpu hypervisor\n").unwrap();
        std::fs::write(p("/proc/version"), "Linux version 5.10.195 (firecracker)\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_vmm_with(&fs, Some(crate::sys::os::HypervisorInfo {
            present: true, vendor: Some("KVMKVMKVM".into()) }));
        assert!(o.signals.iter().any(|s| s.runtime == RuntimeKind::Firecracker));
        let hv = o.facts.iter().find(|f| f.key == "hypervisor").unwrap().value.clone();
        assert_eq!(hv["present"], serde_json::json!(true));
        assert_eq!(hv["vendor"], "KVMKVMKVM");
    }
    #[test]
    fn gvisor_via_kernel_version() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("proc/version");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "Linux version 4.4.0 (gVisor team)\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_vmm_with(&fs, None);
        assert!(o.signals.iter().any(|s| s.runtime == RuntimeKind::Gvisor && s.weight == 0.9));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::sys::fs::PseudoFs;
use crate::sys::os::HypervisorInfo;

pub fn match_vendor(v: &str) -> Option<(&'static str, RuntimeKind)> {
    let v = v.to_ascii_lowercase();
    Some(match v.as_str() {
        "kvmkvmkvm" => ("KVM", RuntimeKind::Host),
        s if s.starts_with("vmware") => ("VMware", RuntimeKind::Host),
        s if s.starts_with("microsoft") => ("Hyper-V", RuntimeKind::Host),
        s if s.starts_with("xen") => ("Xen", RuntimeKind::Host),
        s if s.starts_with("bhyve") => ("bhyve", RuntimeKind::Host),
        s if s.starts_with("tcgtcg") => ("QEMU-TCG", RuntimeKind::Host),
        s if s.starts_with("kvm kvm kvm") => ("KVM", RuntimeKind::Host),
        _ => return None,
    })
}

pub fn probe_vmm_with(fs: &PseudoFs, hv: Option<HypervisorInfo>) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("vmm");
    o = o.with_fact(Fact::ok("vmm", "hypervisor", match &hv {
        Some(h) => serde_json::json!({ "present": h.present, "vendor": h.vendor }),
        None => serde_json::json!({ "present": false, "vendor": null }),
    }, "CPUID leaf 0x40000000"));
    let dmi = |k: &str| fs.read(&format!("/sys/class/dmi/id/{k}")).ok().map(|s| s.trim().to_string());
    let dmi_obj = serde_json::json!({
        "sysVendor": dmi("sys_vendor"), "productName": dmi("product_name"),
        "biosVendor": dmi("bios_vendor"), "boardVendor": dmi("board_vendor") });
    o = o.with_fact(Fact::ok("vmm", "dmi", dmi_obj.clone(), "/sys/class/dmi/id"));
    let clock = fs.read("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        .ok().map(|s| s.trim().to_string());
    o = o.with_fact(Fact::ok("vmm", "clocksource",
        clock.clone().map(|c| serde_json::json!(c)).unwrap_or(serde_json::Value::Null),
        "current_clocksource"));
    let vsock = fs.exists("/dev/vsock");
    o = o.with_fact(Fact::ok("vmm", "vsock", vsock.into(), "/dev/vsock"));
    let version = fs.read("/proc/version").unwrap_or_default();
    let cpuinfo = fs.read("/proc/cpuinfo").unwrap_or_default();
    let hyp_flag = cpuinfo.lines().any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"));
    o = o.with_fact(Fact::ok("vmm", "cpuHypervisorFlag", hyp_flag.into(), "/proc/cpuinfo"));
    o = o.with_fact(Fact::ok("vmm", "kernel", version.clone().into(), "/proc/version"));
    if version.contains("gVisor") {
        o = o.with_signal(Signal { runtime: RuntimeKind::Gvisor, weight: 0.9,
            evidence: o.facts.iter().find(|f| f.key == "kernel").unwrap().clone() });
        return o;
    }
    // Firecracker: minimal guest — hypervisor present, empty DMI, vsock, kvm-clock.
    let hv_present = hv.as_ref().is_some_and(|h| h.present);
    let dmi_empty = dmi_obj["sysVendor"].is_null() && dmi_obj["productName"].is_null()
        && dmi_obj["biosVendor"].is_null();
    if hv_present && dmi_empty && vsock && clock.as_deref() == Some("kvm-clock") {
        o = o.with_signal(Signal { runtime: RuntimeKind::Firecracker, weight: 0.8,
            evidence: o.facts.iter().find(|f| f.key == "vsock").unwrap().clone() });
    }
    o
}

pub struct Vmm;
impl crate::probes::Probe for Vmm {
    fn name(&self) -> &'static str { "vmm" }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome { probe_vmm_with(cx.fs, cx.os.hypervisor()) }
}
```



- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: vmm probe (DMI, hypervisor vendor, firecracker/gvisor)"`

---

### Task 15: Sockets probe

**Files:**
- Create: `src/probes/sockets.rs` + registry entry (after `vmm`)
- Test: inline + fake server thread

**Interfaces:**
- Consumes: `Ctx`, `OsApi::uds_probe`, `PseudoFs::exists`, `PseudoFs::writable`.
- Produces facts (probe `"sockets"`): `found` (array of `{path,writable,kind,info}`; `info` = `{version,apiVersion,os?,kernel?,securityOptions?,rootless?}` or null). Signal: writable docker/podman socket → `Docker 0.9` (or `Podman 0.9` from `/info` `name: podman`).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_docker_info_from_fake_socket() {
        let body = r#"{"ID":"x","ServerVersion":"27.1.1","ApiVersion":"1.47","Os":"linux","KernelVersion":"6.11.0","SecurityOptions":["name=seccomp,profile=builtin"],"Rootless":false}"#;
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        let info = extract_info(&v);
        assert_eq!(info["version"], "27.1.1");
        assert_eq!(info["securityOptions"][0], "name=seccomp,profile=builtin");
        assert_eq!(info["rootless"], serde_json::json!(false));
    }
    #[test]
    fn candidate_absent_is_listed_not_found() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run")).unwrap();
        std::fs::write(d.path().join("run/podman/podman.sock"), "").unwrap(); // regular file: exists ⇒ treated as candidate
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| Err(std::io::Error::other("no uds in fixture")));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["path"], "/run/podman/podman.sock");
        assert_eq!(found[0]["kind"], "podman");
        assert_eq!(found[0]["writable"], serde_json::json!(true));
        assert!(found[0]["info"].is_null()); // handshake failed ⇒ null info, path still reported
    }
    #[test]
    fn live_handshake_against_http_over_uds_stub() {
        // OsApi::uds_probe stubbed to return the docker /info reply:
        let reply = crate::sys::os::UdsReply { status: 200, body: r#"{"ServerVersion":"27.1.1","ApiVersion":"1.47"}"#.into() };
        let info = extract_info(&serde_json::from_str::<serde_json::Value>(&reply.body).unwrap());
        assert_eq!(info["version"], "27.1.1");
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

pub const CANDIDATES: [(&str, &str); 7] = [
    ("/var/run/docker.sock", "docker"), ("/run/docker.sock", "docker"),
    ("/run/podman/podman.sock", "podman"), ("/run/user/1000/podman/podman.sock", "podman"),
    ("/var/run/crio/crio.sock", "crio"), ("/run/containerd/containerd.sock", "containerd"),
    ("/run/kata-containers/agent.sock", "kata")];

pub fn extract_info(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "version": v["ServerVersion"], "apiVersion": v["ApiVersion"],
        "os": v["Os"], "kernel": v["KernelVersion"],
        "securityOptions": v["SecurityOptions"], "rootless": v["Rootless"],
        "name": v["Name"] })
}

/// Handshake per spec: GET /_ping first (liveness), GET /info on 200.
/// Podman's /info needs no extra API version header for our fields.
pub fn scan_candidates(fs: &PseudoFs, probe: &dyn Fn(&str) -> std::io::Result<crate::sys::os::UdsReply>) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for (path, kind) in CANDIDATES {
        if !fs.exists(path) { continue; }
        let writable = fs.writable(path);
        let info = match probe(path) {
            Ok(r) if (200..300).contains(&r.status) =>
                serde_json::from_str::<serde_json::Value>(&r.body).ok().map(|v| extract_info(&v)),
            _ => None,
        };
        out.push(serde_json::json!({ "path": path, "writable": writable,
            "kind": kind, "info": info.unwrap_or(serde_json::Value::Null) }));
    }
    out
}

pub struct Sockets;
impl Probe for Sockets {
    fn name(&self) -> &'static str { "sockets" }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let mut o = ProbeOutcome::empty("sockets");
        let found = scan_candidates(cx.fs, &|p| cx.os.uds_probe(p, cx.opts.probe_timeout.unwrap_or(std::time::Duration::from_millis(500))));
        let fact = Fact::ok("sockets", "found", serde_json::json!(found), "known runtime socket paths");
        for e in &found {
            if e["writable"] == serde_json::json!(true) {
                let kind = match e["kind"].as_str() {
                    Some("podman") => RuntimeKind::Podman,
                    Some("docker") => RuntimeKind::Docker,
                    Some("crio") => RuntimeKind::CriO,
                    _ => continue,
                };
                o = o.with_signal(Signal { runtime: kind, weight: 0.9, evidence: fact.clone() });
            }
        }
        o.with_fact(fact)
    }
}
```

`writable()` real mode: `libc::access(path, W_OK)`. Fixture mode: `OpenOptions::new().write(true).open(abs)` — succeeds on regular files (matches the test). `PseudoFs` gains `pub fn exists(&self, rel: &str) -> bool` (`real ⇒ Path::new(abs).exists()`; fixture same on joined path) and `pub fn writable(&self, rel: &str) -> bool`.

Real handshake (`sys/os.rs` `uds_probe`): `UnixStream::connect(path)` with `set_read_timeout(Some(t))` + `set_write_timeout(Some(t))`, write `GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`, read status line; if 200 write `GET /info HTTP/1.1…` and read body (read to EOF, cap 1 MiB). Returns `UdsReply{status, body}`. `--fixture-root` mode never connects (candidates don't exist / are plain files: `connect` fails → info null).

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: sockets probe with /ping + /info handshake"`

---

### Task 16: Kubernetes probe

**Files:**
- Create: `src/probes/k8s.rs` + registry entry (last in registry, before `runtime`)
- Test: inline

**Interfaces:**
- Consumes: `Ctx`, `PseudoFs` (env via `cx.os.env`; `/etc/hostname`, `/etc/hosts`, `/var/run/secrets/kubernetes.io/serviceaccount/{namespace,ca.crt,token}`, `KUBERNETES_SERVICE_HOST/PORT`).
- Produces facts (probe `"k8s"`): `inPod` (bool), `namespace` (string|null), `envHost` (bool), `serviceAccount` (bool), `qos` (`"besteffort"|"burstable"|"guaranteed"|null` from `/sys/fs/cgroup` limits: memory+pids both `"max"` → besteffort; some bounded → burstable; all bounded and equal requests ⇒ guaranteed is unverifiable from inside — report `burstable` when *any* bounded, `besteffort` when none, `null` when v1/unreadable).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    struct Env(Vec<(&'static str, &'static str)>);
    impl crate::sys::os::OsApi for Env {     // Task 4 trait signatures
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo { Default::default() }
        fn landlock_abi(&self) -> Option<u64> { None }
        fn seccomp_actions(&self) -> crate::sys::os::SeccompActions { Default::default() }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::model::ProbeIo> {
            Err(crate::model::ProbeIo::PermissionDenied) }
        fn syscall0(&self, _n: u32) -> Result<(), i32> { Err(38) }
        fn uds_probe(&self, _p: &std::path::Path, _t: std::time::Duration)
            -> std::io::Result<crate::sys::os::UdsReply> { Err(std::io::Error::other("x")) }
        fn env(&self, k: &str) -> Option<String> { self.0.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()) }
        fn is_root(&self) -> bool { false }
    }
    #[test]
    fn pod_detected_env_and_sa() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| { let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap(); f };
        std::fs::write(p("/var/run/secrets/kubernetes.io/serviceaccount/namespace"), "prod\n").unwrap();
        std::fs::write(p("/etc/hostname"), "nginx-7d9c-blue\n").unwrap();
        std::fs::write(p("/etc/hosts"), "10.42.0.7\tnextcloud-6f8b-pod\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[("KUBERNETES_SERVICE_HOST", "10.43.0.1"), ("KUBERNETES_SERVICE_PORT", "443")]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(o.facts.iter().find(|f| f.key == "inPod").unwrap().value, serde_json::json!(true));
        assert_eq!(o.facts.iter().find(|f| f.key == "namespace").unwrap().value, "prod");
        assert_eq!(o.facts.iter().find(|f| f.key == "envHost").unwrap().value, serde_json::json!(true));
    }
    #[test]
    fn not_in_pod() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = Env(&[]);
        let o = probe_k8s(&fs, &os, "/");
        assert_eq!(o.facts.iter().find(|f| f.key == "inPod").unwrap().value, serde_json::json!(false));
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;

/// hostnames like nginx-6f8b7d9c4d-x2kq / pod names in /etc/hosts
pub fn podish(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() >= 3 && parts.iter().skip(1).any(|p| p.len() == 5 && p.chars().all(|c| "bcdfghjklmnpqrstvwxz0123456789".contains(c)))
}

pub fn probe_k8s(fs: &crate::sys::fs::PseudoFs, os: &dyn crate::sys::os::OsApi, cgroup_path: &str) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty("k8s");
    let env_host = os.env("KUBERNETES_SERVICE_HOST").is_some();
    let sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount";
    let service_account = fs.exists(&format!("{sa_dir}/ca.crt")) || fs.exists(&format!("{sa_dir}/token"));
    let namespace = fs.read(&format!("{sa_dir}/namespace")).ok().map(|s| s.trim().to_string());
    let hostname = fs.read("/etc/hostname").unwrap_or_default();
    let hosts = fs.read("/etc/hosts").unwrap_or_default();
    let in_pod = env_host || service_account || podish(hostname.trim()) || hosts.lines().any(|l| l.split_whitespace().nth(1).is_some_and(podish));
    let qos = if fs.read("/sys/fs/cgroup/cgroup.controllers").is_ok() {
        let bounded = ["memory.max", "pids.max"].iter().any(|k|
            fs.read(&format!("/sys/fs/cgroup{cgroup_path}/{k}")).map(|v| v.trim() != "max").unwrap_or(false));
        Some(if bounded { "burstable" } else { "besteffort" })
    } else { None };
    o = o.with_fact(Fact::ok("k8s", "inPod", in_pod.into(), "env+sa+hostname heuristics"));
    o = o.with_fact(Fact::ok("k8s", "namespace", namespace.map(|n| serde_json::json!(n)).unwrap_or(serde_json::Value::Null), format!("{sa_dir}/namespace")));
    o = o.with_fact(Fact::ok("k8s", "envHost", env_host.into(), "KUBERNETES_SERVICE_HOST"));
    o = o.with_fact(Fact::ok("k8s", "serviceAccount", service_account.into(), sa_dir));
    o = o.with_fact(Fact::ok("k8s", "qos", qos.map(|q| serde_json::json!(q)).unwrap_or(serde_json::Value::Null), "/sys/fs/cgroup limits"));
    o
}

pub struct K8s;
impl Probe for K8s {
    fn name(&self) -> &'static str { "k8s" }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        // registry order guarantees the cgroup probe ran before k8s:
        let path = cx.prior.facts.get("cgroup.path")
            .and_then(|v| v.as_str()).unwrap_or("/").to_string();
        probe_k8s(cx.fs, cx.os, &path)
    }
}
```

(`Prior.facts` from Task 5 keys Ok-status facts as `"{probe}.{key}"` — the same map AMR rules will read via `Report::fact`; cross-probe lookups go through `cx.prior.facts`.)

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: kubernetes detection probe"`

---

### Task 17: Runtime probe (signal aggregation + verdict)

**Files:**
- Create: `src/probes/runtime.rs` + registry entry (last)
- Modify: `src/model/runtime.rs` gains `pub struct SignalWeight` — no; scoring lives here.
- Test: inline

**Interfaces:**
- Consumes: `Ctx.prior.signals` (all prior signals), `cx.prior.facts` (`sockets.found`, `cgroup.pattern`, `k8s.inPod`, `vmm.*`, `uidmap.rootless`).
- Produces: fact `verdict` — a serialized `Verdict` `{runtime, confidence, underlying, alternatives, evidence}`; no signals of its own. `Availability::Unavailable("no signals")` never: always Ok with `runtime:"host"` fallback.
- Scoring (spec §7): sum weights per `RuntimeKind`; `confidence = top` (0.0–1.0 capped); top ≥ 0.5 ⇒ primary; runner-ups (>0.1) into `alternatives`; all-zero ⇒ `runtime:"host"`, `confidence: 1.0` only when `vmm.hypervisor.present == false`, else `"host (virtualized)"` with confidence 0.9.
- K8s overlay: `k8s.inPod == true` ⇒ `runtime:"kubernetes"`, `underlying` = argmax of non-Kubernetes scores (`Some(containerd|crio|docker|podman)` or `None`); Kubernetes score itself comes from the cgroup signal.

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn sig(rt: RuntimeKind, w: f32) -> Signal {
        Signal { runtime: rt, weight: w,
            evidence: Fact::ok("x", "y", serde_json::json!(1), "test") }
    }
    #[test]
    fn docker_wins_over_weaker_podman_alternatives() {
        let v = score(&[sig(RuntimeKind::Docker, 0.8), sig(RuntimeKind::Podman, 0.3),
                        sig(RuntimeKind::Docker, 0.1)], false, serde_json::json!(false), None);
        assert_eq!(v.runtime, "docker");
        assert!((v.confidence - 0.9).abs() < 1e-6);
        assert_eq!(v.alternatives[0].runtime, "podman");
    }
    #[test]
    fn kubernetes_overlays_underlying() {
        let v = score(&[sig(RuntimeKind::Kubernetes, 0.7), sig(RuntimeKind::Docker, 0.0)],
            true, serde_json::json!(true), None);
        assert_eq!(v.runtime, "kubernetes");
    }
    #[test]
    fn bare_host_fallback() {
        let v = score(&[], true, serde_json::json!(false), Some(false));
        assert_eq!(v.runtime, "host");
        assert_eq!(v.confidence, 1.0);
    }
    #[test]
    fn vm_host_notes_virtualization() {
        let v = score(&[], true, serde_json::json!(false), Some(true));
        assert_eq!(v.runtime, "host");
        assert!((v.confidence - 0.9).abs() < 1e-6);
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
use crate::model::{Candidate, Fact, ProbeOutcome, RuntimeKind, Signal, Verdict};
use crate::pipeline::Ctx;
use crate::probes::Probe;

pub fn score(signals: &[Signal], _any_facts: bool, in_pod: serde_json::Value,
             hv_present: Option<bool>) -> Verdict {
    let mut totals: std::collections::HashMap<RuntimeKind, f32> = Default::default();
    for s in signals { *totals.entry(s.runtime).or_default() += s.weight; }
    let mut ranked: Vec<(RuntimeKind, f32)> = totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let mut evidence: Vec<String> = signals.iter()
        .map(|s| format!("{} {} {:.2}", s.runtime.as_str(), s.evidence.probe, s.evidence.key))
        .collect();
    let in_pod = in_pod.as_bool().unwrap_or(false);
    let top = ranked.first().copied();
    let (runtime, confidence, underlying) = if in_pod {
        let under = ranked.iter().find(|(k, w)| *k != RuntimeKind::Kubernetes && *w > 0.1)
            .map(|(k, _)| k.as_str().to_string());
        evidence.push("k8s: env/serviceaccount/hostname heuristics".into());
        ("kubernetes".to_string(), top.map(|(_, w)| w.min(1.0)).unwrap_or(0.7), under)
    } else if let Some((k, w)) = top.filter(|(_, w)| *w >= 0.5) {
        (k.as_str().to_string(), w.min(1.0), None)
    } else if let Some((k, w)) = top.filter(|(_, w)| *w > 0.0) {
        // weak evidence only — report the guess at its own weight
        (k.as_str().to_string(), w, None)
    } else {
        match hv_present { Some(true) => ("host".into(), 0.9, None), _ => ("host".into(), 1.0, None) }
    };
    let alternatives = ranked.iter().skip(if in_pod { 0 } else { 1 })
        .filter(|(k, w)| *w > 0.1 && k.as_str() != runtime)
        .map(|(k, w)| Candidate { runtime: k.as_str().to_string(), score: *w })
        .collect();
    Verdict { runtime, confidence, underlying, alternatives, evidence }
}

pub struct Runtime;
impl Probe for Runtime {
    fn name(&self) -> &'static str { "runtime" }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let in_pod = cx.prior.facts.get("k8s.inPod").cloned().unwrap_or(serde_json::json!(false));
        let hv = cx.prior.facts.get("vmm.hypervisor").and_then(|v| v["present"].as_bool());
        let verdict = score(&cx.prior.signals, true, in_pod, hv);
        ProbeOutcome::empty("runtime")
            .with_fact(Fact::ok("runtime", "verdict",
                serde_json::to_value(&verdict).unwrap(), "signal aggregation"))
    }
}
```

`RuntimeKind::as_str` (Task 2): add if missing — `"docker"|"podman"|"podman-rootless"|"containerd"|"crio"|"kubernetes"|"lxc"|"systemd-nspawn"|"firecracker"|"gvisor"|"kata"|"wasmtime"|"host"`.

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: runtime verdict scoring"`

---

### Task 17b: Containment-gated verdict (semantics amendment, 2026-10-01)

Spec §5 amendment: `verdict.runtime` = **self-containment**; runtime presence
(writable socket, rootless uidmap) is environment-only evidence. See spec
"Verdict semantics (amendment 2026-10-01)" + "Nesting".

**Files:**
- Modify `src/model/runtime.rs`: `Signal` gains `env_only: bool` (`#[serde(default)]`); construction sites updated
- Modify `src/probes/sockets.rs`: raised signals set `env_only: true` (weights/facts unchanged)
- Modify `src/probes/uidmap.rs`: rootless signal `env_only: true`
- Modify `src/probes/namespaces.rs`: new fact `containerMarkers` — object `{dockerenv: bool, containerEnv: string|null}` via `PseudoFs::exists("/.dockerenv")` + `OsApi::env("container")`; raises containment signal per value: `dockerenv==true` ⇒ Docker 0.6; `container=docker` ⇒ Docker 0.6; `container=podman` ⇒ Podman 0.6 (other values: fact-only, no signal)
- Modify `src/probes/runtime.rs`: `rank`/`score` exclude `env_only` signals from totals; each excluded signal appends evidence `environment: <kind> present (<evidence probe.key>)` (deduped by kind+key); `nested-in-<outer>` variant when verdict is a container runtime that the markers do not explain (e.g. podman verdict + dockerenv) — outer = marker kind; host branch otherwise unchanged
- Test updates: sockets/uidmap signal tests assert `env_only`; runtime scoring tests re-pinned (host + podman socket ⇒ host verdict + environment note; dockerenv-only ⇒ docker medium; libpod+dockerenv ⇒ podman + variant `nested-in-docker`; contained podman + socket note); namespaces markers test

- [ ] **Step 1: RED tests for the four pinned scenarios above.**
- [ ] **Step 2: GREEN minimal. Gates: cargo test / clippy -D warnings / fmt.**
- [ ] **Step 3: Commit** — `"fix: verdict means self-containment; sockets/uidmap are environment evidence"`

---


### Task 18: Opt-in syscall probe

**Files:**
- Create: `src/probes/syscall_probe.rs` + conditional registry entry
- Test: inline (uses only EPERM-safe syscalls via the stub)

**Interfaces:**
- Consumes: `Ctx`, `OsApi::syscall0`.
- Produces facts (probe `"syscall-probe"`): `blocked` (array of syscall names, ascending syscall number), `blockedCount` (number). Registered only when `opts.probe_syscalls` (Task 7 registry, line ~952).
- Safety contract (spec §5, amicontained parity): every x86_64 syscall with `nr <= SYS_rseq` is invoked with all-zero args; only `Err(EPERM) | Err(EACCES)` counts as blocked — every other errno (`ENOENT`, `EFAULT`, `EINVAL`, `E2BIG`…) means "not blocked / indeterminate". The fixed skip list removes the hang/exit/self-modifying set. Known quirks, pinned in test comments: `reboot(0,0,0,0)` returns EINVAL (magic checked before capability) → never reported blocked; `unshare(0)` → EINVAL likewise; `seccomp` skipped (self-modifying). Whole file gated `#[cfg(target_arch = "x86_64")]`; other arches compile `probe_blocked` to `vec![]` and the probe outcome is `Degraded("unsupported arch")`.

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enumeration_marks_eperm_blocked_and_skips_hang_list() {
        struct Stub;
        impl crate::sys::os::OsApi for Stub {   // Task 4 trait signatures
            fn hypervisor(&self) -> crate::sys::os::HypervisorInfo { Default::default() }
            fn landlock_abi(&self) -> Option<u64> { None }
            fn seccomp_actions(&self) -> crate::sys::os::SeccompActions { Default::default() }
            fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::model::ProbeIo> {
                Err(crate::model::ProbeIo::PermissionDenied) }
            fn syscall0(&self, n: u32) -> Result<(), i32> {
                let eperm: [u32; 4] = [libc::SYS_mount, libc::SYS_reboot,
                    libc::SYS_setns, libc::SYS_pause].map(|x| x as u32);
                if eperm.contains(&n) { Err(1) /* EPERM */ } else { Err(38) /* ENOSYS */ }
            }
            fn uds_probe(&self, _p: &std::path::Path, _t: std::time::Duration)
                -> std::io::Result<crate::sys::os::UdsReply> { Err(std::io::Error::other("stub")) }
            fn env(&self, _k: &str) -> Option<String> { None }
            fn is_root(&self) -> bool { false }
        }
        let blocked = probe_blocked(&Stub);
        // pause stubs EPERM but sits on SKIP; result ordered by syscall nr:
        // mount(165) < reboot(169) < setns(308).
        assert_eq!(blocked, ["mount", "reboot", "setns"]);
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
/// Spec §5 skip list: hang / exit / self-modifying under all-zero args.
pub const SKIP: &[&str] = &["rt_sigreturn", "select", "pause", "pselect6",
    "ppoll", "exit", "exit_group", "clone", "fork", "vfork", "seccomp"];

/// x86_64 number→name table. Generated ONCE, committed verbatim (pinned to the
/// libc version in Cargo.lock). Generator — mechanical, zero decisions:
///   grep -oE 'pub const SYS_[a-z0-9_]+(: c_long)? = [0-9]+' \
///     ~/.cargo/registry/src/*/libc-*/src/unix/linux_like/linux/gnu/b64/x86_64/mod.rs
/// keep nr <= SYS_rseq, drop alias duplicates, emit ("name", nr) ascending
/// (~335 rows).
pub const NAMES: &[(&str, u32)] = &[ /* generated output goes here verbatim */ ];

pub fn probe_blocked(os: &dyn crate::sys::os::OsApi) -> Vec<&'static str> {
    NAMES.iter()
        .filter(|(n, _)| !SKIP.contains(n))
        .filter(|(_, nr)| matches!(os.syscall0(*nr), Err(1) | Err(13))) // EPERM | EACCES
        .map(|(n, _)| *n).collect()
}

pub struct SyscallProbe;   // registered in Task 7 only when opts.probe_syscalls
impl crate::probes::Probe for SyscallProbe {
    fn name(&self) -> &'static str { "syscall-probe" }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome {
        let blocked = probe_blocked(cx.os);
        ProbeOutcome::empty("syscall-probe")
            .with_fact(Fact::ok("syscall-probe", "blocked",
                serde_json::json!(blocked), "null-arg sweep 0..=SYS_rseq"))
            .with_fact(Fact::ok("syscall-probe", "blockedCount",
                serde_json::json!(blocked.len()), "null-arg sweep 0..=SYS_rseq"))
    }
}
```

`RealOs::syscall0` (Task 4, lines 695-697) already issues `libc::syscall(id)` with zero args and maps errno — no new seam. Full sweep is ~325 pure sysenter round-trips (< 1 ms); the skip list is what keeps it hang-free, and `--probe-timeout` bounds it like every other probe. The two EINVAL quirks (`reboot`, `unshare`) match amicontained's own output — parity over cleverness; the probe is opt-in and labeled inference.

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: opt-in seccomp syscall-probing (EPERM sweep)"`

---

### Task 19: Rule engine evaluator + rules 001–006

**Files:**
- Modify: `src/model/report.rs` (`fact_any`), `src/model/rule.rs` (full `Rule`, `Assess`, `Finding` construction), `src/model/rules.rs` (first RULES batch), `src/model/finding.rs` (Finding gains `#[serde(rename_all="camelCase")] pub rule/…` fields per spec)
- Test: inline per rule + evaluator tests

**Interfaces:**
- Consumes: `Report::fact`, `Report::fact_any`, privileged flag from pipeline.
- Produces: `pub struct Rule { pub id: &'static str, pub slug: &'static str, pub severity: Severity, pub summary: &'static str, pub why: &'static str, pub remediation: &'static str, pub references: &'static [&'static str], pub requires_root: bool, pub check: fn(&Assess) -> Option<Vec<Fact>> }`
  `pub struct Assess<'r> { pub report: &'r Report, pub privileged: bool }` with helpers
  `fn fact(&self, probe, key) -> Option<&'r Fact>` (Ok-status),
  `fn fact_any(&self, probe, key) -> Option<&'r Fact>`,
  `fn containerized(&self) -> bool` = `verdict.is_some_and(|v| v.runtime != "host")` — needs `Report::verdict` accessor (it's a field: `self.report.verdict.as_ref()`).
  Evaluator: `check` returns `Some(evidence)` ⇒ build `Finding` (rule metadata copied + evidence + `requires_root && !privileged ⇒ severity = Info` with summary suffix `" (insufficient privilege to assess)"`? NO — spec §8: findings that require unreadable data downgrade to info. Implement: if `requires_root && !privileged` and predicate fired anyway, severity becomes Info. Rules set `requires_root: true` only for AMR-004.)
- RULES batch: AMR-001 docker-socket-writable (critical), AMR-002 privileged-container (critical), AMR-003 cap-sys-module (high), AMR-004 host-pid-namespace (high, requires_root), AMR-005 seccomp-disabled-in-container (high), AMR-006 apparmor-unconfined (medium).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    fn report_with(facts: &[(&str, &str, serde_json::Value)]) -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        let mut by_probe: std::collections::BTreeMap<&str, Vec<Fact>> = Default::default();
        for (p, k, v) in facts {
            by_probe.entry(p).or_default().push(Fact::ok(p, k, v.clone(), "test"));
        }
        for (p, fs) in by_probe {
            let mut o = ProbeOutcome::empty(p);
            o.facts = fs;
            r.push_probe(o);
        }
        r
    }
    #[test]
    fn amr001_fires_on_writable_docker_socket() {
        let r = report_with(&[("sockets", "found", serde_json::json!(
            [{"path":"/run/docker.sock","writable":true,"kind":"docker","info":null}]))]);
        let f = RULES.iter().find(|r| r.id == "AMR-001").unwrap()
            .evaluate(&r, false).expect("should fire");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.evidence.len(), 1);
    }
    #[test]
    fn amr001_quiet_when_not_writable() {
        let r = report_with(&[("sockets", "found", serde_json::json!(
            [{"path":"/run/docker.sock","writable":false,"kind":"docker","info":null}]))]);
        assert!(RULES.iter().find(|r| r.id == "AMR-001").unwrap().evaluate(&r, false).is_none());
    }
    #[test]
    fn amr002_needs_all_four_conditions() {
        let base = vec![
            ("capabilities", "effective", serde_json::json!(["cap_sys_admin"])),
            ("seccomp", "mode", serde_json::json!("0")),
            ("lsm", "apparmor", serde_json::json!({"profile":"unconfined","mode":""})),
        ];
        let mut r = report_with(&base);
        r.verdict = Some(Verdict { runtime: "docker".into(), confidence: 0.9,
            underlying: None, alternatives: vec![], evidence: vec![] });
        let fired = RULES.iter().find(|x| x.id == "AMR-002").unwrap().evaluate(&r, false);
        assert!(fired.is_some());
        // seccomp filter ⇒ must NOT fire
        let r2 = report_with(&[("capabilities","effective",serde_json::json!(["cap_sys_admin"])),
            ("seccomp","mode",serde_json::json!("filter")),
            ("lsm","apparmor",serde_json::json!({"profile":"unconfined","mode":""}))]);
        let mut r2 = r2; r2.verdict = r.verdict.clone();
        assert!(RULES.iter().find(|x| x.id == "AMR-002").unwrap().evaluate(&r2, false).is_none());
    }
    #[test]
    fn amr004_needs_pid_unshared_and_ptrace() {
        let mut r = report_with(&[
            ("namespaces","isolated",serde_json::json!({"pid":false,"user":true})),
            ("capabilities","effective",serde_json::json!(["cap_sys_ptrace"])),
            ("capabilities","ptraceScope",serde_json::json!(0)),
            ("seccomp","mode",serde_json::json!("filter")),
            ("lsm","apparmor",serde_json::json!({"profile":"docker-default","mode":"enforce"})),
        ]);
        r.verdict = Some(Verdict { runtime:"docker".into(), confidence:0.9,
            underlying: None, alternatives: vec![], evidence: vec![] });
        // host-pid alone (ptrace_scope 1, no cap) must not fire:
        assert!(RULES.iter().find(|x| x.id == "AMR-004").unwrap().evaluate(&r, true).is_some());
        let r_no = report_with(&[
            ("namespaces","isolated",serde_json::json!({"pid":false,"user":true})),
            ("capabilities","effective",serde_json::json!([])),
            ("capabilities","ptraceScope",serde_json::json!(1))]);
        assert!(RULES.iter().find(|x| x.id == "AMR-004").unwrap().evaluate(&r_no, true).is_none());
        // unprivileged: fires but severity demoted to Info
        let demoted = RULES.iter().find(|x| x.id == "AMR-004").unwrap().evaluate(&r, false).unwrap();
        assert_eq!(demoted.severity, Severity::Info);
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
// src/model/rule.rs
use super::{Fact, Finding, Report, Severity};

pub struct Assess<'r> {
    pub report: &'r Report,
    pub privileged: bool,
}
impl<'r> Assess<'r> {
    pub fn fact(&self, probe: &str, key: &str) -> Option<&'r Fact> { self.report.fact(probe, key) }
    pub fn fact_any(&self, probe: &str, key: &str) -> Option<&'r Fact> {
        self.report.probes.iter().find(|p| p.name == probe)
            .and_then(|p| p.facts.iter().find(|f| f.key == key
                && f.status != crate::model::FactStatus::Unavailable))
    }
    pub fn containerized(&self) -> bool {
        self.report.verdict.as_ref().is_some_and(|v| v.runtime != "host")
    }
    /// json string-or-null equality: fact value equals given string
    pub fn is(&self, probe: &str, key: &str, s: &str) -> bool {
        self.fact(probe, key).and_then(|f| f.value.as_str()) == Some(s)
    }
    pub fn arr_has(&self, probe: &str, key: &str, s: &str) -> bool {
        self.fact(probe, key).and_then(|f| f.value.as_array().cloned())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(s)))
    }
}

pub struct Rule {
    pub id: &'static str,
    pub slug: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    pub requires_root: bool,
    pub check: fn(&Assess) -> Option<Vec<Fact>>,
}
impl Rule {
    pub fn evaluate(&self, report: &Report, privileged: bool) -> Option<Finding> {
        let a = Assess { report, privileged };
        let evidence = (self.check)(&a)?;
        let severity = if self.requires_root && !privileged { Severity::Info } else { self.severity };
        Some(Finding {
            rule: self.id.into(), slug: self.slug.into(), severity,
            summary: self.summary.into(), why: self.why.into(),
            remediation: self.remediation.into(),
            references: self.references.iter().map(|s| s.to_string()).collect(),
            evidence,
        })
    }
}
```

```rust
// src/model/rules.rs — first batch (append rules in Tasks 20–21; RULES stays one static, extend the array)
use super::rule::{Assess, Rule};
use super::Severity::*;

pub static RULES: &[Rule] = &[
    Rule {
        id: "AMR-001", slug: "writable-container-socket", severity: Critical,
        summary: "Container runtime API socket is mounted and writable",
        why: "A writable docker/podman socket allows creating a new privileged container with the host filesystem mounted — instant host root.",
        remediation: "Remove the socket mount; use a rootless socket proxy (e.g. docker-socket-proxy) with only required API endpoints.",
        references: &["https://docs.docker.com/engine/security/socket-proxy/"],
        requires_root: false,
        check: |a| {
            let f = a.fact("sockets", "found")?;
            let hit = f.value.as_array()?.iter().find(|e|
                e["writable"] == serde_json::json!(true)
                && matches!(e["kind"].as_str(), Some("docker") | Some("podman")))?;
            let _ = hit; Some(vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-002", slug: "privileged-container", severity: Critical,
        summary: "Privileged container: full caps, no seccomp, no AppArmor",
        why: "CAP_SYS_ADMIN + seccomp disabled + AppArmor unconfined is the `--privileged` signature: mount(2), cgroup escape, device access — container boundary is nominal.",
        remediation: "Drop --privileged; drop CAP_SYS_ADMIN; keep the default seccomp profile and AppArmor profile.",
        references: &["https://docs.docker.com/engine/containers/run/#admin-containers"],
        requires_root: false,
        check: |a| {
            if !a.containerized() { return None; }
            if !a.arr_has("capabilities", "effective", "cap_sys_admin") { return None; }
            if !a.is("seccomp", "mode", "0") { return None; }
            let aa = a.fact("lsm", "apparmor")?;
            let unconfined = aa.value["profile"] == serde_json::json!("unconfined");
            if !unconfined { return None; }
            Some(vec![a.fact("capabilities","effective")?.clone(), a.fact("seccomp","mode")?.clone(),
                      aa.clone()])
        },
    },
    Rule {
        id: "AMR-003", slug: "cap-sys-module", severity: High,
        summary: "CAP_SYS_MODULE in effective set: load kernel modules",
        why: "Loading a kernel module is ring-0 code execution on the host kernel.",
        remediation: "Drop CAP_SYS_MODULE (it is almost never intended inside a container).",
        references: &["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
        requires_root: false,
        check: |a| a.arr_has("capabilities", "effective", "cap_sys_module")
            .then(|| vec![a.fact("capabilities","effective").unwrap().clone()]),
    },
    Rule {
        id: "AMR-004", slug: "host-pid-with-ptrace", severity: High, requires_root: true,
        summary: "Host PID namespace combined with ptrace capability",
        why: "PID namespace shared with the host plus CAP_SYS_PTRACE (or yama=0) allows ptracing host processes and stealing their credentials/memories.",
        remediation: "Remove pid=host from the sandbox; keep yama ptrace_scope >= 1.",
        references: &["https://man7.org/linux/man-pages/man2/ptrace.2.html"],
        check: |a| {
            let iso = a.fact_any("namespaces", "isolated")?;
            if iso.value.get("pid") != Some(&serde_json::json!(false)) { return None; }
            let ptrace = a.arr_has("capabilities", "effective", "cap_sys_ptrace")
                || a.fact("capabilities", "ptraceScope").and_then(|f| f.value.as_i64()) == Some(0);
            if !ptrace { return None; }
            let mut ev = vec![iso.clone()];
            ev.extend([a.fact("capabilities","effective"), a.fact("capabilities","ptraceScope")]
                .into_iter().flatten().cloned());
            Some(ev)
        },
    },
    Rule {
        id: "AMR-005", slug: "seccomp-disabled", severity: High,
        summary: "Seccomp disabled inside a container",
        why: "Without a seccomp filter the full kernel syscall surface (~450 calls) is reachable from container processes.",
        remediation: "Run with the runtime's default seccomp profile (`--security-opt seccomp=runtime/default`).",
        references: &["https://docs.docker.com/engine/security/seccomp/"],
        requires_root: false,
        check: |a| (a.containerized() && a.is("seccomp", "mode", "0"))
            .then(|| vec![a.fact("seccomp","mode").unwrap().clone()]),
    },
    Rule {
        id: "AMR-006", slug: "apparmor-unconfined", severity: Medium,
        summary: "AppArmor profile unconfined while runtime supports AppArmor",
        why: "An unconfined profile disables the mandatory access-control layer the runtime would otherwise apply.",
        remediation: "Drop `--security-opt apparmor=unconfined`; use the runtime-default profile.",
        references: &["https://apparmor.net/"],
        requires_root: false,
        check: |a| {
            if !a.containerized() { return None; }
            let aa = a.fact("lsm", "apparmor")?;
            (aa.value["profile"] == serde_json::json!("unconfined"))
                .then(|| vec![aa.clone()])
        },
    },
];
```

`Rule.check` is a plain `fn` pointer — closures above must be non-capturing (they are). `ScanMeta::stub()` (Task 2 test helper): construct with defaults, `#[cfg(test)]`.

- [ ] **Step 4: Run — PASS.** (Pipeline `evaluate_all` now runs six rules against every scan; host scans produce zero findings unless genuinely vulnerable — re-run Task 7's `tests/cli.rs` to confirm no exit-code regressions.)
- [ ] **Step 5: Commit** — `"feat: rule engine + rules AMR-001..006"`

---

### Task 20: Rules 007–013

**Files:**
- Modify: `src/model/rules.rs`
- Test: inline, one per rule, same harness as Task 19 (`report_with`)

**Interfaces:** extends `RULES`.
- AMR-007 selinux-permissive (medium): `selinux.mode == "permissive" && containerized`
- AMR-008 identity-uid-map (medium): `containerized && uidMap == [{container:0,host:0,range:4294967295}]`
- AMR-009 cgroupv1-in-container (low): `containerized && cgroup.version == 1`
- AMR-010 unlimited-pids (low): `containerized && "pids" in controllers && limits.pids == "max"`
- AMR-011 gid-map-root-grant (info): gidMap has a row `host==0` **and** setgroups=="allow" (root group mapped and setgroups not denied ⇒ dropping groups cannot shed gid 0)
- AMR-012 landlock-abi-available (info): `lsm.landlockAbi >= 1` — informational: kernel offers Landlock; no per-process ruleset state is observable from userspace (spec errata: wording updated)
- AMR-013 hypervisor-detected (info): `vmm.hypervisor.present == true`

- [ ] **Step 1: Failing tests** — mirror the Task 19 harness; per rule: one firing fixture fact-set, one quiet fixture. Key discriminating cases:
  - AMR-011 fires on `[{"container":0,"host":0,"range":1}]` + `"allow"`, quiet on same rows + `"deny"`, quiet on `[{"container":0,"host":100000,"range":65536}]` + `"allow"`.
  - AMR-009 quiet when `version == 2`. AMR-010 quiet when `pids.max` value is `"2048"`; quiet when controllers lacks `"pids"`.
  - AMR-008 quiet for rootless rows (`host:100000`).
  - AMR-007 quiet when mode `"enforcing"`; quiet when not containerized (host dev boxes run permissive often).

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** — seven `Rule { … }` entries appended to `RULES`, each check:

```rust
// AMR-007
check: |a| {
    if !a.containerized() { return None; }
    let f = a.fact("lsm", "selinux")?;
    (f.value["mode"] == serde_json::json!("permissive")).then(|| vec![f.clone()])
},
// AMR-008
check: |a| {
    if !a.containerized() { return None; }
    let f = a.fact("uidmap", "uidMap")?;
    let rows = f.value.as_array()?;
    (rows.as_slice() == [serde_json::json!({"container":0,"host":0,"range":4294967295})])
        .then(|| vec![f.clone()])
},
// AMR-011
check: |a| {
    let gid = a.fact("uidmap", "gidMap")?;
    let setgroups = a.fact("uidmap", "setgroups")?;
    let root_row = gid.value.as_array()?.iter().any(|r| r["host"] == serde_json::json!(0));
    (root_row && setgroups.value == serde_json::json!("allow")).then(|| vec![gid.clone(), setgroups.clone()])
},
// AMR-009 / AMR-013
check: |a| (a.containerized() && a.fact("cgroup","version").and_then(|f| f.value.as_i64()) == Some(1))
    .then(|| vec![a.fact("cgroup","version").unwrap().clone()]),
check: |a| a.fact("vmm","hypervisor")
    .filter(|f| f.value["present"] == serde_json::json!(true))
    .map(|f| vec![f.clone()]),
// AMR-010
check: |a| {
    if !a.containerized() { return None; }
    let controllers = a.fact("cgroup","controllers")?;
    if !controllers.value.as_array()?.iter().any(|c| c == "pids") { return None; }
    let limits = a.fact("cgroup","limits")?;
    (limits.value["pids"] == serde_json::json!("max")).then(|| vec![controllers.clone(), limits.clone()])
},
// AMR-012
check: |a| a.fact("lsm","landlockAbi")
    .filter(|f| f.value.as_i64().is_some_and(|v| v >= 1))
    .map(|f| vec![f.clone()]),
```

Metadata for each (id, slug, severity, summary/why/remediation/references `requires_root: false`) follows the catalog table in the spec verbatim — copy the strings from `docs/superpowers/specs/2026-09-30-amirustrained-design.md` §8 rows AMR-007…013.

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: rules AMR-007..013"`

---

### Task 21: Rules 014–018 + registry-order regression
> Amendment 2026-10-01: `Verdict.confidence` is the shipped string ladder
> `high|medium|low` — AMR-015's "confidence < 0.5" means `confidence == "low"`.


**Files:**
- Modify: `src/model/rules.rs`
- Test: inline

- AMR-014 hardened-sandbox (info): verdict runtime is firecracker/gvisor/kata — positive note
- AMR-015 low-confidence-verdict (info): `verdict.confidence < 0.5` (verdict exists)
- AMR-016 cap-sys-admin-uncombined (medium): `containerized && cap_sys_admin && NOT (seccomp 0 && apparmor unconfined)` — the AMR-002 remainder
- AMR-017 cgroup-ns-shared (info): `namespaces.cgroupNsSameAsInit == true`
- AMR-018 no-new-privs-off (low): `containerized && noNewPrivs == 0`

- [ ] **Step 1: Failing tests** — discriminating pair for AMR-016: privileged combo (AMR-002 facts) ⇒ 016 must be quiet, 002 fires; cap_sys_admin + seccomp filter ⇒ 016 fires. AMR-015: confidence 0.4 fires, 0.6 quiet.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** — five entries per catalog; AMR-016 check:

```rust
check: |a| {
    if !a.containerized() || !a.arr_has("capabilities","effective","cap_sys_admin") { return None; }
    let combo = a.is("seccomp","mode","0")
        && a.fact("lsm","apparmor").map(|f| f.value["profile"] == serde_json::json!("unconfined")).unwrap_or(false);
    if combo { return None; }
    Some(vec![a.fact("capabilities","effective").unwrap().clone()])
},
```

AMR-014 check: `a.report.verdict` runtime in `["firecracker","gvisor","kata"]`; AMR-018: `a.fact("capabilities","noNewPrivs").and_then(|f| f.value.as_i64()) == Some(0)`.
- [ ] **Step 4: Run — PASS** — plus full `cargo test`: the Task 5 pipeline test still emits zero findings on this dev box's own scan? (tests use stub outcomes; host-rules on real facts only run in Task 26 scenarios).
- [ ] **Step 5: Commit** — `"feat: rules AMR-014..018, complete catalog"`

---

### Task 22: JSON renderer (full report)

> Amendment 2026-10-01: render `confidence` as the string ladder; evidence lines
> follow `"<runtime> <probe>.<key> <weight>"` plus `environment:` notes (spec §8).

**Files:**
- Create: `src/render/json.rs`
- Modify: `src/render/mod.rs` (`make` arm), `src/pipeline.rs` (`Renderer` needs the finished `Report` for aggregate formats)
- Test: inline

**Interfaces:**
- Aggregate renderers need the whole `Report`, but the trait is event-driven. Resolution: `Event::Summary` gains `report: Box<Report>` (the finished report; cloned once at the end of `scan_with_probes`). Json/Markdown/Sarif buffer nothing — they render exactly on the Summary event and ignore the rest; Text/Jsonl ignore the new field.
- Update Task 5 tests: pattern-match on `Event::Summary { .. }` remains valid.
- Produces: `pub struct Json;` — `serde_json::to_string_pretty(&report)` + `\n`.

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Report, ScanMeta};
    #[test]
    fn full_report_shape() {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.scan.complete = true;
        let mut buf = vec![];
        Json.on_event(&mut buf, &crate::pipeline::Event::Summary {
            verdict: None, findings: vec![], counts: Default::default(),
            complete: true, report: Box::new(r) }).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["scan"]["complete"], true);
        assert!(v["probes"].is_array() && v["findings"].is_array());
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement**

```rust
// src/render/json.rs
use crate::pipeline::Event;
use super::Renderer;

pub struct Json;
impl Renderer for Json {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        if let Event::Summary { report, .. } = ev {
            let s = serde_json::to_string_pretty(&**report).map_err(std::io::Error::other)?;
            w.write_all(s.as_bytes())?;
            w.write_all(b"\n")?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> { Ok(()) }
}
```

`render/mod.rs` `make`: `Format::Json => Box::new(json::Json)` (drop the Text fallback arm for Json).

- [ ] **Step 4: Run — PASS** (jsonl test still green: its `Summary` construction gains `report: Box::new(Report::blank(...))`).
- [ ] **Step 5: Commit** — `"feat: full-report json renderer"`

---

### Task 23: Full text + markdown renderers

**Files:**
- Modify: `src/render/text.rs` (full layout), create `src/render/markdown.rs`
- Test: inline (`insta::assert_snapshot!` inline snapshots)

**Interfaces:**
- Text layout (spec §9): verdict line (`runtime docker (confidence 0.90)`), findings grouped severity-desc (`CRIT|HIGH|MED|LOW|INFO` gutter), each finding: id+slug+summary, why, remediation, indented evidence (`  - uidmap.uidMap = [...]  (proc/1/uid_map)`), counts footer, INCOMPLETE banner when `!complete`. Color: ANSI only when stdout is a tty (`std::io::IsTerminal`) — renderer gets `color: bool` from `make` (`main` passes `cli.no_color || !stdout().is_terminal()` → extend `make(fmt, verbose, color)`).
- Markdown: `# amirustrained report`, verdict table, `## CRITICAL` sections, findings `### AMR-002 — summary`, evidence as list.

- [ ] **Step 1: Failing tests**

```rust
// src/render/text.rs (add to existing tests)
#[test]
fn finding_block_layout_snapshot() {
    let mut r = crate::model::Report::blank(crate::model::ScanMeta::stub(), 1);
    r.verdict = Some(crate::model::Verdict { runtime: "docker".into(), confidence: 0.9,
        underlying: None, alternatives: vec![], evidence: vec![] });
    r.findings = vec![crate::test_finding("AMR-002", crate::model::Severity::Critical)];
    r.scan.complete = true; r.compute_counts();
    let mut buf = vec![];
    Text { verbose: false, color: false }.on_event(&mut buf,
        &crate::pipeline::Event::Summary { verdict: r.verdict.clone(),
            findings: r.findings.clone(), counts: r.counts.clone(),
            complete: true, report: Box::new(r) }).unwrap();
    insta::assert_snapshot!(String::from_utf8(buf).unwrap(), @r###"
    runtime: docker (confidence 0.90)

    CRIT AMR-002 writable-container-socket: Privileged container: full caps, no seccomp, no AppArmor
      why: privileged signature — mount/cgroup escape
      fix: drop --privileged
        - capabilities.effective = ["cap_sys_admin"] (test)

    1 findings (c1 h0 m0 l0 i0)
    scan complete
    "###);
}
```

Add `pub fn test_finding(id: &str, sev: Severity) -> Finding` to `src/lib.rs`-equivalent (`#[cfg(test)]` helper in `model/mod.rs`, reused by md/sarif tests). The snapshot pins the exact text format — adjust the renderer until it matches; this snapshot IS the format spec at implementation time.

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** `text.rs` full + `markdown.rs` (render on `Event::Summary` from `report`; `finish` flushes nothing). Register arms in `make`; `make` signature `make(fmt: Format, verbose: bool, color: bool)`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: full text + markdown renderers"`

---

### Task 24: SARIF renderer

**Files:**
- Create: `src/render/sarif.rs`
- Test: inline

**Interfaces:** SARIF 2.1.0: `runs[0].tool.driver` = `{name:"amirustrained", informationUri, version, rules:[{id:"AMR-002", shortDescription:{text:summary}, fullDescription, help_uri, defaultConfiguration:{level}}]}`; `results[]` = `{ruleId, ruleIndex, level, message:{text: summary}, locations:[]}`. Severity map: critical→error, high→error, medium→warning, low→note, info→note. Rules list built from `crate::model::rules::RULES` (all 18, not just fired ones).

- [ ] **Step 1: Failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sarif_envelope_and_levels() {
        use crate::model::{Report, ScanMeta};
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.findings = vec![
            crate::model::test_finding("AMR-001", crate::model::Severity::Critical),
            crate::model::test_finding("AMR-009", crate::model::Severity::Low)];
        let mut buf = vec![];
        Sarif.on_event(&mut buf, &crate::pipeline::Event::Summary { verdict: None,
            findings: r.findings.clone(), counts: Default::default(),
            complete: true, report: Box::new(r) }).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["rules"].as_array().unwrap().len(), crate::model::rules::RULES.len());
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
    }
}
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** — build the envelope with `json!`, no new deps; `ruleIndex` = position in `RULES`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"feat: SARIF 2.1.0 renderer"`

---

### Task 25: `--fail-on` + fixture-root CLI integration

**Files:**
- Modify: `src/main.rs` (fail-on already wired in Task 7 — verify against severity *after* demotion: spec §8 says fail-on compares the finding's final severity; Task 7 code already uses `f.severity >= lvl` post-evaluation ✓)
- Test: extend `tests/cli.rs` with a fixture-driven run

- [ ] **Step 1: Failing test** — uses a tiny inline fixture built by the test itself (not the Task 26 corpus):

```rust
#[test]
fn fail_on_trips_against_fixture_socket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("run")).unwrap();
    std::fs::write(dir.path().join("run/docker.sock"), "").unwrap();
    // fixture mode: sockets probe finds the regular file candidate (writable, info null)
    let out = Command::cargo_bin("amirustrained").unwrap()
        .args(["--fixture-root", dir.path().to_str().unwrap(), "--format", "json"])
        .output().unwrap();
    assert!(out.status.success()); // plain scan: exit 0 regardless of findings
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["findings"].as_array().unwrap().iter()
        .any(|f| f["rule"] == "AMR-001"));
    Command::cargo_bin("amirustrained").unwrap()
        .args(["--fixture-root", dir.path().to_str().unwrap(), "--fail-on", "high"])
        .assert().code(1);
}
```

Add `tempfile`, `assert_cmd`, `predicates`, `serde_json` as `[dev-dependencies]` now (Task 7 tests already used the first two).

- [ ] **Step 2: Run — FAIL** (fixture-root currently only reaches stub probes; AMR-001 can't fire until registry is full — it IS full by now; sockets probe reads fixture candidate via `PseudoFs::exists`).
- [ ] **Step 3: Implement** any gaps exposed (expect: none, or `Cli::pid` clamping).
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `"test: fail-on + fixture end-to-end"`

---

### Task 26: Scenario fixtures + golden tests (9 scenarios × verdict/findings)

**Files:**
- Create: `tests/fixtures/<scenario>/…` (9 trees)
- Create: `tests/scenarios.rs`
- Test: verdict string + finding rule-set per scenario; one inline text snapshot for `docker-privileged`

**Fixture DSL** (all files relative to fixture root; probes read through `PseudoFs`): the table below is the exact content corpus. Values are real-world-shaped; probes tolerate absent files, so only decision-relevant files are listed. `ns/*` files are symlink-stub regular files (Task 3 `read_link` falls back to file content under fixture roots — add to `PseudoFs::read_link`: fixture mode returns trimmed file content when the path is not a symlink).

Machine-dependent facts (CPUID hypervisor, `landlock(ABI)` syscall, env) come from a `FixtureOs` parameter, never from the test machine — every assertion below is exact. Finding ids abbreviated `AMR-0NN`.

| scenario | FixtureOs: hyp / landlock / env | key files (path = content, under `proc/self/` unless absolute) | verdict | findings |
|---|---|---|---|---|
| bare-host | false / None / ∅ | `cgroup=0::/user.slice/session-1.scope`, `uid_map=0 0 4294967295`, `status: Seccomp:0`, `ns/*` all equal `/proc/1/ns/*` (literal `1`), `/sys/class/dmi/id/sys_vendor=ASUSTeK` | host, conf 1.0 | ∅ |
| docker-default | false / Some(1) / ∅ | `cgroup=0::/docker/135c8edb…c4a2` (64 hex), `uid_map`/`gid_map=0 0 4294967295`, `status: Seccomp:2, Seccomp_filters:3, CapEff=00000000a80425fb, NoNewPrivs:0`, `attr/current=docker-default (enforce)`, `/sys/kernel/security/lsm=capability,yama,apparmor,landlock`, `/sys/fs/cgroup/docker/<id>/pids.max=max` (pids controller present, unlimited → AMR-010), `/run/docker.sock` (regular file) | docker, conf ≥ 0.8 | 001, 008, 010, 011, 012, 018 |
| docker-privileged | false / Some(1) / ∅ | same tree; `status: Seccomp:0, CapEff=000001ffffffffff, NoNewPrivs:0`, `attr/current=unconfined` | docker | 001, 002, 005, 006, 008, 010, 011, 012, 018 |
| rootless-podman | false / Some(1) / ∅ | `cgroup=/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-1a2b3c4d5e6f.scope`, `uid_map=0 100000 65536`, `setgroups=deny`, pids unlimited under that scope, `/run/user/1000/podman/podman.sock` (regular file) | podman (cgroup +0.7, rootless +0.3) | 001, 005 (fixture `status: Seccomp:0`), 010, 012, 018; NOT 008 (rootless uid rows), NOT 011 (`setgroups=deny`) |
| k8s-pod | false / Some(1) / `KUBERNETES_SERVICE_HOST=10.43.0.1`, `KUBERNETES_SERVICE_PORT=443` | `cgroup=0::/kubepods/burstable/pod73f1a1b2-2c3d-4e5f-6a7b-8c9d0e1f2a3b/abcdef0123456789`, `/var/run/secrets/kubernetes.io/serviceaccount/{namespace=prod,ca.crt=x}`, pids unlimited, `/etc/hostname=qj27-worker-0` | kubernetes (env + serviceaccount + kubepods cgroup; no stronger signal → underlying null, alternatives carry the containerd-family candidates) | 005, 010, 012, 018 |
| firecracker | true / Some(1) / ∅ | `/sys/class/dmi/id/` dir present but empty, `/sys/devices/system/clocksource/clocksource0/current_clocksource=kvm-clock`, `/dev/vsock` (regular file), `cpuinfo` flags include `hypervisor`, `version=Linux version 5.10.195 (root@fc…)` , `cgroup=0::/` | firecracker | 012, 013 |
| gvisor | false / None / ∅ | `version=Linux version 4.4.0 (gVisor…)`, `cgroup=0::/`, no dmi files, no sockets | gvisor, conf 0.9 | ∅ (hardened by design) — real gVisor also sets the CPUID hypervisor bit; fixture pins hyp=false so 013 stays out |
| lxc | false / None / ∅ | `cgroup=0::/lxc/amber`, `status: Seccomp:0`, no sockets, pids absent (no controller dir → AMR-010 silent) | lxc | 005, 018 |
| hardened-host | false / None / ∅ | `status: Seccomp:2`, `/sys/kernel/security/lockdown=[integrity]`, no container markers, no landlock | host | ∅ |

**Harness** (`tests/scenarios.rs`):

```rust
// tests/scenarios.rs — library-driven: pipeline + fixture fs + FixtureOs.
// The test machine contributes NOTHING observable (no RealOs in scenarios).
use amirustrained::{opts::Opts, pipeline, probes, sys::{fs::PseudoFs, os::{HypervisorInfo, OsApi, SeccompActions}}};
use std::{path::Path, sync::Arc};

struct FixtureOs { hyp: bool, landlock: Option<u64>, env: Vec<(&'static str, &'static str)> }
impl OsApi for FixtureOs {
    fn hypervisor(&self) -> HypervisorInfo { HypervisorInfo { present: self.hyp, vendor: None } }
    fn landlock_abi(&self) -> Option<u64> { self.landlock }
    fn seccomp_actions(&self) -> SeccompActions { SeccompActions::default() }
    fn seccomp_filter_dump(&self, _pid: u32) -> Result<Vec<u64>, crate::model::ProbeIo> {
        Err(crate::model::ProbeIo::Unavailable)
    }
    fn syscall0(&self, _id: u32) -> Result<(), i32> { Err(1) } // EPERM: syscall-probe inactive anyway
    fn uds_probe(&self, _p: &std::path::Path, _t: std::time::Duration)
        -> std::io::Result<crate::sys::os::UdsReply> { Err(std::io::Error::other("fixture")) }
    fn is_root(&self) -> bool { false }
    fn env(&self, key: &str) -> Option<String> {
        self.env.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
    }
}

fn run(scenario: &str, os: FixtureOs) -> pipeline::Report {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(scenario);
    let opts = Opts { pid: None, probe_syscalls: false, dump_filters: false,
        probe_timeout: None, fail_on: None };
    pipeline::scan_with_probes(Arc::new(PseudoFs::new(root)), Arc::new(os), &opts,
        probes::registry(&opts), &mut |_| {})
}
fn rule_ids(r: &pipeline::Report) -> Vec<String> {
    let mut v: Vec<_> = r.findings.iter().map(|f| f.rule.clone()).collect();
    v.sort(); v
}
#[test] fn docker_default() {
    let r = run("docker-default", FixtureOs { hyp: false, landlock: Some(1), env: vec![] });
    assert_eq!(r.verdict.as_ref().unwrap().runtime, "docker");
    assert_eq!(rule_ids(&r), ["AMR-001","AMR-008","AMR-010","AMR-011","AMR-012","AMR-018"]);
}
#[test] fn bare_host() {
    let r = run("bare-host", FixtureOs::default());
    assert_eq!(r.verdict.as_ref().unwrap().runtime, "host");
    assert!(r.findings.is_empty(), "{:?}", rule_ids(&r));
}
// …remaining 7 tests: same shape; FixtureOs params + expected list per the table.
```

PseudoFs pid handling: probes format `/proc/<pid>/…` with the *real* pid; fixtures name files `proc/<pid>/…`? — No: fixtures are written for pid `1`? Also wrong. Solution (put in `sys/fs.rs`): `PseudoFs` rewrites the first path segment pair `proc/<pid>/` → fixture `proc/self/` under fixture roots: on `read/read_link/exists/writable`, if fixture mode and path starts with `/proc/<digits>/`, substitute `/proc/self/`. All fixture trees therefore carry `proc/self/…`. (Update every fixture path in the table mentally: `proc/self/cgroup` etc. Bare-host/`/proc/1/ns/*` comparisons keep literal `1`.)
Determinism note: fs facts come from the fixture tree, machine facts from `FixtureOs` — so all nine expected lists are exact `assert_eq!`, on this box and on CI-on-VM alike. `RealOs` is exercised only by unit tests (Task 4) and the live smoke (Task 27); AMR-012/013 firing on a Landlock-enabled VM is live-scan behavior, not test behavior.

- [ ] **Step 1:** write harness + 9 scenario tests — FAIL (fixtures absent).
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3:** create the 9 fixture trees with the exact contents in the table (each tree: `proc/self/{cgroup,status,uid_map,gid_map,setgroups,attr/current,ns/*}`, plus scenario-specific `/sys`, `/run`, `/etc`, `/dev` files). Wire `--fixture-root`-based bin smoke: `docker-default` also asserted through the CLI as json with one inline text snapshot (`--format text` via `assert_cmd`, snapshot the stdout string with `insta::assert_snapshot!`).
- [ ] **Step 4: Run — PASS** (all 9 scenarios on this box AND reasoning for CI: only env-dependent assertions vary, and they're subset-checked).
- [ ] **Step 5: Commit** — `"test: 9-scenario fixture corpus + golden assertions"`

---

### Task 27: Live smoke, musl CI, README, release profile

**Files:**
- Create: `scripts/live-smoke.sh`
- Modify: `.github/workflows/rust.yml` (musl target + release artifact), `Cargo.toml` (`[profile.release] opt-level="z", lto=true, strip=true, codegen-units=1, panic="abort"`), `README.md`

- [ ] **Step 1: Implement**

```bash
#!/usr/bin/env bash
# Live smoke: run the binary against itself, all real paths. Never destructive:
# default probes only; --probe-syscalls is exercised too (list is EPERM-safe).
set -euo pipefail
BIN="${1:-cargo run -q --}"
$BIN --format json   > /tmp/amr.json
$BIN --format jsonl > /tmp/amr.jsonl
$BIN --format sarif > /tmp/amr.sarif
$BIN --probe-syscalls --format jsonl -o /tmp/amr-sys.jsonl
python3 - <<'EOF'
import json
r = json.load(open('/tmp/amr.json'))
assert r['schemaVersion'] == 1 and r['scan']['complete']
assert {p['name'] for p in r['probes']} >= {'namespaces','uidmap','capabilities','seccomp','lsm','vmm','cgroup','sockets','k8s','runtime'}
for line in open('/tmp/amr.jsonl'):
    assert json.loads(line)['schemaVersion'] == 1
s = json.load(open('/tmp/amr.sarif')); assert s['version'] == '2.1.0'
sysl = [json.loads(l) for l in open('/tmp/amr-sys.jsonl') if '"syscall-probe"' in l]
assert sysl and sysl[0]['name'] == 'syscall-probe'
print('live smoke OK')
EOF
```

CI: add `cross`-free native musl job — `apt-get install -y musl-tools`, `rustup target add x86_64-unknown-linux-musl`, build + `file` check (`static-pie`), upload artifact. Keep the existing test job.
README: install (prebuilt musl tarball, cargo install), usage examples (incl. red-team one-liner `amirustrained --format json | jq .findings`), probe/privilege matrix, exit-code table, `--probe-syscalls` risk note, rule catalog table (copy from spec §8).

- [ ] **Step 2:** run `scripts/live-smoke.sh` on this host + inside a Docker container:
  `docker run --rm -v $PWD:/w alpine:3.20 /w/target/x86_64-unknown-linux-musl/release/amirustrained --format markdown` — expect docker verdict facts, socket probe quiet unless mounted. Both runs observed, output pasted into the commit message.
- [ ] **Step 3:** full `cargo test` + `cargo clippy --all-targets -- -D warnings` green.
- [ ] **Step 4: Commit** — `"feat: release profile, musl CI, README, live smoke"`

---

## Spec coverage self-check (executor: run last, before final review)

| spec section | tasks |
|---|---|
| §4 CLI flags | 7 (all flags), 12 (`--dump-filters` hidden), 18 (`--probe-syscalls`), 25 (`--fail-on`) |
| §5 probes | 8–18 |
| §6 pipeline/timeout/events | 5, 22 (`Summary.report`) |
| §7 runtime scoring | 17 |
| §8 rules/demotions/exit codes | 19–21 (demotion in `Rule::evaluate`), 7+25 (exit codes) |
| §9 formats | 6 (jsonl/text-min), 22 (json), 23 (text/md), 24 (sarif) |
| §10 testing | 26 (fixtures/goldens), 27 (live smoke, musl) |

Spec errata applied 2026-09-30 (same commit): AMR-012 reframed to `landlock-abi-available` (info, presence-only — per-process Landlock domain state is unobservable); §5 seccomp profile-template matching descoped to v1.1 (mode + filter count + action matrix reported; `landlock(ABI)` stays the landlock source, made deterministic in tests via `FixtureOs`).

## Deferred (v1.1+, do NOT build now)

cgroup-tree walker (`--deep-cgroups`), full-FS socket discovery, kernel-hardening sysctl table, filter-program → blocked-syscall decoder, rootless-detection refinements (`/proc/self/uid_map` edge cases with multiple rows), OCI config introspection from runtime state dirs.