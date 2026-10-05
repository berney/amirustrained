# Mounts & Filesystem Isolation Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement comprehensive Linux mount topology and filesystem sandboxing audit via `/proc/self/mountinfo`, path-agnostic capability/DAC-driven staging detection (`rw` + `exec` + `fs.writable`), container-aware rules `AMR-030..033`, centralized mount parsing in `src/sys/fs.rs` (reused in `namespaces.rs`), `Rule.verbose_only` finding suppression to eliminate terminal noise, and updated scenario tests.

**Architecture:** A centralized parser in `src/sys/fs.rs` parses `/proc/self/mountinfo` with octal unescaping and fallback to `/proc/mounts`. `src/probes/namespaces.rs` reuses this parser for `hidepid`. A dedicated `src/probes/mounts.rs` probe extracts security facts (`mounts.staging`, `mounts.sensitive_unmasked`, `mounts.shared_propagation`, `mounts.host_leaks`). Rules `AMR-030..033` evaluate container isolation and staging posture in `src/model/rules.rs`. A `verbose_only: bool` field on `Rule` allows human text renderers in `src/render/text.rs` to hide low-priority informational findings unless `--verbose` is provided.

**Tech Stack:** Rust edition 2024, `rustix`, `libc`, `serde`/`serde_json`, `insta`.

**Spec:** `docs/superpowers/specs/2026-10-06-mounts-and-filesystem-isolation-design.md`

## Global Constraints
- Target static musl platforms: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `riscv64gc-unknown-linux-musl`. Zero dynamic C library linkages.
- Non-destructive and passive: mounts auditing is strictly read-only inspection of procfs/sysfs and DAC accessibility.
- Path-agnostic staging detection: never hardcode `/tmp` or `/dev/shm` as required paths; evaluate any mount where `rw` is set, `noexec` is absent, and `fs.writable(&mount_point)` is true.
- Output contract: human mode is concise and avoids noise (`verbose_only` Info findings hidden unless `-v`); machine formats (JSON/YAML/SARIF) are exhaustive and always output 100% of findings and mount tables.
- Zero regression on existing 12 scenarios and snapshots.

---

### Task 1: Centralized `parse_mountinfo` in `src/sys/fs.rs` with Octal Unescaping

**Files:**
- Modify: `src/sys/fs.rs`
- Test: `src/sys/fs.rs` (inline unit tests)

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct MountEntry {
      pub mount_id: u32,
      pub parent_id: u32,
      pub major_minor: String,
      pub root: String,
      pub mount_point: String,
      pub mount_options: Vec<String>,
      pub optional_fields: Vec<String>,
      pub fstype: String,
      pub mount_source: String,
      pub super_options: Vec<String>,
  }

  pub fn unescape_octal(s: &str) -> String;
  pub fn parse_mountinfo(content: &str) -> Vec<MountEntry>;
  ```

- [ ] **Step 1: Write unit tests for `unescape_octal` and `parse_mountinfo`**
In `src/sys/fs.rs`, write unit tests covering:
1. `unescape_octal`: `\040` $\to$ space, `\011` $\to$ tab, `\012` $\to$ newline, `\134` $\to$ `\`.
2. Standard 11-field `/proc/self/mountinfo` line with optional fields (`shared:1 master:2`).
3. 10-field `/proc/self/mountinfo` line without optional fields.
4. Legacy 6-field `/proc/mounts` line fallback.
5. Handling malformed lines gracefully (skipped, no panic).

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test sys::fs::tests::mountinfo`
Expected: FAIL (unimplemented).

- [ ] **Step 3: Implement `MountEntry`, `unescape_octal`, and `parse_mountinfo`**
Implement in `src/sys/fs.rs`:
- `unescape_octal`: scans for `\`, parses 3 octal digits, decodes byte.
- `parse_mountinfo`:
  - Splits lines.
  - If line has a `-` separator: split into left (mountinfo fields 1..6 + optional fields) and right (fstype, source, super_options).
  - Parse `mount_id`, `parent_id`, `major_minor`, `root` (unescaped), `mount_point` (unescaped), `mount_options` (comma-split).
  - Gather tokens between `mount_options` and `-` into `optional_fields`.
  - Right tokens: `fstype`, `mount_source` (unescaped), `super_options` (comma-split).
  - If no `-` (legacy `/proc/mounts` 6-field format): map source, mount_point, fstype, options into `MountEntry` with default IDs.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test sys::fs::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/sys/fs.rs
git commit -m "feat(sys): add centralized parse_mountinfo with octal unescaping in sys::fs"
```

---

### Task 2: Refactor `namespaces.rs` to Use `parse_mountinfo`

**Files:**
- Modify: `src/probes/namespaces.rs:65-85`
- Test: `src/probes/namespaces.rs`

**Interfaces:**
- Refactors `pub fn parse_hidepid(mounts_content: &str) -> String` to delegate to `crate::sys::fs::parse_mountinfo`.

- [ ] **Step 1: Write/verify unit test for `parse_hidepid`**
Ensure unit tests in `src/probes/namespaces.rs` assert `parse_hidepid` accurately extracts `hidepid=2` from both `/proc/mounts` and `/proc/self/mountinfo` formats, defaulting to `"0"`.

- [ ] **Step 2: Refactor `parse_hidepid`**
In `src/probes/namespaces.rs`:
- Update `parse_hidepid` to call `crate::sys::fs::parse_mountinfo(mounts_content)`.
- Find entry where `entry.mount_point == "/proc"` or `entry.fstype == "proc"`.
- Search `entry.mount_options` and `entry.super_options` for `opt.strip_prefix("hidepid=")`.
- Return extracted value, or `"0"` if absent.

- [ ] **Step 3: Run namespace tests to verify they pass**
Run: `cargo test probes::namespaces::tests`
Expected: PASS.

- [ ] **Step 4: Commit**
```bash
git add src/probes/namespaces.rs
git commit -m "refactor(namespaces): delegate hidepid parsing to sys::fs::parse_mountinfo"
```

---

### Task 3: Dedicated `Mounts` Probe (`src/probes/mounts.rs`)

**Files:**
- Create: `src/probes/mounts.rs`
- Modify: `src/probes/mod.rs`

**Interfaces:**
- Produces: `pub struct Mounts;` implementing `crate::probes::Probe`.
- Exports facts under `mounts`:
  - `mounts.count`: usize
  - `mounts.staging`: Vec<StagingMount> (filtered where `rw` + lacks `noexec` + `fs.writable(&mount_point)`)
  - `mounts.sensitive_unmasked`: Vec<String> (unmasked or writable `/proc/kcore`, `/proc/sys`, etc.)
  - `mounts.shared_propagation`: Vec<String> (mount points with `shared:` or `master:` tags)
  - `mounts.host_leaks`: Vec<String> (mounts exposing host root or host sockets)
  - `mounts.all`: Vec<MountEntry>

- [ ] **Step 1: Write unit tests for `Mounts` probe security classification**
In `src/probes/mounts.rs`, write tests using `PseudoFs`:
1. Staging classification: mount with `rw` and no `noexec` is emitted in `mounts.staging` IF `fs.writable` is true. If directory is read-only DAC, it is NOT in `mounts.staging`.
2. Missing flags computed: detects absence of `noexec`, `nosuid`, `nodev`.
3. Sensitive unmasked paths: flags writable `/proc/sys` and unmasked `/proc/kcore`.
4. Shared propagation: flags entries with `shared:1` or `master:2`.
5. Host leaks: flags entries with `root == "/"` from host device or `/host` mount point.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test probes::mounts::tests`
Expected: FAIL (unimplemented).

- [ ] **Step 3: Implement `src/probes/mounts.rs`**
Implement the probe:
- Read `/proc/self/mountinfo`, fallback `/proc/mounts`.
- Parse via `crate::sys::fs::parse_mountinfo`.
- Filter staging candidates checking `rw`, `!noexec`, and `fs.writable(&entry.mount_point)`.
- Filter sensitive unmasked paths (`/proc/sys` writable, `/proc/kcore` present, `/sys/firmware` accessible).
- Filter shared propagation tags.
- Filter host root/socket leaks.
- Register `pub mod mounts;` in `src/probes/mod.rs` and add `Arc::new(mounts::Mounts)` to `registry()` in `src/probes/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test probes::mounts::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/probes/mounts.rs src/probes/mod.rs
git commit -m "feat(probes): add dedicated mounts and filesystem isolation probe"
```

---

### Task 4: `Rule.verbose_only` Flag & Rules `AMR-030..033`

**Files:**
- Modify: `src/model/rule.rs`
- Modify: `src/model/rules.rs`

**Interfaces:**
- `Rule.verbose_only: bool` added to `Rule` in `src/model/rule.rs`.
- Produces:
  - `AMR-030`: `staging-mount-unhardened` (Medium/High in container, Info with `verbose_only` on bare host)
  - `AMR-031`: `sensitive-proc-sys-unmasked` (High, `container_only: true`)
  - `AMR-032`: `shared-mount-propagation` (Medium, `container_only: true`)
  - `AMR-033`: `host-filesystem-exposed` (Critical, `container_only: true`)

- [ ] **Step 1: Write rule engine unit tests for `AMR-030..033`**
In `src/model/rules.rs`, write tests covering:
1. `AMR-030`: fires as Medium in container when staging mount is writable by caller; elevates to High if `nodev` is missing with `CAP_MKNOD`. Fires as Info on bare host with `verbose_only = true`.
2. `AMR-031`: fires High in container when sensitive `/proc` or `/sys` interfaces are unmasked; silenced on bare host.
3. `AMR-032`: fires Medium in container when mounts carry `shared:` propagation; silenced on bare host.
4. `AMR-033`: fires Critical in container when host root `/` or `/host` is mounted; silenced on bare host.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test model::rules::tests::mount_rules`
Expected: FAIL.

- [ ] **Step 3: Update `Rule` struct and implement rules `AMR-030..033`**
- In `src/model/rule.rs`: add `pub verbose_only: bool` to `Rule`.
- Update all existing rules in `RULES` with `verbose_only: false`.
- Implement `AMR-030` through `AMR-033` in `src/model/rules.rs`.
- Update rule uniqueness and registry order tests in `src/model/rules.rs`.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test model::rules::tests`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/model/rule.rs src/model/rules.rs
git commit -m "feat(rules): add Rule.verbose_only and rules AMR-030..033 for mount security"
```

---

### Task 5: Output Rendering: Verbose-Only Filter & Staging Mount Display

**Files:**
- Modify: `src/render/text.rs`
- Modify: `tests/cli.rs`

**Interfaces:**
- Filters `verbose_only` findings in standard human text output unless `cx.opts.verbose` is true.
- Updates summary footer: `N findings (c0 h1 m1 l0 i0) [K verbose notices hidden — run with -v]`.
- Formats `AMR-030` staging mounts list cleanly (truncated if >5).

- [ ] **Step 1: Write render tests for `verbose_only` filtering and staging mount layout**
In `src/render/text.rs` and `tests/cli.rs`, write tests asserting:
1. When a finding has `verbose_only == true` and severity is Info, it is hidden on standard runs and visible with `--verbose`.
2. The summary count displays hidden notices notation when suppressed.
3. Compact mode (`--compact`) also respects `verbose_only` suppression.

- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test render::text::tests::verbose_only`
Expected: FAIL.

- [ ] **Step 3: Implement `verbose_only` filter and staging formatting in `src/render/text.rs`**
In `src/render/text.rs`:
- Count and filter out findings matching `f.severity == Severity::Info && rule.verbose_only && !cx.opts.verbose`.
- In summary footer, render `format!(" [{} verbose notices hidden — run with -v]", hidden_count)` when `hidden_count > 0`.
- Format `AMR-030` staging evidence cleanly with per-mount missing flag lists and truncation.

- [ ] **Step 4: Run tests to verify they pass**
Run: `cargo test render::text::tests && cargo test --test cli`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add src/render/text.rs tests/cli.rs
git commit -m "feat(render): filter verbose_only findings in text output and format staging mounts"
```

---

### Task 6: Scenario Fixture Testing (`tests/scenarios.rs`)

**Files:**
- Modify: `tests/fixtures/docker-default/proc/self/mountinfo`
- Modify: `tests/fixtures/docker-privileged/proc/self/mountinfo`
- Modify: `tests/fixtures/rootless-podman/proc/self/mountinfo`
- Modify: `tests/scenarios.rs`

**Interfaces:**
- All 12 existing scenarios pass with authentic mountinfo fixtures.

- [ ] **Step 1: Add `/proc/self/mountinfo` to container fixtures**
Add realistic container `mountinfo` fixtures:
- `docker-default`: standard masked `/proc/kcore`, read-only `/proc/sys`, `noexec,nosuid,nodev` on `/dev/shm`.
- `docker-privileged`: unmasked `/proc/sys` writable, host root exposed, triggering `AMR-031` and `AMR-033`.
- `rootless-podman`: rootless user mount table.

- [ ] **Step 2: Write scenario assertions in `tests/scenarios.rs`**
Add assertions verifying:
- `docker-privileged`: `AMR-031` and `AMR-033` fire.
- `docker-default`: `AMR-031..033` do NOT fire.
- Update snapshot files if needed.

- [ ] **Step 3: Run scenario suite to verify it passes**
Run: `cargo test --test scenarios`
Expected: PASS.

- [ ] **Step 4: Commit**
```bash
git add tests/fixtures/ tests/scenarios.rs
git commit -m "test(scenarios): add mountinfo fixture scaffolding and scenario assertions"
```

---

### Task 7: Architectural Contracts & Documentation (`AGENTS.md`, `README.md`)

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/BACKLOG.md`

- [ ] **Step 1: Update `AGENTS.md`**
Document:
- `Rule.verbose_only` contract: how low-priority informational posture is silenced in default terminal mode to prevent fatigue while preserving 100% machine completeness.
- Mounts probe sequence and staging evaluation invariants.

- [ ] **Step 2: Update `README.md`**
Document:
- Rules `AMR-030` through `AMR-033` in the catalog.
- Explain staging mount identification and container mount isolation auditing.

- [ ] **Step 3: Run full quality gates**
Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: 100% PASS with 0 warnings.

- [ ] **Step 4: Commit**
```bash
git add AGENTS.md README.md docs/BACKLOG.md
git commit -m "docs: document mounts probe and AMR-030..033 in README and AGENTS.md"
```
