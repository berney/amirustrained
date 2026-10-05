# Design Specification: Mounts & Filesystem Isolation Audit

- **Date:** 2026-10-06
- **Author:** bdawg / amirustrained contributors
- **Status:** Draft / Approved by Human Partner
- **Target Release:** v0.3.0

---

## 1. Executive Summary

This specification introduces comprehensive auditing for **Linux mount topology, filesystem sandboxing, staging ground identification, and container isolation boundaries** via `/proc/self/mountinfo`. It also introduces a clean, standards-compliant **verbose-only finding suppression mechanism** (`Rule.verbose_only`) to eliminate terminal alert fatigue while preserving complete machine reporting.

### Key Additions
1. **Dedicated Mounts Probe (`src/probes/mounts.rs`):**
   - Full parser for `/proc/self/mountinfo` (with fallback to `/proc/mounts`).
   - Extracts all 10-11 standard fields, including mount options, in-tree root, and mount propagation tags (`shared:X`, `master:X`).
   - Generates structured facts: `mounts.all`, `mounts.staging`, `mounts.sensitive_unmasked`, `mounts.shared_propagation`, `mounts.host_leaks`.
2. **Path-Agnostic, Capability-Driven Staging Detection:**
   - Evaluates **actual attack viability**, not hardcoded paths like `/tmp` or `/dev/shm`.
   - Checks if any mount point across the entire filesystem is:
     1. Mounted `rw` (writable at the VFS layer).
     2. Lacks `noexec` (permits code execution).
     3. Is **actually writable by the current identity** via an immediate $O(1)$ DAC query (`fs.writable(&mount_point)`).
   - Flags missing hardening options: `noexec`, `nosuid`, `nodev`.
3. **Container-Aware Findings Model (`AMR-030` through `AMR-033`):**
   - `AMR-030: staging-mount-unhardened` (Medium/High in container, Info/verbose-only on bare host).
   - `AMR-031: sensitive-proc-sys-unmasked` (High, container-only).
   - `AMR-032: shared-mount-propagation` (Medium, container-only).
   - `AMR-033: host-filesystem-exposed` (Critical, container-only).
4. **`Rule.verbose_only` Filtering Mechanism:**
   - Enables low-priority informational findings to remain hidden in standard human terminal output, appearing only when `--verbose` is provided.
   - Standard output indicates hidden notices: `N findings (c0 h1 m1 l0 i0) [K verbose notices hidden — run with -v]`.
   - Machine formats (`json`, `yaml`, `sarif`) always export 100% of findings, strictly adhering to Tenet 2.
5. **Backlog Expansion:**
   - Records the opt-in recursive crawler (`--hunt-staging [PATH]` with `-xdev`) in `docs/BACKLOG.md`.

---

## 2. Architecture & Data Flow

```mermaid
graph TD
    CLI[CLI Flags: default vs -v vs --compact] --> Pipeline[Pipeline Engine]

    subgraph Probes
        MI[/proc/self/mountinfo<br/>or /proc/mounts] --> MountProbe[src/probes/mounts.rs<br/>MountEntry Parser<br/>DAC fs.writable Check]
    end

    MountProbe --> Facts[(Structured Facts Map)]
    Facts --> F1[mounts.staging<br/>rw + exec + writable by caller]
    Facts --> F2[mounts.sensitive_unmasked<br/>unmasked /proc/kcore, writable /proc/sys]
    Facts --> F3[mounts.shared_propagation<br/>shared:X or master:X in container]
    Facts --> F4[mounts.host_leaks<br/>root = / or /host exposed]

    F1 & F2 & F3 & F4 --> RulesEngine[src/model/rules.rs<br/>AMR-030..033 Evaluation<br/>Container-Aware Severity]

    RulesEngine --> Renderer[src/render/text.rs<br/>Verbose-Only Filtering<br/>Truncated Staging Output]
```

---

## 3. Data Model & Component Specifications

### 3.1 Mounts Probe (`src/probes/mounts.rs`)

- **Probe Registration:** `name: "mounts"`, `FACT_PROBE: "mounts"`. Registered in default pipeline in `src/pipeline.rs`.
- **Primary Source:** `/proc/self/mountinfo`.
- **Fallback Source:** `/proc/mounts` (populates standard fields; `optional_fields` left empty).
- **Data Structures:**

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingMount {
    pub mount_point: String,
    pub fstype: String,
    pub writable_by_caller: bool,
    pub missing_flags: Vec<String>, // "noexec", "nosuid", "nodev"
    pub options: Vec<String>,
}
```

### 3.2 Security Classification Algorithms

1. **Staging Grounds Filter:**
   - For every `entry` in parsed mount table:
     - Check `entry.mount_options.contains(&"rw".to_string())`.
     - Check `!entry.mount_options.contains(&"noexec".to_string())`.
     - Evaluate DAC writability: `let writable = fs.writable(&entry.mount_point);`.
     - Compute `missing_flags`: check presence of `noexec`, `nosuid`, `nodev`.
     - Emit `StagingMount` if `writable == true`.
2. **Sensitive Pseudo-Filesystem Masking Filter:**
   - Flag if `/proc/sys` is mounted `rw` (and not covered by read-only sub-mounts).
   - Flag if `/proc/kcore` exists and is not a masked dummy (`st_size > 0` and not on `/dev/null` or masked tmpfs).
   - Flag if `/proc/sysrq-trigger` is writable.
   - Flag if `/sys/firmware` is accessible.
3. **Mount Propagation Filter:**
   - Inspect `entry.optional_fields`. If any field starts with `shared:` or `master:` $\to$ flag in `mounts.shared_propagation`.
4. **Host Leaks Filter:**
   - Check if `entry.root == "/"` and `entry.mount_source` points to a host block device (e.g. `/dev/sda*`, `/dev/nvme*`) while running inside a container namespace.
   - Check if `entry.mount_point` matches `/host` or contains host system paths (`/var/run/docker.sock`, `/run/containerd/containerd.sock`).

---

## 4. Rule Engine & Findings Model

### 4.1 Finding Rules Catalog (`AMR-030` through `AMR-033`)

| Rule ID | Identifier | Default Severity | `container_only` | `verbose_only` | Trigger Invariants |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AMR-030`** | `staging-mount-unhardened` | **Medium** (Container) / **Info** (Bare Host) | `false` | `true` when Info (bare host) | Mount point is `rw`, lacks `noexec`, and is **writable by the current caller** (`writable_by_caller == true`). Severity elevates to **High** in a container if `nodev` is also missing with `CAP_MKNOD`. |
| **`AMR-031`** | `sensitive-proc-sys-unmasked` | **High** | `true` | `false` | `/proc/sys` is writable from container, or sensitive interfaces (`/proc/kcore`, `/proc/sysrq-trigger`, `/sys/firmware`) are unmasked. |
| **`AMR-032`** | `shared-mount-propagation` | **Medium** | `true` | `false` | Mount carries `shared:X` or `master:X` propagation inside a container namespace. |
| **`AMR-033`** | `host-filesystem-exposed` | **Critical** | `true` | `false` | Host root (`/`) or host system directory is mounted directly into the container. |

### 4.2 `Rule.verbose_only` Contract
- Added to `Rule` in `src/model/rule.rs`:
  ```rust
  pub struct Rule {
      ...
      pub verbose_only: bool,
  }
  ```
- Evaluated during rendering: if `rule.verbose_only` is true and `opts.verbose` is false, human text renderers omit the finding card and increment the `hidden_verbose_count`.

---

## 5. Output Formatting & UX

### 5.1 Terminal Text Rendering (`src/render/text.rs`)

1. **Staging Mounts Output:**
   - Displayed with path, filesystem type, and missing flags:
     ```text
     MEDIUM AMR-030 staging-mount-unhardened: Writable mount allows code execution and device creation
       - /data/scratch (tmpfs, rw): missing noexec, nosuid, nodev
       - /mnt/share (ext4, rw): missing noexec, nosuid
     ```
   - Truncated if >5 entries: `... (N more staging mounts — run with --verbose)`.

2. **Verbose-Only Summary Line:**
   - Standard output when notices are suppressed:
     ```text
     2 findings (c0 h1 m1 l0 i0) [3 verbose notices hidden — run with -v]
     ```
   - On `--verbose`: renders all finding cards and omits the bracketed hidden counter.

---

## 6. Backlog Expansion (`docs/BACKLOG.md`)

Update `docs/BACKLOG.md` to record the opt-in recursive crawler:
- **Feature:** `--hunt-staging [PATH]` (or `--hunt-writable [PATH]`)
- **Constraints:**
  - Bound to single filesystem (`-xdev` / `--one-file-system`).
  - Cap recursion at depth 4, 1,000 directories, and 5-second deadline.
  - Identifies nested directories writable by current credentials on non-`noexec` mounts.

---

## 7. Testing Strategy

1. **Unit Tests (`src/probes/mounts.rs`):**
   - Parse standard 11-field `/proc/self/mountinfo` with and without optional propagation fields.
   - Parse legacy 6-field `/proc/mounts`.
   - Test staging classification: verify non-writable mounts (`writable_by_caller == false`) do not fire.
   - Test sensitive unmasked paths and propagation parsing.
2. **Rule Engine Unit Tests (`src/model/rules.rs`):**
   - Test `AMR-030` container calibration: fires as Medium in container, Info with `verbose_only` on bare host.
   - Test `AMR-031..033` container gating: silenced on bare host fixtures.
3. **Render Tests (`src/render/text.rs`):**
   - Verify `verbose_only` findings are hidden by default and shown with `-v`.
   - Verify summary counts display hidden verbose count notation.
4. **Scenario Tests (`tests/scenarios.rs`):**
   - Add mountinfo fixtures to existing container scenarios (`docker-default`, `docker-privileged`, `rootless-podman`).
