# amirustrained — Feature Backlog & Future Milestones

This document tracks prioritized future capability and audit milestones descoped from earlier releases.

---

## 1. Mounts & Filesystem Isolation Audit (Complete — Spec: 2026-10-06)
**Theme:** Filesystem sandboxing, payload staging ground identification, and mount flag hygiene via `/proc/self/mountinfo`.
- **Completed Scope:**
  - Full `/proc/self/mountinfo` parsing (mount options, in-tree root, propagation tags) with fallback to `/proc/mounts`.
  - Capability/DAC-driven staging detection: checks `rw`, lack of `noexec`, and $O(1)$ DAC writability (`fs.writable`).
  - Rules `AMR-030..033` (staging-mount-unhardened, sensitive-proc-sys-unmasked, shared-mount-propagation, host-filesystem-exposed).
  - `Rule.verbose_only` suppression mechanism for low-priority informational posture.
- **Follow-up Sub-Item: Recursive Filesystem Staging Hunter (`--hunt-staging [PATH]` / `--hunt-writable`)**
  - Opt-in CLI recursive directory traversal (`fd`-style tree crawler).
  - Bound strictly to a single filesystem (`-xdev` / `--one-file-system`).
  - Enforce bounded depth (max depth 4), directory count cap (1,000 dirs), and strict 5-second deadline.
  - Recursively identifies nested subdirectories/files writable by current credentials on non-`noexec` mounts.

---

## 2. Init Systems, Service Managers & Scheduled Tasks (Data-Attack Surfaces)
**Theme:** Converting arbitrary file write or local unprivileged primitives into execution via running daemons.
- **Target Analysis:**
  - **Init / Process Supervisor Detection:** Identify active init manager (PID 1 inspect: `systemd`, `init`, `s6-svscan`, `runit`, `supervisord`, `container-init`, etc.).
  - **Cron & Timer Daemons:**
    - Detect active cron daemons (`crond`, `cron`, `anacron`, `atd`) and systemd timer generators.
    - Check writability of `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs`, `/etc/anacrontab`.
  - **Systemd & Service Drop-in Injection:**
    - Check writability of `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/run/systemd/system/`.
    - Check writability of systemd generator directories (`/run/systemd/generator*`).
  - **Dynamic Linker & SUID/SGID Binary Hijacking Paths:**
    - Writable `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*`, `/etc/ld.so.preload`.
    - Path hygiene in standard search paths.
- **Finding Model:** Emit high/medium findings only when the corresponding daemon or service manager is actively running and the persistence/drop-in path is writable by the current identity.

---

## 3. Native Privilege & Sandbox Diff Subcommand (`amirustrained diff`)
**Theme:** Native, self-contained privilege elevation and boundary delta engine without requiring host utilities (`diff`, `patch`, `python`, `jq`) inside distroless or minimal containers.
- **Usage Models:**
  - `amirustrained diff <baseline.json>`: compares a previously saved JSON scan against the *live* current environment.
  - `amirustrained diff <run1.json> <run2.json>`: compares two recorded JSON/YAML runs offline.
- **Semantic Delta Scope:**
  - **Identity & Credential Delta:** `uid: 1000 -> 0`, `gid: 1000 -> 0`, `groups: +0(root), +10(wheel)`.
  - **Capabilities Delta:** `CapEff: 0x0000000000000000 -> 0x000001ffffffffff (+41 caps)`.
  - **Sandboxing Transition:** `no_new_privs: 1 -> 0`, `seccomp: 2 -> 0`, `lockdown: integrity -> none`.
  - **Namespace Delta:** detects escaped namespaces (e.g. `mnt:[4026531841] -> mnt:[4026531999]` host mount ns).
  - **Findings Delta:** `+ AMR-022 (HIGH)`, `- AMR-001`.
- **Output Formats:**
  - `--format text` (default): ANSI color-coded unified summary.
  - `--format markdown`: clean Markdown table ready for pentest reports and documentation.
  - `--format json`: machine-readable delta object for CI/CD regression gates.
