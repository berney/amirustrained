# amirustrained — Feature Backlog & Future Milestones

This document tracks prioritized future capability and audit milestones descoped from earlier releases.

---

## 1. Mounts & Filesystem Isolation Audit (Next Priority)
**Theme:** Filesystem sandboxing, payload staging ground identification, and mount flag hygiene.
- **Data Source:** `/proc/self/mountinfo`.
- **Target Analysis:**
  - Enumerate writable (`rw`) mount points that lack `noexec` and `nosuid` (prime staging locations for binaries, exploits, or shared libraries).
  - Enumerate mounts with `dev` enabled in unprivileged or container contexts.
  - Detect unmasked or sensitive pseudo-filesystem mounts (e.g. unmasked `/proc/kcore`, `/proc/sched_debug`, `/sys/firmware`, `/sys/fs/cgroup` writable).
  - Detect shared mounts or host root leaks (`/`, `/host`, `/var/run`).
- **Output:** Flag writable+executable mounts, suspicious mount propagation (`shared`), and missing hardening flags on `tmpfs`/`/dev/shm`.

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
