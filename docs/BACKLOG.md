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
