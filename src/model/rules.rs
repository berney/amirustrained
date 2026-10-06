use super::rule::{Assess, Rule};
use super::{Fact, Finding, Report, RuntimeKind, Severity};

/// Rule registry; Tasks 20-21 append entries (append-only in id-space, spec §6:
/// insertion order is stable, ids need not sort numerically — see AMR-022).
pub static RULES: &[Rule] = &[
    Rule {
        id: "AMR-001",
        slug: "container-socket-exposed",
        severity: Severity::Critical,
        summary: "Container runtime API socket is reachable and writable",
        why: "The Docker/Podman API is served by the runtime daemon as root: whoever can write to \
              the socket can create a container that mounts the entire host filesystem with \
              full privileges — one API call from contained user to host root \
              (the docker.sock exposure class, cf. CVE-2019-5736-era runtime escapes).",
        remediation: "Remove the socket mount from the workload; if the API is genuinely needed, \
                      broker it through a least-privilege proxy (docker-socket-proxy) exposing \
                      only the required endpoints, and restrict which users may reach it.",
        references: &[
            "https://docs.docker.com/engine/security/socket-proxy/",
            "https://www.cyberark.com/resources/threat-research-blog/expose-docker-socket-by-accident",
        ],
        requires_root: false,
        // Socket exposure is reachable-from-host, not containment-gated: the
        // rule fires on a Host verdict by design, applicability never false.
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            let f = a.fact("sockets", "found")?;
            let hits: Vec<&serde_json::Value> = f
                .value
                .as_array()?
                .iter()
                .filter(|e| {
                    e["writable"] == serde_json::Value::Bool(true)
                        && matches!(e["kind"].as_str(), Some("docker") | Some("podman"))
                        // Peer not confirmed rootless: rootless sockets belong to
                        // AMR-022; an unknown peer is treated as root (fail loud).
                        && e["info"]["rootless"] != serde_json::Value::Bool(true)
                })
                .collect();
            if hits.is_empty() {
                return None;
            }
            // Evidence = the matching entries only, info/SecurityOptions intact.
            let mut ev = f.clone();
            ev.value = serde_json::Value::Array(hits.into_iter().cloned().collect());
            Some(vec![ev])
        },
    },
    Rule {
        id: "AMR-002",
        slug: "privileged-container",
        severity: Severity::High,
        summary: "Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement",
        why: "This is the `--privileged` signature: CAP_SYS_ADMIN plus no seccomp filter plus \
              nothing confining the task with mandatory access control — an explicit AppArmor \
              `unconfined` profile, or no AppArmor while SELinux is permissive or absent from \
              the active LSM stack. Mount filesystems, reach raw devices, drive cgroup \
              release_agent — the container boundary is nominal and kernel-interface exploits \
              run unopposed by every mitigation the runtime would provide.",
        remediation: "Drop `--privileged` and CAP_SYS_ADMIN; keep the runtime's default seccomp \
                      and AppArmor profiles and add back only the specific capabilities the \
                      workload needs.",
        references: &[
            "https://docs.docker.com/engine/containers/run/#admin-containers",
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
        ],
        requires_root: false,
        // Membership in the §6 container-gated set (Rule::container_only
        // mirrors the shared_kernel_containment() conjunct in check).
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            if !a.arr_has("capabilities", "effective", "cap_sys_admin")
                || !a.is("seccomp", "mode", "disabled")
            {
                return None;
            }
            // Evidence cites the fact that DECIDED the MAC leg (ReviewT19b-2):
            // the aa witness on the unconfined branch, lsm.selinux on the
            // permissive branch, lsm.list on the absent branch.
            let mac = mac_unconfining_fact(a)?;
            Some(vec![
                a.fact("capabilities", "effective")?.clone(),
                a.fact("seccomp", "mode")?.clone(),
                mac,
            ])
        },
    },
    Rule {
        id: "AMR-003",
        slug: "cap-sys-module",
        severity: Severity::High,
        summary: "CAP_SYS_MODULE in the effective capability set",
        why: "CAP_SYS_MODULE allows inserting kernel modules — arbitrary code executing in ring 0 \
              on the host kernel, where container isolation no longer applies at all. It is \
              almost never intended inside a container.",
        remediation: "Drop CAP_SYS_MODULE (`--cap-drop CAP_SYS_MODULE`) and consider host-side \
                      module signature enforcement (`module.sig_enforce=1`).",
        references: &[
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            "https://docs.kernel.org/admin-guide/module-signing.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            if !a.arr_has("capabilities", "effective", "cap_sys_module") {
                return None;
            }
            Some(vec![a.fact("capabilities", "effective")?.clone()])
        },
    },
    Rule {
        id: "AMR-004",
        slug: "host-pid-ns-ptraceable",
        severity: Severity::High,
        summary: "Host PID namespace with ptrace access to host processes",
        why: "Sharing the host PID namespace exposes every host process; with Yama \
              ptrace_scope 0 or CAP_SYS_PTRACE the holder can ptrace them — stealing \
              credentials and memory out of ssh-agents, browsers, and whatever root runs, \
              then escalating through those identities.",
        remediation: "Remove `pid=host` from the sandbox, keep `kernel.yama.ptrace_scope` >= 1, \
                      and drop CAP_SYS_PTRACE unless a debugger genuinely requires it.",
        references: &[
            "https://man7.org/linux/man-pages/man2/ptrace.2.html",
            "https://www.kernel.org/doc/html/latest/security/Yama.html",
        ],
        requires_root: true,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            // Host PID ns is tautological on a bare host: the finding is about a
            // contained process that shares it.
            if !a.shared_kernel_containment() {
                return None;
            }
            // Host PID ns: own pid-ns inode matches pid 1's (`isolated.pid == false`).
            let iso = a.fact("namespaces", "isolated")?;
            if iso.value.get("pid") != Some(&serde_json::Value::Bool(false)) {
                return None;
            }
            let caps = a.fact("capabilities", "effective");
            let scope = a.fact("capabilities", "ptraceScope");
            let has_cap = caps.is_some_and(|f| {
                f.value
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("cap_sys_ptrace")))
            });
            let scope_zero = scope.is_some_and(|f| f.value.as_i64() == Some(0));
            if !has_cap && !scope_zero {
                return None;
            }
            let mut ev = vec![iso.clone()];
            ev.extend(caps.cloned());
            ev.extend(scope.cloned());
            Some(ev)
        },
    },
    Rule {
        id: "AMR-005",
        slug: "seccomp-disabled-in-container",
        severity: Severity::Medium,
        summary: "Seccomp filter disabled inside a container",
        why: "With seccomp mode 0 every syscall the kernel implements is reachable from \
              container processes; the mitigation that normally removes the kernel entry \
              points behind container escapes (fsconfig/af_packet class, CVE-2022-0185 and \
              friends) is switched off.",
        remediation: "Start the container with the runtime's default seccomp profile \
                      (`--security-opt seccomp=runtime/default`) and extend a custom profile \
                      only for calls the workload genuinely needs.",
        references: &["https://docs.docker.com/engine/security/seccomp/"],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            let mode = a.fact("seccomp", "mode")?;
            (mode.value.as_str() == Some("disabled")).then_some(vec![mode.clone()])
        },
    },
    Rule {
        id: "AMR-006",
        slug: "apparmor-unconfined-in-container",
        severity: Severity::Medium,
        summary: "AppArmor mandatory access control not applied inside a container",
        why: "The runtime's default AppArmor profile blocks file and proc writes and \
              privileged operations that seccomp alone lets through; an unconfined profile — \
              or no AppArmor in an otherwise LSM-enforced kernel — drops the last \
              mandatory-access layer between the workload and the host kernel.",
        remediation: "Remove `--security-opt apparmor=unconfined` so the runtime-default profile \
                      applies; if AppArmor is absent while other LSMs are active, enable it on \
                      the host (`apparmor=1 security=apparmor`) instead of running unconfined.",
        references: &[
            "https://docs.docker.com/engine/security/apparmor/",
            "https://apparmor.net/",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            let aa = a.fact("lsm", "apparmor")?;
            if aa.value.get("profile").and_then(|p| p.as_str()) == Some("unconfined") {
                return Some(vec![aa.clone()]);
            }
            // Absent branch: no AppArmor profile at all (null fact) while the
            // kernel enforces other LSMs. A null fact with AppArmor *in* the
            // stack is an unreadable label, not absence — stay silent.
            if !aa.value.is_null() {
                return None;
            }
            let list = a.fact("lsm", "list")?;
            let lsms_active_without_apparmor = list.value.as_array().is_some_and(|l| {
                !l.is_empty() && !l.iter().any(|x| x.as_str() == Some("apparmor"))
            });
            if !lsms_active_without_apparmor {
                return None;
            }
            Some(vec![aa.clone(), list.clone()])
        },
    },
    // Appended in id-space (spec §6): rootless runtime peers are a separate,
    // uid-scoped detection — claiming host root for them overclaims (erratum).
    Rule {
        id: "AMR-022",
        slug: "rootless-socket-exposed",
        severity: Severity::High,
        summary: "Rootless container runtime API socket is reachable and writable",
        why: "A rootless runtime daemon serves this socket as an ordinary unprivileged host \
              user: whoever can write to it launches containers as that uid — read access to \
              its home directory, keys, cron, and any sudo grant it holds. That is a \
              container-to-host-user escape, not a host-root promise.",
        remediation: "Remove the socket mount from the workload and broker the API through a \
                      least-privilege proxy; treat the owning user account like any other \
                      interactive host account.",
        references: &[
            "https://docs.docker.com/engine/security/rootless/",
            "https://podman.io/docs/security",
        ],
        requires_root: false,
        // Ungated like AMR-001 (see its note): fires on a Host verdict too.
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            let f = a.fact("sockets", "found")?;
            let hits: Vec<&serde_json::Value> = f
                .value
                .as_array()?
                .iter()
                .filter(|e| {
                    e["writable"] == serde_json::Value::Bool(true)
                        && matches!(e["kind"].as_str(), Some("docker") | Some("podman"))
                        && e["info"]["rootless"] == serde_json::Value::Bool(true)
                })
                .collect();
            if hits.is_empty() {
                return None;
            }
            let mut ev = f.clone();
            ev.value = serde_json::Value::Array(hits.into_iter().cloned().collect());
            Some(vec![ev])
        },
    },
    // Task 20 batch: registry order is append-stable in insertion order, not
    // numeric — AMR-022 keeps its id-space-append slot above these (spec §6).
    Rule {
        id: "AMR-007",
        slug: "selinux-permissive-in-container",
        severity: Severity::Medium,
        summary: "SELinux context present while the policy runs permissive",
        why: "Permissive SELinux logs denials but enforces none of them: the task's \
              label is decorative, and every containment assumption that rests on \
              mandatory access control is void — on RHEL-family hosts SELinux is the \
              only active LSM, so permissive here means no MAC layer at all, while \
              the audit log quietly accumulates the attacks that were not stopped.",
        remediation: "Return SELinux to enforcing (`setenforce 1`, `enforcing=1` on the \
                      kernel command line) and resolve the logged denials through an \
                      `audit2allow` policy review instead of leaving the system \
                      permissive; per-domain permissive is a debugging tool, not a \
                      deployment mode.",
        references: &["https://www.kernel.org/doc/html/latest/security/selinux/index.html"],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            // No containment gate (spec condition verbatim): permissive MAC on a
            // bare host is a real hardening gap, not a tautology like AMR-003/004.
            let f = a.fact("lsm", "selinux")?;
            (f.value.get("mode").and_then(|m| m.as_str()) == Some("permissive"))
                .then(|| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-008",
        slug: "identity-uidmap",
        severity: Severity::Medium,
        summary: "User namespace keeps no identity isolation: uid_map is the full identity mapping",
        why: "A single `0 0 4294967295` line maps every container uid onto the same \
              host uid: uid 0 inside *is* uid 0 outside, so DAC checks agree with the \
              host — a file this process may write by ownership, the host owner can \
              write back. The namespace buys no identity isolation; it only satisfies \
              the runtime's userns bookkeeping (spec §6: DAC root == host root).",
        remediation: "Use a real user namespace: rootless runtime mode (podman) or \
                      `--userns-remap` (docker) places container uid 0 on an \
                      unprivileged subordinate range instead of the identity mapping.",
        references: &[
            "https://man7.org/linux/man-pages/man7/id_mappings.7.html",
            "https://man7.org/linux/man-pages/man7/user_namespaces.7.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            let f = a.fact("uidmap", "uidMap")?;
            // Full-array equality: exactly one 0→0 full-range row is the
            // no-userns-isolation layout; extra/partial rows are not.
            let identity = serde_json::json!([{"container": 0, "host": 0, "range": u32::MAX}]);
            (f.value == identity).then(|| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-009",
        slug: "cgroup-v1-container",
        severity: Severity::Low,
        summary: "Container runs on the legacy cgroup v1 hierarchy",
        why: "cgroup v1 carries the `release_agent`/`notify_on_release` host-exec \
              interfaces behind the classic container escapes (CVE-2022-0492 and \
              family): a task that can reach or remount a writable v1 hierarchy while \
              holding CAP_SYS_ADMIN runs helpers on the host. v1 also lacks the \
              userns-aware delegation that makes v2 safe to hand container slices over.",
        remediation: "Boot/migrate the host to the unified hierarchy (cgroup v2 is the \
                      default on every current distribution); where v1 is unavoidable, \
                      mount the container's cgroupfs read-only.",
        references: &[
            "https://man7.org/linux/man-pages/man7/cgroups.7.html",
            "https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            let f = a.fact("cgroup", "version")?;
            (f.value.as_i64() == Some(1)).then(|| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-010",
        slug: "no-pids-limit",
        severity: Severity::Low,
        summary: "pids controller present but unlimited (pids.max = max)",
        why: "The pids controller is delegated to the container's scope yet capped at \
              `max` — the kernel's spelling of unlimited: one contained fork bomb \
              exhausts host PIDs and task_struct memory and wedges every other \
              workload, the runtime itself included. The mitigation is present and \
              switched off, not missing.",
        remediation: "Set a per-container pid limit (`--pids-limit` on docker/podman, \
                      or write `pids.max` in the container's scope) so a runaway stays \
                      inside its own slice.",
        references: &[
            "https://man7.org/linux/man-pages/man7/cgroups.7.html",
            "https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            if !a.arr_has("cgroup", "controllers", "pids") {
                return None;
            }
            let limits = a.fact("cgroup", "limits")?;
            if limits.value.get("pids").and_then(|p| p.as_str()) != Some("max") {
                return None;
            }
            Some(vec![
                a.fact("cgroup", "controllers")?.clone(),
                limits.clone(),
            ])
        },
    },
    Rule {
        id: "AMR-011",
        slug: "gid-map-includes-0",
        severity: Severity::Medium,
        summary: "gid_map maps host gid 0 while setgroups is not denied",
        why: "A gid_map line reaching host gid 0 hands the namespace root-group \
              membership, and while `setgroups` reads `allow` any process can re-add \
              groups — including gid 0 — so dropping them is not durable: whatever \
              host root-group membership unlocks (group-writable root files, cron \
              directories) is reachable again on a whim. Rootless runtimes write \
              `deny` when they create the namespace for exactly this reason.",
        remediation: "Write `deny` to the namespace's `setgroups` file (the rootless \
                      runtime default) and keep host gid 0 out of the gid_map — map \
                      only subordinate gid ranges.",
        references: &[
            "https://man7.org/linux/man-pages/man2/setgroups.2.html",
            "https://man7.org/linux/man-pages/man7/id_mappings.7.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            // Containment gate (spec §6 erratum, live host scan 2026-10-01):
            // init-ns gid_map is trivially `0 0 4294967295` with setgroups
            // allow — a constant on a bare host, same reasoning as the
            // AMR-003/004 gates.
            if !a.shared_kernel_containment() {
                return None;
            }
            let gid = a.fact("uidmap", "gidMap")?;
            let maps_host_root = gid.value.as_array().is_some_and(|rows| {
                rows.iter()
                    .any(|r| r.get("host").and_then(|h| h.as_i64()) == Some(0))
            });
            if !maps_host_root {
                return None;
            }
            let setgroups = a.fact("uidmap", "setgroups")?;
            (setgroups.value.as_str() == Some("allow"))
                .then(|| vec![gid.clone(), setgroups.clone()])
        },
    },
    Rule {
        id: "AMR-012",
        slug: "landlock-abi-available",
        severity: Severity::Info,
        summary: "Landlock LSM available in this kernel (ABI version reported)",
        why: "The landlock(2) ruleset syscall answers with an ABI version, so the \
              kernel offers in-process filesystem sandboxing that any workload here \
              could use and nothing at kernel level stops the runtime from adopting \
              it. Per-process Landlock domain state is not observable through \
              procfs: this finding claims presence only, never disuse.",
        remediation: "Informational — no action required. To confine a workload \
                      proactively, apply a Landlock ruleset to it (systemd \
                      `Landlock=` settings, or a landlock-aware launcher).",
        references: &[
            "https://man7.org/linux/man-pages/man7/landlock.7.html",
            "https://www.kernel.org/doc/html/latest/userspace-api/landlock.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            a.fact("lsm", "landlockAbi")
                .filter(|f| f.value.as_i64().is_some_and(|v| v >= 1))
                .map(|f| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-013",
        slug: "virtualized",
        severity: Severity::Info,
        summary: "Running on a hypervisor (VMM boundary detected)",
        why: "CPUID reports a hypervisor interface: this environment sits inside a \
              virtual machine. Context, not a defect — the escape path out of a \
              guest crosses the VMM attack surface, a different exploit class under \
              a different patch authority than the kernel or container boundary, so \
              isolation and hardening claims should be scoped accordingly.",
        remediation: "Informational — no action required. Where the threat model \
                      cares about the boundary, assess the hypervisor host separately \
                      from this guest.",
        references: &["https://www.kernel.org/doc/html/latest/virt/kvm/index.html"],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            a.fact("vmm", "hypervisor")
                .filter(|f| f.value.get("present") == Some(&serde_json::Value::Bool(true)))
                .map(|f| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-014",
        slug: "strong-isolation-runtime",
        severity: Severity::Info,
        summary: "Running inside a strong-isolation runtime (firecracker, gVisor, or kata)",
        why: "Positive note: the verdict names a hypervisor- or kernel-separated \
              runtime — an escape must cross a dedicated VMM (firecracker), a \
              Sentry kernel (gVisor), or an agent-managed guest (kata) instead of \
              the host kernel directly, which shrinks the in-guest kernel attack \
              surface to a fraction of the container-boundary class. Audit \
              priorities shift from runc-style escapes to the VMM layer.",
        remediation: "Informational — no action required. Keep the VMM/guest kernel \
                      pinned and patched: it is now the dominant boundary.",
        references: &[
            "https://firecracker-microvm.github.io/",
            "https://gvisor.dev/docs/",
            "https://katacontainers.io/",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            // Typed RuntimeKind match on the fusion verdict (not a string):
            // spec row 210 names the three strong-isolation variants.
            let v = a.report.verdict.as_ref()?;
            matches!(
                v.runtime,
                RuntimeKind::Firecracker | RuntimeKind::Gvisor | RuntimeKind::Kata
            )
            .then(|| verdict_fact(a))?
        },
    },
    Rule {
        id: "AMR-015",
        slug: "unrecognized-runtime",
        severity: Severity::Info,
        summary: "Runtime verdict is low-confidence: identify the environment manually",
        why: "No containment candidate scored above the fingerprint threshold, so \
              the reported runtime is a lead, not a fact (spec row 211). Every \
              isolation claim reasoned from the wrong containment — trusting or \
              dismissing a container boundary that may not exist — is unsound; \
              confirm the environment out-of-band (orchestrator config, scan from \
              the host side) before relying on it.",
        remediation: "Informational — verify the runtime out-of-band, then re-scan; \
                      the fingerprint and its alternatives stay in the report for \
                      re-derivation.",
        references: &[],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            // Plan amendment: Verdict::confidence is the string ladder
            // high|medium|low — match "low" exactly, never a numeric < 0.5.
            let v = a.report.verdict.as_ref()?;
            (v.confidence == "low").then(|| verdict_fact(a))?
        },
    },
    Rule {
        id: "AMR-016",
        slug: "cap-sys-admin-no-combo",
        severity: Severity::Medium,
        summary: "CAP_SYS_ADMIN held while some runtime restraints remain active",
        why: "The weaker sibling of AMR-002 (spec row 212): CAP_SYS_ADMIN mounts \
              filesystems and drives the cgroup release_agent interfaces, but the \
              full privileged signature is not met — a seccomp filter still filters \
              syscalls, or AppArmor/SELinux still confines the task. One convenience \
              flip (seccomp=unconfined, apparmor=unconfined) completes the AMR-002 \
              combo, so the partial grant is worth removing before it is widened.",
        remediation: "Drop CAP_SYS_ADMIN (`--cap-drop CAP_SYS_ADMIN`) and hand back \
                      only the specific capability the workload needs, instead of \
                      removing the restraints that still hold.",
        references: &[
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            "https://docs.docker.com/engine/containers/run/#admin-containers",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            if !a.arr_has("capabilities", "effective", "cap_sys_admin") {
                return None;
            }
            // Exact complement of AMR-002's AMENDED combo (seccomp mode 0 ∧
            // MAC-unconfining per erratum ReviewT19 F3 as amended 2026-10-01 —
            // an aa `complain` profile counts as unconfining too, so
            // aa-complain+seccomp=0 is likewise 002's territory — NOT the stale
            // AppArmor-only sketch): privileged-on-SELinux-permissive stays
            // 002's territory, quiet here.
            let amr002_combo =
                a.is("seccomp", "mode", "disabled") && mac_unconfining_fact(a).is_some();
            if amr002_combo {
                return None;
            }
            // Evidence: the grant plus whichever restraints are HOLDING. Unknown
            // — absent, null, or seccomp `unknown` — is not a restraint, so with
            // none observable the rule stays silent instead of asserting one it
            // cannot cite (fail closed, as AMR-002's null-list branch does).
            let restraints: Vec<Fact> = [
                a.fact("seccomp", "mode")
                    .filter(|f| matches!(f.value.as_str(), Some("filter") | Some("strict"))),
                // ReviewT21b: complain-mode profiles log only and confine
                // nothing — only `enforce` holds. The probe always emits a mode
                // ("" for an unconfined task, probes/lsm.rs), so requiring the
                // exact string also subsumes the null-value and unconfined legs.
                a.fact("lsm", "apparmor")
                    .filter(|f| f.value.get("mode").and_then(|m| m.as_str()) == Some("enforce")),
                a.fact("lsm", "selinux")
                    .filter(|f| f.value.get("mode").and_then(|m| m.as_str()) == Some("enforcing")),
            ]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
            if restraints.is_empty() {
                return None;
            }
            let mut ev = vec![a.fact("capabilities", "effective")?.clone()];
            ev.extend(restraints);
            Some(ev)
        },
    },
    Rule {
        id: "AMR-017",
        slug: "cgroupns-host",
        severity: Severity::Info,
        summary: "Container shares the host cgroup namespace",
        why: "The container's cgroup-ns inode equals pid 1's: contained processes \
              enumerate the whole host cgroup tree — every neighbouring tenant's \
              scope names and limit files — instead of only their own subtree: \
              information about the host's workload layout, and a mapped target \
              for limit- or notification-oriented attacks. Private cgroupns is the \
              modern runtime default, so this is explicit configuration or an old \
              runtime. On a bare host the equality is the init-ns constant \
              (spec row 213): gated.",
        remediation: "Start the container with `--cgroupns=private` (docker >= 20.10 \
                      default, podman default) so it sees only its own cgroup subtree.",
        references: &[
            "https://docs.docker.com/engine/reference/run/",
            "https://man7.org/linux/man-pages/man7/cgroups.7.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            // Degraded pid-1 comparison leaves the fact null: unknown is not equal.
            a.fact("namespaces", "cgroupNsSameAsInit")
                .filter(|f| f.value == serde_json::Value::Bool(true))
                .map(|f| vec![f.clone()])
        },
    },
    Rule {
        id: "AMR-018",
        slug: "no-new-privs-unset",
        severity: Severity::Low,
        summary: "NoNewPrivs unset: execve can still gain privileges",
        why: "With NoNewPrivs 0 an execve inside the container may gain privileges \
              via setuid bits or file capabilities: a suid-root helper inside the \
              image steps contained uid → container-root, and whatever the \
              container's (possibly broad) capability set then reaches becomes \
              reachable. The flag is a one-way kernel lock on privilege \
              acquisition for the whole process lifecycle. Every ordinary process \
              on a bare host sits at 0 — a constant, not a finding there \
              (spec row 214): gated.",
        remediation: "Run the workload with `--security-opt no-new-privileges` \
                      (docker/podman) or `NoNewPrivileges=yes` (systemd) unless it \
                      genuinely needs setuid transitions.",
        references: &[
            "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
            "https://man7.org/linux/man-pages/man2/prctl.2.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            a.fact("capabilities", "noNewPrivs")
                .filter(|f| f.value.as_i64() == Some(0))
                .map(|f| vec![f.clone()])
        },
    },
    // Task 28 batch: the eBPF exposure pair. AMR-019 joins the shared-kernel
    // container gate (spec §6 row + erratum 2026-10-01: guest bpf() is
    // guest-kernel-local under VM verdicts); AMR-020 stays ungated per its §6
    // row — a held capability is exposure wherever the process sits.
    Rule {
        id: "AMR-019",
        slug: "bpf-unpriv-open",
        severity: Severity::Medium,
        summary: "Inside a shared-kernel container and unprivileged_bpf_disabled \
                  is 0 (or absent pre-5.13): any local uid can reach bpf() from a \
                  weak foothold",
        why: "The knob decides whether callers without CAP_BPF/CAP_PERFMON may \
              call bpf(): at 0 — or on legacy kernels that predate the knob, \
              where nothing else gates the syscall — any local uid, including \
              foothold uids that hold none of the container's capabilities, may \
              load eBPF programs into the shared host kernel. The verifier and \
              JIT have historically been a rich LPE bug class, so this is a \
              kernel-attack-surface promise from the weakest position inside \
              the containment. Gated per the §6 container-gate erratum \
              (2026-10-01): on a bare host the state is a machine-wide sysctl \
              an admin can read in one line, and under VM-family verdicts the \
              guest bpf() hits the GUEST kernel — no host surface opens, the \
              same reason the AMR-004-class host rules are exempt there.",
        remediation: "Set `kernel.unprivileged_bpf_disabled = 1` (changeable) \
                      or `2` (immutable until reboot) via a host sysctl drop \
                      (e.g. /etc/sysctl.d/90-bpf.conf); the container image \
                      cannot set it — this is a host-level knob.",
        references: &[
            "https://man7.org/linux/man-pages/man2/bpf.2.html",
            "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            let r = a.fact("ebpf", "reachability")?;
            if r.value
                .get("unprivilegedOpen")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                return None;
            }
            // The deciding computed fact, plus the raw knob posture it was
            // derived from (present whenever the probe ran; optional leg).
            let mut evidence = vec![r.clone()];
            evidence.extend(a.fact("ebpf", "knobs").cloned());
            Some(evidence)
        },
    },
    Rule {
        id: "AMR-020",
        slug: "cap-bpf-or-perfmon",
        severity: Severity::Low,
        summary: "CapEff includes CAP_BPF or CAP_PERFMON: program load / map \
                  read possible without full root",
        why: "CAP_BPF alone grants eBPF program load and map creation; \
              CAP_PERFMON (5.8+) grants map read access and perf-attached \
              probing — either short-circuits the full-root assumption, and \
              together they are nearly the whole BPF surface without \
              CAP_SYS_ADMIN or uid 0. Loaded programs execute with kernel \
              privileges the seccomp/caps posture otherwise confines \
              everything else to. Ungated per spec §6: a capability this \
              process holds is exposure wherever it sits (a trivially full \
              root CapEff satisfies it too — severity low is calibrated to \
              that noise floor).",
        remediation: "Drop CAP_BPF/CAP_PERFMON unless the workload genuinely \
                      runs eBPF: `--cap-drop ALL` then re-add what is needed \
                      (docker/podman), `securityContext.capabilities.drop` \
                      (k8s), or `CapabilityBoundingSet=` (systemd).",
        references: &[
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            "https://man7.org/linux/man-pages/man2/bpf.2.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.arr_has("capabilities", "effective", "cap_bpf")
                && !a.arr_has("capabilities", "effective", "cap_perfmon")
            {
                return None;
            }
            a.fact("capabilities", "effective")
                .cloned()
                .map(|f| vec![f])
        },
    },
    // Task 29: the confirmed-open kernel surface. Opt-in evidence only —
    // the `ebpf.load` fact exists exactly when `--probe-ebpf` ran, and only
    // an Ok-status `status == "ok"` counts (Report::fact filters degraded,
    // so artifact-missing/parse-failed can never satisfy the check).
    Rule {
        id: "AMR-021",
        slug: "ebpf-load-succeeded",
        severity: Severity::High,
        summary: "--probe-ebpf only: trivial program load succeeded in a \
                  shared-kernel container — bpf() reachable past \
                  seccomp/LSM/cap drops; kernel attack surface confirmed open",
        why: "This is not a knob reading: the process actually loaded a \
              program into the kernel via bpf(BPF_PROG_LOAD). Every gate a \
              shared-kernel containment is supposed to provide — seccomp \
              syscall filtering, capability drops, LSM, the \
              unprivileged_bpf_disabled knob — demonstrably failed to stop \
              this caller, and loaded code runs in kernel context, subject \
              only to the verifier. Gated per the §6 container-gate erratum \
              (2026-10-01): on a bare host load ability is ordinary root \
              behavior the admin granted, and under VM-family verdicts the \
              program lands in the GUEST kernel — the high severity is \
              specifically about the SHARED host kernel being reachable \
              from inside a containment.",
        remediation: "From the containment side: drop CAP_BPF and \
                      CAP_SYS_ADMIN (`--cap-drop ALL` + re-add), keep \
                      seccomp on the default profile (it blocks bpf()), \
                      confine with LSM. From the host side: set \
                      `kernel.unprivileged_bpf_disabled = 2` (immutable \
                      until reboot) and audit why the container's gates \
                      allowed the call at all — this finding means they \
                      did not.",
        references: &[
            "https://man7.org/linux/man-pages/man2/bpf.2.html",
            "https://docs.kernel.org/bpf/verifier/index.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: |a| {
            if !a.shared_kernel_containment() {
                return None;
            }
            a.fact("ebpf", "load")
                .filter(|f| f.value.get("status").and_then(serde_json::Value::as_str) == Some("ok"))
                .cloned()
                .map(|f| vec![f])
        },
    },
    Rule {
        id: "AMR-023",
        slug: "kernel-module-loading-permitted",
        severity: Severity::High,
        summary: "Kernel module loading is permitted: ring 0 execution accessible via finit_module/init_module or unconstrained modules",
        why: "Inserting a kernel module loads arbitrary code directly into ring 0 on the host kernel, bypassing all user-mode isolation, namespaces, seccomp, and LSM protections. Holding CAP_SYS_MODULE with modules enabled allows full host takeover.",
        remediation: "Disable kernel module loading via sysctl (kernel.modules_disabled = 1), drop CAP_SYS_MODULE from effective and bounding capability sets, or enforce kernel module signature verification (module.sig_enforce = 1).",
        references: &[
            "https://docs.kernel.org/admin-guide/module-signing.html",
            "https://man7.org/linux/man-pages/man2/finit_module.2.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr023,
    },
    Rule {
        id: "AMR-024",
        slug: "kexec-kernel-replacement-permitted",
        severity: Severity::High,
        summary: "Kexec kernel replacement is permitted: new kernel image can be loaded and booted directly into ring 0",
        why: "Kexec allows rebooting into a new arbitrary kernel without going through BIOS/firmware/bootloader verification. Holding CAP_SYS_BOOT with kexec enabled and kernel lockdown disabled allows replacing the running kernel and gaining arbitrary ring 0 execution.",
        remediation: "Disable kexec via sysctl (kernel.kexec_load_disabled = 1), enable kernel lockdown (lockdown=integrity or lockdown=confidentiality), or drop CAP_SYS_BOOT.",
        references: &[
            "https://man7.org/linux/man-pages/man2/kexec_load.2.html",
            "https://docs.kernel.org/admin-guide/kernel-parameters.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr024,
    },
    Rule {
        id: "AMR-025",
        slug: "raw-memory-access-permitted",
        severity: Severity::Critical,
        summary: "Raw physical memory or port I/O access is permitted via /dev/mem, /dev/kmem, or iopl",
        why: "Direct access to physical memory (/dev/mem, /dev/kmem) or hardware I/O ports (iopl) allows reading and writing kernel memory, page tables, and hardware registers directly, completely subverting kernel protections and privilege separation.",
        remediation: "Ensure /dev/mem and /dev/kmem device nodes are not present or accessible in the filesystem, enable kernel lockdown (lockdown=integrity or lockdown=confidentiality), and drop CAP_SYS_RAWIO.",
        references: &[
            "https://man7.org/linux/man-pages/man4/mem.4.html",
            "https://man7.org/linux/man-pages/man2/iopl.2.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr025,
    },
    Rule {
        id: "AMR-026",
        slug: "user-mode-helper-writable",
        severity: Severity::High,
        summary: "Kernel user-mode helper path (core_pattern or modprobe) is writable",
        why: "Kernel user-mode helper paths (/proc/sys/kernel/core_pattern and /proc/sys/kernel/modprobe) are executed directly by the host kernel in the root namespace as root. Writing an arbitrary command or executable path achieves instant unconfined host code execution.",
        remediation: "Mount /proc/sys read-only, mask /proc/sys/kernel/core_pattern and /proc/sys/kernel/modprobe, or use filesystem protections to prevent write access.",
        references: &[
            "https://man7.org/linux/man-pages/man5/core.5.html",
            "https://docs.kernel.org/admin-guide/sysctl/kernel.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr026,
    },
    Rule {
        id: "AMR-027",
        slug: "acpi-table-injection-writable",
        severity: Severity::High,
        summary: "ACPI table customization interface (/sys/kernel/config/acpi/table) is writable",
        why: "A writable ACPI table customization interface allows dynamically injecting custom ACPI DSDT/SSDT tables (CONFIG_ACPI_CUSTOM_METHOD). Custom AML byte-code executed by the kernel's ACPI interpreter can access arbitrary physical memory and I/O ports.",
        remediation: "Ensure configfs is not mounted or writable inside unprivileged environments, and disable CONFIG_ACPI_CUSTOM_METHOD in the kernel configuration.",
        references: &[
            "https://docs.kernel.org/admin-guide/acpi/initrd_table_override.html",
            "https://www.kernel.org/doc/Documentation/acpi/method-customizing.txt",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr027,
    },
    Rule {
        id: "AMR-028",
        slug: "kexec-module-lockdown-bypass",
        severity: Severity::High,
        summary: "Kexec kernel replacement is permitted while kernel module loading is blocked (lockdown bypass)",
        why: "Direct kernel module loading is blocked, but kexec replacement remains permitted. An attacker can bypass the restriction on loading unsigned code or modules into the running kernel by replacing the entire kernel image with an unconstrained one via kexec.",
        remediation: "Disable kexec via sysctl (kernel.kexec_load_disabled = 1), enable kernel lockdown (lockdown=integrity or lockdown=confidentiality), or drop CAP_SYS_BOOT.",
        references: &[
            "https://man7.org/linux/man-pages/man2/kexec_load.2.html",
            "https://docs.kernel.org/admin-guide/module-signing.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr028,
    },
    Rule {
        id: "AMR-029",
        slug: "kernel-execution-probe-report",
        severity: Severity::Info,
        summary: "Active kernel execution probe confirmed all tested ring 0 pathways are closed or restricted",
        why: "An active kernel execution probe (--probe-kernel-execution) ran non-destructive boundary syscall tests and confirmed that kernel module loading (finit_module, init_module), kexec replacement (kexec_load, kexec_file_load), and port I/O (iopl) are denied or restricted.",
        remediation: "No action required: kernel execution attack surface is actively verified closed.",
        references: &[
            "https://man7.org/linux/man-pages/man2/finit_module.2.html",
            "https://man7.org/linux/man-pages/man2/kexec_load.2.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: check_amr029,
    },
    Rule {
        id: "AMR-030",
        slug: "staging-mount-unhardened",
        severity: Severity::Medium,
        summary: "Writable mount allows code execution and device creation",
        why: "A mount point is mounted read-write without noexec, allowing arbitrary binary execution. If nodev is also missing and the process holds CAP_MKNOD, device nodes can be created to bypass device isolation.",
        remediation: "Mount temporary and staging directories with noexec, nosuid, and nodev options.",
        references: &[
            "https://docs.kernel.org/filesystems/sharedsubtree.html",
            "https://man7.org/linux/man-pages/man2/mount.2.html",
        ],
        requires_root: false,
        container_only: false,
        verbose_only: true,
        severity_of: Some(severity_amr030),
        check: check_amr030,
    },
    Rule {
        id: "AMR-031",
        slug: "sensitive-proc-sys-unmasked",
        severity: Severity::High,
        summary: "Sensitive /proc or /sys pseudo-filesystem paths are unmasked or writable inside container",
        why: "Container isolation requires masking sensitive /proc and /sys interfaces (e.g. /proc/sys, /proc/kcore, /proc/sysrq-trigger, /sys/firmware). Writable sysctl knobs or unmasked raw memory interfaces allow kernel modification or host compromise.",
        remediation: "Ensure the container runtime masks /proc/kcore, /proc/sysrq-trigger, and /sys/firmware, and mounts /proc/sys read-only.",
        references: &[
            "https://docs.docker.com/engine/security/#masked-paths-in-default-runtime",
            "https://man7.org/linux/man-pages/man5/proc.5.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: check_amr031,
    },
    Rule {
        id: "AMR-032",
        slug: "shared-mount-propagation",
        severity: Severity::Medium,
        summary: "Container mount carries shared or master mount propagation flags",
        why: "Mounts with shared or master propagation can leak mount and unmount events across namespace boundaries, potentially affecting host filesystems or allowing denial-of-service.",
        remediation: "Configure container mounts with private or slave propagation flags (e.g., rprivate).",
        references: &[
            "https://docs.kernel.org/filesystems/sharedsubtree.html",
            "https://man7.org/linux/man-pages/man7/mount_namespaces.7.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: check_amr032,
    },
    Rule {
        id: "AMR-033",
        slug: "host-filesystem-exposed",
        severity: Severity::Critical,
        summary: "Host root filesystem or system control directories are mounted directly inside container",
        why: "Mounting the host root (/) or host directories directly inside a container completely breaks filesystem isolation, allowing container processes to access or modify host system binaries, configurations, and sensitive credentials.",
        remediation: "Do not bind-mount host root (/) or host system directories into containers. Use scoped volume mounts.",
        references: &[
            "https://docs.docker.com/engine/security/#general-guidelines-for-container-security",
            "https://man7.org/linux/man-pages/man7/mount_namespaces.7.html",
        ],
        requires_root: false,
        container_only: true,
        verbose_only: false,
        severity_of: None,
        check: check_amr033,
    },
];

pub fn evaluate_all(report: &Report, privileged: bool) -> Vec<Finding> {
    RULES
        .iter()
        .filter_map(|r| r.evaluate(report, privileged))
        .collect()
}

/// Spec §6 erratum F3: MAC is not confining the task when AppArmor explicitly reports
/// `unconfined` or a `complain`-mode profile (log-only, confines nothing — erratum
/// 2026-10-01), or when no AppArmor fact applies (null value) and SELinux is permissive
/// or absent from the active LSM list. An `enforcing` SELinux with AppArmor absent keeps
/// the rule silent — fail closed on ambiguous stacks (null list) and on confining aa
/// modes. Returns the fact that DECIDED the leg (ReviewT19b-2): the aa witness on the
/// unconfined and complain branches, `lsm.selinux` on the permissive branch, `lsm.list`
/// on the absent branch — AMR-002 cites it as evidence; AMR-016 takes the complement
/// (`.is_none()`).
fn mac_unconfining_fact(a: &Assess) -> Option<Fact> {
    let aa = a.fact("lsm", "apparmor")?;
    if let Some(profile) = aa.value.get("profile").and_then(|p| p.as_str()) {
        // Erratum 2026-10-01 (ReviewT2324b DELTA-1): a `complain`-mode profile logs
        // denials only and confines nothing, so it is MAC-unconfining like an
        // explicit `unconfined` profile. Fail closed on every other mode: `enforce`
        // and `kill` confine, and a missing/empty mode on a confined profile proves
        // nothing (ReviewT21b's exact-string discipline).
        return (profile == "unconfined"
            || aa.value.get("mode").and_then(|m| m.as_str()) == Some("complain"))
        .then(|| aa.clone());
    }
    if !aa.value.is_null() {
        return None;
    }
    if let Some(sel) = a
        .fact("lsm", "selinux")
        .filter(|f| f.value.get("mode").and_then(|m| m.as_str()) == Some("permissive"))
    {
        return Some(sel.clone());
    }
    a.fact("lsm", "list")
        .filter(|f| {
            f.value
                .as_array()
                .is_some_and(|l| !l.iter().any(|x| x.as_str() == Some("selinux")))
        })
        .cloned()
}

/// AMR-014/015 findings must cite evidence like every other rule (spec §6); their
/// subject is the fusion verdict, which the `runtime` probe already reports as the
/// Ok fact `runtime.verdict`. Cite that fact rather than re-wrapping the verdict: a
/// hand-built clone would share its (probe, key) identity while disagreeing with it
/// on `source` and value shape, and `pipeline.rs` derives `report.verdict` from this
/// very fact, so it is present whenever the verdict is.
fn verdict_fact(a: &Assess) -> Option<Vec<Fact>> {
    a.fact("runtime", "verdict").cloned().map(|f| vec![f])
}

fn check_amr023(a: &Assess) -> Option<Vec<Fact>> {
    let has_cap_eff = a.arr_has("capabilities", "effective", "cap_sys_module");
    let has_cap_bnd = a.arr_has("capabilities", "bounding", "cap_sys_module");
    if !has_cap_eff && !has_cap_bnd {
        return None;
    }

    if a.fact("kernel.surface", "modules_disabled")
        .and_then(|f| f.value.as_bool())
        == Some(true)
    {
        return None;
    }

    let exec_finit = a.fact("kernel.exec", "finit_module");
    let exec_init = a.fact("kernel.exec", "init_module");
    let finit_permitted = exec_finit
        .and_then(|f| f.value.get("status"))
        .and_then(|s| s.as_str())
        == Some("permitted");
    let init_permitted = exec_init
        .and_then(|f| f.value.get("status"))
        .and_then(|s| s.as_str())
        == Some("permitted");

    let has_exec = exec_finit.is_some() || exec_init.is_some();
    let config_opts = a.fact("kernel.config", "options");
    let config_modules = config_opts
        .and_then(|f| f.value.get("CONFIG_MODULES"))
        .and_then(|v| v.as_str())
        == Some("y");
    let config_sig_force = config_opts
        .and_then(|f| f.value.get("CONFIG_MODULE_SIG_FORCE"))
        .and_then(|v| v.as_str())
        == Some("y");
    let config_permitted = config_modules && !config_sig_force;

    let permitted = if has_exec {
        finit_permitted || init_permitted
    } else {
        config_permitted
    };

    if !permitted {
        return None;
    }

    let mut ev = Vec::new();
    if has_cap_eff {
        ev.extend(a.fact("capabilities", "effective").cloned());
    } else if has_cap_bnd {
        ev.extend(a.fact("capabilities", "bounding").cloned());
    }
    ev.extend(a.fact("kernel.surface", "modules_disabled").cloned());
    if finit_permitted {
        ev.extend(exec_finit.cloned());
    }
    if init_permitted {
        ev.extend(exec_init.cloned());
    }
    if !has_exec && config_permitted {
        ev.extend(config_opts.cloned());
    }
    Some(ev)
}

fn check_amr024(a: &Assess) -> Option<Vec<Fact>> {
    if !a.arr_has("capabilities", "effective", "cap_sys_boot") {
        return None;
    }

    if a.fact("kernel.surface", "kexec_load_disabled")
        .and_then(|f| f.value.as_bool())
        == Some(true)
    {
        return None;
    }

    if matches!(
        a.fact("kernel.surface", "lockdown")
            .and_then(|f| f.value.as_str()),
        Some("integrity" | "confidentiality")
    ) {
        return None;
    }

    let exec_load = a.fact("kernel.exec", "kexec_load");
    let exec_file = a.fact("kernel.exec", "kexec_file_load");
    let load_permitted = exec_load
        .and_then(|f| f.value.get("status"))
        .and_then(|s| s.as_str())
        == Some("permitted");
    let file_permitted = exec_file
        .and_then(|f| f.value.get("status"))
        .and_then(|s| s.as_str())
        == Some("permitted");

    let has_exec = exec_load.is_some() || exec_file.is_some();
    let config_opts = a.fact("kernel.config", "options");
    let config_kexec = config_opts
        .and_then(|f| f.value.get("CONFIG_KEXEC"))
        .and_then(|v| v.as_str())
        == Some("y");
    let config_kexec_file = config_opts
        .and_then(|f| f.value.get("CONFIG_KEXEC_FILE"))
        .and_then(|v| v.as_str())
        == Some("y");

    let permitted = if has_exec {
        load_permitted || file_permitted
    } else {
        config_kexec || config_kexec_file
    };

    if !permitted {
        return None;
    }

    let mut ev = Vec::new();
    ev.extend(a.fact("capabilities", "effective").cloned());
    ev.extend(a.fact("kernel.surface", "kexec_load_disabled").cloned());
    ev.extend(a.fact("kernel.surface", "lockdown").cloned());
    if load_permitted {
        ev.extend(exec_load.cloned());
    }
    if file_permitted {
        ev.extend(exec_file.cloned());
    }
    if !has_exec && (config_kexec || config_kexec_file) {
        ev.extend(config_opts.cloned());
    }
    Some(ev)
}

fn check_amr025(a: &Assess) -> Option<Vec<Fact>> {
    if matches!(
        a.fact("kernel.surface", "lockdown")
            .and_then(|f| f.value.as_str()),
        Some("integrity" | "confidentiality")
    ) {
        return None;
    }

    let dev_mem_acc = a.is("kernel.surface", "dev_mem", "accessible");
    let dev_kmem_acc = a.is("kernel.surface", "dev_kmem", "accessible");
    let iopl_fact = a.fact("kernel.exec", "iopl");
    let iopl_permitted = iopl_fact
        .and_then(|f| f.value.get("status"))
        .and_then(|s| s.as_str())
        == Some("permitted");

    if !dev_mem_acc && !dev_kmem_acc && !iopl_permitted {
        return None;
    }

    let mut ev = Vec::new();
    if dev_mem_acc {
        ev.extend(a.fact("kernel.surface", "dev_mem").cloned());
    }
    if dev_kmem_acc {
        ev.extend(a.fact("kernel.surface", "dev_kmem").cloned());
    }
    if iopl_permitted {
        ev.extend(iopl_fact.cloned());
    }
    ev.extend(a.fact("kernel.surface", "lockdown").cloned());
    Some(ev)
}

fn check_amr026(a: &Assess) -> Option<Vec<Fact>> {
    let core_writable = a
        .fact("kernel.surface", "core_pattern")
        .and_then(|f| f.value.get("writable"))
        .and_then(|w| w.as_bool())
        == Some(true);
    let modprobe_writable = a
        .fact("kernel.surface", "modprobe")
        .and_then(|f| f.value.get("writable"))
        .and_then(|w| w.as_bool())
        == Some(true);

    if !core_writable && !modprobe_writable {
        return None;
    }

    let mut ev = Vec::new();
    if core_writable {
        ev.extend(a.fact("kernel.surface", "core_pattern").cloned());
    }
    if modprobe_writable {
        ev.extend(a.fact("kernel.surface", "modprobe").cloned());
    }
    Some(ev)
}

fn check_amr027(a: &Assess) -> Option<Vec<Fact>> {
    let acpi_fact = a.fact("kernel.surface", "acpi_table_writable")?;
    if acpi_fact.value.as_bool() != Some(true) {
        return None;
    }
    Some(vec![acpi_fact.clone()])
}

fn check_amr028(a: &Assess) -> Option<Vec<Fact>> {
    if check_amr023(a).is_some() {
        return None;
    }
    let kexec_ev = check_amr024(a)?;

    let mut ev = kexec_ev;
    if let Some(f) = a.fact("kernel.surface", "modules_disabled")
        && !ev.iter().any(|e| e.probe == f.probe && e.key == f.key)
    {
        ev.push(f.clone());
    }
    if let Some(f) = a.fact("kernel.config", "options")
        && !ev.iter().any(|e| e.probe == f.probe && e.key == f.key)
    {
        ev.push(f.clone());
    }
    for key in ["finit_module", "init_module"] {
        if let Some(f) = a.fact("kernel.exec", key)
            && !ev.iter().any(|e| e.probe == f.probe && e.key == f.key)
        {
            ev.push(f.clone());
        }
    }
    Some(ev)
}

fn check_amr029(a: &Assess) -> Option<Vec<Fact>> {
    let keys = [
        "finit_module",
        "init_module",
        "kexec_load",
        "kexec_file_load",
        "iopl",
    ];
    let mut ev = Vec::new();
    for key in keys {
        if let Some(f) = a.fact("kernel.exec", key) {
            ev.push(f.clone());
        }
    }
    if ev.is_empty() {
        return None;
    }

    // AMR-029 confirms all Ring 0 pathways are verified closed.
    // All present execution tests must report "denied", "unsupported", or "unsupported_arch".
    // If any test reported "error" (e.g. IPC failure or timeout), it is NOT verified closed.
    let all_closed = ev.iter().all(|f| {
        matches!(
            f.value.get("status").and_then(|s| s.as_str()),
            Some("denied" | "unsupported" | "unsupported_arch")
        )
    });
    if !all_closed {
        return None;
    }

    let any_error = a.report.probes.iter().flat_map(|p| &p.facts).any(|f| {
        f.probe == "kernel.exec" && f.value.get("status").and_then(|s| s.as_str()) == Some("error")
    });
    if any_error {
        return None;
    }

    if check_amr023(a).is_some()
        || check_amr024(a).is_some()
        || check_amr025(a).is_some()
        || check_amr026(a).is_some()
        || check_amr027(a).is_some()
        || check_amr028(a).is_some()
    {
        return None;
    }

    Some(ev)
}

fn check_amr030(a: &Assess) -> Option<Vec<Fact>> {
    let f = a.fact("mounts", "staging")?;
    let arr = f.value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    Some(vec![f.clone()])
}

/// Dynamic severity for AMR-030 (`staging-mount-unhardened`), the rule's
/// `severity_of` hook:
/// - Host verdict: Info — no containment boundary for the mount to weaken.
/// - Anything else (shared-kernel container, VM-family sandbox, or verdict
///   absent = containment unknown): Medium, elevating to High when a staging
///   mount lacks `nodev` and the caller holds `cap_mknod`.
fn severity_amr030(a: &Assess, evidence: &[Fact]) -> Severity {
    if a.report
        .verdict
        .as_ref()
        .is_some_and(|v| v.runtime == RuntimeKind::Host)
    {
        return Severity::Info;
    }
    let has_cap_mknod = a.arr_has("capabilities", "effective", "cap_mknod");
    let missing_nodev = evidence.iter().any(|fact| {
        fact.value.as_array().is_some_and(|arr| {
            arr.iter().any(|entry| {
                let in_missing = entry
                    .get("missing_flags")
                    .and_then(|f| f.as_array())
                    .is_some_and(|flags| flags.iter().any(|flag| flag == "nodev"));
                let not_in_options = entry
                    .get("options")
                    .and_then(|opts| opts.as_array())
                    .is_some_and(|opts| !opts.iter().any(|o| o == "nodev"));
                in_missing || not_in_options
            })
        })
    });
    if has_cap_mknod && missing_nodev {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn check_amr031(a: &Assess) -> Option<Vec<Fact>> {
    if !a.shared_kernel_containment() {
        return None;
    }
    let f = a.fact("mounts", "sensitive_unmasked")?;
    let arr = f.value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    Some(vec![f.clone()])
}

fn check_amr032(a: &Assess) -> Option<Vec<Fact>> {
    if !a.shared_kernel_containment() {
        return None;
    }
    let f = a.fact("mounts", "shared_propagation")?;
    let arr = f.value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    Some(vec![f.clone()])
}

fn check_amr033(a: &Assess) -> Option<Vec<Fact>> {
    if !a.shared_kernel_containment() {
        return None;
    }
    let f = a.fact("mounts", "host_leaks")?;
    let arr = f.value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    Some(vec![f.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Fact, FactStatus, ProbeOutcome, Report, RuntimeKind, ScanMeta, Severity, Verdict,
    };
    use serde_json::json;

    /// One probe outcome per distinct probe name, all facts Ok-status.
    fn report_with(facts: &[(&str, &str, serde_json::Value)]) -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        let mut by_probe: std::collections::BTreeMap<&str, Vec<Fact>> = Default::default();
        for (p, k, v) in facts {
            by_probe
                .entry(p)
                .or_default()
                .push(Fact::ok(p, k, v.clone(), "test".into()));
        }
        for (p, fs) in by_probe {
            let mut o = ProbeOutcome::empty(p);
            o.facts = fs;
            r.push_probe(o);
        }
        r
    }
    fn verdict(runtime: RuntimeKind) -> Verdict {
        Verdict {
            runtime,
            variant: None,
            confidence: "high".into(),
            alternatives: vec![],
            evidence: vec![],
        }
    }

    /// The Ok fact `probes/runtime.rs::run` emits (runtime.rs:242-247): the fused
    /// verdict serialized whole under source "signal aggregation". AMR-014/015
    /// cite this very fact, so test reports carry it alongside the typed verdict.
    fn verdict_report(v: Verdict) -> Report {
        let mut o = ProbeOutcome::empty("runtime");
        o.facts.push(Fact::ok(
            "runtime",
            "verdict",
            serde_json::to_value(&v).expect("Verdict is serializable"),
            "signal aggregation".into(),
        ));
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.push_probe(o);
        r.verdict = Some(v);
        r
    }
    fn rule(id: &str) -> &'static Rule {
        RULES.iter().find(|r| r.id == id).expect("rule registered")
    }
    /// The exact entry shapes `probes/sockets.rs::scan_candidates` emits.
    fn sock(path: &str, kind: &str, writable: bool) -> serde_json::Value {
        json!({"path": path, "writable": writable, "kind": kind, "info": null})
    }

    // ---------------------------------------------------------------- AMR-001

    #[test]
    fn amr001_fires_on_writable_docker_socket_evidence_lists_only_hits() {
        let r = report_with(&[(
            "sockets",
            "found",
            json!([
                sock("/run/docker.sock", "docker", true),
                sock("/run/containerd/containerd.sock", "containerd", true),
                sock("/var/run/docker.sock", "docker", false),
            ]),
        )]);
        let f = rule("AMR-001").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.evidence.len(), 1);
        // Evidence carries only the matching entry, with its info payload intact.
        assert_eq!(f.evidence[0].value.as_array().unwrap().len(), 1);
        assert_eq!(f.evidence[0].value[0]["path"], "/run/docker.sock");
    }

    #[test]
    fn amr001_evidence_includes_security_options() {
        let mut hit = sock("/run/docker.sock", "docker", true);
        hit["info"] = json!({"securityOptions": ["name=apparmor", "seccomp"], "rootless": null});
        let r = report_with(&[("sockets", "found", json!([hit]))]);
        let f = rule("AMR-001").evaluate(&r, false).unwrap();
        assert_eq!(
            f.evidence[0].value[0]["info"]["securityOptions"][0],
            "name=apparmor"
        );
    }

    #[test]
    fn amr001_quiet_when_nothing_writable_or_no_runtime_kind() {
        let r = report_with(&[(
            "sockets",
            "found",
            json!([
                sock("/run/docker.sock", "docker", false),
                sock("/run/containerd/containerd.sock", "containerd", true),
            ]),
        )]);
        assert!(rule("AMR-001").evaluate(&r, false).is_none());
        assert!(rule("AMR-022").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr001_fires_on_host_verdict_writable_podman_socket() {
        // Environment-only evidence is still finding-grade: a writable podman
        // socket is host root for any local user even on a bare host.
        let mut r = report_with(&[(
            "sockets",
            "found",
            json!([sock("/run/podman/podman.sock", "podman", true)]),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert_eq!(
            rule("AMR-001").evaluate(&r, true).unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn rootless_podman_socket_fires_amr022_not_amr001() {
        let mut entry = sock("/run/user/1000/podman/podman.sock", "podman", true);
        entry["info"] = json!({"version": "5.0.0", "rootless": true});
        let r = report_with(&[("sockets", "found", json!([entry]))]);
        assert!(
            rule("AMR-001").evaluate(&r, false).is_none(),
            "rootless peer must not claim host root"
        );
        let f = rule("AMR-022").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(
            f.evidence[0].value[0]["path"],
            "/run/user/1000/podman/podman.sock"
        );
    }

    #[test]
    fn rooted_socket_fires_amr001_not_amr022() {
        let mut entry = sock("/run/docker.sock", "docker", true);
        entry["info"] = json!({"rootless": false});
        let r = report_with(&[("sockets", "found", json!([entry]))]);
        assert_eq!(
            rule("AMR-001").evaluate(&r, false).unwrap().severity,
            Severity::Critical
        );
        assert!(rule("AMR-022").evaluate(&r, false).is_none());
    }

    #[test]
    fn unknown_rootless_peer_fails_loud_as_amr001() {
        // info null (dead socket / failed handshake): unknown peer is treated as root.
        let r = report_with(&[(
            "sockets",
            "found",
            json!([sock("/run/docker.sock", "docker", true)]),
        )]);
        assert!(rule("AMR-001").evaluate(&r, false).is_some());
        assert!(rule("AMR-022").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-002

    fn amr002_facts(
        mode: &str,
        aa: serde_json::Value,
    ) -> Vec<(&'static str, &'static str, serde_json::Value)> {
        vec![
            (
                "capabilities",
                "effective",
                json!(["cap_chown", "cap_sys_admin"]),
            ),
            ("seccomp", "mode", json!(mode)),
            ("lsm", "apparmor", aa),
        ]
    }

    /// The exact `lsm` emission for a SELinux host (probes/lsm.rs: {context, mode}).
    fn selinux_facts(mode: &'static str) -> Vec<(&'static str, &'static str, serde_json::Value)> {
        vec![
            ("lsm", "list", json!(["lockdown", "yama", "selinux"])),
            (
                "lsm",
                "selinux",
                json!({"context": "docker_t", "mode": mode}),
            ),
        ]
    }

    #[test]
    fn amr002_fires_on_full_privileged_signature() {
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-002").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.len(), 3);
    }

    #[test]
    fn amr002_vetoed_by_seccomp_filter() {
        let mut r = report_with(&amr002_facts(
            "filter",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr002_vetoed_by_confined_apparmor() {
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "docker-default", "mode": "enforce"}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr002_vetoed_by_host_verdict() {
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-002").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr002_fires_when_apparmor_absent_and_selinux_permissive() {
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.extend(selinux_facts("permissive"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert_eq!(
            rule("AMR-002")
                .evaluate(&r, false)
                .expect("must fire")
                .severity,
            Severity::High
        );
    }

    #[test]
    fn amr002_fires_when_neither_apparmor_nor_selinux_in_lsm_stack() {
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.push(("lsm", "list", json!(["lockdown", "yama"])));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_some());
    }

    #[test]
    fn amr002_quiet_when_apparmor_absent_but_selinux_enforcing() {
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.extend(selinux_facts("enforcing"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr002_evidence_cites_the_deciding_mac_fact() {
        // ReviewT19b-2: on the aa-null branches the witness is the fact that
        // decided the MAC verdict, not the null apparmor fact alone.
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.extend(selinux_facts("permissive"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-002").evaluate(&r, false).expect("must fire");
        let keys: Vec<(&str, &str)> = f
            .evidence
            .iter()
            .map(|e| (e.probe.as_str(), e.key.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                ("capabilities", "effective"),
                ("seccomp", "mode"),
                ("lsm", "selinux")
            ]
        );
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.push(("lsm", "list", json!(["lockdown", "yama"])));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-002").evaluate(&r, false).expect("must fire");
        assert_eq!(f.evidence[2].key, "list");
        // aa-unconfined branch unchanged: the apparmor fact itself.
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-002").evaluate(&r, false).expect("must fire");
        assert_eq!(f.evidence[2].key, "apparmor");
    }

    #[test]
    fn amr002_fires_on_apparmor_complain_mode() {
        // Erratum 2026-10-01 (ReviewT2324b DELTA-1): a `complain`-mode profile logs
        // denials only and confines nothing, so seccomp disabled + aa complain +
        // no SELinux is the `--privileged` posture — the High combo must fire and
        // cite the aa witness. AMR-016 stays quiet: the complete combo is 002's
        // territory, and 016 already refuses to call a complain profile a restraint.
        let mut facts = amr002_facts(
            "disabled",
            json!({"profile": "docker-default", "mode": "complain"}),
        );
        facts.push(("lsm", "list", json!(["apparmor", "lockdown", "yama"])));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-002")
            .evaluate(&r, false)
            .expect("complain-mode aa must count as MAC-unconfining");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(
            (f.evidence[2].probe.as_str(), f.evidence[2].key.as_str()),
            ("lsm", "apparmor"),
            "the complain-mode aa fact must be the cited MAC witness"
        );
        assert_eq!(f.evidence[2].value["mode"], "complain");
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
        // Fail closed elsewhere: a confined profile with no mode string is not
        // complain and not unconfined — the combo stays silent (ReviewT21b's
        // exact-string discipline, applied to the 002 leg).
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "docker-default"}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-003

    #[test]
    fn amr003_fires_on_cap_sys_module_in_container() {
        let mut r = report_with(&[("capabilities", "effective", json!(["cap_sys_module"]))]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-003").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn amr003_quiet_on_host_verdict_even_with_cap() {
        // On a bare host CapEff is by-design; the finding is about a *contained* holder.
        let mut r = report_with(&[("capabilities", "effective", json!(["cap_sys_module"]))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-003").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr003_quiet_without_cap_sys_module() {
        let mut r = report_with(&[(
            "capabilities",
            "effective",
            json!(["cap_chown", "cap_net_raw"]),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-003").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-004

    fn amr004_facts(
        pid_isolated: bool,
        scope: u64,
        caps: &[&str],
    ) -> Vec<(&'static str, &'static str, serde_json::Value)> {
        vec![
            (
                "namespaces",
                "isolated",
                json!({"pid": pid_isolated, "user": true}),
            ),
            ("capabilities", "effective", json!(caps)),
            ("capabilities", "ptraceScope", json!(scope)),
        ]
    }

    fn amr004_report(
        pid_isolated: bool,
        scope: u64,
        caps: &[&str],
        runtime: RuntimeKind,
    ) -> Report {
        let mut r = report_with(&amr004_facts(pid_isolated, scope, caps));
        r.verdict = Some(verdict(runtime));
        r
    }

    #[test]
    fn amr004_fires_full_severity_privileged_with_cap() {
        let r = amr004_report(false, 1, &["cap_sys_ptrace"], RuntimeKind::Docker);
        let f = rule("AMR-004").evaluate(&r, true).expect("must fire");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn amr004_fires_on_yama_scope_zero_without_cap() {
        let r = amr004_report(false, 0, &[], RuntimeKind::Podman);
        assert!(rule("AMR-004").evaluate(&r, true).is_some());
    }

    #[test]
    fn amr004_quiet_on_scope_one_without_cap() {
        let r = amr004_report(false, 1, &[], RuntimeKind::Docker);
        assert!(rule("AMR-004").evaluate(&r, true).is_none());
    }

    #[test]
    fn amr004_quiet_when_pid_namespace_isolated() {
        let r = amr004_report(true, 0, &["cap_sys_ptrace"], RuntimeKind::Docker);
        assert!(rule("AMR-004").evaluate(&r, true).is_none());
    }

    #[test]
    fn amr004_quiet_on_host_verdict_even_with_ptrace_reach() {
        // Host PID ns is tautological on a bare host: no containment, no finding.
        let r = amr004_report(false, 0, &["cap_sys_ptrace"], RuntimeKind::Host);
        assert!(rule("AMR-004").evaluate(&r, true).is_none());
    }

    #[test]
    fn amr004_fired_but_unprivileged_demotes_to_info_with_suffix() {
        let r = amr004_report(false, 1, &["cap_sys_ptrace"], RuntimeKind::Docker);
        let f = rule("AMR-004").evaluate(&r, false).expect("fires demoted");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            f.summary,
            format!(
                "{} (insufficient privilege to assess)",
                rule("AMR-004").summary
            )
        );
        assert!(
            !f.evidence.is_empty(),
            "a fired demotion keeps its evidence"
        );
    }

    #[test]
    fn amr004_unfired_but_unprivileged_still_emits_info_note() {
        // Spec §6 erratum F4: the privilege downgrade must be reachable — the
        // info note lands whether or not the root-gated inputs were readable.
        let r = amr004_report(false, 1, &[], RuntimeKind::Docker);
        let f = rule("AMR-004")
            .evaluate(&r, false)
            .expect("info note always present");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.evidence.is_empty());
        assert!(f.summary.ends_with("(insufficient privilege to assess)"));
    }

    #[test]
    fn amr004_host_verdict_unprivileged_suppresses_privilege_note() {
        // Spec §6 amendment (ReviewT19b J1): a container-gated rule at a Host
        // verdict is inapplicable, not unassessable — the note is suppressed.
        let r = amr004_report(false, 0, &["cap_sys_ptrace"], RuntimeKind::Host);
        assert!(rule("AMR-004").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr004_missing_verdict_unprivileged_still_emits_note() {
        // Amendment J1 boundary: no verdict = containment unknown ⇒ the F4
        // note stays (suppression keys on flag + Host verdict only; the
        // unprivileged-Docker note path is pinned by the two tests above).
        let r = report_with(&amr004_facts(false, 1, &[]));
        let f = rule("AMR-004").evaluate(&r, false).expect("note present");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.summary.ends_with("(insufficient privilege to assess)"));
    }

    // ---------------------------------------------------------------- AMR-005

    #[test]
    fn amr005_fires_medium_in_container_with_seccomp_disabled() {
        let mut r = report_with(&[("seccomp", "mode", json!("disabled"))]);
        r.verdict = Some(verdict(RuntimeKind::Podman));
        let f = rule("AMR-005").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn amr005_quiet_on_host_verdict() {
        let mut r = report_with(&[("seccomp", "mode", json!("disabled"))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-005").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr005_quiet_when_filtered_in_container() {
        let mut r = report_with(&[("seccomp", "mode", json!("filter"))]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-005").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-006

    #[test]
    fn amr006_fires_medium_on_unconfined_profile_in_container() {
        let mut r = report_with(&[
            ("lsm", "list", json!(["lockdown", "yama", "apparmor"])),
            (
                "lsm",
                "apparmor",
                json!({"profile": "unconfined", "mode": ""}),
            ),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-006").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn amr006_fires_when_apparmor_absent_while_other_lsms_active() {
        // The lsm probe reports a null `apparmor` fact when the profile label
        // is not applicable (AppArmor not in the active stack).
        let mut r = report_with(&[
            ("lsm", "list", json!(["lockdown", "yama", "selinux"])),
            ("lsm", "apparmor", serde_json::Value::Null),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Podman));
        let f = rule("AMR-006").evaluate(&r, false).expect("must fire");
        assert!(f.evidence.iter().any(|e| e.key == "list"));
    }

    #[test]
    fn amr006_quiet_when_confined() {
        let mut r = report_with(&[(
            "lsm",
            "apparmor",
            json!({"profile": "containers-custom", "mode": "enforce"}),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-006").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr006_quiet_on_host_verdict() {
        let mut r = report_with(&[(
            "lsm",
            "apparmor",
            json!({"profile": "unconfined", "mode": ""}),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-006").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr006_quiet_when_no_lsm_stack_active() {
        let mut r = report_with(&[
            ("lsm", "list", json!([])),
            ("lsm", "apparmor", serde_json::Value::Null),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-006").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr006_quiet_when_apparmor_active_but_label_unreadable() {
        // aa null while AppArmor *is* in the stack means an unreadable label,
        // not an absent profile — too ambiguous to fire.
        let mut r = report_with(&[
            ("lsm", "list", json!(["apparmor"])),
            ("lsm", "apparmor", serde_json::Value::Null),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-006").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-007

    #[test]
    fn amr007_fires_medium_on_permissive_selinux_without_containment_gate() {
        // Spec condition is `context present ∧ permissive` only: permissive MAC
        // on a bare host is a true hardening gap (spec wins over the plan gate).
        let mut r = report_with(&selinux_facts("permissive"));
        r.verdict = Some(verdict(RuntimeKind::Host));
        let f = rule("AMR-007").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.evidence[0].key, "selinux");
    }

    #[test]
    fn amr007_quiet_when_enforcing() {
        let r = report_with(&selinux_facts("enforcing"));
        assert!(rule("AMR-007").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr007_quiet_when_context_or_mode_absent() {
        // Non-SELinux hosts emit an Ok-status null; a masked enforce file
        // leaves `mode` null. Neither satisfies "context present ∧ permissive".
        let r = report_with(&[("lsm", "selinux", serde_json::Value::Null)]);
        assert!(rule("AMR-007").evaluate(&r, false).is_none());
        let r = report_with(&[(
            "lsm",
            "selinux",
            json!({"context": "docker_t", "mode": null}),
        )]);
        assert!(rule("AMR-007").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-008

    /// The exact `uidmap` map emission (probes/uidmap.rs: MapRow rows
    /// `{container, host, range}`).
    fn map_rows(rows: &[(u32, u32, u32)]) -> serde_json::Value {
        serde_json::Value::Array(
            rows.iter()
                .map(|&(container, host, range)| {
                    json!({"container": container, "host": host, "range": range})
                })
                .collect(),
        )
    }

    #[test]
    fn amr008_fires_on_full_identity_uidmap_in_container() {
        let mut r = report_with(&[("uidmap", "uidMap", map_rows(&[(0, 0, u32::MAX)]))]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-008").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.evidence[0].key, "uidMap");
    }

    #[test]
    fn amr008_quiet_on_rootless_subordinate_rows() {
        let mut r = report_with(&[("uidmap", "uidMap", map_rows(&[(0, 100000, 65536)]))]);
        r.verdict = Some(verdict(RuntimeKind::Podman));
        assert!(rule("AMR-008").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr008_quiet_on_host_verdict() {
        // A bare host's uid_map is the identity mapping by design: gated.
        let mut r = report_with(&[("uidmap", "uidMap", map_rows(&[(0, 0, u32::MAX)]))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-008").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-009

    #[test]
    fn amr009_fires_low_on_cgroup_v1_in_container() {
        let mut r = report_with(&[("cgroup", "version", json!(1))]);
        r.verdict = Some(verdict(RuntimeKind::Lxc));
        let f = rule("AMR-009").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.evidence[0].key, "version");
    }

    #[test]
    fn amr009_quiet_on_unified_v2() {
        let mut r = report_with(&[("cgroup", "version", json!(2))]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-009").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr009_quiet_on_host_verdict() {
        let mut r = report_with(&[("cgroup", "version", json!(1))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-009").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-010

    fn amr010_report(controllers: serde_json::Value, limits: serde_json::Value) -> Report {
        let mut r = report_with(&[
            ("cgroup", "controllers", controllers),
            ("cgroup", "limits", limits),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        r
    }

    #[test]
    fn amr010_fires_low_when_pids_controller_present_but_unlimited() {
        let r = amr010_report(
            json!(["cpu", "memory", "pids"]),
            json!({"memory": "max", "pids": "max"}),
        );
        let f = rule("AMR-010").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Low);
        // Evidence carries both the controller list and the unlimited limit.
        let keys: Vec<&str> = f.evidence.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["controllers", "limits"]);
    }

    #[test]
    fn amr010_quiet_when_pids_limited() {
        let r = amr010_report(json!(["pids"]), json!({"pids": "2048"}));
        assert!(rule("AMR-010").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr010_quiet_without_pids_controller() {
        // lxc fixture shape: no pids controller — absence is not "unlimited".
        let r = amr010_report(json!(["cpu", "memory"]), json!({}));
        assert!(rule("AMR-010").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr010_quiet_on_host_verdict() {
        // Mirror of the AMR-008/009 host-quiet pins: the gate is behavioral,
        // not fixture accident — every other 010 fixture is Docker-verdicted.
        let mut r = report_with(&[
            ("cgroup", "controllers", json!(["pids"])),
            ("cgroup", "limits", json!({"pids": "max"})),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-010").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-011

    fn amr011_report(gid_rows: serde_json::Value, setgroups: &str) -> Report {
        // Containment gate (spec §6 erratum, live host scan): host-0 gid rows
        // only mean movement when there is a container to move from.
        let mut r = report_with(&[
            ("uidmap", "gidMap", gid_rows),
            ("uidmap", "setgroups", json!(setgroups)),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        r
    }

    #[test]
    fn amr011_fires_medium_on_host0_gid_row_with_setgroups_allow() {
        // Severity is medium (spec §6 row 207), not the plan's info.
        let r = amr011_report(map_rows(&[(0, 0, 1)]), "allow");
        let f = rule("AMR-011").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
        // Evidence is BOTH facts: the mapping and the non-denial.
        let keys: Vec<&str> = f.evidence.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["gidMap", "setgroups"]);
    }

    #[test]
    fn amr011_quiet_when_setgroups_denied() {
        let r = amr011_report(map_rows(&[(0, 0, 1)]), "deny");
        assert!(rule("AMR-011").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr011_quiet_without_host0_row() {
        let r = amr011_report(map_rows(&[(0, 100000, 65536)]), "allow");
        assert!(rule("AMR-011").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr011_quiet_on_host_verdict() {
        // Erratum reasoning: init-ns gid_map is trivially `0 0 4294967295`
        // with setgroups allow — ungated, every bare host fires on a constant.
        let mut r = report_with(&[
            ("uidmap", "gidMap", map_rows(&[(0, 0, u32::MAX)])),
            ("uidmap", "setgroups", json!("allow")),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-011").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-012

    #[test]
    fn amr012_fires_info_at_abi_boundary() {
        let r = report_with(&[("lsm", "landlockAbi", json!(1))]);
        let f = rule("AMR-012")
            .evaluate(&r, false)
            .expect("abi 1 must fire");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence[0].key, "landlockAbi");
    }

    #[test]
    fn amr012_quiet_when_abi_null_zero_or_absent() {
        // Unsupported syscall / absent securityfs: Ok-status null (probes/lsm.rs).
        let r = report_with(&[("lsm", "landlockAbi", serde_json::Value::Null)]);
        assert!(rule("AMR-012").evaluate(&r, false).is_none());
        let r = report_with(&[("lsm", "landlockAbi", json!(0))]);
        assert!(rule("AMR-012").evaluate(&r, false).is_none());
        assert!(
            rule("AMR-012")
                .evaluate(&Report::blank(ScanMeta::stub(), 1), false)
                .is_none()
        );
    }

    // ---------------------------------------------------------------- AMR-013

    #[test]
    fn amr013_fires_info_when_hypervisor_present() {
        let r = report_with(&[(
            "vmm",
            "hypervisor",
            json!({"present": true, "vendor": "KVM"}),
        )]);
        let f = rule("AMR-013").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence[0].value["vendor"], "KVM");
    }

    #[test]
    fn amr013_quiet_on_bare_hw() {
        let r = report_with(&[(
            "vmm",
            "hypervisor",
            json!({"present": false, "vendor": null}),
        )]);
        assert!(rule("AMR-013").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-014

    #[test]
    fn amr014_fires_info_on_strong_isolation_verdicts() {
        for runtime in [
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let r = verdict_report(verdict(runtime));
            let f = rule("AMR-014")
                .evaluate(&r, false)
                .expect("strong-isolation runtime must fire");
            assert_eq!(f.severity, Severity::Info);
            // ReviewT21: evidence must be the runtime probe's own verdict fact —
            // byte-identical to the emission in probes/runtime.rs: `source`
            // "signal aggregation" and the full serialized Verdict shape.
            assert_eq!(f.evidence[0].probe, "runtime");
            assert_eq!(f.evidence[0].key, "verdict");
            assert_eq!(f.evidence[0].source, "signal aggregation");
            for key in [
                "runtime",
                "variant",
                "confidence",
                "alternatives",
                "evidence",
            ] {
                assert!(
                    f.evidence[0].value.get(key).is_some(),
                    "verdict fact keeps the full serialized Verdict (missing {key})"
                );
            }
        }
    }

    #[test]
    fn amr014_quiet_on_ordinary_and_missing_verdicts() {
        for runtime in [
            RuntimeKind::Docker,
            RuntimeKind::Kubernetes,
            RuntimeKind::Host,
        ] {
            let mut r = Report::blank(ScanMeta::stub(), 1);
            r.verdict = Some(verdict(runtime));
            assert!(rule("AMR-014").evaluate(&r, false).is_none());
        }
        assert!(
            rule("AMR-014")
                .evaluate(&Report::blank(ScanMeta::stub(), 1), false)
                .is_none()
        );
    }

    // ---------------------------------------------------------------- AMR-015

    #[test]
    fn amr015_fires_info_on_low_confidence_verdict() {
        // Plan amendment: the Verdict confidence is a string ladder
        // (high|medium|low) — "low" exactly, never a numeric < 0.5.
        let mut v = verdict(RuntimeKind::Lxc);
        v.confidence = "low".into();
        let r = verdict_report(v);
        let f = rule("AMR-015").evaluate(&r, false).expect("low must fire");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence[0].value["confidence"], "low");
        assert_eq!(f.evidence[0].source, "signal aggregation");
    }

    #[test]
    fn amr015_quiet_on_confident_or_absent_verdict() {
        for confidence in ["high", "medium"] {
            let mut r = Report::blank(ScanMeta::stub(), 1);
            let mut v = verdict(RuntimeKind::Docker);
            v.confidence = confidence.into();
            r.verdict = Some(v);
            assert!(rule("AMR-015").evaluate(&r, false).is_none());
        }
        assert!(
            rule("AMR-015")
                .evaluate(&Report::blank(ScanMeta::stub(), 1), false)
                .is_none()
        );
        // Fail closed: a verdict with no citable runtime.verdict fact stays silent.
        let mut r = Report::blank(ScanMeta::stub(), 1);
        let mut v = verdict(RuntimeKind::Lxc);
        v.confidence = "low".into();
        r.verdict = Some(v);
        assert!(rule("AMR-015").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-016

    #[test]
    fn amr016_quiet_when_amr002_combo_complete_apparmor() {
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_some());
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr016_quiet_when_amr002_combo_complete_selinux_permissive() {
        // The combo is AMR-002's AMENDED one: privileged-on-SELinux-permissive
        // is 002's territory and stays QUIET on 016 (the plan sketch's
        // AppArmor-only complement is stale — erratum ReviewT19 F3).
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.extend(selinux_facts("permissive"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-002").evaluate(&r, false).is_some());
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr016_fires_medium_when_seccomp_filter_holds() {
        let mut r = report_with(&amr002_facts(
            "filter",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-016").evaluate(&r, false).expect("must fire");
        assert_eq!(f.severity, Severity::Medium);
        let keys: Vec<&str> = f.evidence.iter().map(|e| e.key.as_str()).collect();
        assert!(
            keys.contains(&"effective") && keys.contains(&"mode"),
            "evidence must show the cap and the restraint: {keys:?}"
        );
    }

    #[test]
    fn amr016_fires_when_apparmor_absent_but_selinux_enforcing() {
        let mut facts = amr002_facts("disabled", serde_json::Value::Null);
        facts.extend(selinux_facts("enforcing"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-016").evaluate(&r, false).is_some());
    }

    #[test]
    fn amr016_silent_when_lsm_degraded_and_seccomp_disabled() {
        // ReviewT21 P2: a `--probe-timeout` dropped the lsm probe and seccomp
        // reports "disabled" — no restraint is evidenced, so 016 must stay
        // silent instead of asserting a restraint it cannot cite (fail closed,
        // as AMR-002's null-list branch does).
        let mut r = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_admin"])),
            ("seccomp", "mode", json!("disabled")),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr016_evidence_cites_only_holding_restraints() {
        // seccomp filter and SELinux enforcing hold; the present-but-unconfined
        // AppArmor profile is NOT a restraint and must not be cited as one.
        let mut facts = amr002_facts("filter", json!({"profile": "unconfined", "mode": ""}));
        facts.extend(selinux_facts("enforcing"));
        let mut r = report_with(&facts);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-016").evaluate(&r, false).expect("must fire");
        assert!(
            f.evidence
                .iter()
                .any(|e| e.probe == "seccomp" && e.key == "mode")
        );
        assert!(
            f.evidence
                .iter()
                .any(|e| e.probe == "lsm" && e.key == "selinux")
        );
        assert!(
            !f.evidence
                .iter()
                .any(|e| e.probe == "lsm" && e.key == "apparmor"),
            "unconfined AppArmor is not a holding restraint: {:?}",
            f.evidence
                .iter()
                .map(|e| (&e.probe, &e.key))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn amr016_complain_profile_not_a_restraint() {
        // ReviewT21b: a complain-mode profile logs only and confines nothing;
        // counting it as holding would let a cap_sys_admin container claim a
        // restraint that holds no syscall, mount, or device. With seccomp
        // disabled and SELinux absent no restraint holds — silent (fail closed).
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "docker-default", "mode": "complain"}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
        // With a seccomp filter present the rule fires, but only seccomp may
        // be cited — the complain profile must not appear among the restraints.
        let mut r = report_with(&amr002_facts(
            "filter",
            json!({"profile": "docker-default", "mode": "complain"}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-016").evaluate(&r, false).expect("must fire");
        assert!(
            !f.evidence
                .iter()
                .any(|e| e.probe == "lsm" && e.key == "apparmor"),
            "complain AppArmor is not a holding restraint: {:?}",
            f.evidence
                .iter()
                .map(|e| (&e.probe, &e.key))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn amr016_fires_when_only_apparmor_enforce_holds() {
        // The positive leg: an enforcing profile DOES confine, so with seccomp
        // disabled the enforce mode alone is a citable holding restraint.
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "docker-default", "mode": "enforce"}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-016").evaluate(&r, false).expect("must fire");
        assert!(
            f.evidence
                .iter()
                .any(|e| e.probe == "lsm" && e.key == "apparmor"),
            "enforce-mode AppArmor must be cited as holding"
        );
    }

    #[test]
    fn amr016_quiet_without_cap_sys_admin_or_containment() {
        let mut r = report_with(&[
            ("capabilities", "effective", json!(["cap_chown"])),
            ("seccomp", "mode", json!("filter")),
        ]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
        // Full combo facts on a bare host: gated like AMR-002.
        let mut r = report_with(&amr002_facts(
            "disabled",
            json!({"profile": "unconfined", "mode": ""}),
        ));
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-016").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-017

    fn amr017_report(cgroup_ns: serde_json::Value) -> Report {
        let mut r = report_with(&[("namespaces", "cgroupNsSameAsInit", cgroup_ns)]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        r
    }

    #[test]
    fn amr017_fires_info_when_cgroup_ns_matches_init() {
        let f = rule("AMR-017")
            .evaluate(&amr017_report(json!(true)), false)
            .expect("must fire");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence[0].key, "cgroupNsSameAsInit");
    }

    #[test]
    fn amr017_quiet_when_isolated_null_or_host() {
        assert!(
            rule("AMR-017")
                .evaluate(&amr017_report(json!(false)), false)
                .is_none()
        );
        // Degraded pid-1 comparison: null is unknown, never "equal".
        assert!(
            rule("AMR-017")
                .evaluate(&amr017_report(serde_json::Value::Null), false)
                .is_none()
        );
        // Bare host: the equality is the init-ns constant (spec row 213).
        let mut r = report_with(&[("namespaces", "cgroupNsSameAsInit", json!(true))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-017").evaluate(&r, false).is_none());
    }

    // ---------------------------------------------------------------- AMR-018

    fn amr018_report(nnp: serde_json::Value) -> Report {
        let mut r = report_with(&[("capabilities", "noNewPrivs", nnp)]);
        r.verdict = Some(verdict(RuntimeKind::Podman));
        r
    }

    #[test]
    fn amr018_fires_low_when_no_new_privs_unset() {
        let f = rule("AMR-018")
            .evaluate(&amr018_report(json!(0)), false)
            .expect("must fire");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.evidence[0].key, "noNewPrivs");
    }

    #[test]
    fn amr018_quiet_when_set_null_or_host() {
        assert!(
            rule("AMR-018")
                .evaluate(&amr018_report(json!(1)), false)
                .is_none()
        );
        assert!(
            rule("AMR-018")
                .evaluate(&amr018_report(serde_json::Value::Null), false)
                .is_none()
        );
        // Ordinary host processes sit at 0: a constant, not a finding (row 214).
        let mut r = report_with(&[("capabilities", "noNewPrivs", json!(0))]);
        r.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-018").evaluate(&r, false).is_none());
    }

    // ------------------------------------------------------------ cross-cutting

    #[test]
    fn unavailable_and_degraded_status_never_satisfies_a_predicate() {
        // The value alone must never satisfy a rule: a non-Ok status fact with
        // a firing payload stays silent.
        for status in [FactStatus::Unavailable, FactStatus::Degraded] {
            let mut f = Fact::ok(
                "capabilities",
                "effective",
                json!(["cap_sys_module"]),
                "test".into(),
            );
            f.status = status;
            let mut r = Report::blank(ScanMeta::stub(), 1);
            r.verdict = Some(verdict(RuntimeKind::Docker));
            r.push_probe(ProbeOutcome::empty("capabilities").with_fact(f));
            assert!(
                rule("AMR-003").evaluate(&r, true).is_none(),
                "{status:?}-status fact must not satisfy a predicate"
            );
        }
    }

    #[test]
    fn registry_order_is_exact_and_unique() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        // Registry order is append-stable, not numeric: AMR-022 was an
        // id-space append (ReviewT19 F2) and keeps its slot; Task 21 appended
        // 014–018 after AMR-013, Task 28 appended 019–020, Task 29 021,
        // Task 6 appended 023–029, Task 4 appended 030–033.
        assert_eq!(
            ids,
            [
                "AMR-001", "AMR-002", "AMR-003", "AMR-004", "AMR-005", "AMR-006", "AMR-022",
                "AMR-007", "AMR-008", "AMR-009", "AMR-010", "AMR-011", "AMR-012", "AMR-013",
                "AMR-014", "AMR-015", "AMR-016", "AMR-017", "AMR-018", "AMR-019", "AMR-020",
                "AMR-021", "AMR-023", "AMR-024", "AMR-025", "AMR-026", "AMR-027", "AMR-028",
                "AMR-029", "AMR-030", "AMR-031", "AMR-032", "AMR-033",
            ]
        );
    }

    #[test]
    fn registry_checks_are_distinct_functions() {
        for (i, a) in RULES.iter().enumerate() {
            for b in RULES[i + 1..].iter() {
                assert!(
                    !std::ptr::fn_addr_eq(a.check, b.check),
                    "{} and {} share a check",
                    a.id,
                    b.id
                );
            }
        }
    }

    // ── ReviewT26 F3: VM-family verdicts are not shared-kernel containments ──

    /// Every conjunct the container-gated rules ask for, so silence can only
    /// come from the applicability gate: full-privilege CapEff (cap_sys_admin,
    /// cap_sys_module, cap_sys_ptrace), seccomp disabled, an explicit aa
    /// `unconfined` profile, identity id mappings with setgroups allow, cgroup
    /// v1 with an unlimited pids controller, host pid-ns at Yama 0, the shared
    /// host cgroup-ns, the eBPF unprivileged load path open (knob 0), and a
    /// hypervisor witness. (AMR-016 is the deliberate
    /// exception: the full AMR-002 combo is present, and its exact complement
    /// is silent by design.)
    fn fully_gated_open_facts() -> Vec<(&'static str, &'static str, serde_json::Value)> {
        vec![
            (
                "capabilities",
                "effective",
                json!([
                    "cap_chown",
                    "cap_sys_admin",
                    "cap_sys_module",
                    "cap_sys_ptrace"
                ]),
            ),
            ("capabilities", "noNewPrivs", json!(0)),
            ("capabilities", "ptraceScope", json!(0)),
            ("seccomp", "mode", json!("disabled")),
            (
                "lsm",
                "apparmor",
                json!({"profile": "unconfined", "mode": ""}),
            ),
            ("uidmap", "uidMap", map_rows(&[(0, 0, u32::MAX)])),
            ("uidmap", "gidMap", map_rows(&[(0, 0, u32::MAX)])),
            ("uidmap", "setgroups", json!("allow")),
            ("cgroup", "version", json!(1)),
            ("cgroup", "controllers", json!(["pids", "memory"])),
            ("cgroup", "limits", json!({"pids": "max", "memory": "max"})),
            (
                "namespaces",
                "isolated",
                json!({"pid": false, "user": false}),
            ),
            ("namespaces", "cgroupNsSameAsInit", json!(true)),
            (
                "vmm",
                "hypervisor",
                json!({"present": true, "vendor": "KVMKVMKVM"}),
            ),
            (
                "ebpf",
                "reachability",
                json!({"capPathOpen": true, "unprivilegedOpen": true}),
            ),
            (
                "ebpf",
                "knobs",
                json!({"unprivilegedBpfDisabled": 0, "lockdown": null}),
            ),
        ]
    }

    /// `report_with`'s grouping applied to an existing report: the VM-family
    /// reports need the runtime probe's own verdict fact, which only
    /// `verdict_report` emits, alongside the gated facts.
    fn extend_with_facts(
        r: &mut Report,
        facts: &[(&'static str, &'static str, serde_json::Value)],
    ) {
        let mut by_probe: std::collections::BTreeMap<&str, Vec<Fact>> = Default::default();
        for (p, k, v) in facts {
            by_probe
                .entry(p)
                .or_default()
                .push(Fact::ok(p, k, v.clone(), "test".into()));
        }
        for (p, fs) in by_probe {
            let mut o = ProbeOutcome::empty(p);
            o.facts = fs;
            r.push_probe(o);
        }
    }

    #[test]
    fn vm_family_verdicts_quiet_every_container_only_rule() {
        // Spec §6 erratum 2026-10-01 (ReviewT26 F3): the container gate is a
        // SHARED-KERNEL containment verdict; firecracker/gVisor/kata close it
        // even with every gated conjunct open.
        for runtime in [
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let mut r = verdict_report(verdict(runtime));
            extend_with_facts(&mut r, &fully_gated_open_facts());
            for gated in RULES.iter().filter(|g| g.container_only) {
                assert!(
                    gated.evaluate(&r, true).is_none(),
                    "{} must not fire under a {runtime:?} verdict",
                    gated.id
                );
            }
            // The J1 note leg keys on the same predicate: AMR-004 (the one
            // requires_root gated rule) is inapplicable under a VM verdict,
            // not unassessable — no insufficient-privilege note.
            assert!(rule("AMR-004").evaluate(&r, false).is_none());
        }
    }

    #[test]
    fn shared_kernel_verdicts_fire_the_gated_rules_on_the_same_facts() {
        // The mirror of the VM exemption: identical facts, container verdicts
        // — the gate opens. One representative pinned per container verdict,
        // plus AMR-019 (Task 28) pinned on two of them.
        for (runtime, id) in [
            (RuntimeKind::Docker, "AMR-003"),
            (RuntimeKind::Podman, "AMR-008"),
            (RuntimeKind::Lxc, "AMR-011"),
            (RuntimeKind::Kubernetes, "AMR-018"),
            (RuntimeKind::Docker, "AMR-019"),
            (RuntimeKind::Podman, "AMR-019"),
        ] {
            let mut r = report_with(&fully_gated_open_facts());
            r.verdict = Some(verdict(runtime));
            assert!(
                rule(id).evaluate(&r, true).is_some(),
                "{id} must fire under a {runtime:?} verdict with the gated facts open"
            );
        }
    }

    #[test]
    fn vm_family_verdicts_still_fire_the_013_and_014_info_notes() {
        // The exemption's honest output: the virtualization note and the
        // strong-isolation note stay reportable under VM verdicts.
        for runtime in [
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let mut r = verdict_report(verdict(runtime));
            extend_with_facts(&mut r, &fully_gated_open_facts());
            for id in ["AMR-013", "AMR-014"] {
                assert!(
                    rule(id).evaluate(&r, false).is_some(),
                    "{id} must fire under a {runtime:?} verdict"
                );
            }
        }
    }

    // ── Task 28: AMR-019/020 eBPF exposure ────────────────────────────────

    fn ebpf_open_facts() -> Vec<(&'static str, &'static str, serde_json::Value)> {
        vec![
            (
                "ebpf",
                "reachability",
                json!({"capPathOpen": true, "unprivilegedOpen": true}),
            ),
            (
                "ebpf",
                "knobs",
                json!({"unprivilegedBpfDisabled": 0, "lockdown": null}),
            ),
        ]
    }

    #[test]
    fn amr019_fires_in_shared_kernel_containers_with_the_unpriv_path_open() {
        for runtime in [
            RuntimeKind::Docker,
            RuntimeKind::Podman,
            RuntimeKind::Kubernetes,
            RuntimeKind::Lxc,
        ] {
            let mut facts = ebpf_open_facts();
            facts.push(("capabilities", "effective", json!(["cap_chown"])));
            let mut r = report_with(&facts);
            r.verdict = Some(verdict(runtime));
            let f = rule("AMR-019")
                .evaluate(&r, true)
                .expect("must fire under a shared-kernel verdict");
            assert_eq!(f.severity, Severity::Medium);
            // Evidence: the deciding reachability fact, plus the raw knob
            // posture it was computed from.
            assert_eq!(f.evidence.len(), 2, "{runtime:?}");
            assert_eq!(f.evidence[0].key, "reachability");
            assert_eq!(f.evidence[1].key, "knobs");
        }
    }

    #[test]
    fn amr019_silent_when_the_unprivileged_path_is_closed_or_unknown() {
        for (unpriv, label) in [
            (json!(false), "knob 1/2 closed"),
            (serde_json::Value::Null, "reachability null"),
        ] {
            let mut r = report_with(&[(
                "ebpf",
                "reachability",
                json!({"capPathOpen": true, "unprivilegedOpen": unpriv}),
            )]);
            r.verdict = Some(verdict(RuntimeKind::Docker));
            assert!(
                rule("AMR-019").evaluate(&r, true).is_none(),
                "AMR-019 must stay silent: {label}"
            );
        }
        // Fact absent at all (eBPF probe degraded away): nothing to decide on.
        let mut r = report_with(&[("capabilities", "effective", json!([]))]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-019").evaluate(&r, true).is_none());
        // Degraded-status reachability never satisfies the predicate either.
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let mut o = ProbeOutcome::empty("ebpf");
        o.facts.push(Fact::degraded(
            "ebpf",
            "reachability",
            serde_json::Value::Null,
            "test".into(),
        ));
        r.push_probe(o);
        assert!(rule("AMR-019").evaluate(&r, true).is_none());
    }

    #[test]
    fn amr019_silent_at_host_and_vm_verdicts_even_with_open_reachability() {
        // Host gate + spec §6 erratum 2026-10-01: guest bpf() hits the guest
        // kernel, so the same open posture that fires under Docker is quiet
        // under Host and under every VM-family verdict.
        for runtime in [
            RuntimeKind::Host,
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let mut facts = ebpf_open_facts();
            facts.push(("capabilities", "effective", json!(["cap_chown"])));
            let mut r = report_with(&facts);
            r.verdict = Some(verdict(runtime));
            assert!(
                rule("AMR-019").evaluate(&r, true).is_none(),
                "AMR-019 must stay silent under a {runtime:?} verdict"
            );
        }
    }

    #[test]
    fn amr020_fires_on_cap_bpf_or_cap_perfmon_anywhere() {
        // Ungated per spec §6: a held capability is exposure wherever the
        // process sits — host, container, or VM guest alike.
        for runtime in [
            RuntimeKind::Host,
            RuntimeKind::Docker,
            RuntimeKind::Firecracker,
        ] {
            for cap in ["cap_bpf", "cap_perfmon"] {
                let mut r =
                    report_with(&[("capabilities", "effective", json!(["cap_chown", cap]))]);
                r.verdict = Some(verdict(runtime));
                let f = rule("AMR-020")
                    .evaluate(&r, true)
                    .expect("must fire on an open cap");
                assert_eq!(f.severity, Severity::Low);
                assert_eq!(f.evidence.len(), 1);
                assert_eq!(f.evidence[0].probe, "capabilities");
                assert_eq!(f.evidence[0].key, "effective");
            }
        }
    }

    #[test]
    fn amr020_silent_without_bpf_or_perfmon() {
        // The full pre-5.8 root set (bits 0..37) predates CAP_BPF/CAP_PERFMON:
        // exactly what a legacy guest-root CapEff decodes to, and no fire.
        let mut r = report_with(&[(
            "capabilities",
            "effective",
            json!([
                "cap_sys_admin",
                "cap_sys_module",
                "cap_perf",
                "cap_sys_ptrace"
            ]),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-020").evaluate(&r, true).is_none());
        // Fact absent: unknown is not held.
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-020").evaluate(&r, true).is_none());
    }

    // ── Task 29: AMR-021 confirmed-open kernel surface ────────────────────

    #[test]
    fn amr021_fires_only_on_a_confirmed_load_in_a_shared_kernel_container() {
        let mut r = report_with(&[(
            "ebpf",
            "load",
            json!({"status": "ok", "errno": null, "message": null}),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Podman));
        let f = rule("AMR-021")
            .evaluate(&r, false)
            .expect("a real load in a shared-kernel container is high");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence[0].probe, "ebpf");
        assert_eq!(f.evidence[0].key, "load");
    }

    #[test]
    fn amr021_silent_on_denials_and_without_the_opt_in_fact() {
        for denial in [
            json!({"status": "eperm-no-caps", "errno": 1, "message": null}),
            json!({"status": "verifier-reject", "errno": 22, "message": "R1 !read_ok"}),
            json!({"status": "artifact-missing", "errno": null, "message": null}),
            json!({"status": "object-parse-failed", "errno": null, "message": "bad"}),
        ] {
            let mut r = report_with(&[("ebpf", "load", denial)]);
            r.verdict = Some(verdict(RuntimeKind::Docker));
            assert!(
                rule("AMR-021").evaluate(&r, false).is_none(),
                "only a completed load may fire"
            );
        }
        // The common case: no --probe-ebpf, no fact.
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-021").evaluate(&r, false).is_none());
    }

    #[test]
    fn amr021_silent_at_host_and_vm_verdicts_even_with_load_ok() {
        // The §6 erratum in its sharpest form: the SAME confirmed load is
        // high inside a shared-kernel container, ordinary on a host (root
        // was root), and guest-kernel-local under firecracker/gVisor/kata.
        for runtime in [
            RuntimeKind::Host,
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let mut r = report_with(&[("ebpf", "load", json!({"status": "ok"}))]);
            r.verdict = Some(verdict(runtime));
            assert!(
                rule("AMR-021").evaluate(&r, true).is_none(),
                "AMR-021 must stay silent under a {runtime:?} verdict"
            );
        }
    }

    // ── Task 6: AMR-023..029 Kernel Execution & Attack Surface ───────────

    #[test]
    fn kernel_execution_rules_amr023_module_loading() {
        // 1. AMR-023 fires when finit_module is permitted (with cap_sys_module in effective)
        let r = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_module"])),
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "permitted"}),
            ),
        ]);
        let f = rule("AMR-023")
            .evaluate(&r, false)
            .expect("AMR-023 must fire when finit_module is permitted");
        assert_eq!(f.severity, Severity::High);

        // Also fires when cap_sys_module is only in bounding
        let r_bnd = report_with(&[
            ("capabilities", "bounding", json!(["cap_sys_module"])),
            ("kernel.exec", "init_module", json!({"status": "permitted"})),
        ]);
        assert!(rule("AMR-023").evaluate(&r_bnd, false).is_some());

        // Also fires when passive CONFIG_MODULES == "y"
        let r_cfg = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_module"])),
            ("kernel.config", "options", json!({"CONFIG_MODULES": "y"})),
        ]);
        assert!(rule("AMR-023").evaluate(&r_cfg, false).is_some());

        // Silent on passive config alone when CONFIG_MODULE_SIG_FORCE == "y"
        let r_cfg_sig_force = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_module"])),
            (
                "kernel.config",
                "options",
                json!({
                    "CONFIG_MODULES": "y",
                    "CONFIG_MODULE_SIG_FORCE": "y",
                }),
            ),
        ]);
        assert!(
            rule("AMR-023").evaluate(&r_cfg_sig_force, false).is_none(),
            "AMR-023 must NOT fire on passive config alone when CONFIG_MODULE_SIG_FORCE == y"
        );

        // Silent when modules_disabled == true
        let r_dis = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_module"])),
            ("kernel.surface", "modules_disabled", json!(true)),
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "permitted"}),
            ),
        ]);
        assert!(rule("AMR-023").evaluate(&r_dis, false).is_none());

        // Silent without cap_sys_module
        let r_nocap = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_admin"])),
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "permitted"}),
            ),
        ]);
        assert!(rule("AMR-023").evaluate(&r_nocap, false).is_none());
    }

    #[test]
    fn kernel_execution_rules_amr024_kexec() {
        // Fires when cap_sys_boot held, kexec_load permitted, lockdown not integrity/confidentiality
        let r = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            ("kernel.surface", "lockdown", json!("none")),
        ]);
        let f = rule("AMR-024")
            .evaluate(&r, false)
            .expect("AMR-024 must fire when kexec permitted");
        assert_eq!(f.severity, Severity::High);

        // Fires when kexec_file_load permitted
        let r_file = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "permitted"}),
            ),
        ]);
        assert!(rule("AMR-024").evaluate(&r_file, false).is_some());

        // Fires when passive CONFIG_KEXEC == "y" or CONFIG_KEXEC_FILE == "y"
        let r_cfg = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.config", "options", json!({"CONFIG_KEXEC": "y"})),
        ]);
        assert!(rule("AMR-024").evaluate(&r_cfg, false).is_some());

        // Silent when lockdown is integrity
        let r_lock = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            ("kernel.surface", "lockdown", json!("integrity")),
        ]);
        assert!(rule("AMR-024").evaluate(&r_lock, false).is_none());

        // Silent when lockdown is confidentiality
        let r_conf = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            ("kernel.surface", "lockdown", json!("confidentiality")),
        ]);
        assert!(rule("AMR-024").evaluate(&r_conf, false).is_none());

        // Silent when kexec_load_disabled == true
        let r_dis = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.surface", "kexec_load_disabled", json!(true)),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
        ]);
        assert!(rule("AMR-024").evaluate(&r_dis, false).is_none());

        // Silent without cap_sys_boot
        let r_nocap = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_admin"])),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
        ]);
        assert!(rule("AMR-024").evaluate(&r_nocap, false).is_none());
    }

    #[test]
    fn kernel_execution_rules_amr025_raw_memory() {
        // dev_mem accessible -> Critical
        let r_mem = report_with(&[
            ("kernel.surface", "dev_mem", json!("accessible")),
            ("kernel.surface", "lockdown", json!("none")),
        ]);
        let f = rule("AMR-025")
            .evaluate(&r_mem, false)
            .expect("AMR-025 must fire on dev_mem accessible");
        assert_eq!(f.severity, Severity::Critical);

        // dev_kmem accessible -> Critical
        let r_kmem = report_with(&[("kernel.surface", "dev_kmem", json!("accessible"))]);
        assert!(rule("AMR-025").evaluate(&r_kmem, false).is_some());

        // iopl permitted -> Critical
        let r_iopl = report_with(&[("kernel.exec", "iopl", json!({"status": "permitted"}))]);
        assert!(rule("AMR-025").evaluate(&r_iopl, false).is_some());

        // Silent when lockdown is integrity or confidentiality
        let r_lock = report_with(&[
            ("kernel.surface", "dev_mem", json!("accessible")),
            ("kernel.surface", "lockdown", json!("integrity")),
        ]);
        assert!(rule("AMR-025").evaluate(&r_lock, false).is_none());

        // Silent when restricted or absent
        let r_abs = report_with(&[
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("restricted")),
            ("kernel.exec", "iopl", json!({"status": "denied"})),
        ]);
        assert!(rule("AMR-025").evaluate(&r_abs, false).is_none());
    }

    #[test]
    fn kernel_execution_rules_amr026_usmh_writable() {
        // core_pattern writable -> High
        let r_core = report_with(&[(
            "kernel.surface",
            "core_pattern",
            json!({"pattern": "|/bin/helper", "writable": true}),
        )]);
        let f = rule("AMR-026")
            .evaluate(&r_core, false)
            .expect("AMR-026 must fire when core_pattern is writable");
        assert_eq!(f.severity, Severity::High);

        // modprobe writable -> High
        let r_mod = report_with(&[(
            "kernel.surface",
            "modprobe",
            json!({"path": "/sbin/modprobe", "writable": true}),
        )]);
        assert!(rule("AMR-026").evaluate(&r_mod, false).is_some());

        // Silent when neither writable
        let r_ro = report_with(&[
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
        ]);
        assert!(rule("AMR-026").evaluate(&r_ro, false).is_none());
    }

    #[test]
    fn kernel_execution_rules_amr027_acpi_table_writable() {
        let r_acpi = report_with(&[("kernel.surface", "acpi_table_writable", json!(true))]);
        let f = rule("AMR-027")
            .evaluate(&r_acpi, false)
            .expect("AMR-027 must fire when acpi_table_writable is true");
        assert_eq!(f.severity, Severity::High);

        let r_ro = report_with(&[("kernel.surface", "acpi_table_writable", json!(false))]);
        assert!(rule("AMR-027").evaluate(&r_ro, false).is_none());
    }

    #[test]
    fn kernel_execution_rules_amr028_chained_kexec_bypass_and_suppression() {
        // AMR-028 fires when kexec is open AND modules are blocked
        let r_bypass = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_boot"])),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            ("kernel.surface", "modules_disabled", json!(true)),
        ]);
        let f = rule("AMR-028")
            .evaluate(&r_bypass, false)
            .expect("AMR-028 must fire when kexec open and modules blocked");
        assert_eq!(f.severity, Severity::High);
        // AMR-024 also fires
        assert!(rule("AMR-024").evaluate(&r_bypass, false).is_some());
        // AMR-023 does not fire
        assert!(rule("AMR-023").evaluate(&r_bypass, false).is_none());

        // AMR-028 is SUPPRESSED when direct module loading is open (AMR-023 fires)
        let r_suppressed = report_with(&[
            (
                "capabilities",
                "effective",
                json!(["cap_sys_boot", "cap_sys_module"]),
            ),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "permitted"}),
            ),
        ]);
        assert!(
            rule("AMR-023").evaluate(&r_suppressed, false).is_some(),
            "AMR-023 must fire"
        );
        assert!(
            rule("AMR-024").evaluate(&r_suppressed, false).is_some(),
            "AMR-024 must fire"
        );
        assert!(
            rule("AMR-028").evaluate(&r_suppressed, false).is_none(),
            "AMR-028 must be suppressed when AMR-023 fires"
        );

        // AMR-028 is silent when kexec is NOT permitted (AMR-024 does not fire)
        let r_nokexec = report_with(&[
            ("capabilities", "effective", json!(["cap_sys_admin"])),
            ("kernel.surface", "modules_disabled", json!(true)),
        ]);
        assert!(rule("AMR-028").evaluate(&r_nokexec, false).is_none());

        // AMR-028 fires when module loading is blocked by active probe denial even if CONFIG_MODULES=y
        let r_active_blocked = report_with(&[
            (
                "capabilities",
                "effective",
                json!(["cap_sys_boot", "cap_sys_module"]),
            ),
            ("kernel.exec", "kexec_load", json!({"status": "permitted"})),
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            ("kernel.config", "options", json!({"CONFIG_MODULES": "y"})),
        ]);
        assert!(
            rule("AMR-023").evaluate(&r_active_blocked, false).is_none(),
            "AMR-023 must not fire when active probe denied"
        );
        assert!(
            rule("AMR-024").evaluate(&r_active_blocked, false).is_some(),
            "AMR-024 must fire"
        );
        assert!(
            rule("AMR-028").evaluate(&r_active_blocked, false).is_some(),
            "AMR-028 must fire when active probe confirmed modules blocked"
        );

        // AMR-028 fires when module loading is blocked passively by CONFIG_MODULE_SIG_FORCE=y and kexec is open
        let r_sig_force_kexec = report_with(&[
            (
                "capabilities",
                "effective",
                json!(["cap_sys_boot", "cap_sys_module"]),
            ),
            (
                "kernel.config",
                "options",
                json!({
                    "CONFIG_MODULES": "y",
                    "CONFIG_MODULE_SIG_FORCE": "y",
                    "CONFIG_KEXEC": "y",
                }),
            ),
        ]);
        assert!(
            rule("AMR-023")
                .evaluate(&r_sig_force_kexec, false)
                .is_none(),
            "AMR-023 must not fire when CONFIG_MODULE_SIG_FORCE=y"
        );
        assert!(
            rule("AMR-028")
                .evaluate(&r_sig_force_kexec, false)
                .is_some(),
            "AMR-028 must fire when module loading is blocked by CONFIG_MODULE_SIG_FORCE=y and kexec is open"
        );
    }

    #[test]
    fn kernel_execution_rules_amr029_opt_in_probe_report() {
        // AMR-029 fires when active probe ran (kernel.exec facts present) AND none of AMR-023..028 fired
        let r_safe = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        let f = rule("AMR-029")
            .evaluate(&r_safe, false)
            .expect("AMR-029 must fire when active probe confirmed all closed");
        assert_eq!(f.severity, Severity::Info);

        // Also fires when non-x86 iopl status is "unsupported_arch" and others denied
        let r_unsupported_arch = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "unsupported_arch", "errno": 38, "error_name": "ENOSYS"}),
            ),
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        assert!(
            rule("AMR-029")
                .evaluate(&r_unsupported_arch, false)
                .is_some()
        );

        // AMR-029 does NOT fire when active probe did not run (no kernel.exec facts)
        let r_noprobe = report_with(&[("kernel.surface", "dev_mem", json!("absent"))]);
        assert!(rule("AMR-029").evaluate(&r_noprobe, false).is_none());

        // AMR-029 does NOT fire when any of AMR-023..028 fired (e.g. dev_mem accessible)
        let r_unsafe = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            ("kernel.surface", "dev_mem", json!("accessible")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        assert!(rule("AMR-025").evaluate(&r_unsafe, false).is_some());
        assert!(rule("AMR-029").evaluate(&r_unsafe, false).is_none());

        // AMR-029 does NOT fire when any active probe test reported status == "error" (e.g. timeout / IPC failure)
        let r_error = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        assert!(
            rule("AMR-029").evaluate(&r_error, false).is_none(),
            "AMR-029 must not fire when any test has status == error"
        );

        // AMR-029 does NOT fire when all tests timed out / errored
        let r_all_error = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "error", "errno": libc::ETIMEDOUT, "error_name": "ETIMEDOUT"}),
            ),
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        assert!(
            rule("AMR-029").evaluate(&r_all_error, false).is_none(),
            "AMR-029 must not fire when all tests timed out / errored"
        );

        // AMR-029 fires when tests are a combination of denied and unsupported
        let r_unsupported = report_with(&[
            (
                "kernel.exec",
                "finit_module",
                json!({"status": "unsupported", "errno": libc::ENOSYS, "error_name": "ENOSYS"}),
            ),
            (
                "kernel.exec",
                "init_module",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_load",
                json!({"status": "denied", "errno": 1, "error_name": "EPERM"}),
            ),
            (
                "kernel.exec",
                "kexec_file_load",
                json!({"status": "unsupported", "errno": libc::ENOSYS, "error_name": "ENOSYS"}),
            ),
            (
                "kernel.exec",
                "iopl",
                json!({"status": "unsupported_arch", "errno": libc::ENOSYS, "error_name": "ENOSYS"}),
            ),
            ("kernel.surface", "dev_mem", json!("absent")),
            ("kernel.surface", "dev_kmem", json!("absent")),
            (
                "kernel.surface",
                "core_pattern",
                json!({"pattern": "|/bin/helper", "writable": false}),
            ),
            (
                "kernel.surface",
                "modprobe",
                json!({"path": "/sbin/modprobe", "writable": false}),
            ),
            ("kernel.surface", "acpi_table_writable", json!(false)),
        ]);
        assert!(
            rule("AMR-029").evaluate(&r_unsupported, false).is_some(),
            "AMR-029 must fire when all pathways are verified denied, unsupported, or unsupported_arch"
        );
    }

    // ---------------------------------------------------------------- AMR-030..033 (Mounts)

    #[test]
    fn mount_rules_amr030_staging_mount_unhardened() {
        let staging_mount_with_nodev = json!([{
            "mount_point": "/tmp",
            "fstype": "tmpfs",
            "writable_by_caller": true,
            "missing_flags": ["noexec", "nosuid"],
            "options": ["rw", "nodev"]
        }]);

        let staging_mount_missing_nodev = json!([{
            "mount_point": "/tmp",
            "fstype": "tmpfs",
            "writable_by_caller": true,
            "missing_flags": ["noexec", "nosuid", "nodev"],
            "options": ["rw"]
        }]);

        // Container with staging mount and nodev -> Medium
        let mut r_med = report_with(&[("mounts", "staging", staging_mount_with_nodev.clone())]);
        r_med.verdict = Some(verdict(RuntimeKind::Docker));
        let f_med = rule("AMR-030")
            .evaluate(&r_med, false)
            .expect("AMR-030 must fire in container");
        assert_eq!(f_med.severity, Severity::Medium);
        assert_eq!(f_med.evidence.len(), 1);
        assert_eq!(f_med.evidence[0].probe, "mounts");
        assert_eq!(f_med.evidence[0].key, "staging");

        // Container with missing nodev AND cap_mknod -> High
        let mut r_high = report_with(&[
            ("mounts", "staging", staging_mount_missing_nodev.clone()),
            ("capabilities", "effective", json!(["cap_mknod"])),
        ]);
        r_high.verdict = Some(verdict(RuntimeKind::Docker));
        let f_high = rule("AMR-030")
            .evaluate(&r_high, false)
            .expect("AMR-030 must fire as High with cap_mknod");
        assert_eq!(f_high.severity, Severity::High);

        // Container with missing nodev but WITHOUT cap_mknod -> remains Medium
        let mut r_no_mknod = report_with(&[
            ("mounts", "staging", staging_mount_missing_nodev.clone()),
            ("capabilities", "effective", json!(["cap_chown"])),
        ]);
        r_no_mknod.verdict = Some(verdict(RuntimeKind::Docker));
        let f_no_mknod = rule("AMR-030")
            .evaluate(&r_no_mknod, false)
            .expect("AMR-030 fires Medium without cap_mknod");
        assert_eq!(f_no_mknod.severity, Severity::Medium);

        // Bare host with staging mount -> Info and rule has verbose_only = true
        let mut r_host = report_with(&[("mounts", "staging", staging_mount_missing_nodev)]);
        r_host.verdict = Some(verdict(RuntimeKind::Host));
        let rule_030 = rule("AMR-030");
        assert!(
            rule_030.verbose_only,
            "AMR-030 rule must have verbose_only = true"
        );
        let f_host = rule_030
            .evaluate(&r_host, false)
            .expect("AMR-030 fires as Info on bare host");
        assert_eq!(f_host.severity, Severity::Info);

        // Empty staging mounts -> does NOT fire
        let mut r_empty = report_with(&[("mounts", "staging", json!([]))]);
        r_empty.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-030").evaluate(&r_empty, false).is_none());
    }

    #[test]
    fn amr030_verbose_only_never_hides_container_findings() {
        // verbose_only hides a finding iff severity == Info && !verbose: the
        // flag is set, yet a contained process's finding is >= Medium and so
        // stays visible in default text output.
        let rule_030 = rule("AMR-030");
        assert!(rule_030.verbose_only);
        let mut r = report_with(&[(
            "mounts",
            "staging",
            json!([{"mount_point": "/tmp", "missing_flags": ["noexec"], "options": ["rw", "nodev"]}]),
        )]);
        r.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule_030.evaluate(&r, false).expect("fires in container");
        assert!(f.severity >= Severity::Medium, "got {:?}", f.severity);
    }

    #[test]
    fn amr030_downgrades_to_info_only_on_host_verdict() {
        let missing_nodev = json!([{
            "mount_point": "/tmp",
            "missing_flags": ["noexec", "nosuid", "nodev"],
            "options": ["rw"]
        }]);
        let with_nodev = json!([{
            "mount_point": "/tmp",
            "missing_flags": ["noexec"],
            "options": ["rw", "nodev"]
        }]);
        // Absent verdict = containment unknown: no downgrade.
        let r_absent = report_with(&[("mounts", "staging", with_nodev.clone())]);
        assert!(r_absent.verdict.is_none());
        let f = rule("AMR-030").evaluate(&r_absent, false).expect("fires");
        assert_eq!(f.severity, Severity::Medium);
        // VM-family sandboxes are not Host: no downgrade, and the nodev +
        // cap_mknod elevation still applies.
        for runtime in [
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
        ] {
            let mut r = report_with(&[("mounts", "staging", with_nodev.clone())]);
            r.verdict = Some(verdict(runtime));
            let f = rule("AMR-030").evaluate(&r, false).expect("fires");
            assert_eq!(f.severity, Severity::Medium, "{runtime:?}");

            let mut r = report_with(&[
                ("mounts", "staging", missing_nodev.clone()),
                ("capabilities", "effective", json!(["cap_mknod"])),
            ]);
            r.verdict = Some(verdict(runtime));
            let f = rule("AMR-030").evaluate(&r, false).expect("fires");
            assert_eq!(f.severity, Severity::High, "{runtime:?}");
        }
        // Host verdict downgrades even with the High conjuncts open.
        let mut r_host = report_with(&[
            ("mounts", "staging", missing_nodev),
            ("capabilities", "effective", json!(["cap_mknod"])),
        ]);
        r_host.verdict = Some(verdict(RuntimeKind::Host));
        let f = rule("AMR-030").evaluate(&r_host, false).expect("fires");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn mount_rules_amr031_sensitive_proc_sys_unmasked() {
        let unmasked = json!(["/proc/sys", "/proc/kcore"]);

        // In container -> High
        let mut r_cont = report_with(&[("mounts", "sensitive_unmasked", unmasked.clone())]);
        r_cont.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-031")
            .evaluate(&r_cont, false)
            .expect("AMR-031 must fire in container");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].probe, "mounts");
        assert_eq!(f.evidence[0].key, "sensitive_unmasked");

        // On bare host -> silenced
        let mut r_host = report_with(&[("mounts", "sensitive_unmasked", unmasked)]);
        r_host.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-031").evaluate(&r_host, false).is_none());

        // Empty -> does NOT fire
        let mut r_empty = report_with(&[("mounts", "sensitive_unmasked", json!([]))]);
        r_empty.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-031").evaluate(&r_empty, false).is_none());
    }

    #[test]
    fn mount_rules_amr032_shared_mount_propagation() {
        let shared = json!(["/var/lib/docker", "/mnt/share"]);

        // In container -> Medium
        let mut r_cont = report_with(&[("mounts", "shared_propagation", shared.clone())]);
        r_cont.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-032")
            .evaluate(&r_cont, false)
            .expect("AMR-032 must fire in container");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].probe, "mounts");
        assert_eq!(f.evidence[0].key, "shared_propagation");

        // On bare host -> silenced
        let mut r_host = report_with(&[("mounts", "shared_propagation", shared)]);
        r_host.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-032").evaluate(&r_host, false).is_none());

        // Empty -> does NOT fire
        let mut r_empty = report_with(&[("mounts", "shared_propagation", json!([]))]);
        r_empty.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-032").evaluate(&r_empty, false).is_none());
    }

    #[test]
    fn mount_rules_amr033_host_filesystem_exposed() {
        let leaks = json!(["/host", "/"]);

        // In container -> Critical
        let mut r_cont = report_with(&[("mounts", "host_leaks", leaks.clone())]);
        r_cont.verdict = Some(verdict(RuntimeKind::Docker));
        let f = rule("AMR-033")
            .evaluate(&r_cont, false)
            .expect("AMR-033 must fire in container");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].probe, "mounts");
        assert_eq!(f.evidence[0].key, "host_leaks");

        // On bare host -> silenced
        let mut r_host = report_with(&[("mounts", "host_leaks", leaks)]);
        r_host.verdict = Some(verdict(RuntimeKind::Host));
        assert!(rule("AMR-033").evaluate(&r_host, false).is_none());

        // Empty -> does NOT fire
        let mut r_empty = report_with(&[("mounts", "host_leaks", json!([]))]);
        r_empty.verdict = Some(verdict(RuntimeKind::Docker));
        assert!(rule("AMR-033").evaluate(&r_empty, false).is_none());
    }
}
