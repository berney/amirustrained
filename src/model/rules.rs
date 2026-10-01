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
        // 014–018 after AMR-013, Task 28 appended 019–020, Task 29 021.
        assert_eq!(
            ids,
            [
                "AMR-001", "AMR-002", "AMR-003", "AMR-004", "AMR-005", "AMR-006", "AMR-022",
                "AMR-007", "AMR-008", "AMR-009", "AMR-010", "AMR-011", "AMR-012", "AMR-013",
                "AMR-014", "AMR-015", "AMR-016", "AMR-017", "AMR-018", "AMR-019", "AMR-020",
                "AMR-021",
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
}
