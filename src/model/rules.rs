use super::rule::{Assess, Rule};
use super::{Finding, Report, Severity};

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
        check: |a| {
            if !a.containerized() {
                return None;
            }
            if !a.arr_has("capabilities", "effective", "cap_sys_admin")
                || !a.is("seccomp", "mode", "disabled")
            {
                return None;
            }
            let aa = a.fact("lsm", "apparmor")?;
            if !mac_unconfining(a) {
                return None;
            }
            Some(vec![
                a.fact("capabilities", "effective")?.clone(),
                a.fact("seccomp", "mode")?.clone(),
                aa.clone(),
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            // Host PID ns is tautological on a bare host: the finding is about a
            // contained process that shares it.
            if !a.containerized() {
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            if !a.containerized() {
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
        check: |a| {
            // Ungated per spec text: a host-gid-0 grant with setgroups allowed
            // moves toward root wherever the layout is found.
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
        check: |a| {
            a.fact("vmm", "hypervisor")
                .filter(|f| f.value.get("present") == Some(&serde_json::Value::Bool(true)))
                .map(|f| vec![f.clone()])
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
/// `unconfined`, or when no AppArmor fact applies (null value) and SELinux is permissive
/// or absent from the active LSM list. An `enforcing` SELinux with AppArmor absent keeps
/// the rule silent — fail closed on ambiguous stacks (null list).
fn mac_unconfining(a: &Assess) -> bool {
    let Some(aa) = a.fact("lsm", "apparmor") else {
        return false;
    };
    if let Some(profile) = aa.value.get("profile").and_then(|p| p.as_str()) {
        return profile == "unconfined";
    }
    if !aa.value.is_null() {
        return false;
    }
    let selinux_permissive = a
        .fact("lsm", "selinux")
        .is_some_and(|f| f.value.get("mode").and_then(|m| m.as_str()) == Some("permissive"));
    let selinux_absent = a.fact("lsm", "list").is_some_and(|f| {
        f.value
            .as_array()
            .is_some_and(|l| !l.iter().any(|x| x.as_str() == Some("selinux")))
    });
    selinux_permissive || selinux_absent
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

    // ---------------------------------------------------------------- AMR-011

    fn amr011_report(gid_rows: serde_json::Value, setgroups: &str) -> Report {
        report_with(&[
            ("uidmap", "gidMap", gid_rows),
            ("uidmap", "setgroups", json!(setgroups)),
        ])
    }

    #[test]
    fn amr011_fires_medium_on_host0_gid_row_with_setgroups_allow() {
        // Ungated per spec text; severity is medium (spec), not the plan's info.
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
        // id-space append (ReviewT19 F2) and keeps its slot.
        assert_eq!(
            ids,
            [
                "AMR-001", "AMR-002", "AMR-003", "AMR-004", "AMR-005", "AMR-006", "AMR-022",
                "AMR-007", "AMR-008", "AMR-009", "AMR-010", "AMR-011", "AMR-012", "AMR-013",
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
}
