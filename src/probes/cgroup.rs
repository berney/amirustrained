use super::Probe;
use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::pipeline::Ctx;
use crate::sys::fs::{PseudoFs, errno_of};

const PROBE: &str = "cgroup";

/// Maps a cgroup path to a runtime kind plus the stable pattern string the
/// fact reports. Ordered most-specific first: a kubepods slice outranks any
/// docker/libpod wording inside it, and `libpod-` scopes also live under
/// `/user.slice`, so the systemd fallback must come last.
///
/// `(None, Some(pattern))` is a hint only (systemd-managed, or the bare root
/// cgroup of a container without its own naming); it never signals a runtime.
pub fn classify(path: &str) -> (Option<RuntimeKind>, Option<&'static str>) {
    let hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
    if path.contains("kubepods") {
        return (Some(RuntimeKind::Kubernetes), Some("kubernetes"));
    }
    if path.contains("libpod-") {
        return (Some(RuntimeKind::Podman), Some("podman"));
    }
    if path.contains("/docker/") || path.starts_with("docker-") {
        let last = path.rsplit(['/', '-']).next().unwrap_or("");
        if hex64(last) || path.contains("/docker/") {
            return (Some(RuntimeKind::Docker), Some("docker"));
        }
    }
    if path.starts_with("/lxc") || path.contains("/lxc.payload.") {
        return (Some(RuntimeKind::Lxc), Some("lxc"));
    }
    if path.contains("machine-nspawn") || path.contains("nspawn") {
        return (Some(RuntimeKind::SystemdNspawn), Some("nspawn"));
    }
    if path.starts_with("/user.slice") || path.starts_with("/system.slice") {
        return (None, Some("systemd"));
    }
    if path == "/" {
        return (None, Some("root"));
    }
    (None, None)
}

/// Reads `/proc/<pid>/cgroup` and, on unified hierarchies, the matching
/// `/sys/fs/cgroup` limit/controller files. An unreadable cgroup file is the
/// only hard failure: the probe degrades to a single `unavailable` fact
/// (nothing may guess a version or path from it) and never crashes.
pub fn probe_cgroup(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let src = format!("/proc/{pid}/cgroup");
    let raw = match fs.read(&src) {
        Ok(raw) => raw,
        Err(e) => return o.with_fact(Fact::unavailable(PROBE, "path", src, errno_of(&e))),
    };
    let (version, path) = parse_cgroup_line(&raw);
    let (kind, pattern) = classify(&path);
    o = o.with_fact(Fact::ok(PROBE, "version", version.into(), src.clone()));
    o = o.with_fact(Fact::ok(PROBE, "path", path.clone().into(), src));
    let pattern_fact = Fact::ok(
        PROBE,
        "pattern",
        pattern
            .map(|p| serde_json::json!(p))
            .unwrap_or(serde_json::Value::Null),
        path.clone(),
    );
    o = o.with_fact(pattern_fact.clone());
    if version == 2 {
        let cgroot = "/sys/fs/cgroup";
        if let Ok(c) = fs.read(&format!("{cgroot}/cgroup.controllers")) {
            o = o.with_fact(Fact::ok(
                PROBE,
                "controllers",
                c.split_whitespace().collect::<Vec<_>>().into(),
                format!("{cgroot}/cgroup.controllers"),
            ));
        }
        // `"max"` is the kernel's spelling of unlimited; reported verbatim.
        let mut limits = serde_json::Map::new();
        for k in ["memory.max", "pids.max", "cpu.max"] {
            if let Ok(v) = fs.read(&format!("{cgroot}{path}/{k}")) {
                limits.insert(k.trim_end_matches(".max").into(), v.into());
            }
        }
        o = o.with_fact(Fact::ok(
            PROBE,
            "limits",
            serde_json::Value::Object(limits),
            format!("{cgroot}{path}"),
        ));
    }
    if let Some(rt) = kind {
        let w = match rt {
            RuntimeKind::Docker => 0.8,
            RuntimeKind::Kubernetes => 0.7,
            RuntimeKind::Podman => 0.7,
            RuntimeKind::Lxc => 0.7,
            RuntimeKind::SystemdNspawn => 0.6,
            _ => 0.0,
        };
        if w > 0.0 {
            o = o.with_signal(Signal {
                runtime: rt,
                weight: w,
                evidence: pattern_fact,
                // Own-cgroup classification is self-containment proof: it scores.
                env_only: false,
            });
        }
    }
    o
}

/// Detects the hierarchy version from the first line and extracts its path:
/// v2 is the single `0::/path` line, v1 lists `N:controllers:/path` per
/// hierarchy. Hybrid hosts list the v1 lines first, so the first line decides
/// (the brief's rule; no second-guessing of mixed layouts).
pub fn parse_cgroup_line(raw: &str) -> (u8, String) {
    let first = raw.lines().next().unwrap_or("");
    if let Some(rest) = first.strip_prefix("0::") {
        (2, rest.to_string())
    } else {
        (1, first.rsplit(':').next().unwrap_or("/").to_string())
    }
}

pub struct Cgroup;

impl Probe for Cgroup {
    fn name(&self) -> &'static str {
        PROBE
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_cgroup(cx.fs, cx.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;

    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, c) in files {
            let full = d.path().join(p.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        }
        d
    }

    fn fact<'a>(o: &'a ProbeOutcome, key: &str) -> &'a Fact {
        o.facts
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("missing fact {key}"))
    }

    #[test]
    fn classifies_runtime_paths() {
        assert_eq!(
            classify("/docker/135c8edbc014a110669e20515a1a90d3f4d2ee5c50ee50a03e6a9ed7d1c8c4a2").0,
            Some(RuntimeKind::Docker)
        );
        assert_eq!(
            classify("/kubepods/besteffort/pod73f1a1b2-1234/cpu.slice").0,
            Some(RuntimeKind::Kubernetes)
        );
        assert_eq!(
            classify(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-1a2b3c4d.scope"
            )
            .0,
            Some(RuntimeKind::Podman)
        );
        assert_eq!(classify("/lxc/mycontainer").0, Some(RuntimeKind::Lxc));
        assert_eq!(
            classify("/machine.slice/machine-nspawn1.scope").0,
            Some(RuntimeKind::SystemdNspawn)
        );
        assert_eq!(classify("/user.slice/session-1.scope").0, None);
        assert_eq!(classify("/user.slice/session-1.scope").1, Some("systemd"));
    }

    #[test]
    fn v2_and_limits() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sys/fs/cgroup/user.slice")).unwrap();
        std::fs::write(
            d.path().join("sys/fs/cgroup/cgroup.controllers"),
            "cpu memory pids\n",
        )
        .unwrap();
        std::fs::write(d.path().join("sys/fs/cgroup/user.slice/pids.max"), "2048\n").unwrap();
        std::fs::write(
            d.path().join("sys/fs/cgroup/user.slice/memory.max"),
            "max\n",
        )
        .unwrap();
        std::fs::create_dir_all(d.path().join("proc/9")).unwrap();
        std::fs::write(d.path().join("proc/9/cgroup"), "0::/user.slice\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 9);
        assert_eq!(
            o.facts.iter().find(|f| f.key == "version").unwrap().value,
            serde_json::json!(2)
        );
        assert_eq!(
            o.facts.iter().find(|f| f.key == "limits").unwrap().value["pids"],
            "2048"
        );
        assert_eq!(
            o.facts.iter().find(|f| f.key == "limits").unwrap().value["memory"],
            "max"
        );
    }

    #[test]
    fn v1_first_line_yields_docker_signal_and_no_v2_facts() {
        // v1 layout: many `N:ctrl:/path` lines; the brief parses the first
        // line's path and never emits controllers/limits (v2-only facts).
        let hex = "135c8edbc014a110669e20515a1a90d3f4d2ee5c50ee50a03e6a9ed7d1c8c4a2";
        let d = fixture(&[(
            "proc/12/cgroup",
            &format!("11:name=systemd:/docker/{hex}\n5:cpu,cpuacct:/docker/{hex}\n"),
        )]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 12);
        assert_eq!(fact(&o, "version").value, serde_json::json!(1));
        assert_eq!(fact(&o, "path").value, format!("/docker/{hex}"));
        assert_eq!(fact(&o, "pattern").value, "docker");
        assert!(
            o.facts
                .iter()
                .all(|f| f.key != "controllers" && f.key != "limits"),
            "controllers/limits are v2-only"
        );
        assert_eq!(o.signals.len(), 1);
        assert_eq!(o.signals[0].runtime, RuntimeKind::Docker);
        assert_eq!(o.signals[0].weight, 0.8);
        assert_eq!(o.signals[0].evidence.key, "pattern");
    }

    #[test]
    fn hybrid_reports_version_from_first_line() {
        // Hybrid hosts list the v1 hierarchies first and `0::` last; per the
        // brief the version comes from the first line, so this reads as v1.
        let d = fixture(&[(
            "proc/8/cgroup",
            "1:name=systemd:/user.slice/user-1000.slice/session-1.scope\n0::/user.slice/user-1000.slice/session-1.scope\n",
        )]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 8);
        assert_eq!(fact(&o, "version").value, serde_json::json!(1));
        assert_eq!(
            fact(&o, "path").value,
            "/user.slice/user-1000.slice/session-1.scope"
        );
        assert_eq!(fact(&o, "pattern").value, "systemd");
        assert!(o.signals.is_empty());
    }

    #[test]
    fn v2_lists_controllers_and_omits_absent_limit_keys() {
        let d = fixture(&[
            ("proc/9/cgroup", "0::/user.slice\n"),
            (
                "sys/fs/cgroup/cgroup.controllers",
                "cpuset cpu io memory pids\n",
            ),
            ("sys/fs/cgroup/user.slice/cpu.max", "max 100000\n"),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 9);
        assert_eq!(
            fact(&o, "controllers").value,
            serde_json::json!(["cpuset", "cpu", "io", "memory", "pids"])
        );
        assert_eq!(
            fact(&o, "controllers").source,
            "/sys/fs/cgroup/cgroup.controllers"
        );
        let limits = fact(&o, "limits");
        assert_eq!(limits.value, serde_json::json!({ "cpu": "max 100000" }));
        assert!(limits.value.get("memory").is_none());
        assert!(limits.value.get("pids").is_none());
    }

    #[test]
    fn unreadable_cgroup_yields_only_an_unavailable_path_fact() {
        // Nothing readable: the probe degrades to a single unavailable `path`
        // fact carrying ENOENT; no version/pattern guesses, no signals.
        let d = fixture(&[]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 9);
        assert_eq!(o.name, "cgroup");
        assert_eq!(o.facts.len(), 1);
        let p = fact(&o, "path");
        assert_eq!(p.status, FactStatus::Unavailable);
        assert_eq!(p.source, "/proc/9/cgroup");
        assert_eq!(p.value["unavailable"], serde_json::json!(true));
        assert_eq!(p.value["errno"], serde_json::json!(2));
        assert!(o.signals.is_empty());
    }

    #[test]
    fn signal_weights_follow_the_table() {
        let cases = [
            (
                "/docker/135c8edbc014a110669e20515a1a90d3f4d2ee5c50ee50a03e6a9ed7d1c8c4a2",
                RuntimeKind::Docker,
                0.8f32,
                "docker",
            ),
            (
                "/kubepods/burstable/pod73f1a1b2-1234/cri-containerd-1a2b.scope",
                RuntimeKind::Kubernetes,
                0.7,
                "kubernetes",
            ),
            (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-1a2b3c4d.scope",
                RuntimeKind::Podman,
                0.7,
                "podman",
            ),
            ("/lxc/mycontainer", RuntimeKind::Lxc, 0.7, "lxc"),
            (
                "/machine.slice/machine-nspawn1.scope",
                RuntimeKind::SystemdNspawn,
                0.6,
                "nspawn",
            ),
        ];
        for (path, kind, weight, pattern) in cases {
            let d = fixture(&[("proc/7/cgroup", &format!("0::{path}\n"))]);
            let fs = crate::sys::fs::PseudoFs::new(d.path().into());
            let o = probe_cgroup(&fs, 7);
            assert_eq!(o.signals.len(), 1, "{path} must emit exactly one signal");
            assert_eq!(o.signals[0].runtime, kind, "{path}");
            assert_eq!(o.signals[0].weight, weight, "{path}");
            assert_eq!(o.signals[0].evidence.key, "pattern");
            assert_eq!(o.signals[0].evidence.value, pattern);
        }
    }

    #[test]
    fn systemd_and_root_patterns_carry_no_signal() {
        for (path, pattern) in [("/user.slice/session-1.scope", "systemd"), ("/", "root")] {
            let d = fixture(&[("proc/7/cgroup", &format!("0::{path}\n"))]);
            let fs = crate::sys::fs::PseudoFs::new(d.path().into());
            let o = probe_cgroup(&fs, 7);
            assert_eq!(fact(&o, "pattern").value, pattern);
            assert!(o.signals.is_empty(), "{path} must not signal a runtime");
        }
        // An unclassifiable path leaves pattern null — still no signal.
        assert_eq!(classify("/foo/bar"), (None, None));
        let d = fixture(&[("proc/7/cgroup", "0::/foo/bar\n")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_cgroup(&fs, 7);
        assert_eq!(fact(&o, "pattern").value, serde_json::Value::Null);
        assert!(o.signals.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_smoke_is_structurally_wellformed() {
        // Structural shape only: never assert this host's runtime verdict.
        let o = probe_cgroup(&crate::sys::fs::PseudoFs::real(), std::process::id());
        assert_eq!(o.name, "cgroup");
        assert!(o.facts.iter().all(|f| f.probe == "cgroup"));
        let version = fact(&o, "version").value.clone();
        assert!(version == serde_json::json!(1) || version == serde_json::json!(2));
        assert!(fact(&o, "path").value.is_string());
        let pattern = fact(&o, "pattern").value.clone();
        assert!(pattern.is_string() || pattern.is_null());
        if version == serde_json::json!(2) {
            if let Some(c) = o.facts.iter().find(|f| f.key == "controllers") {
                assert!(
                    c.value.as_array().unwrap().iter().all(|v| v.is_string()),
                    "controllers must be strings"
                );
            }
            let limits = fact(&o, "limits");
            assert!(limits.value.is_object());
            assert!(
                limits
                    .value
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|v| v.is_string())
            );
        }
        for s in &o.signals {
            assert!(s.weight > 0.0 && s.weight <= 0.8);
            assert_eq!(s.evidence.key, "pattern");
        }
    }
}
