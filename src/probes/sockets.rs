//! Container-runtime socket discovery (Task 15).
//!
//! Fixed candidate list — no recursive walk — probed through `PseudoFs` for
//! existence/write access; a Docker-compatible handshake (`GET /_ping` for
//! liveness, then `GET /info` for version details) runs over the unix socket
//! via `OsApi::uds_probe`. A present-but-unreachable socket is still listed
//! (writable flag + null info); only absent candidates are dropped.

use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

/// Known runtime socket paths, in report order. Fixed list by design: a
/// recursive socket hunt buys noise and traversal risk, not coverage.
pub const CANDIDATES: [(&str, &str); 7] = [
    ("/var/run/docker.sock", "docker"),
    ("/run/docker.sock", "docker"),
    ("/run/podman/podman.sock", "podman"),
    ("/run/user/1000/podman/podman.sock", "podman"),
    ("/var/run/crio/crio.sock", "crio"),
    ("/run/containerd/containerd.sock", "containerd"),
    ("/run/kata-containers/agent.sock", "kata"),
];

/// Pull the reportable fields out of a Docker/Podman `/info` reply. Absent
/// keys surface as JSON null rather than being dropped, so the fact shape
/// stays stable for the rule engine and schema consumers. `name` carries
/// Podman's self-identification (`"name": "podman"`).
pub fn extract_info(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "version": v["ServerVersion"],
        "apiVersion": v["ApiVersion"],
        "os": v["Os"],
        "kernel": v["KernelVersion"],
        "securityOptions": v["SecurityOptions"],
        "rootless": v["Rootless"],
        "name": v["Name"],
    })
}

/// Scan the fixed candidate list through `fs`. Every *existing* candidate
/// becomes a `found` entry — present-but-unwritable and present-but-dead are
/// reported (writable flag / null info); only absent paths are dropped.
/// `probe` performs the HTTP-over-uds handshake (`OsApi::uds_probe` live,
/// canned replies in tests), keyed by the candidate path.
pub fn scan_candidates(
    fs: &PseudoFs,
    probe: &dyn Fn(&str) -> std::io::Result<crate::sys::os::UdsReply>,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for (path, kind) in CANDIDATES {
        if !fs.exists(path) {
            continue;
        }
        let writable = fs.writable(path);
        let info = match probe(path) {
            Ok(r) if (200..300).contains(&r.status) => {
                serde_json::from_str::<serde_json::Value>(&r.body)
                    .ok()
                    .map(|v| extract_info(&v))
            }
            // Connect refused / timeout / non-2xx: path stays, info is null.
            _ => None,
        };
        out.push(serde_json::json!({
            "path": path,
            "writable": writable,
            "kind": kind,
            "info": info.unwrap_or(serde_json::Value::Null),
        }));
    }
    out
}

pub struct Sockets;
impl Probe for Sockets {
    fn name(&self) -> &'static str {
        "sockets"
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let mut o = ProbeOutcome::empty("sockets");
        let found = scan_candidates(cx.fs, &|p| {
            cx.os.uds_probe(
                std::path::Path::new(p),
                cx.opts
                    .probe_timeout
                    .unwrap_or(std::time::Duration::from_millis(500)),
            )
        });
        let fact = Fact::ok(
            "sockets",
            "found",
            serde_json::json!(found),
            "known runtime socket paths".into(),
        );
        for e in &found {
            if e["writable"] == serde_json::json!(true) {
                // A writable socket proves the runtime is present and
                // reachable on this machine — environment evidence, not this
                // process's own containment: it scores nothing and lands as
                // an `environment:` note (spec §5 amendment 2026-10-01).
                // containerd/kata stay fact-only (no kind map entry).
                let kind = match e["kind"].as_str() {
                    Some("podman") => RuntimeKind::Podman,
                    Some("docker") => RuntimeKind::Docker,
                    Some("crio") => RuntimeKind::CriO,
                    _ => continue,
                };
                o = o.with_signal(Signal {
                    runtime: kind,
                    weight: 0.9,
                    evidence: fact.clone(),
                    env_only: true,
                });
            }
        }
        o.with_fact(fact)
    }
}

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
        std::fs::create_dir_all(d.path().join("run/podman")).unwrap(); // brief typo: parent of the sock path
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
        let reply = crate::sys::os::UdsReply {
            status: 200,
            body: r#"{"ServerVersion":"27.1.1","ApiVersion":"1.47"}"#.into(),
        };
        let info = extract_info(&serde_json::from_str::<serde_json::Value>(&reply.body).unwrap());
        assert_eq!(info["version"], "27.1.1");
    }

    // ── presence / write-access distinction ──────────────────────────────

    #[test]
    fn unwritable_socket_is_listed_with_writable_false() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root writes anywhere; the denied≠absent split needs an unprivileged uid
        }
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run")).unwrap();
        let sock = d.path().join("run/docker.sock");
        std::fs::write(&sock, "").unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o444)).unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| Err(std::io::Error::other("no uds in fixture")));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["path"], "/run/docker.sock"); // permission-denied ≠ absent
        assert_eq!(found[0]["writable"], serde_json::json!(false));
        assert!(found[0]["info"].is_null());
    }

    #[test]
    fn multiple_candidates_report_in_candidate_order() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run/containerd")).unwrap();
        std::fs::create_dir_all(d.path().join("var/run")).unwrap();
        std::fs::write(d.path().join("var/run/docker.sock"), "").unwrap();
        std::fs::write(d.path().join("run/containerd/containerd.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| Err(std::io::Error::other("no uds in fixture")));
        assert_eq!(found.len(), 2);
        // CANDIDATES order, not directory-traversal order: docker before containerd.
        assert_eq!(found[0]["path"], "/var/run/docker.sock");
        assert_eq!(found[1]["path"], "/run/containerd/containerd.sock");
    }

    // ── handshake failure modes ───────────────────────────────────────────

    #[test]
    fn non_2xx_status_keeps_path_and_nulls_info() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("var/run")).unwrap();
        std::fs::write(d.path().join("var/run/docker.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| {
            Ok(crate::sys::os::UdsReply {
                status: 403,
                body: "forbidden".into(),
            })
        });
        assert_eq!(found[0]["path"], "/var/run/docker.sock");
        assert!(found[0]["info"].is_null()); // 403 is not a usable handshake
    }

    #[test]
    fn handshake_timeout_degrades_to_null_info() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("var/run")).unwrap();
        std::fs::write(d.path().join("var/run/docker.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "uds read timed out",
            ))
        });
        assert_eq!(found[0]["path"], "/var/run/docker.sock");
        assert_eq!(found[0]["writable"], serde_json::json!(true));
        assert!(found[0]["info"].is_null());
    }

    #[test]
    fn malformed_json_body_degrades_to_null_info() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("var/run")).unwrap();
        std::fs::write(d.path().join("var/run/docker.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let found = scan_candidates(&fs, &|_| {
            Ok(crate::sys::os::UdsReply {
                status: 200,
                body: "not json".into(),
            })
        });
        assert!(found[0]["info"].is_null()); // 200 + garbage body ⇒ no info, path kept
    }

    // ── Probe::run through Ctx (stubbed OsApi) ────────────────────────────

    struct StubOs {
        status: u16,
        body: &'static str,
    }
    impl crate::sys::os::OsApi for StubOs {
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            Default::default()
        }
        fn landlock_abi(&self) -> Option<u64> {
            None
        }
        fn seccomp_actions(&self) -> crate::sys::os::SeccompActions {
            Default::default()
        }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::sys::fs::ProbeIo> {
            Err(crate::sys::fs::ProbeIo::PermissionDenied)
        }
        fn syscall0(&self, _n: u32) -> Result<(), i32> {
            Err(38)
        }
        fn uds_probe(
            &self,
            _p: &std::path::Path,
            _t: std::time::Duration,
        ) -> std::io::Result<crate::sys::os::UdsReply> {
            Ok(crate::sys::os::UdsReply {
                status: self.status,
                body: self.body.to_string(),
            })
        }
        fn env(&self, _k: &str) -> Option<String> {
            None
        }
        fn is_root(&self) -> bool {
            false
        }
    }

    #[test]
    fn run_emits_docker_signal_with_handshake_info() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("var/run")).unwrap();
        std::fs::write(d.path().join("var/run/docker.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            status: 200,
            body: r#"{"ServerVersion":"27.1.1","ApiVersion":"1.47","Name":"host-a"}"#,
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        let o = Sockets.run(&cx);
        assert_eq!(o.name, "sockets");
        assert_eq!(o.facts.len(), 1);
        assert_eq!(o.facts[0].probe, "sockets");
        assert_eq!(o.facts[0].key, "found");
        assert_eq!(o.facts[0].source, "known runtime socket paths");
        assert_eq!(o.facts[0].value[0]["info"]["version"], "27.1.1");
        assert_eq!(o.facts[0].value[0]["info"]["apiVersion"], "1.47");
        assert_eq!(o.signals.len(), 1);
        assert_eq!(o.signals[0].runtime, RuntimeKind::Docker);
        assert!((o.signals[0].weight - 0.9).abs() < f32::EPSILON);
        assert!(
            o.signals[0].env_only,
            "a reachable socket is environment presence, not containment"
        );
    }

    #[test]
    fn run_emits_podman_signal_for_writable_podman_socket() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run/podman")).unwrap();
        std::fs::write(d.path().join("run/podman/podman.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            status: 200,
            body: r#"{"ServerVersion":"5.2.0","ApiVersion":"1.47","Name":"podman"}"#,
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        let o = Sockets.run(&cx);
        assert_eq!(o.signals.len(), 1);
        assert_eq!(o.signals[0].runtime, RuntimeKind::Podman);
        assert!(o.signals[0].env_only);
    }

    #[test]
    fn writable_containerd_socket_lists_but_signals_nothing() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run/containerd")).unwrap();
        std::fs::write(d.path().join("run/containerd/containerd.sock"), "").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            status: 200,
            body: r#"{"ServerVersion":"1.7.18"}"#,
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        let o = Sockets.run(&cx);
        // containerd/kata/crio-unknown kinds are facts-only: no RuntimeKind signal.
        assert_eq!(o.facts[0].value[0]["kind"], "containerd");
        assert!(o.signals.is_empty());
    }

    #[test]
    fn empty_fixture_yields_empty_found_and_no_signals() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            status: 200,
            body: "{}",
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        let o = Sockets.run(&cx);
        assert_eq!(o.facts[0].value, serde_json::json!([]));
        assert!(o.signals.is_empty());
    }
}
