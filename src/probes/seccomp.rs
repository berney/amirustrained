//! seccomp probe — read-only seccomp state: mode + filter count from
//! `/proc/<pid>/status`, per-action support from `SECCOMP_GET_ACTION_AVAIL`
//! (via `OsApi`), and an optional ptrace filter-program dump gated on
//! root + `--dump-filters`. Never installs or modifies seccomp state.

use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::errno_of;
use crate::sys::os::SeccompActions;

const PROBE: &str = "seccomp";

/// Extracts `(mode, filter_count)` from a `/proc/<pid>/status` body.
/// `Seccomp:` values 0/1/2 map to `disabled`/`strict`/`filter`; any other
/// value the kernel enum does not define stays `unknown` (honest, not a
/// guess). `None` means the `Seccomp:` line is absent entirely — pre-3.5
/// kernels or a masked procfs — which the probe degrades, never crashes.
pub fn parse_mode(status: &str) -> Option<(&'static str, Option<u32>)> {
    let mut mode = None;
    let mut count = None;
    for line in status.lines() {
        let mut it = line.splitn(2, ':');
        match (it.next().unwrap_or(""), it.next().unwrap_or("").trim()) {
            ("Seccomp", "0") => mode = Some("disabled"),
            ("Seccomp", "1") => mode = Some("strict"),
            ("Seccomp", "2") => mode = Some("filter"),
            ("Seccomp", _) => mode = Some("unknown"),
            ("Seccomp_filters", v) => count = v.parse().ok(),
            _ => {}
        }
    }
    mode.map(|m| (m, count))
}

pub struct Seccomp;

impl Probe for Seccomp {
    fn name(&self) -> &'static str {
        PROBE
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let mut o = ProbeOutcome::empty(PROBE);
        let src = format!("/proc/{}/status", cx.pid);
        let (mode, count) = match cx.fs.read(&src) {
            Ok(s) => parse_mode(&s)
                .map(|(m, c)| (m.to_string(), c))
                .unwrap_or_else(|| ("unknown".into(), None)),
            Err(e) => return o.with_fact(Fact::unavailable(PROBE, "mode", src, errno_of(&e))),
        };
        o = o.with_fact(Fact::ok(PROBE, "mode", mode.clone().into(), src.clone()));
        o = o.with_fact(Fact::ok(
            PROBE,
            "filterCount",
            count
                .map(|c| serde_json::json!(c))
                .unwrap_or(serde_json::Value::Null),
            src,
        ));
        let actions: SeccompActions = cx.os.seccomp_actions();
        // Serializing a struct of bools is infallible.
        o = o.with_fact(Fact::ok(
            PROBE,
            "actions",
            serde_json::to_value(actions).unwrap(),
            "SECCOMP_GET_ACTION_AVAIL".into(),
        ));
        if mode == "unknown" {
            o.availability = Availability::Degraded("Seccomp line absent from status".into());
        }
        // Filter *program* dump: ptrace attach only pays off (and is only
        // permitted) as root, and only behind the hidden `--dump-filters`.
        // A refused/denied attach is an unavailable fact, never a crash.
        if cx.opts.dump_filters && cx.os.is_root() {
            let src = "PTRACE_SECCOMP_GET_FILTER".to_string();
            match cx.os.seccomp_filter_dump(cx.pid) {
                Ok(words) => {
                    o = o.with_fact(Fact::ok(PROBE, "filterDump", serde_json::json!(words), src));
                }
                Err(e) => {
                    o = o.with_fact(Fact::unavailable(PROBE, "filterDump", src, errno_of(&e)));
                }
            }
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;
    use crate::sys::fs::ProbeIo;
    use crate::sys::os::SeccompActions;
    struct StubOs {
        actions: SeccompActions,
        root: bool,
    }
    impl crate::sys::os::OsApi for StubOs {
        // signatures MUST match Task 4 trait
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            Default::default()
        }
        fn landlock_abi(&self) -> Option<u64> {
            None
        }
        fn seccomp_actions(&self) -> SeccompActions {
            self.actions
        }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, ProbeIo> {
            Err(ProbeIo::PermissionDenied)
        }
        fn syscall0(&self, _n: u32) -> Result<(), i32> {
            Err(38)
        } // ENOSYS
        fn uds_probe(
            &self,
            _p: &std::path::Path,
            _t: std::time::Duration,
        ) -> std::io::Result<crate::sys::os::UdsReply> {
            Err(std::io::Error::other("stub"))
        }
        fn env(&self, _k: &str) -> Option<String> {
            None
        }
        fn is_root(&self) -> bool {
            self.root
        }
    }
    use crate::pipeline::Ctx;
    fn cx<'a>(
        fs: &'a crate::sys::fs::PseudoFs,
        os: &'a dyn crate::sys::os::OsApi,
        opts: &'a crate::opts::Opts,
    ) -> Ctx<'a> {
        Ctx {
            pid: 1234,
            uid: 1000,
            fs,
            os,
            opts,
            prior: crate::pipeline::Prior::default(),
        }
    }
    fn opts(dump_filters: bool) -> crate::opts::Opts {
        crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters,
        }
    }
    fn status_fs(dir: &tempfile::TempDir, status: &str) {
        std::fs::create_dir_all(dir.path().join("proc/1234")).unwrap();
        std::fs::write(dir.path().join("proc/1234/status"), status).unwrap();
    }

    #[test]
    fn mode_and_actions_from_status_and_avail() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("proc/1234")).unwrap();
        std::fs::write(
            d.path().join("proc/1234/status"),
            "Seccomp:\t2\nSeccomp_filters:\t3\n",
        )
        .unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            actions: SeccompActions {
                kill_process: true,
                kill_thread: true,
                ..Default::default()
            },
            root: false,
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts));
        assert_eq!(
            o.facts.iter().find(|f| f.key == "mode").unwrap().value,
            "filter"
        );
        assert_eq!(
            o.facts
                .iter()
                .find(|f| f.key == "filterCount")
                .unwrap()
                .value,
            serde_json::json!(3)
        );
        let a = o
            .facts
            .iter()
            .find(|f| f.key == "actions")
            .unwrap()
            .value
            .clone();
        assert_eq!(a["killProcess"], serde_json::json!(true));
        assert_eq!(a["userNotif"], serde_json::json!(false));
    }
    #[test]
    fn missing_seccomp_line_degrades_unknown() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("proc/1234")).unwrap();
        std::fs::write(d.path().join("proc/1234/status"), "Name:\tx\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            actions: SeccompActions::default(),
            root: false,
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts));
        assert_eq!(
            o.facts.iter().find(|f| f.key == "mode").unwrap().value,
            "unknown"
        );
        assert!(matches!(
            o.availability,
            crate::model::Availability::Degraded(_)
        ));
    }

    #[test]
    fn parse_mode_maps_values_and_ignores_noise() {
        assert_eq!(parse_mode("Seccomp:\t0\n"), Some(("disabled", None)));
        assert_eq!(parse_mode("Seccomp:\t1\n"), Some(("strict", None)));
        assert_eq!(
            parse_mode("Seccomp:\t2\nSeccomp_filters:\t7\n"),
            Some(("filter", Some(7)))
        );
        // A value the kernel enum does not define yet stays honest as unknown.
        assert_eq!(parse_mode("Seccomp:\t3\n"), Some(("unknown", None)));
        // No Seccomp line at all ⇒ None (the probe maps that to unknown+degraded).
        assert_eq!(parse_mode("Name:\tx\nCapEff:\t0000\n"), None);
    }

    #[test]
    fn mode_disabled_zero_yields_null_filter_count() {
        let d = tempfile::tempdir().unwrap();
        status_fs(&d, "Seccomp:\t0\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            actions: SeccompActions::default(),
            root: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(false)));
        assert_eq!(
            o.facts.iter().find(|f| f.key == "mode").unwrap().value,
            "disabled"
        );
        assert_eq!(
            o.facts
                .iter()
                .find(|f| f.key == "filterCount")
                .unwrap()
                .value,
            serde_json::Value::Null
        );
        assert!(matches!(o.availability, crate::model::Availability::Ok));
    }

    #[test]
    fn actions_fact_serializes_full_matrix_camel_case() {
        let d = tempfile::tempdir().unwrap();
        status_fs(&d, "Seccomp:\t2\nSeccomp_filters:\t1\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            actions: SeccompActions {
                kill_process: true,
                kill_thread: true,
                trap: true,
                errno: true,
                log: true,
                trace: true,
                user_notif: true,
                probed_ok: true,
            },
            root: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(false)));
        let a = o
            .facts
            .iter()
            .find(|f| f.key == "actions")
            .unwrap()
            .value
            .clone();
        let obj = a.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "errno",
                "killProcess",
                "killThread",
                "log",
                "probedOk",
                "trace",
                "trap",
                "userNotif"
            ]
        );
        assert!(keys.iter().all(|k| obj[*k] == serde_json::json!(true)));
    }

    #[test]
    fn unreadable_status_is_unavailable_mode_with_errno() {
        let d = tempfile::tempdir().unwrap(); // no proc/1234/status at all
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            actions: SeccompActions::default(),
            root: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(false)));
        let mode = o.facts.iter().find(|f| f.key == "mode").unwrap();
        assert_eq!(mode.status, FactStatus::Unavailable);
        assert_eq!(mode.value["errno"], serde_json::json!(2)); // ENOENT
        // Early return: nothing was queried, so no keys beyond `mode`.
        assert_eq!(o.facts.len(), 1);
    }

    #[test]
    fn filter_dump_requires_root_and_flag() {
        let d = tempfile::tempdir().unwrap();
        status_fs(&d, "Seccomp:\t2\nSeccomp_filters:\t1\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());

        // root but flag off ⇒ no dump attempted
        let os = StubOs {
            actions: SeccompActions::default(),
            root: true,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(false)));
        assert!(!o.facts.iter().any(|f| f.key == "filterDump"));

        // flag on but unprivileged ⇒ no dump attempted
        let os = StubOs {
            actions: SeccompActions::default(),
            root: false,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(true)));
        assert!(!o.facts.iter().any(|f| f.key == "filterDump"));
    }

    #[test]
    fn filter_dump_denied_degrades_to_unavailable_fact() {
        let d = tempfile::tempdir().unwrap();
        status_fs(&d, "Seccomp:\t2\nSeccomp_filters:\t2\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        // StubOs attach is always PermissionDenied (yama/ptrace_scope honest).
        let os = StubOs {
            actions: SeccompActions::default(),
            root: true,
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(true)));
        let dump = o.facts.iter().find(|f| f.key == "filterDump").unwrap();
        assert_eq!(dump.status, FactStatus::Unavailable);
        assert_eq!(dump.value["errno"], serde_json::json!(13)); // EACCES
        assert_eq!(dump.source, "PTRACE_SECCOMP_GET_FILTER");
    }

    #[test]
    fn filter_dump_ok_reports_raw_words() {
        struct DumpOs {
            words: Vec<u64>,
        }
        impl crate::sys::os::OsApi for DumpOs {
            fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
                Default::default()
            }
            fn landlock_abi(&self) -> Option<u64> {
                None
            }
            fn seccomp_actions(&self) -> SeccompActions {
                SeccompActions::default()
            }
            fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, ProbeIo> {
                Ok(self.words.clone())
            }
            fn syscall0(&self, _n: u32) -> Result<(), i32> {
                Err(38)
            }
            fn uds_probe(
                &self,
                _p: &std::path::Path,
                _t: std::time::Duration,
            ) -> std::io::Result<crate::sys::os::UdsReply> {
                Err(std::io::Error::other("stub"))
            }
            fn env(&self, _k: &str) -> Option<String> {
                None
            }
            fn is_root(&self) -> bool {
                true
            }
        }
        let d = tempfile::tempdir().unwrap();
        status_fs(&d, "Seccomp:\t2\nSeccomp_filters:\t1\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        // Two raw BPF sockwords: a `ret ALLOW`-ish header + payload, opaque here.
        let os = DumpOs {
            words: vec![0x0020_0000_0006_0000, 0x7ffc_0000_0000_0000],
        };
        let o = Seccomp.run(&cx(&fs, &os, &opts(true)));
        let dump = o.facts.iter().find(|f| f.key == "filterDump").unwrap();
        assert_eq!(dump.status, FactStatus::Ok);
        assert_eq!(
            dump.value,
            serde_json::json!([0x0020_0000_0006_0000u64, 0x7ffc_0000_0000_0000u64])
        );
    }
}
