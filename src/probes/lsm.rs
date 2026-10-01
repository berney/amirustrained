//! lsm probe — read-only LSM posture: the active LSM stack from
//! `/sys/kernel/security/lsm`, the current task label from
//! `/proc/<pid>/attr/current` (AppArmor profile or SELinux context), the
//! kernel lockdown level, and the Landlock ABI version via
//! `OsApi::landlock_abi`. Every source degrades to a null fact when absent;
//! nothing here writes to or mutates any LSM interface.

use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

const PROBE: &str = "lsm";

/// Builds the `lsm` outcome from fixture-rooted reads plus the Landlock ABI
/// level (`None` ⇒ syscall unsupported). The same `attr/current` label feeds
/// both LSM facts: AppArmor parses it as `profile (mode)`, SELinux reports it
/// verbatim as `context`. An unconfined AppArmor task labels as `unconfined`
/// with an empty mode — rules match on the profile string.
pub fn parse_lsm(fs: &PseudoFs, pid: u32, landlock_abi: Option<u64>) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let list = fs
        .read("/sys/kernel/security/lsm")
        .ok()
        .map(|s| s.trim().split(',').map(String::from).collect::<Vec<_>>());
    o = o.with_fact(Fact::ok(
        PROBE,
        "list",
        list.as_ref()
            .map_or(serde_json::Value::Null, |l| serde_json::json!(l)),
        "/sys/kernel/security/lsm".into(),
    ));
    // current profile label — AppArmor OR SELinux context, same file.
    // Kernel security labels are NUL-terminated (the same convention the
    // hypervisor vendor string gets in `RealOs`); trim it so reported
    // profile/context strings stay exact.
    let label = fs
        .read(&format!("/proc/{pid}/attr/current"))
        .ok()
        .map(|s| s.trim().trim_end_matches('\0').trim().to_string());
    // A missing lsm list hides nothing: AppArmor stays eligible whenever the
    // kernel does not advertise its stack (a masked securityfs).
    let apparmor = list
        .as_ref()
        .is_none_or(|l| l.iter().any(|x| x == "apparmor"));
    let aa = match (&label, apparmor) {
        (Some(l), true) => {
            let (profile, mode) = match l.rsplit_once(" (") {
                Some((p, rest)) => (p.to_string(), rest.trim_end_matches(')').to_string()),
                None => (l.clone(), String::new()),
            };
            Some(serde_json::json!({ "profile": profile, "mode": mode }))
        }
        _ => None,
    };
    o = o.with_fact(Fact::ok(
        PROBE,
        "apparmor",
        aa.unwrap_or(serde_json::Value::Null),
        format!("/proc/{pid}/attr/current"),
    ));
    let selinux = list
        .as_ref()
        .is_some_and(|l| l.iter().any(|x| x == "selinux"));
    let sel = if selinux {
        label.as_ref().map(|l| {
            serde_json::json!({
                "context": l,
                "mode": fs.read("/sys/fs/selinux/enforce").ok().map(|e| {
                    if e.trim() == "1" { "enforcing" } else { "permissive" }
                }),
            })
        })
    } else {
        None
    };
    o = o.with_fact(Fact::ok(
        PROBE,
        "selinux",
        sel.unwrap_or(serde_json::Value::Null),
        "/sys/fs/selinux/enforce".into(),
    ));
    let lockdown = fs.read("/sys/kernel/security/lockdown").ok().and_then(|s| {
        s.split([' ', ']'])
            .find(|t| t.starts_with('['))
            .map(|t| t.trim_start_matches('[').to_string())
    });
    o = o.with_fact(Fact::ok(
        PROBE,
        "lockdown",
        lockdown
            .map(|l| serde_json::json!(l))
            .unwrap_or(serde_json::Value::Null),
        "/sys/kernel/security/lockdown".into(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "landlockAbi",
        landlock_abi
            .map(|a| serde_json::json!(a))
            .unwrap_or(serde_json::Value::Null),
        "SYS_LANDLOCK_CREATE_RULESET".into(),
    ));
    o
}

pub struct Lsm;

impl Probe for Lsm {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        parse_lsm(cx.fs, cx.pid, cx.os.landlock_abi())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apparmor_and_selinux_and_landlock() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| {
            let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            f
        };
        std::fs::write(
            p("/sys/kernel/security/lsm"),
            "capability,apparmor,landlock\n",
        )
        .unwrap();
        std::fs::write(p("/proc/7/attr/current"), "docker-default (enforce)\n").unwrap();
        std::fs::write(p("/sys/kernel/security/lockdown"), "[none] integrity\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = parse_lsm(&fs, 7, Some(6));
        assert_eq!(
            o.facts.iter().find(|f| f.key == "list").unwrap().value,
            serde_json::json!(["capability", "apparmor", "landlock"])
        );
        let aa = o
            .facts
            .iter()
            .find(|f| f.key == "apparmor")
            .unwrap()
            .value
            .clone();
        assert_eq!(aa["profile"], "docker-default");
        assert_eq!(aa["mode"], "enforce");
        assert_eq!(
            o.facts
                .iter()
                .find(|f| f.key == "landlockAbi")
                .unwrap()
                .value,
            serde_json::json!(6)
        );
        assert_eq!(
            o.facts.iter().find(|f| f.key == "lockdown").unwrap().value,
            "none"
        );
    }

    #[test]
    fn unconfined_and_missing_securityfs() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("proc/7/attr/current");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "unconfined\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = parse_lsm(&fs, 7, None);
        let aa = o
            .facts
            .iter()
            .find(|f| f.key == "apparmor")
            .unwrap()
            .value
            .clone();
        assert_eq!(aa["profile"], "unconfined");
        assert!(
            o.facts
                .iter()
                .any(|f| f.key == "selinux" && f.value.is_null())
        );
        assert!(
            o.facts
                .iter()
                .any(|f| f.key == "landlockAbi" && f.value.is_null())
        );
    }

    fn w(dir: &tempfile::TempDir, rel: &str, body: &str) {
        let f = dir.path().join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, body).unwrap();
    }
    fn fact(o: &crate::model::ProbeOutcome, key: &str) -> serde_json::Value {
        o.facts.iter().find(|f| f.key == key).unwrap().value.clone()
    }

    #[test]
    fn selinux_host_nulls_apparmor_and_maps_enforce_flag() {
        let d = tempfile::tempdir().unwrap();
        w(&d, "sys/kernel/security/lsm", "capability,selinux\n");
        w(
            &d,
            "proc/7/attr/current",
            "system_u:system_r:container_t:s0\0",
        );
        w(&d, "sys/fs/selinux/enforce", "1\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = parse_lsm(&fs, 7, None);
        // AppArmor is not in the advertised stack: the label is SELinux
        // context, so the apparmor fact must stay null.
        assert!(fact(&o, "apparmor").is_null());
        let sel = fact(&o, "selinux");
        assert_eq!(sel["context"], "system_u:system_r:container_t:s0");
        assert_eq!(sel["mode"], "enforcing");
    }

    #[test]
    fn selinux_permissive_flag_and_missing_enforce_file_null_mode() {
        let d = tempfile::tempdir().unwrap();
        w(&d, "sys/kernel/security/lsm", "selinux\n");
        w(&d, "proc/7/attr/current", "unconfined_service_t\n");
        w(&d, "sys/fs/selinux/enforce", "0\n");
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        assert_eq!(
            fact(&parse_lsm(&fs, 7, None), "selinux")["mode"],
            "permissive"
        );
        std::fs::remove_file(d.path().join("sys/fs/selinux/enforce")).unwrap();
        assert!(fact(&parse_lsm(&fs, 7, None), "selinux")["mode"].is_null());
    }

    struct StubOs {
        landlock: Option<u64>,
    }
    impl crate::sys::os::OsApi for StubOs {
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            Default::default()
        }
        fn landlock_abi(&self) -> Option<u64> {
            self.landlock
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
            Err(std::io::Error::other("stub"))
        }
        fn env(&self, _k: &str) -> Option<String> {
            None
        }
        fn is_root(&self) -> bool {
            false
        }
    }

    #[test]
    fn run_consumes_ctx_landlock_abi_and_degrades_empty_fs() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs { landlock: Some(7) };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: false,
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let cx = crate::pipeline::Ctx {
            pid: 4242,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: crate::pipeline::Prior::default(),
        };
        let o = Lsm.run(&cx);
        assert_eq!(o.name, "lsm");
        assert_eq!(fact(&o, "landlockAbi"), serde_json::json!(7));
        // No readable sources at all: every file-backed fact is null.
        assert!(fact(&o, "list").is_null());
        assert!(fact(&o, "apparmor").is_null());
        assert!(fact(&o, "selinux").is_null());
        assert!(fact(&o, "lockdown").is_null());
    }
}
