use super::Probe;
use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::sys::fs::PseudoFs;

const PROBE: &str = "namespaces";

/// Namespace link files reported under `/proc/<pid>/ns`. Nine entries including
/// `pid_for_children`: the spec's "8 ns types" counts the kernel-visible
/// families, so we report every link file the kernel exposes there and let an
/// unknown one surface as `null` rather than dropping the key.
const NS_TYPES: [&str; 9] = [
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_ns",
    "user",
];

/// One `/proc/<pid>/ns/<type>` link target, e.g. `pid:[4026531836]`.
///
/// `None` deliberately collapses absent (pre-4.9 kernels have no `time`/`time_ns`,
/// a hidden pid means the whole directory is gone) and unreadable (EACCES under
/// `hidepid`): both leave the isolation state unknown, and no rule may read a
/// guess out of either. The probe degrades, never crashes.
fn ns_link(fs: &PseudoFs, pid: u32, ns: &str) -> Option<String> {
    fs.read_link(&format!("/proc/{pid}/ns/{ns}")).ok()
}

/// Compares the target's namespaces against pid 1, the host root namespace:
/// differing inodes ⇒ the process is isolated in that namespace type.
///
/// pid 1 is the baseline, so an unreadable `/proc/1/ns` makes the comparison —
/// and only the comparison — unreliable: own inodes are still reported and
/// `isolated` degrades to per-type nulls.
pub fn probe_namespaces(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let own_src = format!("/proc/{pid}/ns");
    let mut isolated = serde_json::Map::new();
    let mut inodes = serde_json::Map::new();
    // Captured from the cgroup pair inside the loop; `None` ⇒ unknown → null.
    let mut cgroup_same_as_init: Option<bool> = None;
    let mut init_unreadable = false;
    for ns in NS_TYPES {
        let own = ns_link(fs, pid, ns);
        let init = ns_link(fs, 1, ns);
        if own.is_some() && init.is_none() {
            init_unreadable = true;
        }
        isolated.insert(
            ns.to_string(),
            match (&own, &init) {
                (Some(a), Some(b)) => serde_json::json!(a != b),
                _ => serde_json::Value::Null,
            },
        );
        if let Some(a) = &own {
            inodes.insert(ns.to_string(), a.clone().into());
            if ns == "cgroup" {
                cgroup_same_as_init = init.as_ref().map(|b| a == b);
            }
        }
    }
    let isolated_value = serde_json::Value::Object(isolated);
    o = o.with_fact(if init_unreadable {
        Fact::degraded(PROBE, "isolated", isolated_value, own_src.clone())
    } else {
        Fact::ok(PROBE, "isolated", isolated_value, own_src.clone())
    });
    o = o.with_fact(Fact::ok(
        PROBE,
        "inodes",
        serde_json::Value::Object(inodes),
        own_src,
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "cgroupNsSameAsInit",
        serde_json::json!(cgroup_same_as_init),
        "/proc/1/ns/cgroup".into(),
    ));
    if init_unreadable {
        o.availability = Availability::Degraded("pid 1 namespaces unreadable".into());
    }
    o
}

pub struct Namespaces;

impl Probe for Namespaces {
    fn name(&self) -> &'static str {
        PROBE
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_namespaces(cx.fs, cx.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Fact, FactStatus};

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
    fn isolated_vs_init() {
        let d = fixture(&[
            ("proc/42/ns/pid", "pid:[4026532192]"),
            ("proc/1/ns/pid", "pid:[4026531836]"),
            ("proc/42/ns/net", "net:[4026532195]"),
            ("proc/1/ns/net", "net:[4026532195]"),
            ("proc/42/ns/cgroup", "cgroup:[4026532190]"),
            ("proc/1/ns/cgroup", "cgroup:[4026531999]"),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        let f = o.facts.iter().find(|f| f.key == "isolated").unwrap();
        assert_eq!(f.value["pid"], serde_json::json!(true));
        assert_eq!(f.value["net"], serde_json::json!(false));
        assert_eq!(
            o.facts
                .iter()
                .find(|f| f.key == "cgroupNsSameAsInit")
                .unwrap()
                .value,
            serde_json::json!(false)
        );
    }

    #[test]
    fn degraded_when_init_unreadable() {
        let d = fixture(&[("proc/42/ns/pid", "pid:[4026532192]")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        assert!(matches!(
            o.availability,
            crate::model::Availability::Degraded(_)
        ));
        let f = o.facts.iter().find(|f| f.key == "isolated").unwrap();
        assert_eq!(f.value["pid"], serde_json::Value::Null);
    }

    #[test]
    fn isolated_fact_degrades_with_the_availability() {
        let d = fixture(&[("proc/42/ns/pid", "pid:[4026532192]")]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        let iso = fact(&o, "isolated");
        assert_eq!(iso.status, FactStatus::Degraded);
        assert_eq!(iso.source, "/proc/42/ns");
        // Every reported type stays present as a key, unknown ones as null.
        assert_eq!(iso.value.as_object().unwrap().len(), NS_TYPES.len());
        for t in NS_TYPES {
            assert!(iso.value.get(t).is_some(), "missing key {t}");
        }
        // Absent-vs-unreadable: our own readable link is still reported verbatim.
        assert_eq!(fact(&o, "inodes").value["pid"], "pid:[4026532192]");
        assert_eq!(
            fact(&o, "cgroupNsSameAsInit").value,
            serde_json::Value::Null
        );
    }

    #[test]
    fn own_inodes_are_emitted_and_absent_types_are_not_fabricated() {
        // `net` is absent on *both* sides (kernel-less type), which is not the same
        // as pid 1 being unreadable — the comparison stays confident elsewhere.
        let d = fixture(&[
            ("proc/42/ns/pid", "pid:[4026532192]"),
            ("proc/42/ns/user", "user:[4026532000]"),
            ("proc/1/ns/pid", "pid:[4026532192]"),
            ("proc/1/ns/user", "user:[4026531991]"),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 42);
        let inodes = fact(&o, "inodes");
        assert_eq!(inodes.status, FactStatus::Ok);
        assert_eq!(inodes.source, "/proc/42/ns");
        assert_eq!(inodes.value["pid"], "pid:[4026532192]");
        assert_eq!(inodes.value["user"], "user:[4026532000]");
        assert!(
            inodes.value.get("net").is_none(),
            "absent own link must not appear in inodes"
        );
        assert_eq!(fact(&o, "isolated").value["pid"], serde_json::json!(false));
        assert_eq!(fact(&o, "isolated").value["user"], serde_json::json!(true));
        assert_eq!(
            fact(&o, "isolated").value["net"],
            serde_json::Value::Null,
            "absent on both sides is unknown, not false"
        );
        assert_eq!(fact(&o, "isolated").status, FactStatus::Ok);
        assert_eq!(
            o.availability,
            crate::model::Availability::Ok,
            "both-absent must not degrade the probe"
        );
    }

    #[test]
    fn nothing_readable_yields_nulls_never_a_fabricated_verdict() {
        let d = fixture(&[]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_namespaces(&fs, 9);
        assert_eq!(o.name, "namespaces");
        assert_eq!(o.facts.len(), 3);
        let iso = fact(&o, "isolated");
        assert_eq!(iso.status, FactStatus::Ok);
        for t in NS_TYPES {
            assert_eq!(iso.value[t], serde_json::Value::Null, "{t} must be null");
        }
        assert_eq!(fact(&o, "inodes").value, serde_json::json!({}));
        assert_eq!(
            fact(&o, "cgroupNsSameAsInit").value,
            serde_json::Value::Null
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_smoke_is_structurally_wellformed() {
        // Structural shape only: never assert this host's isolation verdict.
        let o = probe_namespaces(&crate::sys::fs::PseudoFs::real(), std::process::id());
        assert_eq!(o.name, "namespaces");
        assert_eq!(o.facts.len(), 3);
        assert!(o.facts.iter().all(|f| f.probe == "namespaces"));
        for key in ["isolated", "inodes", "cgroupNsSameAsInit"] {
            assert!(o.facts.iter().any(|f| f.key == key), "missing {key}");
        }
        let iso = fact(&o, "isolated");
        assert_eq!(iso.value.as_object().unwrap().len(), NS_TYPES.len());
        for t in NS_TYPES {
            let v = &iso.value[t];
            assert!(v.is_boolean() || v.is_null(), "{t} must be bool|null: {v}");
        }
        assert!(fact(&o, "inodes").value.is_object());
        let cg = fact(&o, "cgroupNsSameAsInit").value.clone();
        assert!(cg.is_boolean() || cg.is_null());
    }
}
