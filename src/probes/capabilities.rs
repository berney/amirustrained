use serde::Serialize;
use serde_json::Value;

use super::Probe;
use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::sys::fs::{PseudoFs, errno_of};

/// The 41 Linux capabilities (`CAP_CHOWN` .. `CAP_CHECKPOINT_RESTORE`), lowercased
/// and indexed by capability number — exactly the bit positions the kernel writes
/// into the `Cap*` masks of `/proc/<pid>/status`.
const CAP_NAMES: [&str; 41] = [
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// Expands a `u64` capability mask into the matching capability names, lowest first.
/// Bits above `cap_checkpoint_restore` are ignored.
pub fn decode(bits: u64) -> Vec<&'static str> {
    CAP_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1u64 << i) != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Capability sets and related hardening flags parsed from `/proc/<pid>/status`.
/// Fields the running kernel does not export (older `CapLastEff`, gated `SecureBits`)
/// stay `None` rather than being fabricated as `0x0`.
#[derive(Debug, Default)]
pub struct StatusCaps {
    pub effective: Vec<&'static str>,
    pub permitted: Vec<&'static str>,
    pub inheritable: Vec<&'static str>,
    pub bounding: Vec<&'static str>,
    pub ambient: Vec<&'static str>,
    pub last_effective: Option<u64>,
    pub no_new_privs: Option<u64>,
    pub secure_bits: Option<String>,
}

/// Parses the `Cap*` / `NoNewPrivs` / `SecureBits` lines. Unknown lines are ignored;
/// a malformed mask decodes to no capabilities rather than failing the whole body.
pub fn parse_status_caps(status: &str) -> StatusCaps {
    let mut out = StatusCaps::default();
    for line in status.lines() {
        let mut it = line.splitn(2, ':');
        let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        let bits = u64::from_str_radix(v, 16).unwrap_or(0);
        match k {
            "CapEff" => out.effective = decode(bits),
            "CapPrm" => out.permitted = decode(bits),
            "CapInh" => out.inheritable = decode(bits),
            "CapBnd" => out.bounding = decode(bits),
            "CapAmb" => out.ambient = decode(bits),
            "CapLastEff" => out.last_effective = Some(bits),
            "NoNewPrivs" => out.no_new_privs = v.parse().ok(),
            "SecureBits" => out.secure_bits = Some(v.to_string()),
            _ => {}
        }
    }
    out
}

const PROBE: &str = "capabilities";
const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Serializes a probe value to JSON. Every capability value (numbers, `&str`,
/// `Vec<&'static str>`) is infallible to serialize, so the `Null` fallback keeps
/// this total — probes never panic on serialization.
fn json<T: Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// Builds a fact from an optional value: `Some` ⇒ Ok, `None` ⇒ degraded `null`
/// (the kernel did not export the line, which is absent-safe, not an error).
fn opt_fact(key: &str, source: &str, value: Option<Value>) -> Fact {
    match value {
        Some(v) => Fact::ok(PROBE, key, v, source.into()),
        None => Fact::degraded(PROBE, key, Value::Null, source.into()),
    }
}

pub fn probe_capabilities(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let status_src = format!("/proc/{pid}/status");
    match fs.read(&status_src) {
        Ok(status) => {
            let c = parse_status_caps(&status);
            // The five core sets are exported on every Linux: absent ⇒ empty set, Ok.
            for (key, names) in [
                ("effective", c.effective),
                ("permitted", c.permitted),
                ("inheritable", c.inheritable),
                ("bounding", c.bounding),
                ("ambient", c.ambient),
            ] {
                o = o.with_fact(Fact::ok(PROBE, key, json(names), status_src.clone()));
            }
            o = o.with_fact(opt_fact(
                "lastEffective",
                &status_src,
                c.last_effective.map(|b| json(decode(b))),
            ));
            o = o.with_fact(opt_fact(
                "noNewPrivs",
                &status_src,
                c.no_new_privs.map(json),
            ));
            o = o.with_fact(opt_fact("secureBits", &status_src, c.secure_bits.map(json)));
        }
        Err(e) => {
            // Unreadable status (e.g. another user's pid with host-PID, EACCES): the
            // whole source is unavailable, reported honestly with the errno.
            let errno = errno_of(&e);
            for key in [
                "effective",
                "permitted",
                "inheritable",
                "bounding",
                "ambient",
                "lastEffective",
                "noNewPrivs",
                "secureBits",
            ] {
                o = o.with_fact(Fact::unavailable(PROBE, key, status_src.clone(), errno));
            }
        }
    }
    // Yama ptrace_scope lives under the same fixture-remapped root. Absent
    // (no Yama LSM) or unparseable ⇒ degraded null (rule AMR-004 tolerates it).
    match fs.read(PTRACE_SCOPE) {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) => o = o.with_fact(Fact::ok(PROBE, "ptraceScope", json(n), PTRACE_SCOPE.into())),
            Err(_) => {
                o = o.with_fact(Fact::degraded(
                    PROBE,
                    "ptraceScope",
                    Value::Null,
                    PTRACE_SCOPE.into(),
                ))
            }
        },
        Err(_) => {
            o = o.with_fact(Fact::degraded(
                PROBE,
                "ptraceScope",
                Value::Null,
                PTRACE_SCOPE.into(),
            ))
        }
    }
    o
}

pub struct Capabilities;

impl Probe for Capabilities {
    fn name(&self) -> &'static str {
        PROBE
    }
    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_capabilities(cx.fs, cx.pid)
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

    // ---- Brief Step 1 tests (verbatim) ----
    #[test]
    fn decode_known_bits() {
        let caps = decode((1u64 << 21) | 1);
        assert!(caps.contains(&"cap_chown") && caps.contains(&"cap_sys_admin"));
    }
    #[test]
    fn decode_bpf_perfmon_checkpoint() {
        let v = (1u64 << 39) | (1u64 << 38) | (1u64 << 40);
        let caps = decode(v);
        assert!(
            caps.contains(&"cap_bpf")
                && caps.contains(&"cap_perfmon")
                && caps.contains(&"cap_checkpoint_restore")
        );
    }
    #[test]
    fn status_parse_pulls_all_sets() {
        let status = "CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";
        let p = parse_status_caps(status);
        assert_eq!(p.effective.len(), 41);
        assert_eq!(p.no_new_privs, Some(0));
    }

    // ---- run-level behaviour ----
    const FULL_STATUS: &str = "Name:\tproctest\n\
        CapInh:\t0000000000000000\n\
        CapPrm:\t000001ffffffffff\n\
        CapEff:\t00000000a80425fb\n\
        CapBnd:\t000001ffffffffff\n\
        CapAmb:\t0000000000000000\n\
        CapLastEff:\t00000000a80425fb\n\
        NoNewPrivs:\t0\n\
        Seccomp:\t2\n\
        SecureBits:\t00000000\n";

    fn fact<'a>(o: &'a ProbeOutcome, key: &str) -> &'a Fact {
        o.facts
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("missing fact {key}"))
    }

    #[test]
    fn run_emits_all_facts_and_reads_ptrace_scope() {
        let d = fixture(&[
            ("proc/7/status", FULL_STATUS),
            ("proc/sys/kernel/yama/ptrace_scope", "0\n"),
        ]);
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_capabilities(&fs, 7);
        assert_eq!(o.name, "capabilities");
        assert_eq!(o.facts.len(), 9);

        let eff = fact(&o, "effective");
        assert_eq!(eff.status, FactStatus::Ok);
        assert_eq!(eff.source, "/proc/7/status");
        let arr = eff.value.as_array().unwrap();
        assert!(arr.contains(&serde_json::json!("cap_chown")));
        // docker-default effective set drops CAP_SYS_ADMIN — discriminating.
        assert!(!arr.contains(&serde_json::json!("cap_sys_admin")));

        assert_eq!(fact(&o, "permitted").value.as_array().unwrap().len(), 41);
        assert_eq!(fact(&o, "noNewPrivs").value, serde_json::json!(0));
        assert_eq!(fact(&o, "secureBits").value, serde_json::json!("00000000"));

        let le = fact(&o, "lastEffective");
        assert_eq!(le.status, FactStatus::Ok);
        assert_eq!(le.value, eff.value);

        let ps = fact(&o, "ptraceScope");
        assert_eq!(ps.status, FactStatus::Ok);
        assert_eq!(ps.value, serde_json::json!(0));
        assert_eq!(ps.source, "/proc/sys/kernel/yama/ptrace_scope");
    }

    #[test]
    fn absent_status_marks_derived_facts_unavailable() {
        let d = fixture(&[]);
        let o = probe_capabilities(&crate::sys::fs::PseudoFs::new(d.path().into()), 9);
        assert_eq!(o.facts.len(), 9);
        for key in [
            "effective",
            "permitted",
            "inheritable",
            "bounding",
            "ambient",
            "lastEffective",
            "noNewPrivs",
            "secureBits",
        ] {
            let f = fact(&o, key);
            assert_eq!(f.status, FactStatus::Unavailable, "{key} unavailable");
            assert_eq!(f.value["errno"], 2, "{key} ENOENT");
        }
        // ptrace_scope has its own degraded contract, not unavailable.
        assert_eq!(fact(&o, "ptraceScope").status, FactStatus::Degraded);
        assert_eq!(fact(&o, "ptraceScope").value, serde_json::Value::Null);
    }

    #[test]
    fn ptrace_scope_absent_degrades_null() {
        let d = fixture(&[("proc/7/status", FULL_STATUS)]);
        let o = probe_capabilities(&crate::sys::fs::PseudoFs::new(d.path().into()), 7);
        assert_eq!(fact(&o, "effective").status, FactStatus::Ok);
        let ps = fact(&o, "ptraceScope");
        assert_eq!(ps.status, FactStatus::Degraded);
        assert_eq!(ps.value, serde_json::Value::Null);
    }

    #[test]
    fn missing_kernel_versioned_lines_degrade_not_fabricate() {
        // Pre-5.8 kernels have no CapLastEff; keep it honest rather than 0x0.
        let status = "CapEff:\t0000000000000001\nCapPrm:\t0000000000000001\n\
            CapBnd:\t0000000000000001\n";
        let d = fixture(&[("proc/7/status", status)]);
        let o = probe_capabilities(&crate::sys::fs::PseudoFs::new(d.path().into()), 7);
        assert_eq!(
            fact(&o, "effective").value,
            serde_json::json!(["cap_chown"])
        );
        for key in ["lastEffective", "noNewPrivs", "secureBits"] {
            assert_eq!(
                fact(&o, key).status,
                FactStatus::Degraded,
                "{key} should degrade when the line is absent"
            );
            assert_eq!(fact(&o, key).value, serde_json::Value::Null);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_smoke_is_structurally_wellformed() {
        // Structural shape only: never assert this host's actual capability values.
        let o = probe_capabilities(&crate::sys::fs::PseudoFs::real(), std::process::id());
        assert_eq!(o.name, "capabilities");
        assert_eq!(o.facts.len(), 9);
        assert!(o.facts.iter().all(|f| f.probe == "capabilities"));
        for key in [
            "effective",
            "permitted",
            "inheritable",
            "bounding",
            "ambient",
            "lastEffective",
            "noNewPrivs",
            "secureBits",
            "ptraceScope",
        ] {
            assert!(o.facts.iter().any(|f| f.key == key), "missing {key}");
        }
        let eff = fact(&o, "effective");
        assert_eq!(
            eff.status,
            FactStatus::Ok,
            "own /proc/self/status is readable"
        );
        assert!(eff.value.is_array());
    }
}
