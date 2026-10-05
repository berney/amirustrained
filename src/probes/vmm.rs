//! vmm probe — read-only virtualization posture: hypervisor presence and
//! CPUID vendor leaf, SMBIOS strings from `/sys/class/dmi/id`, the current
//! clocksource, the Firecracker vsock device node, the `/proc/cpuinfo`
//! `hypervisor` flag, and the kernel version string. Every unreadable or
//! root-only source degrades to a null/false/empty fact; the probe never
//! crashes on a masked interface.

use crate::model::{Fact, ProbeOutcome, RuntimeKind, Signal};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;
use crate::sys::os::HypervisorInfo;

const PROBE: &str = "vmm";

/// CPUID leaf `0x40000000` vendor signature → friendly name (spec §7 vendor
/// table), lower-case prefix match over the 12-byte signature. `None` for
/// anything unrecognized, including bare `"TCG"` (only the repeated
/// `TCGTCG…` form QEMU emits counts).
// Vendor-name table per the Task 14 brief; the probe reports the raw vendor
// string, so no in-binary caller consumes the friendly names yet.
#[allow(dead_code)]
pub fn match_vendor(v: &str) -> Option<&'static str> {
    let v = v.to_ascii_lowercase();
    Some(match v.as_str() {
        "kvmkvmkvm" => "KVM",
        s if s.starts_with("vmware") => "VMware",
        s if s.starts_with("microsoft") => "Hyper-V",
        s if s.starts_with("xen") => "Xen",
        s if s.starts_with("bhyve") => "bhyve",
        s if s.starts_with("tcgtcg") => "QEMU-TCG",
        s if s.starts_with("kvm kvm kvm") => "KVM",
        _ => return None,
    })
}

/// Builds the `vmm` outcome from injected hypervisor info (`None` ⇒ CPUID
/// unavailable, e.g. non-x86) plus fixture-rooted reads. A `/proc/version`
/// containing `gVisor` short-circuits (weight 0.9) before the Firecracker
/// composite (weight 0.8) is considered, so gVisor wins when both match.
pub fn probe_vmm_with(fs: &PseudoFs, hv: Option<HypervisorInfo>) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    o = o.with_fact(Fact::ok(
        PROBE,
        "hypervisor",
        match &hv {
            Some(h) => serde_json::json!({ "present": h.present, "vendor": h.vendor.clone() }),
            None => serde_json::json!({ "present": false, "vendor": null }),
        },
        "CPUID leaf 0x40000000".into(),
    ));
    let dmi = |k: &str| {
        fs.read(&format!("/sys/class/dmi/id/{k}"))
            .ok()
            .map(|s| s.trim().to_string())
    };
    let dmi_obj = serde_json::json!({
        "sysVendor": dmi("sys_vendor"),
        "productName": dmi("product_name"),
        "biosVendor": dmi("bios_vendor"),
        "boardVendor": dmi("board_vendor")
    });
    o = o.with_fact(Fact::ok(
        PROBE,
        "dmi",
        dmi_obj.clone(),
        "/sys/class/dmi/id".into(),
    ));
    let clock = fs
        .read("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        .ok()
        .map(|s| s.trim().to_string());
    o = o.with_fact(Fact::ok(
        PROBE,
        "clocksource",
        clock
            .as_ref()
            .map_or(serde_json::Value::Null, |c| serde_json::json!(c)),
        "current_clocksource".into(),
    ));
    let vsock = fs.exists("/dev/vsock");
    o = o.with_fact(Fact::ok(PROBE, "vsock", vsock.into(), "/dev/vsock".into()));
    let version = fs.read("/proc/version").unwrap_or_default();
    let cpuinfo = fs.read("/proc/cpuinfo").unwrap_or_default();
    let hyp_flag = cpuinfo
        .lines()
        .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"));
    o = o.with_fact(Fact::ok(
        PROBE,
        "cpuHypervisorFlag",
        hyp_flag.into(),
        "/proc/cpuinfo".into(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "kernel",
        version.clone().into(),
        "/proc/version".into(),
    ));
    if version.contains("gVisor") {
        let kernel = o.facts.iter().find(|f| f.key == "kernel").unwrap().clone();
        o = o.with_signal(Signal {
            runtime: RuntimeKind::Gvisor,
            weight: 0.9,
            evidence: kernel,
            // Running *inside* the sandbox is containment: it scores.
            env_only: false,
        });
        return o;
    }
    // Firecracker: minimal guest — hypervisor present, empty DMI, vsock, kvm-clock.
    let hv_present = hv.as_ref().is_some_and(|h| h.present);
    let dmi_empty = dmi_obj["sysVendor"].is_null()
        && dmi_obj["productName"].is_null()
        && dmi_obj["biosVendor"].is_null();
    if hv_present && dmi_empty && vsock && clock.as_deref() == Some("kvm-clock") {
        let vsock_fact = o.facts.iter().find(|f| f.key == "vsock").unwrap().clone();
        o = o.with_signal(Signal {
            runtime: RuntimeKind::Firecracker,
            weight: 0.8,
            evidence: vsock_fact,
            env_only: false,
        });
    }
    o
}

pub struct Vmm;

impl Probe for Vmm {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_vmm_with(cx.fs, Some(cx.os.hypervisor()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hypervisor_vendor_table() {
        assert_eq!(match_vendor("KVMKVMKVM"), Some("KVM"));
        assert_eq!(match_vendor("VMwareVMware"), Some("VMware"));
        assert_eq!(match_vendor("Microsoft hv"), Some("Hyper-V"));
        assert_eq!(match_vendor("bhyve bhyve "), Some("bhyve"));
        assert_eq!(match_vendor("TCGTCGTCGTCG"), Some("QEMU-TCG"));
    }
    #[test]
    fn firecracker_composite() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| {
            let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            f
        };
        std::fs::create_dir_all(p("/sys/class/dmi/id")).unwrap(); // empty dmi dir
        std::fs::write(
            p("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
            "kvm-clock\n",
        )
        .unwrap();
        std::fs::create_dir_all(p("/dev")).unwrap();
        std::fs::write(p("/dev/vsock"), "").unwrap();
        std::fs::write(
            p("/proc/cpuinfo"),
            "processor\t: 0\nflags\t\t: fpu hypervisor\n",
        )
        .unwrap();
        std::fs::write(p("/proc/version"), "Linux version 5.10.195 (firecracker)\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_vmm_with(
            &fs,
            Some(crate::sys::os::HypervisorInfo {
                present: true,
                vendor: Some("KVMKVMKVM".into()),
            }),
        );
        assert!(
            o.signals
                .iter()
                .any(|s| s.runtime == RuntimeKind::Firecracker)
        );
        let hv = o
            .facts
            .iter()
            .find(|f| f.key == "hypervisor")
            .unwrap()
            .value
            .clone();
        assert_eq!(hv["present"], serde_json::json!(true));
        assert_eq!(hv["vendor"], "KVMKVMKVM");
    }
    #[test]
    fn gvisor_via_kernel_version() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("proc/version");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "Linux version 4.4.0 (gVisor team)\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_vmm_with(&fs, None);
        assert!(
            o.signals
                .iter()
                .any(|s| s.runtime == RuntimeKind::Gvisor && s.weight == 0.9)
        );
    }

    fn fact(o: &ProbeOutcome, key: &str) -> serde_json::Value {
        o.facts.iter().find(|f| f.key == key).unwrap().value.clone()
    }

    #[test]
    fn vendor_table_xen_spaced_kvm_and_misses() {
        assert_eq!(match_vendor("XenVMMXenVMM"), Some("Xen"));
        assert_eq!(match_vendor("kvm kvm kvm kvm"), Some("KVM"));
        assert_eq!(match_vendor("TCG"), None);
        assert_eq!(match_vendor("AuthenticAMD"), None);
    }
    #[test]
    fn bare_metal_full_fact_shape_no_signals() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let o = probe_vmm_with(&fs, None);
        assert_eq!(o.name, "vmm");
        assert!(o.signals.is_empty());
        let keys: Vec<&str> = o.facts.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "hypervisor",
                "dmi",
                "clocksource",
                "vsock",
                "cpuHypervisorFlag",
                "kernel"
            ]
        );
        let hv = fact(&o, "hypervisor");
        assert_eq!(hv["present"], serde_json::json!(false));
        assert!(hv["vendor"].is_null());
        let dmi = fact(&o, "dmi");
        for k in ["sysVendor", "productName", "biosVendor", "boardVendor"] {
            assert!(dmi[k].is_null(), "{k} must be null when unreadable");
        }
        assert!(fact(&o, "clocksource").is_null());
        assert_eq!(fact(&o, "vsock"), serde_json::json!(false));
        assert_eq!(fact(&o, "cpuHypervisorFlag"), serde_json::json!(false));
        assert_eq!(fact(&o, "kernel"), "");
    }
    #[test]
    fn gvisor_short_circuits_firecracker_composite() {
        let d = tempfile::tempdir().unwrap();
        let p = |s: &str| {
            let f = d.path().join(s.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            f
        };
        std::fs::create_dir_all(p("/sys/class/dmi/id")).ok();
        std::fs::write(
            p("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
            "kvm-clock\n",
        )
        .unwrap();
        std::fs::write(p("/dev/vsock"), "").unwrap();
        std::fs::write(p("/proc/cpuinfo"), "flags\t\t: fpu hypervisor\n").unwrap();
        std::fs::write(p("/proc/version"), "Linux version 4.4.0 (gVisor team)\n").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        // Everything the Firecracker composite wants, plus a gVisor version:
        // the gVisor check runs first and returns, so only Gvisor signals.
        let o = probe_vmm_with(
            &fs,
            Some(crate::sys::os::HypervisorInfo {
                present: true,
                vendor: Some("KVMKVMKVM".into()),
            }),
        );
        assert!(o.signals.iter().any(|s| s.runtime == RuntimeKind::Gvisor));
        assert!(
            !o.signals
                .iter()
                .any(|s| s.runtime == RuntimeKind::Firecracker)
        );
    }

    struct StubOs {
        hv: crate::sys::os::HypervisorInfo,
    }
    impl crate::sys::os::OsApi for StubOs {
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            self.hv.clone()
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
    fn run_consumes_ctx_hypervisor() {
        let d = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(d.path().into());
        let os = StubOs {
            hv: crate::sys::os::HypervisorInfo {
                present: true,
                vendor: Some("KVMKVMKVM".into()),
            },
        };
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            compact: false,
            probe_ebpf: Vec::new(),
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
        let o = Vmm.run(&cx);
        let hv = fact(&o, "hypervisor");
        assert_eq!(hv["present"], serde_json::json!(true));
        assert_eq!(hv["vendor"], "KVMKVMKVM");
        // Empty fixture: composite sources absent, so no signals.
        assert!(o.signals.is_empty());
    }
}
