use serde_json::json;

use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

pub const PROBE: &str = "kernel-surface";
pub const FACT_PROBE: &str = "kernel.surface";

pub struct KernelSurface;

impl Probe for KernelSurface {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_kernel_surface(cx.fs)
    }
}

pub fn parse_sysctl_bool(raw: &str) -> Option<bool> {
    match raw.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

pub fn parse_lockdown(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Some(start) = trimmed.find('[') {
        let rest = &trimmed[start + 1..];
        let end = rest.find(']')?;
        let mode = rest[..end].trim();
        if mode.is_empty() {
            None
        } else {
            Some(mode.to_string())
        }
    } else if matches!(trimmed, "none" | "integrity" | "confidentiality") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

pub fn check_device(fs: &PseudoFs, path: &str) -> &'static str {
    if !fs.exists(path) {
        "absent"
    } else if fs.writable(path) || fs.readable(path) {
        "accessible"
    } else {
        "denied"
    }
}

pub fn probe_kernel_surface(fs: &PseudoFs) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);

    let modules_disabled = fs
        .read("/proc/sys/kernel/modules_disabled")
        .ok()
        .and_then(|s| parse_sysctl_bool(&s));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "modules_disabled",
        json!(modules_disabled),
        "/proc/sys/kernel/modules_disabled".into(),
    ));

    let kexec_load_disabled = fs
        .read("/proc/sys/kernel/kexec_load_disabled")
        .ok()
        .and_then(|s| parse_sysctl_bool(&s));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "kexec_load_disabled",
        json!(kexec_load_disabled),
        "/proc/sys/kernel/kexec_load_disabled".into(),
    ));

    let kexec_loaded = fs
        .read("/sys/kernel/kexec_loaded")
        .ok()
        .and_then(|s| parse_sysctl_bool(&s));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "kexec_loaded",
        json!(kexec_loaded),
        "/sys/kernel/kexec_loaded".into(),
    ));

    let lockdown = fs
        .read("/sys/kernel/security/lockdown")
        .ok()
        .and_then(|s| parse_lockdown(&s));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "lockdown",
        json!(lockdown),
        "/sys/kernel/security/lockdown".into(),
    ));

    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "dev_mem",
        json!(check_device(fs, "/dev/mem")),
        "/dev/mem".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "dev_kmem",
        json!(check_device(fs, "/dev/kmem")),
        "/dev/kmem".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "dev_port",
        json!(check_device(fs, "/dev/port")),
        "/dev/port".into(),
    ));

    let core_pattern_path = "/proc/sys/kernel/core_pattern";
    let core_pattern = fs.read(core_pattern_path).ok();
    let core_pattern_writable = fs.writable(core_pattern_path);
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "core_pattern",
        json!({
            "pattern": core_pattern,
            "writable": core_pattern_writable,
        }),
        core_pattern_path.into(),
    ));

    let modprobe_path = "/proc/sys/kernel/modprobe";
    let modprobe = fs.read(modprobe_path).ok();
    let modprobe_writable = fs.writable(modprobe_path);
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "modprobe",
        json!({
            "path": modprobe,
            "writable": modprobe_writable,
        }),
        modprobe_path.into(),
    ));

    let livepatch_path = "/sys/kernel/livepatch";
    let livepatch_present = fs.exists(livepatch_path);
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "livepatch_present",
        json!(livepatch_present),
        livepatch_path.into(),
    ));

    let acpi_table_path = "/sys/kernel/config/acpi/table";
    let acpi_table_writable = fs.exists(acpi_table_path) && fs.writable(acpi_table_path);
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "acpi_table_writable",
        json!(acpi_table_writable),
        acpi_table_path.into(),
    ));

    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn modules_disabled_parses_boolean() {
        assert_eq!(parse_sysctl_bool("1\n"), Some(true));
        assert_eq!(parse_sysctl_bool("0\n"), Some(false));
        assert_eq!(parse_sysctl_bool("1"), Some(true));
        assert_eq!(parse_sysctl_bool("0"), Some(false));
        assert_eq!(parse_sysctl_bool(""), None);
        assert_eq!(parse_sysctl_bool("2\n"), None);
        assert_eq!(parse_sysctl_bool("garbage"), None);
    }

    #[test]
    fn lockdown_parses_active_mode() {
        assert_eq!(
            parse_lockdown("[none] integrity confidentiality\n"),
            Some("none".to_string())
        );
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality\n"),
            Some("integrity".to_string())
        );
        assert_eq!(
            parse_lockdown("none integrity [confidentiality]\n"),
            Some("confidentiality".to_string())
        );
        assert_eq!(parse_lockdown("invalid"), None);
        assert_eq!(parse_lockdown("[]"), None);
    }

    #[test]
    fn lockdown_parses_bare_mode() {
        assert_eq!(parse_lockdown("none\n"), Some("none".to_string()));
        assert_eq!(parse_lockdown("integrity\n"), Some("integrity".to_string()));
        assert_eq!(
            parse_lockdown("confidentiality"),
            Some("confidentiality".to_string())
        );
        assert_eq!(parse_lockdown("unknown_mode\n"), None);
    }

    #[test]
    fn core_pattern_and_modprobe_writability() {
        let dir = tempfile::tempdir().unwrap();
        let proc_sys = dir.path().join("proc/sys/kernel");
        std::fs::create_dir_all(&proc_sys).unwrap();

        let cp = proc_sys.join("core_pattern");
        std::fs::write(&cp, "core\n").unwrap();
        std::fs::set_permissions(&cp, std::fs::Permissions::from_mode(0o444)).unwrap();

        let mp = proc_sys.join("modprobe");
        std::fs::write(&mp, "/sbin/modprobe\n").unwrap();

        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_surface(&fs);

        let cp_fact = outcome
            .facts
            .iter()
            .find(|f| f.probe == FACT_PROBE && f.key == "core_pattern")
            .unwrap();
        assert_eq!(
            cp_fact.value,
            json!({ "pattern": "core", "writable": false })
        );

        let mp_fact = outcome
            .facts
            .iter()
            .find(|f| f.probe == FACT_PROBE && f.key == "modprobe")
            .unwrap();
        assert_eq!(
            mp_fact.value,
            json!({ "path": "/sbin/modprobe", "writable": true })
        );
    }

    #[test]
    fn character_device_presence_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("dev");
        std::fs::create_dir_all(&dev).unwrap();

        let mem = dev.join("mem");
        std::fs::write(&mem, "").unwrap();

        let port = dev.join("port");
        std::fs::write(&port, "").unwrap();
        std::fs::set_permissions(&port, std::fs::Permissions::from_mode(0o000)).unwrap();

        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(check_device(&fs, "/dev/mem"), "accessible");
        assert_eq!(check_device(&fs, "/dev/kmem"), "absent");
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(check_device(&fs, "/dev/port"), "denied");
        }
    }

    #[test]
    fn livepatch_and_acpi_presence_and_writability() {
        let dir = tempfile::tempdir().unwrap();
        let sys_kernel = dir.path().join("sys/kernel");
        let livepatch = sys_kernel.join("livepatch");
        let acpi = sys_kernel.join("config/acpi/table");

        std::fs::create_dir_all(&livepatch).unwrap();
        std::fs::create_dir_all(&acpi).unwrap();

        let fs = PseudoFs::new(dir.path().into());
        assert!(fs.exists("/sys/kernel/livepatch"));
        assert!(fs.exists("/sys/kernel/config/acpi/table"));
        assert!(fs.writable("/sys/kernel/config/acpi/table"));

        let outcome = probe_kernel_surface(&fs);
        let livepatch_fact = outcome
            .facts
            .iter()
            .find(|f| f.probe == FACT_PROBE && f.key == "livepatch_present")
            .unwrap();
        assert_eq!(livepatch_fact.value, json!(true));

        let acpi_fact = outcome
            .facts
            .iter()
            .find(|f| f.probe == FACT_PROBE && f.key == "acpi_table_writable")
            .unwrap();
        assert_eq!(acpi_fact.value, json!(true));
    }

    #[test]
    fn full_kernel_surface_probe_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let proc_sys = dir.path().join("proc/sys/kernel");
        let sys_kernel = dir.path().join("sys/kernel");
        let sys_sec = dir.path().join("sys/kernel/security");
        let dev = dir.path().join("dev");
        let livepatch = dir.path().join("sys/kernel/livepatch");
        let acpi = dir.path().join("sys/kernel/config/acpi/table");

        std::fs::create_dir_all(&proc_sys).unwrap();
        std::fs::create_dir_all(&sys_kernel).unwrap();
        std::fs::create_dir_all(&sys_sec).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(&livepatch).unwrap();
        std::fs::create_dir_all(&acpi).unwrap();

        std::fs::write(proc_sys.join("modules_disabled"), "1\n").unwrap();
        std::fs::write(proc_sys.join("kexec_load_disabled"), "0\n").unwrap();
        std::fs::write(sys_kernel.join("kexec_loaded"), "0\n").unwrap();
        std::fs::write(
            sys_sec.join("lockdown"),
            "[none] integrity confidentiality\n",
        )
        .unwrap();
        std::fs::write(
            proc_sys.join("core_pattern"),
            "|/usr/lib/systemd/systemd-coredump %P\n",
        )
        .unwrap();
        std::fs::write(proc_sys.join("modprobe"), "/sbin/modprobe\n").unwrap();
        std::fs::write(dev.join("mem"), "").unwrap();
        std::fs::write(dev.join("port"), "").unwrap();

        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_surface(&fs);

        let fact_val = |key: &str| -> serde_json::Value {
            outcome
                .facts
                .iter()
                .find(|f| f.probe == FACT_PROBE && f.key == key)
                .unwrap_or_else(|| panic!("missing fact key: {key}"))
                .value
                .clone()
        };

        assert_eq!(fact_val("modules_disabled"), json!(true));
        assert_eq!(fact_val("kexec_load_disabled"), json!(false));
        assert_eq!(fact_val("kexec_loaded"), json!(false));
        assert_eq!(fact_val("lockdown"), json!("none"));
        assert_eq!(fact_val("dev_mem"), json!("accessible"));
        assert_eq!(fact_val("dev_kmem"), json!("absent"));
        assert_eq!(fact_val("dev_port"), json!("accessible"));
        assert_eq!(
            fact_val("core_pattern"),
            json!({
                "pattern": "|/usr/lib/systemd/systemd-coredump %P",
                "writable": true
            })
        );
        assert_eq!(
            fact_val("modprobe"),
            json!({
                "path": "/sbin/modprobe",
                "writable": true
            })
        );
        assert_eq!(fact_val("livepatch_present"), json!(true));
        assert_eq!(fact_val("acpi_table_writable"), json!(true));
    }

    #[test]
    fn defaults_when_files_absent() {
        let dir = tempfile::tempdir().unwrap();
        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_surface(&fs);

        let fact_val = |key: &str| -> serde_json::Value {
            outcome
                .facts
                .iter()
                .find(|f| f.probe == FACT_PROBE && f.key == key)
                .unwrap_or_else(|| panic!("missing fact key: {key}"))
                .value
                .clone()
        };

        assert_eq!(fact_val("modules_disabled"), serde_json::Value::Null);
        assert_eq!(fact_val("kexec_load_disabled"), serde_json::Value::Null);
        assert_eq!(fact_val("kexec_loaded"), serde_json::Value::Null);
        assert_eq!(fact_val("lockdown"), serde_json::Value::Null);
        assert_eq!(fact_val("dev_mem"), json!("absent"));
        assert_eq!(fact_val("dev_kmem"), json!("absent"));
        assert_eq!(fact_val("dev_port"), json!("absent"));
        assert_eq!(
            fact_val("core_pattern"),
            json!({ "pattern": null, "writable": false })
        );
        assert_eq!(
            fact_val("modprobe"),
            json!({ "path": null, "writable": false })
        );
        assert_eq!(fact_val("livepatch_present"), json!(false));
        assert_eq!(fact_val("acpi_table_writable"), json!(false));
    }
}
