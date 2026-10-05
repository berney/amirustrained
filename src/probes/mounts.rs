//! Mounts and filesystem isolation probe (Task 3).
//!
//! Audits `/proc/self/mountinfo` (with fallback to `/proc/mounts`) to discover:
//! - Staging areas: writable at VFS and DAC layers, lacking `noexec`
//! - Sensitive pseudo-filesystem unmasking: writable `/proc/sys`, unmasked `/proc/kcore`, etc.
//! - Shared mount propagation: containers with `shared:` or `master:` propagation tags
//! - Host leaks: container mounts exposing host root (`/`) or host control sockets

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Probe;
use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::sys::fs::{MountEntry, PseudoFs, errno_of, parse_mountinfo};

pub const PROBE: &str = "mounts";

/// An identified staging mount candidate that is writable and allows execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingMount {
    pub mount_point: String,
    pub fstype: String,
    pub writable_by_caller: bool,
    pub missing_flags: Vec<String>, // any of "noexec", "nosuid", "nodev" that are absent
    pub options: Vec<String>,
}

pub struct Mounts;

impl Probe for Mounts {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_mounts(cx.fs, cx.pid)
    }
}

/// Identifies if a mount source path corresponds to a host block or partition device.
fn is_host_device(source: &str) -> bool {
    if source.starts_with("/dev/sd")
        || source.starts_with("/dev/nvme")
        || source.starts_with("/dev/vd")
        || source.starts_with("/dev/hd")
        || source.starts_with("/dev/xvd")
        || source.starts_with("/dev/mapper/")
        || source.starts_with("/dev/root")
        || source.starts_with("/dev/dm-")
        || source.starts_with("/dev/md")
        || source.starts_with("/dev/loop")
    {
        return true;
    }
    if source.starts_with("/dev/")
        && !source.starts_with("/dev/pts")
        && !source.starts_with("/dev/shm")
        && !source.starts_with("/dev/mqueue")
        && !source.starts_with("/dev/hugepages")
        && source != "/dev"
    {
        return true;
    }
    false
}

/// Checks if a mount entry exposes host root filesystem or host control sockets.
fn is_host_leak(entry: &MountEntry) -> bool {
    if entry.mount_point == "/host" || entry.mount_point.starts_with("/host/") {
        return true;
    }
    if entry.mount_point == "/var/run/docker.sock"
        || entry.mount_point == "/run/docker.sock"
        || entry.mount_point == "/run/containerd/containerd.sock"
        || entry.mount_point == "/var/run/crio/crio.sock"
        || entry.mount_point == "/run/podman/podman.sock"
    {
        return true;
    }
    if entry.root == "/" && is_host_device(&entry.mount_source) {
        return true;
    }
    false
}

/// Gathers mount facts from `/proc/[pid]/mountinfo` or `/proc/mounts`.
pub fn probe_mounts(fs: &PseudoFs, pid: u32) -> ProbeOutcome {
    let mi_path = format!("/proc/{pid}/mountinfo");
    let (content, src) = match fs.read(&mi_path) {
        Ok(c) => (c, mi_path),
        Err(_) => match fs.read("/proc/self/mountinfo") {
            Ok(c) => (c, "/proc/self/mountinfo".to_string()),
            Err(_) => {
                let m_path = format!("/proc/{pid}/mounts");
                match fs.read(&m_path) {
                    Ok(c) => (c, m_path),
                    Err(_) => match fs.read("/proc/mounts") {
                        Ok(c) => (c, "/proc/mounts".to_string()),
                        Err(e) => {
                            let mut o = ProbeOutcome::empty(PROBE);
                            let err_src = "/proc/self/mountinfo".to_string();
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "all",
                                err_src.clone(),
                                errno_of(&e),
                            ));
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "count",
                                err_src.clone(),
                                errno_of(&e),
                            ));
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "staging",
                                err_src.clone(),
                                errno_of(&e),
                            ));
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "sensitive_unmasked",
                                err_src.clone(),
                                errno_of(&e),
                            ));
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "shared_propagation",
                                err_src.clone(),
                                errno_of(&e),
                            ));
                            o = o.with_fact(Fact::unavailable(
                                PROBE,
                                "host_leaks",
                                err_src,
                                errno_of(&e),
                            ));
                            return o;
                        }
                    },
                }
            }
        },
    };

    let entries = parse_mountinfo(&content);

    // 1. Staging mounts: rw + !noexec + fs.writable
    let mut staging = Vec::new();
    for entry in &entries {
        let is_rw = entry.mount_options.iter().any(|o| o == "rw");
        let has_noexec = entry.mount_options.iter().any(|o| o == "noexec");
        if is_rw
            && !has_noexec
            && fs.writable(&entry.mount_point)
            && !staging
                .iter()
                .any(|s: &StagingMount| s.mount_point == entry.mount_point)
        {
            let mut missing_flags = Vec::new();
            for flag in ["noexec", "nosuid", "nodev"] {
                if !entry.mount_options.iter().any(|o| o == flag) {
                    missing_flags.push(flag.to_string());
                }
            }
            staging.push(StagingMount {
                mount_point: entry.mount_point.clone(),
                fstype: entry.fstype.clone(),
                writable_by_caller: true,
                missing_flags,
                options: entry.mount_options.clone(),
            });
        }
    }

    // 2. Sensitive unmasked paths
    let mut sensitive_unmasked = Vec::new();

    // /proc/sys: writable if mounted rw or if procfs is writable and not covered by ro sub-mount
    let proc_sys_ro = entries
        .iter()
        .any(|e| e.mount_point == "/proc/sys" && e.mount_options.iter().any(|o| o == "ro"));
    let proc_sys_rw = entries
        .iter()
        .any(|e| e.mount_point == "/proc/sys" && e.mount_options.iter().any(|o| o == "rw"));
    if !proc_sys_ro && (proc_sys_rw || (fs.exists("/proc/sys") && fs.writable("/proc/sys"))) {
        sensitive_unmasked.push("/proc/sys".to_string());
    }

    // /proc/kcore: unmasked if present and not covered by masking mount
    let kcore_masked = entries.iter().any(|e| e.mount_point == "/proc/kcore");
    if !kcore_masked && fs.exists("/proc/kcore") {
        sensitive_unmasked.push("/proc/kcore".to_string());
    }

    // /proc/sysrq-trigger: unmasked if writable and not masked
    let sysrq_masked = entries
        .iter()
        .any(|e| e.mount_point == "/proc/sysrq-trigger");
    if !sysrq_masked && fs.exists("/proc/sysrq-trigger") && fs.writable("/proc/sysrq-trigger") {
        sensitive_unmasked.push("/proc/sysrq-trigger".to_string());
    }

    // /sys/firmware: unmasked if accessible and not masked
    let firmware_masked = entries.iter().any(|e| e.mount_point == "/sys/firmware");
    if !firmware_masked && fs.exists("/sys/firmware") && fs.readable("/sys/firmware") {
        sensitive_unmasked.push("/sys/firmware".to_string());
    }

    // 3. Shared propagation
    let mut shared_propagation = Vec::new();
    for entry in &entries {
        if entry
            .optional_fields
            .iter()
            .any(|f| f.starts_with("shared:") || f.starts_with("master:"))
            && !shared_propagation.contains(&entry.mount_point)
        {
            shared_propagation.push(entry.mount_point.clone());
        }
    }

    // 4. Host leaks
    let mut host_leaks = Vec::new();
    for entry in &entries {
        if is_host_leak(entry) && !host_leaks.contains(&entry.mount_point) {
            host_leaks.push(entry.mount_point.clone());
        }
    }

    let mut o = ProbeOutcome::empty(PROBE);
    o = o.with_fact(Fact::ok(
        PROBE,
        "all",
        serde_json::to_value(&entries).unwrap_or(Value::Null),
        src.clone(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "count",
        serde_json::to_value(entries.len()).unwrap_or(Value::Null),
        src.clone(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "staging",
        serde_json::to_value(&staging).unwrap_or(Value::Null),
        src.clone(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "sensitive_unmasked",
        serde_json::to_value(&sensitive_unmasked).unwrap_or(Value::Null),
        src.clone(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "shared_propagation",
        serde_json::to_value(&shared_propagation).unwrap_or(Value::Null),
        src.clone(),
    ));
    o = o.with_fact(Fact::ok(
        PROBE,
        "host_leaks",
        serde_json::to_value(&host_leaks).unwrap_or(Value::Null),
        src,
    ));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;
    use std::os::unix::fs::PermissionsExt;

    fn fixture_fs(files: &[(&str, &str)]) -> (tempfile::TempDir, PseudoFs) {
        let d = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let full = d.path().join(path.trim_start_matches('/'));
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, content).unwrap();
        }
        let fs = PseudoFs::new(d.path().to_path_buf());
        (d, fs)
    }

    #[test]
    fn test_staging_classification_checks_dac_writability() {
        // Mount with rw and no noexec is emitted in mounts.staging IF fs.writable is true.
        // If directory is read-only DAC, it is NOT in mounts.staging.
        let mountinfo = "\
20 1 0:20 / /tmp rw,relatime - tmpfs tmpfs rw\n\
21 1 0:21 / /var/ro_dir rw,relatime - tmpfs tmpfs rw\n";

        let (d, fs) = fixture_fs(&[("proc/self/mountinfo", mountinfo)]);

        let tmp_path = d.path().join("tmp");
        std::fs::create_dir_all(&tmp_path).unwrap();

        let ro_path = d.path().join("var/ro_dir");
        std::fs::create_dir_all(&ro_path).unwrap();
        std::fs::set_permissions(&ro_path, std::fs::Permissions::from_mode(0o555)).unwrap();

        let o = probe_mounts(&fs, 1);
        let staging_fact = o.facts.iter().find(|f| f.key == "staging").unwrap();
        let staging: Vec<StagingMount> =
            serde_json::from_value(staging_fact.value.clone()).unwrap();

        // Restore permissions for clean tempdir removal
        let _ = std::fs::set_permissions(&ro_path, std::fs::Permissions::from_mode(0o755));

        assert_eq!(staging.len(), 1);
        assert_eq!(staging[0].mount_point, "/tmp");
        assert!(staging[0].writable_by_caller);
        assert_eq!(staging[0].fstype, "tmpfs");
        assert!(staging.iter().all(|s| s.mount_point != "/var/ro_dir"));
    }

    #[test]
    fn test_missing_flags_computed() {
        // Detects absence of noexec, nosuid, nodev.
        let mountinfo = "\
30 1 0:30 / /mnt/none rw,relatime - ext4 /dev/sda1 rw\n\
31 1 0:31 / /mnt/nosuid rw,nosuid,relatime - ext4 /dev/sda2 rw\n\
32 1 0:32 / /mnt/nodev rw,nodev,relatime - ext4 /dev/sda3 rw\n\
33 1 0:33 / /mnt/both rw,nosuid,nodev,relatime - ext4 /dev/sda4 rw\n\
34 1 0:34 / /mnt/hardened rw,nosuid,nodev,noexec,relatime - ext4 /dev/sda5 rw\n\
35 1 0:35 / /mnt/ro ro,nosuid,nodev - ext4 /dev/sda6 ro\n";

        let (d, fs) = fixture_fs(&[("proc/self/mountinfo", mountinfo)]);

        for p in &[
            "mnt/none",
            "mnt/nosuid",
            "mnt/nodev",
            "mnt/both",
            "mnt/hardened",
            "mnt/ro",
        ] {
            std::fs::create_dir_all(d.path().join(p)).unwrap();
        }

        let o = probe_mounts(&fs, 1);
        let staging_fact = o.facts.iter().find(|f| f.key == "staging").unwrap();
        let staging: Vec<StagingMount> =
            serde_json::from_value(staging_fact.value.clone()).unwrap();

        assert_eq!(staging.len(), 4);

        let none_m = staging
            .iter()
            .find(|s| s.mount_point == "/mnt/none")
            .unwrap();
        assert_eq!(none_m.missing_flags, vec!["noexec", "nosuid", "nodev"]);

        let nosuid_m = staging
            .iter()
            .find(|s| s.mount_point == "/mnt/nosuid")
            .unwrap();
        assert_eq!(nosuid_m.missing_flags, vec!["noexec", "nodev"]);

        let nodev_m = staging
            .iter()
            .find(|s| s.mount_point == "/mnt/nodev")
            .unwrap();
        assert_eq!(nodev_m.missing_flags, vec!["noexec", "nosuid"]);

        let both_m = staging
            .iter()
            .find(|s| s.mount_point == "/mnt/both")
            .unwrap();
        assert_eq!(both_m.missing_flags, vec!["noexec"]);

        // Hardened (has noexec) and ro (not rw) must NOT be in staging
        assert!(staging.iter().all(|s| s.mount_point != "/mnt/hardened"));
        assert!(staging.iter().all(|s| s.mount_point != "/mnt/ro"));
    }

    #[test]
    fn test_sensitive_unmasked_paths() {
        // Flags writable /proc/sys and unmasked /proc/kcore
        let mountinfo = "40 1 0:40 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
        let (d, fs) = fixture_fs(&[("proc/self/mountinfo", mountinfo)]);

        // Make /proc/sys writable directory
        let sys_path = d.path().join("proc/sys");
        std::fs::create_dir_all(&sys_path).unwrap();

        // Create /proc/kcore file
        let kcore_path = d.path().join("proc/kcore");
        std::fs::write(&kcore_path, b"ELF...").unwrap();

        // Create writable /proc/sysrq-trigger
        let sysrq_path = d.path().join("proc/sysrq-trigger");
        std::fs::write(&sysrq_path, b"").unwrap();

        // Create readable /sys/firmware
        let fw_path = d.path().join("sys/firmware");
        std::fs::create_dir_all(&fw_path).unwrap();

        let o = probe_mounts(&fs, 1);
        let unmasked_fact = o
            .facts
            .iter()
            .find(|f| f.key == "sensitive_unmasked")
            .unwrap();
        let unmasked: Vec<String> = serde_json::from_value(unmasked_fact.value.clone()).unwrap();

        assert!(unmasked.contains(&"/proc/sys".to_string()));
        assert!(unmasked.contains(&"/proc/kcore".to_string()));
        assert!(unmasked.contains(&"/proc/sysrq-trigger".to_string()));
        assert!(unmasked.contains(&"/sys/firmware".to_string()));

        // Now test masked case: /proc/sys mounted ro, /proc/kcore masked by mount, etc.
        let masked_mountinfo = "\
40 1 0:40 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
41 40 0:41 / /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc ro\n\
42 40 0:42 / /proc/kcore rw,nosuid,noexec,relatime - tmpfs tmpfs rw\n\
43 40 0:43 / /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc ro\n\
44 1 0:44 / /sys/firmware ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs ro\n";

        let (d2, fs2) = fixture_fs(&[("proc/self/mountinfo", masked_mountinfo)]);
        std::fs::create_dir_all(d2.path().join("proc/sys")).unwrap();
        std::fs::write(d2.path().join("proc/kcore"), b"ELF...").unwrap();
        std::fs::write(d2.path().join("proc/sysrq-trigger"), b"").unwrap();
        std::fs::create_dir_all(d2.path().join("sys/firmware")).unwrap();

        let o2 = probe_mounts(&fs2, 1);
        let unmasked_fact2 = o2
            .facts
            .iter()
            .find(|f| f.key == "sensitive_unmasked")
            .unwrap();
        let unmasked2: Vec<String> = serde_json::from_value(unmasked_fact2.value.clone()).unwrap();
        assert!(
            unmasked2.is_empty(),
            "expected all sensitive paths to be masked, got: {:?}",
            unmasked2
        );
    }

    #[test]
    fn test_shared_propagation() {
        // Flags entries with shared:1 or master:2
        let mountinfo = "\
50 1 0:50 / /data rw shared:1 - ext4 /dev/sda1 rw\n\
51 1 0:51 / /srv rw master:2 - ext4 /dev/sda2 rw\n\
52 1 0:52 / /var rw shared:1 master:2 - ext4 /dev/sda3 rw\n\
53 1 0:53 / /home rw propagate_from:1 - ext4 /dev/sda4 rw\n\
54 1 0:54 / /usr rw - ext4 /dev/sda5 rw\n";

        let (_d, fs) = fixture_fs(&[("proc/self/mountinfo", mountinfo)]);

        let o = probe_mounts(&fs, 1);
        let prop_fact = o
            .facts
            .iter()
            .find(|f| f.key == "shared_propagation")
            .unwrap();
        let prop: Vec<String> = serde_json::from_value(prop_fact.value.clone()).unwrap();

        assert_eq!(prop, vec!["/data", "/srv", "/var"]);
    }

    #[test]
    fn test_host_leaks() {
        // Flags entries with root == "/" from host device or /host mount point
        let mountinfo = "\
60 1 8:1 / /mnt/host_root rw - ext4 /dev/sda1 rw\n\
61 1 259:1 / /host rw - ext4 /dev/nvme0n1p2 rw\n\
62 1 254:0 /var /host/var rw - ext4 /dev/vda1 rw\n\
63 1 0:63 /docker.sock /var/run/docker.sock rw - tmpfs tmpfs rw\n\
64 1 0:64 / /app rw - overlay overlay rw\n\
65 1 8:1 /subpath /mnt/subpath rw - ext4 /dev/sda1 rw\n";

        let (_d, fs) = fixture_fs(&[("proc/self/mountinfo", mountinfo)]);

        let o = probe_mounts(&fs, 1);
        let leak_fact = o.facts.iter().find(|f| f.key == "host_leaks").unwrap();
        let leaks: Vec<String> = serde_json::from_value(leak_fact.value.clone()).unwrap();

        assert!(leaks.contains(&"/mnt/host_root".to_string()));
        assert!(leaks.contains(&"/host".to_string()));
        assert!(leaks.contains(&"/host/var".to_string()));
        assert!(leaks.contains(&"/var/run/docker.sock".to_string()));
        assert!(!leaks.contains(&"/app".to_string()));
        assert!(!leaks.contains(&"/mnt/subpath".to_string()));
    }

    #[test]
    fn test_fallback_to_proc_mounts() {
        let legacy_mounts = "\
rootfs / rootfs rw 0 0\n\
/dev/sda1 / ext4 rw,relatime 0 0\n\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
tmpfs /tmp tmpfs rw,relatime 0 0\n";

        let (d, fs) = fixture_fs(&[("proc/mounts", legacy_mounts)]);
        std::fs::create_dir_all(d.path().join("tmp")).unwrap();

        let o = probe_mounts(&fs, 1);
        let count_fact = o.facts.iter().find(|f| f.key == "count").unwrap();
        assert_eq!(count_fact.value, serde_json::json!(4));

        let staging_fact = o.facts.iter().find(|f| f.key == "staging").unwrap();
        let staging: Vec<StagingMount> =
            serde_json::from_value(staging_fact.value.clone()).unwrap();
        assert!(staging.iter().any(|s| s.mount_point == "/tmp"));
    }

    #[test]
    fn test_mountinfo_unavailable_returns_unavailable_facts() {
        let (_d, fs) = fixture_fs(&[]);
        let o = probe_mounts(&fs, 1);
        assert_eq!(o.facts.len(), 6);
        for f in &o.facts {
            assert_eq!(f.status, FactStatus::Unavailable);
        }
    }
}
