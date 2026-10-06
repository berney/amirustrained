use sha2::{Digest, Sha256};

use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

pub const PROBE: &str = "kernel-config";
pub const FACT_PROBE: &str = "kernel.config";

pub const WHITELIST: &[&str] = &[
    "CONFIG_MODULES",
    "CONFIG_MODULE_UNLOAD",
    "CONFIG_MODULE_SIG",
    "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_MODULE_SIG_ALL",
    "CONFIG_KEXEC",
    "CONFIG_KEXEC_FILE",
    "CONFIG_KEXEC_SIG",
    "CONFIG_KEXEC_SIG_FORCE",
    "CONFIG_DEVMEM",
    "CONFIG_STRICT_DEVMEM",
    "CONFIG_IO_STRICT_DEVMEM",
    "CONFIG_DEVKMEM",
    "CONFIG_SECURITY_LOCKDOWN_LSM",
    "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY",
    "CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE",
    "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY",
    "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
    "CONFIG_SECURITY_LANDLOCK",
    "CONFIG_SECURITY_APPARMOR",
    "CONFIG_SECURITY_SELINUX",
    "CONFIG_LIVEPATCH",
    "CONFIG_ACPI_CUSTOM_METHOD",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_USER_NS",
];

pub struct KernelConfig;

impl Probe for KernelConfig {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let release = rustix::system::uname()
            .release()
            .to_string_lossy()
            .into_owned();
        probe_kernel_config(cx.fs, &release)
    }
}

pub fn parse_config_line(line: &str) -> Option<(&str, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('#') {
        let rest = rest.trim();
        if let Some(key) = rest.strip_suffix(" is not set") {
            let key = key.trim();
            if key.starts_with("CONFIG_") {
                return Some((key, "n".to_string()));
            }
        }
        return None;
    }
    if let Some((key, val)) = trimmed.split_once('=') {
        let key = key.trim();
        let val = val.trim();
        if key.starts_with("CONFIG_") {
            let clean_val = if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
                &val[1..val.len() - 1]
            } else {
                val
            };
            return Some((key, clean_val.to_string()));
        }
    }
    None
}

pub fn parse_config(text: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        if let Some((key, val)) = parse_config_line(line)
            && WHITELIST.contains(&key)
        {
            map.insert(key.to_string(), serde_json::Value::String(val));
        }
    }
    map
}

pub fn normalize_lf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn probe_kernel_config(fs: &PseudoFs, release: &str) -> ProbeOutcome {
    let candidates = [
        "/proc/config.gz".to_string(),
        format!("/boot/config-{release}"),
        "/proc/config".to_string(),
    ];

    for path in &candidates {
        if let Ok(raw_bytes) = fs.read_to_end(path) {
            let is_gz = path.ends_with(".gz") || raw_bytes.starts_with(&[0x1f, 0x8b]);
            let uncompressed = if is_gz {
                match crate::sys::gz::decompress_gz(&raw_bytes) {
                    Ok(decompressed) => decompressed,
                    Err(_) => continue,
                }
            } else {
                raw_bytes.clone()
            };

            let raw_sha256 = sha256_hex(&raw_bytes);
            let normalized = normalize_lf(&uncompressed);
            let uncompressed_sha256 = sha256_hex(&normalized);
            let text = String::from_utf8_lossy(&normalized);
            let options = parse_config(&text);

            let mut o = ProbeOutcome::empty(PROBE);
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "path",
                serde_json::Value::String(path.clone()),
                path.clone(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "raw_sha256",
                serde_json::Value::String(raw_sha256),
                path.clone(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "uncompressed_sha256",
                serde_json::Value::String(uncompressed_sha256),
                path.clone(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "options",
                serde_json::Value::Object(options),
                path.clone(),
            ));
            return o;
        }
    }

    let mut o = ProbeOutcome::empty(PROBE);
    let fallback = "/proc/config.gz".to_string();
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "path",
        serde_json::Value::Null,
        fallback.clone(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "raw_sha256",
        serde_json::Value::Null,
        fallback.clone(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "uncompressed_sha256",
        serde_json::Value::Null,
        fallback.clone(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "options",
        serde_json::Value::Null,
        fallback,
    ));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde_json::json;
    use std::io::Write;

    fn gzip_bytes(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn parse_not_set_maps_to_n() {
        let (key, val) = parse_config_line("# CONFIG_MODULE_UNLOAD is not set").unwrap();
        assert_eq!(key, "CONFIG_MODULE_UNLOAD");
        assert_eq!(val, "n");
    }

    #[test]
    fn parse_bool_yes_maps_to_y() {
        let (key, val) = parse_config_line("CONFIG_MODULES=y").unwrap();
        assert_eq!(key, "CONFIG_MODULES");
        assert_eq!(val, "y");
    }

    #[test]
    fn parse_quoted_string_strips_quotes() {
        let (key, val) = parse_config_line(r#"CONFIG_DEFAULT_HOSTNAME="box""#).unwrap();
        assert_eq!(key, "CONFIG_DEFAULT_HOSTNAME");
        assert_eq!(val, "box");
    }

    #[test]
    fn whitelist_filtering_discards_unrelated_options() {
        let config = "\
CONFIG_MODULES=y
CONFIG_SND_HDA=y
CONFIG_DEFAULT_HOSTNAME=\"box\"
# CONFIG_MODULE_UNLOAD is not set
CONFIG_USER_NS=y
";
        let opts = parse_config(config);
        assert_eq!(opts.get("CONFIG_MODULES"), Some(&json!("y")));
        assert_eq!(opts.get("CONFIG_MODULE_UNLOAD"), Some(&json!("n")));
        assert_eq!(opts.get("CONFIG_USER_NS"), Some(&json!("y")));
        // Unrelated or not in security whitelist should be discarded:
        assert!(!opts.contains_key("CONFIG_SND_HDA"));
        assert!(!opts.contains_key("CONFIG_DEFAULT_HOSTNAME"));
    }

    #[test]
    fn dual_sha256_computation_raw_vs_uncompressed() {
        let plain = b"CONFIG_MODULES=y\r\nCONFIG_KEXEC=y\r\n";
        let compressed = gzip_bytes(plain);

        let raw_hash = sha256_hex(&compressed);
        let normalized = normalize_lf(plain);
        let uncompressed_hash = sha256_hex(&normalized);

        assert_ne!(raw_hash, uncompressed_hash);
        // Normalized newlines must convert \r\n to \n
        assert_eq!(normalized, b"CONFIG_MODULES=y\nCONFIG_KEXEC=y\n");
    }

    #[test]
    fn probe_absent_emits_null_facts_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_config(&fs, "6.8.0");

        assert_eq!(outcome.name, PROBE);
        let fact = |key: &str| {
            outcome
                .facts
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| panic!("missing fact {key}"))
        };

        let path = fact("path");
        assert_eq!(path.status, FactStatus::Ok);
        assert_eq!(path.value, serde_json::Value::Null);

        let raw_hash = fact("raw_sha256");
        assert_eq!(raw_hash.status, FactStatus::Ok);
        assert_eq!(raw_hash.value, serde_json::Value::Null);

        let uncomp_hash = fact("uncompressed_sha256");
        assert_eq!(uncomp_hash.status, FactStatus::Ok);
        assert_eq!(uncomp_hash.value, serde_json::Value::Null);

        let opts = fact("options");
        assert_eq!(opts.status, FactStatus::Ok);
        assert_eq!(opts.value, serde_json::Value::Null);
    }

    #[test]
    fn probe_discovers_proc_config_gz_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let proc_dir = dir.path().join("proc");
        std::fs::create_dir_all(&proc_dir).unwrap();

        let config_text =
            b"CONFIG_MODULES=y\n# CONFIG_MODULE_UNLOAD is not set\nCONFIG_BPF_SYSCALL=y\n";
        let gz = gzip_bytes(config_text);
        std::fs::write(proc_dir.join("config.gz"), &gz).unwrap();

        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_config(&fs, "6.8.0");

        assert_eq!(outcome.name, PROBE);
        let fact = |key: &str| {
            outcome
                .facts
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| panic!("missing fact {key}"))
        };

        let path = fact("path");
        assert_eq!(path.value, json!("/proc/config.gz"));

        let raw_hash = fact("raw_sha256");
        assert_eq!(raw_hash.value, json!(sha256_hex(&gz)));

        let uncomp_hash = fact("uncompressed_sha256");
        assert_eq!(uncomp_hash.value, json!(sha256_hex(config_text)));

        let opts = fact("options");
        assert_eq!(opts.value["CONFIG_MODULES"], json!("y"));
        assert_eq!(opts.value["CONFIG_MODULE_UNLOAD"], json!("n"));
        assert_eq!(opts.value["CONFIG_BPF_SYSCALL"], json!("y"));
    }

    #[test]
    fn probe_candidate_precedence_proc_config_gz_over_boot_config() {
        let dir = tempfile::tempdir().unwrap();
        let proc_dir = dir.path().join("proc");
        let boot_dir = dir.path().join("boot");
        std::fs::create_dir_all(&proc_dir).unwrap();
        std::fs::create_dir_all(&boot_dir).unwrap();

        let gz = gzip_bytes(b"CONFIG_MODULES=y\n");
        std::fs::write(proc_dir.join("config.gz"), &gz).unwrap();
        std::fs::write(boot_dir.join("config-6.8.0"), b"CONFIG_MODULES=n\n").unwrap();

        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_config(&fs, "6.8.0");

        let fact = |key: &str| {
            outcome
                .facts
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| panic!("missing fact {key}"))
        };

        assert_eq!(fact("path").value, json!("/proc/config.gz"));
        assert_eq!(fact("options").value["CONFIG_MODULES"], json!("y"));
    }

    #[test]
    fn probe_candidate_boot_config_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let boot_dir = dir.path().join("boot");
        std::fs::create_dir_all(&boot_dir).unwrap();

        let plain = b"CONFIG_MODULES=y\nCONFIG_DEVMEM=y\n";
        std::fs::write(boot_dir.join("config-6.8.0"), plain).unwrap();

        let fs = PseudoFs::new(dir.path().into());
        let outcome = probe_kernel_config(&fs, "6.8.0");

        let fact = |key: &str| {
            outcome
                .facts
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| panic!("missing fact {key}"))
        };

        assert_eq!(fact("path").value, json!("/boot/config-6.8.0"));
        assert_eq!(fact("raw_sha256").value, json!(sha256_hex(plain)));
        assert_eq!(fact("uncompressed_sha256").value, json!(sha256_hex(plain)));
        assert_eq!(fact("options").value["CONFIG_DEVMEM"], json!("y"));
    }

    #[test]
    fn run_invokes_probe_via_ctx() {
        let dir = tempfile::tempdir().unwrap();
        let boot_dir = dir.path().join("boot");
        std::fs::create_dir_all(&boot_dir).unwrap();

        let release = rustix::system::uname()
            .release()
            .to_string_lossy()
            .into_owned();
        let path = boot_dir.join(format!("config-{release}"));
        std::fs::write(&path, b"CONFIG_USER_NS=y\n").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        let os = crate::sys::os::RealOs;
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: false,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = Ctx {
            pid: std::process::id(),
            uid: 0,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: Default::default(),
        };

        let outcome = KernelConfig.run(&cx);
        assert_eq!(outcome.name, PROBE);
        let opt_fact = outcome.facts.iter().find(|f| f.key == "options").unwrap();
        assert_eq!(opt_fact.value["CONFIG_USER_NS"], json!("y"));
    }
}
