use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq)]
pub enum ProbeIo {
    NotFound,
    PermissionDenied,
    Other(String),
}

impl From<std::io::Error> for ProbeIo {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            NotFound => ProbeIo::NotFound,
            PermissionDenied => ProbeIo::PermissionDenied,
            _ => ProbeIo::Other(e.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct PseudoFs {
    root: PathBuf,
}

impl PseudoFs {
    pub fn real() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn is_fixture(&self) -> bool {
        self.root != Path::new("/")
    }
    /// Joins `abs` under the fixture root, first relocating any
    /// `/proc/<pid>/…` reference onto the fixture's `proc/self/` subtree
    /// (see [`Self::relocate`]).
    fn p(&self, abs: &str) -> PathBuf {
        self.root.join(self.relocate(abs).trim_start_matches('/'))
    }

    /// Fixture-mode path relocation: `/proc/<pid>/…` → `/proc/self/…`.
    ///
    /// The pipeline hands every probe the *live* target pid (`getpid()`, or
    /// `--pid`), so a fixture tree cannot name the scanned process by number:
    /// every procfs path that addresses the scanned process lands on the
    /// fixture's `proc/self/` subtree, and one corpus of `proc/self/…` files
    /// drives a scan regardless of the pid the harness happens to run under.
    ///
    /// Two paths are deliberately left alone:
    /// - `/proc/1/…` — not the scanned process but the init-namespace
    ///   baseline the namespaces probe compares against. Collapsing both sides
    ///   of that read onto one file would make `isolated.*` false and
    ///   `cgroupNsSameAsInit` true by construction, i.e. it would fabricate the
    ///   very facts the probe exists to measure.
    /// - `/proc/self/…` — already relocatable, and rewriting it would only
    ///   allocate.
    ///
    /// A tree that carries its own numbered process directory (a captured
    /// `/proc/<pid>` copy, or a probe fixture written with an explicit pid)
    /// wins verbatim; `proc/self/` is the fallback for trees that cannot name
    /// the process in advance, never an override of one that can.
    ///
    /// Only a path whose second segment is *entirely* digits is a process
    /// path: `/proc/cpuinfo` and `/proc/123abc/x` are passed through verbatim.
    /// Real roots are never rewritten — `/proc/7/…` means pid 7 there.
    fn relocate<'a>(&self, abs: &'a str) -> Cow<'a, str> {
        if !self.is_fixture() {
            return Cow::Borrowed(abs);
        }
        let Some(rest) = abs.strip_prefix("/proc/") else {
            return Cow::Borrowed(abs);
        };
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (digits, after) = rest.split_at(digits_end);
        // The digits must be the *entire* second segment and a path must
        // follow it: `/proc/cpuinfo`, `/proc/123abc/x` and a bare `/proc/4242`
        // are not process file paths.
        if digits.is_empty() || digits == "1" || !after.starts_with('/') || after.len() == 1 {
            return Cow::Borrowed(abs);
        }
        if self.root.join("proc").join(digits).is_dir() {
            return Cow::Borrowed(abs);
        }
        Cow::Owned(format!("/proc/self/{}", &after[1..]))
    }

    pub fn read(&self, abs: &str) -> Result<String, ProbeIo> {
        Ok(std::fs::read_to_string(self.p(abs))?
            .trim_end_matches('\n')
            .to_string())
    }
    pub fn read_bytes(&self, abs: &str) -> Result<Vec<u8>, ProbeIo> {
        Ok(std::fs::read(self.p(abs))?)
    }
    pub fn read_to_end(&self, abs: &str) -> Result<Vec<u8>, ProbeIo> {
        self.read_bytes(abs)
    }
    pub fn read_link(&self, abs: &str) -> Result<String, ProbeIo> {
        let path = self.p(abs);
        if self.is_fixture() && path.is_file() {
            return Ok(std::fs::read_to_string(path)?.trim().to_string());
        }
        Ok(std::fs::read_link(path)?.to_string_lossy().into_owned())
    }
    pub fn exists(&self, abs: &str) -> bool {
        self.p(abs).exists()
    }
    /// Can `abs` be written? Two modes, per the probe contract: real roots
    /// use `access(2)` with `W_OK` — opening a live AF_UNIX socket or FIFO
    /// would connect or block; `access` never does. Fixture roots open the
    /// joined path `O_WRONLY`: a regular-file socket stand-in counts as
    /// writable exactly when it opens (matches the probe fixtures).
    pub fn writable(&self, abs: &str) -> bool {
        let p = self.p(abs);
        if self.is_fixture() {
            if p.is_dir() {
                let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                    return false;
                };
                return unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 };
            }
            std::fs::OpenOptions::new().write(true).open(p).is_ok()
        } else {
            let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                return false; // embedded NUL: not a path libc can take
            };
            // SAFETY: `c` is a valid NUL-terminated C string; access only queries.
            unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
        }
    }
    pub fn readable(&self, abs: &str) -> bool {
        let p = self.p(abs);
        if self.is_fixture() {
            if p.is_dir() {
                let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                    return false;
                };
                return unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 };
            }
            std::fs::File::open(p).is_ok()
        } else {
            let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                return false;
            };
            unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 }
        }
    }
    #[allow(dead_code)] // Still unused until later probe tasks.
    pub fn list_dir(&self, abs: &str) -> Result<Vec<String>, ProbeIo> {
        let mut v: Vec<String> = std::fs::read_dir(self.p(abs))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        Ok(v)
    }
}

/// The errno a probe should report for a failed pseudo-fs read:
/// `EACCES`/`ENOENT` are meaningful to the rule engine; other errors are not.
pub fn errno_of(e: &ProbeIo) -> Option<i32> {
    match e {
        ProbeIo::PermissionDenied => Some(13),
        ProbeIo::NotFound => Some(2),
        ProbeIo::Other(_) => None,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountEntry {
    pub mount_id: u32,
    pub parent_id: u32,
    pub major_minor: String,
    pub root: String,
    pub mount_point: String,
    pub mount_options: Vec<String>,
    pub optional_fields: Vec<String>,
    pub fstype: String,
    pub mount_source: String,
    pub super_options: Vec<String>,
}

#[allow(dead_code)]
/// Decodes Linux procfs octal escape sequences (e.g. `\040` -> space, `\011` -> tab, `\012` -> newline, `\134` -> `\`).
pub fn unescape_octal(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            let b3 = bytes[i + 3];
            if (b'0'..=b'7').contains(&b1)
                && (b'0'..=b'7').contains(&b2)
                && (b'0'..=b'7').contains(&b3)
            {
                let val = (b1 - b'0') as u16 * 64 + (b2 - b'0') as u16 * 8 + (b3 - b'0') as u16;
                if val <= 255 {
                    out.push(val as u8);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[allow(dead_code)]
/// Parses `/proc/[pid]/mountinfo` content, falling back to legacy `/proc/mounts` format.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        if let Some(dash_idx) = tokens.iter().position(|&t| t == "-") {
            // Standard mountinfo format:
            // Left: mount_id parent_id major_minor root mount_point mount_options [optional_fields...]
            // Right: fstype mount_source [super_options]
            let left = &tokens[..dash_idx];
            let right = &tokens[dash_idx + 1..];

            if left.len() < 6 || right.len() < 2 {
                continue;
            }

            let Ok(mount_id) = left[0].parse::<u32>() else {
                continue;
            };
            let Ok(parent_id) = left[1].parse::<u32>() else {
                continue;
            };
            let major_minor = left[2].to_string();
            let root = unescape_octal(left[3]);
            let mount_point = unescape_octal(left[4]);
            let mount_options = left[5]
                .split(',')
                .filter(|opt| !opt.is_empty())
                .map(String::from)
                .collect();
            let optional_fields = left[6..].iter().map(|&s| s.to_string()).collect();

            let fstype = right[0].to_string();
            let mount_source = unescape_octal(right[1]);
            let super_options = if right.len() > 2 {
                right[2]
                    .split(',')
                    .filter(|opt| !opt.is_empty())
                    .map(String::from)
                    .collect()
            } else {
                Vec::new()
            };

            entries.push(MountEntry {
                mount_id,
                parent_id,
                major_minor,
                root,
                mount_point,
                mount_options,
                optional_fields,
                fstype,
                mount_source,
                super_options,
            });
        } else if tokens.len() >= 4 {
            // Legacy /proc/mounts format:
            // source mount_point fstype options [freq passno]
            let mount_source = unescape_octal(tokens[0]);
            let mount_point = unescape_octal(tokens[1]);
            let fstype = tokens[2].to_string();
            let mount_options = tokens[3]
                .split(',')
                .filter(|opt| !opt.is_empty())
                .map(String::from)
                .collect();

            entries.push(MountEntry {
                mount_id: 0,
                parent_id: 0,
                major_minor: String::new(),
                root: "/".into(),
                mount_point,
                mount_options,
                optional_fields: Vec::new(),
                fstype,
                mount_source,
                super_options: Vec::new(),
            });
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_remap_reads_rooted_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/1")).unwrap();
        std::fs::write(dir.path().join("proc/1/cgroup"), "0::/user.slice/x.scope\n").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(fs.read("/proc/1/cgroup").unwrap(), "0::/user.slice/x.scope");
        assert!(matches!(fs.read("/proc/1/missing"), Err(ProbeIo::NotFound)));
    }
    #[test]
    fn fixture_symlink_stand_in() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/1/ns")).unwrap();
        std::fs::write(dir.path().join("proc/1/ns/pid"), "pid:[4026532192]").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(fs.read_link("/proc/1/ns/pid").unwrap(), "pid:[4026532192]");
    }
    /// A fixture tree is written once under `proc/self/` because the harness
    /// cannot predict the pid it will run under: every seam entry point
    /// relocates `/proc/<digits>/…` there.
    #[test]
    fn fixture_relocates_target_pid_paths_to_self() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/self/ns")).unwrap();
        std::fs::write(dir.path().join("proc/self/cgroup"), "0::/lxc/amber\n").unwrap();
        std::fs::write(dir.path().join("proc/self/ns/pid"), "pid:[4026532192]\n").unwrap();
        std::fs::write(dir.path().join("proc/self/uid_map"), "0 0 4294967295\n").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(fs.read("/proc/4242/cgroup").unwrap(), "0::/lxc/amber");
        assert_eq!(
            fs.read_link("/proc/4242/ns/pid").unwrap(),
            "pid:[4026532192]"
        );
        assert!(fs.exists("/proc/4242/uid_map"));
        assert!(fs.writable("/proc/4242/uid_map"));
        // `proc/self/…` needs no relocation and lands on the same file.
        assert_eq!(fs.read("/proc/self/cgroup").unwrap(), "0::/lxc/amber");
    }
    /// Relocation's boundaries: pid 1 (the init-ns baseline the namespaces
    /// probe compares against) and non-pid procfs paths are never rewritten,
    /// and a real root relocates nothing at all.
    #[test]
    fn relocation_spares_pid_one_non_pid_paths_and_real_roots() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/1/ns")).unwrap();
        std::fs::create_dir_all(dir.path().join("proc/self/ns")).unwrap();
        std::fs::write(dir.path().join("proc/1/ns/pid"), "pid:[4026531836]\n").unwrap();
        std::fs::write(dir.path().join("proc/self/ns/pid"), "pid:[4026532192]\n").unwrap();
        std::fs::write(dir.path().join("proc/version"), "Linux version 6.6.0\n").unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(
            fs.read_link("/proc/1/ns/pid").unwrap(),
            "pid:[4026531836]",
            "pid 1 is the comparison baseline, not the target"
        );
        assert_eq!(
            fs.read_link("/proc/self/ns/pid").unwrap(),
            "pid:[4026532192]"
        );
        assert_eq!(fs.read("/proc/version").unwrap(), "Linux version 6.6.0");
        // Second segment is not all digits, and a bare pid has no file part.
        assert!(matches!(
            fs.read("/proc/123abc/version"),
            Err(ProbeIo::NotFound)
        ));
        assert!(matches!(fs.read("/proc/4242"), Err(ProbeIo::NotFound)));
        // Real root: `/proc/<pid>/…` keeps its literal meaning.
        let real = PseudoFs::real();
        assert!(matches!(
            real.read("/proc/99999999/cgroup"),
            Err(ProbeIo::NotFound)
        ));
    }
    #[test]
    fn fixture_writable_tracks_open_write_access() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("writable"), "").unwrap();
        std::fs::write(dir.path().join("readonly"), "").unwrap();
        std::fs::set_permissions(
            dir.path().join("readonly"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert!(fs.writable("/writable"));
        assert!(!fs.writable("/missing")); // absent ⇒ not writable
        if unsafe { libc::geteuid() } != 0 {
            // root bypasses DAC: the 0444 split only means something unprivileged.
            assert!(!fs.writable("/readonly")); // present-but-denied is its own state
        }
    }
    #[test]
    fn fixture_writable_and_readable_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let acpi = dir.path().join("sys/kernel/config/acpi/table");
        std::fs::create_dir_all(&acpi).unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert!(fs.writable("/sys/kernel/config/acpi/table"));
        assert!(fs.readable("/sys/kernel/config/acpi/table"));
        std::fs::set_permissions(&acpi, std::fs::Permissions::from_mode(0o555)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(!fs.writable("/sys/kernel/config/acpi/table"));
            assert!(fs.readable("/sys/kernel/config/acpi/table"));
        }
    }
    #[test]
    fn real_writable_uses_access_w_ok() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sock-stand-in");
        std::fs::write(&f, "").unwrap();
        let fs = PseudoFs::real(); // root "/" ⇒ abs paths pass through unchanged
        assert!(fs.writable(f.to_str().unwrap()));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(!fs.writable(f.to_str().unwrap()));
        }
        assert!(!fs.writable("/definitely/not/here"));
    }
    /// The precedence that keeps pid-addressed trees working: a fixture that
    /// ships `proc/<pid>/` is read verbatim, and `proc/self/` only takes over
    /// for a pid the tree does not carry.
    #[test]
    fn numbered_process_directory_outranks_the_self_fallback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc/7")).unwrap();
        std::fs::create_dir_all(dir.path().join("proc/self")).unwrap();
        std::fs::write(
            dir.path().join("proc/7/status"),
            "CapEff:\t0000000000000001\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("proc/self/status"),
            "CapEff:\t00000000ffffffff\n",
        )
        .unwrap();
        let fs = PseudoFs::new(dir.path().into());
        assert_eq!(
            fs.read("/proc/7/status").unwrap(),
            "CapEff:\t0000000000000001",
            "an explicit numbered tree is the fixture author's choice"
        );
        // A pid the tree does not carry still lands on `proc/self/`.
        assert_eq!(
            fs.read("/proc/99/status").unwrap(),
            "CapEff:\t00000000ffffffff",
        );
    }
    mod mountinfo {
        use super::*;

        #[test]
        fn test_unescape_octal() {
            assert_eq!(unescape_octal(r"foo\040bar"), "foo bar");
            assert_eq!(
                unescape_octal(r"tab\011newline\012slash\134"),
                "tab\tnewline\nslash\\"
            );
            assert_eq!(unescape_octal("/var/run"), "/var/run");
            assert_eq!(unescape_octal(r"foo\04"), r"foo\04");
            assert_eq!(unescape_octal(r"foo\"), r"foo\");
            assert_eq!(unescape_octal(r"foo\899"), r"foo\899");
            assert_eq!(unescape_octal(r"foo\400bar"), r"foo\400bar");
            assert_eq!(unescape_octal(r"\777"), r"\777");
        }

        #[test]
        fn test_parse_mountinfo_11_field_with_optional() {
            let line = "23 61 0:22 / /sys rw,nosuid shared:1 master:2 - sysfs sysfs rw\n";
            let entries = parse_mountinfo(line);
            assert_eq!(entries.len(), 1);
            let e = &entries[0];
            assert_eq!(e.mount_id, 23);
            assert_eq!(e.parent_id, 61);
            assert_eq!(e.major_minor, "0:22");
            assert_eq!(e.root, "/");
            assert_eq!(e.mount_point, "/sys");
            assert_eq!(e.mount_options, vec!["rw", "nosuid"]);
            assert_eq!(e.optional_fields, vec!["shared:1", "master:2"]);
            assert_eq!(e.fstype, "sysfs");
            assert_eq!(e.mount_source, "sysfs");
            assert_eq!(e.super_options, vec!["rw"]);
        }

        #[test]
        fn test_parse_mountinfo_10_field_without_optional() {
            let line = "27 20 0:25 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
            let entries = parse_mountinfo(line);
            assert_eq!(entries.len(), 1);
            let e = &entries[0];
            assert_eq!(e.mount_id, 27);
            assert_eq!(e.parent_id, 20);
            assert_eq!(e.major_minor, "0:25");
            assert_eq!(e.root, "/");
            assert_eq!(e.mount_point, "/proc");
            assert_eq!(
                e.mount_options,
                vec!["rw", "nosuid", "nodev", "noexec", "relatime"]
            );
            assert!(e.optional_fields.is_empty());
            assert_eq!(e.fstype, "proc");
            assert_eq!(e.mount_source, "proc");
            assert_eq!(e.super_options, vec!["rw"]);
        }

        #[test]
        fn test_parse_mountinfo_legacy_mounts_fallback() {
            let line = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
                        /dev/sda1 /mnt ext4 rw\n";
            let entries = parse_mountinfo(line);
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entries[0],
                MountEntry {
                    mount_id: 0,
                    parent_id: 0,
                    major_minor: String::new(),
                    root: "/".into(),
                    mount_point: "/proc".into(),
                    mount_options: vec![
                        "rw".into(),
                        "nosuid".into(),
                        "nodev".into(),
                        "noexec".into(),
                        "relatime".into()
                    ],
                    optional_fields: Vec::new(),
                    fstype: "proc".into(),
                    mount_source: "proc".into(),
                    super_options: Vec::new(),
                }
            );
            assert_eq!(
                entries[1],
                MountEntry {
                    mount_id: 0,
                    parent_id: 0,
                    major_minor: String::new(),
                    root: "/".into(),
                    mount_point: "/mnt".into(),
                    mount_options: vec!["rw".into()],
                    optional_fields: Vec::new(),
                    fstype: "ext4".into(),
                    mount_source: "/dev/sda1".into(),
                    super_options: Vec::new(),
                }
            );
        }

        #[test]
        fn test_parse_mountinfo_octal_unescaping() {
            let line = "40 20 8:1 /dir\\040root /mount\\040point rw - ext4 /dev/disk\\0401 rw\n";
            let entries = parse_mountinfo(line);
            assert_eq!(entries.len(), 1);
            let e = &entries[0];
            assert_eq!(e.root, "/dir root");
            assert_eq!(e.mount_point, "/mount point");
            assert_eq!(e.mount_source, "/dev/disk 1");
        }

        #[test]
        fn test_parse_mountinfo_malformed_lines() {
            let content = "\n\
                           \n\
                           too few tokens\n\
                           abc 20 0:25 / /proc rw - proc proc rw\n\
                           27 def 0:25 / /proc rw - proc proc rw\n\
                           1 2 3 - ext4 /dev/sda1 rw\n\
                           27 20 0:25 / /proc rw - proc\n\
                           27 20 0:25 / /proc rw,nosuid - proc proc rw\n";
            let entries = parse_mountinfo(content);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].mount_id, 27);
            assert_eq!(entries[0].parent_id, 20);
            assert_eq!(entries[0].mount_point, "/proc");
            assert_eq!(entries[0].fstype, "proc");
        }
    }
}
