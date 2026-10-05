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
            std::fs::OpenOptions::new().write(true).open(p).is_ok()
        } else {
            let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
                return false; // embedded NUL: not a path libc can take
            };
            // SAFETY: `c` is a valid NUL-terminated C string; access only queries.
            unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
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
}
