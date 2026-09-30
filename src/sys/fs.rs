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
    fn p(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn read(&self, abs: &str) -> Result<String, ProbeIo> {
        Ok(std::fs::read_to_string(self.p(abs))?
            .trim_end_matches('\n')
            .to_string())
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
}
