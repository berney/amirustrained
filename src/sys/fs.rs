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
    #[allow(dead_code)] // Still unused until the namespace probes (Task 9+).
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
}
