//! `OsApi` — the syscall seam between probes and the real kernel.
//!
//! Every non-filesystem fact in the pipeline flows through this trait so
//! fixture-rooted tests (Tasks 8-18, 26) substitute fakes with these exact
//! signatures. `RealOs` is the production impl: it must never panic on
//! unexpected kernel responses — it degrades to `None`/`false`/`Err` instead.

use std::path::Path;
use std::time::Duration;

use crate::sys::fs::ProbeIo;

// Consumed by probe tasks (8-18); allow until then.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct HypervisorInfo {
    pub present: bool,
    pub vendor: Option<String>,
}

// Consumed by probe tasks (8-18); allow until then.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompActions {
    pub kill_process: bool,
    pub kill_thread: bool,
    pub trap: bool,
    pub errno: bool,
    pub log: bool,
    pub trace: bool,
    pub user_notif: bool,
    pub probed_ok: bool, // false ⇒ GET_ACTION_AVAIL unsupported (pre-4.14 / EOPNOTSUPP)
}

// Consumed by probe tasks (8-18); allow until then.
#[allow(dead_code)]
#[derive(Debug)]
pub struct UdsReply {
    pub status: u16,
    pub body: String,
}

// Consumed by probe tasks (8-18); allow until then.
#[allow(dead_code)]
pub trait OsApi: Send + Sync {
    fn hypervisor(&self) -> HypervisorInfo;
    fn landlock_abi(&self) -> Option<u64>; // None ⇒ syscall unsupported
    fn seccomp_actions(&self) -> SeccompActions;
    fn seccomp_filter_dump(&self, pid: u32) -> Result<Vec<u64>, ProbeIo>;
    fn syscall0(&self, id: u32) -> Result<(), i32>; // raw arg-less syscall; Err = errno
    fn uds_probe(&self, path: &Path, timeout: Duration) -> std::io::Result<UdsReply>;
    fn env(&self, key: &str) -> Option<String>;
    fn is_root(&self) -> bool; // geteuid() == 0
}

// Consumed by probe tasks (8-18); allow until then.
#[allow(dead_code)]
pub struct RealOs;

#[allow(dead_code)]
impl OsApi for RealOs {
    fn hypervisor(&self) -> HypervisorInfo {
        #[cfg(target_arch = "x86_64")]
        {
            // `__cpuid` is a safe intrinsic on this toolchain; CPUID leaf 1
            // always exists on x86_64.
            let feat = std::arch::x86_64::__cpuid(1);
            let hv_bit = feat.ecx & (1 << 31) != 0;
            if !hv_bit {
                return HypervisorInfo::default();
            }
            // Leaves 0x40000000..: hypervisor vendor string (12 chars across EBX..EDX of leaf 0x40000000).
            // Leaf 0x4000_0000 is a well-known hypervisor leaf; CPUID only writes registers.
            let leaf = std::arch::x86_64::__cpuid(0x4000_0000);
            let bytes: [u8; 12] = leaf
                .ebx
                .to_le_bytes()
                .into_iter()
                .chain(leaf.ecx.to_le_bytes())
                .chain(leaf.edx.to_le_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .expect("exactly 12 bytes from three u32s");
            let vendor = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string();
            HypervisorInfo {
                present: true,
                vendor: Some(vendor),
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        HypervisorInfo::default() // aarch64: DMI-only detection (Task 14)
    }

    fn landlock_abi(&self) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: null attrs + size 0 + QUERY_ABI flag is the documented
            // probe; with QUERY_ABI the kernel reads no memory and returns the
            // ABI version or -errno (ENOSYS ⇒ syscall unsupported).
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    0usize,
                    0usize,
                    1u32, /* LANDLOCK_CREATE_RULESET_VERSION */
                )
            };
            if r < 0 { None } else { Some(r as u64) }
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    fn seccomp_actions(&self) -> SeccompActions {
        #[cfg(target_arch = "x86_64")]
        {
            let mut a = SeccompActions::default();
            // Per-action: seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action). rc == 0 ⇒
            // supported. rc < 0 (EOPNOTSUPP/EINVAL on older kernels, e.g. pre-4.14
            // KILL_PROCESS) leaves that flag false and clears probed_ok —
            // unsupported is not silently "all false": the matrix stays
            // individually honest.
            //
            // The kernel switches on the *exact* action value; these must be the
            // full uapi/linux/seccomp.h class constants with zero data bits.
            // (Empirically verified on this host: e.g. 0x4000_0000 is not
            // SECCOMP_RET_LOG — LOG is 0x7ffc_0000; TRAP is 0x0003_0000, not
            // 1; KILL_PROCESS is 0x8000_0000, not 2.)
            let mut all_ok = true;
            for (act, flag) in [
                (0x8000_0000u32 /*KILL_PROCESS*/, &mut a.kill_process),
                (0x0000_0000u32 /*KILL_THREAD*/, &mut a.kill_thread),
                (0x0003_0000u32 /*TRAP*/, &mut a.trap),
                (0x0005_0000u32 /*ERRNO*/, &mut a.errno),
                (0x7ffc_0000u32 /*LOG*/, &mut a.log),
                (0x7ff0_0000u32 /*TRACE*/, &mut a.trace),
                (0x7fc0_0000u32 /*USER_NOTIF*/, &mut a.user_notif),
            ] {
                let v = act;
                // SAFETY: libc::SYS_seccomp (317 on x86_64) with op
                // GET_ACTION_AVAIL only reads the u32 `v` points at and stores
                // nothing. The raw pointer is FFI-safe to pass to the variadic
                // libc::syscall; a `&` reference is not.
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_seccomp,
                        2u32, /* SECCOMP_GET_ACTION_AVAIL */
                        0u32,
                        &v as *const u32,
                    )
                };
                if rc < 0 {
                    all_ok = false;
                }
                *flag = rc == 0;
            }
            a.probed_ok = all_ok;
            a
        }
        // Non-x86_64: libc::SYS_seccomp may exist (e.g. aarch64) but per the
        // brief keep the probed_ok=false fallback; probing there is deferred.
        #[cfg(not(target_arch = "x86_64"))]
        SeccompActions::default()
    }

    fn seccomp_filter_dump(&self, _pid: u32) -> Result<Vec<u64>, ProbeIo> {
        // ptrace attach + PTRACE_SECCOMP_GET_FILTER; the long form lives in the
        // probe only if root (Task 12 refines). Unprivileged attach is denied
        // by yama/ptrace_scope on typical hosts — PermissionDenied is honest.
        Err(ProbeIo::PermissionDenied)
    }

    fn syscall0(&self, id: u32) -> Result<(), i32> {
        // SAFETY: only the syscall number is passed — no pointers — and any
        // errno is read on the same thread immediately below.
        let rc = unsafe { libc::syscall(id as libc::c_long) };
        if rc < 0 {
            // SAFETY: __errno_location always returns the valid per-thread errno slot.
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(())
        }
    }

    fn uds_probe(&self, path: &Path, timeout: Duration) -> std::io::Result<UdsReply> {
        use std::io::{Read, Write};
        // std has no `UnixStream::connect_timeout`; replicate its semantics.
        let mut s = connect_uds_timeout(path, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.write_all(
            b"GET /info HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        )?;
        let mut buf = String::new();
        // read_to_string caps at stream close; the socket probe enforces the
        // timeout via set_read_timeout (EAGAIN surfaces as a read error —
        // WouldBlock-style mapped to TimedOut by std on blocking sockets).
        s.read_to_string(&mut buf)?;
        let (head, body) = buf.split_once("\r\n\r\n").unwrap_or(("", ""));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        Ok(UdsReply {
            status,
            body: body.to_string(),
        })
    }

    fn env(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn is_root(&self) -> bool {
        // SAFETY: geteuid() is a pure, always-successful libc call.
        unsafe { libc::geteuid() == 0 }
    }
}

/// `UnixStream::connect_timeout` equivalent (std provides none): non-blocking
/// connect, `poll` for writability within `timeout`, surface a deferred
/// connect error, then restore blocking mode for the request/response path.
fn connect_uds_timeout(
    path: &Path,
    timeout: Duration,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: valid AF_UNIX/SOCK_STREAM flags; the fd is wrapped in OwnedFd
    // immediately below, so it is closed on every error path.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, owned fd returned by socket(2).
    let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: an all-zeroed sockaddr_un is a valid placeholder; sun_path is
    // fully populated (with trailing NUL) before the connect below.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path not usable as a unix socket name",
        ));
    }
    for (i, b) in bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char; // sun_path[len] stays NUL
    }

    // SAFETY: `owned` is a valid socket fd and `addr` is an initialized
    // sockaddr_un whose length matches its type.
    let rc = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err); // immediate refusal (ENOENT, ECONNREFUSED, …)
        }
        let mut pfd = libc::pollfd {
            fd: owned.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        // SAFETY: a valid one-element pollfd array; ms is within c_int bounds.
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr < 0 {
            return Err(std::io::Error::last_os_error()); // e.g. EINTR: degrade, don't loop
        }
        if pr == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "unix socket connect timed out",
            ));
        }
        // Writable may still mean connect failed asynchronously: check SO_ERROR.
        let mut soerr: libc::c_int = 0;
        let mut olen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid fd; getsockopt writes exactly `olen` bytes into soerr.
        let grc = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                std::ptr::from_mut(&mut soerr).cast::<libc::c_void>(),
                &mut olen,
            )
        };
        if grc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if soerr != 0 {
            return Err(std::io::Error::from_raw_os_error(soerr));
        }
    }
    // Restore blocking mode for reads/writes below; F_SETFL touches status
    // flags only, so the fd's O_CLOEXEC is preserved.
    // SAFETY: fcntl F_SETFL on a valid fd with a constant flag set.
    if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(std::os::unix::net::UnixStream::from(owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cpuid_returns_consistent_hypervisor_info() {
        let h = RealOs.hypervisor();
        // On bare metal: present=false, vendor=None. On VMs: both Some. Either way
        // the invariant: vendor present ⇔ present.
        assert_eq!(h.vendor.is_some(), h.present);
    }

    #[test]
    fn env_lookup_works() {
        assert!(RealOs.env("PATH").is_some());
    }

    #[test]
    fn env_absent_key_is_none() {
        assert_eq!(RealOs.env("AMIRUSTRAINED_TEST_ABSENT_KEY_9F2C"), None);
    }

    #[test]
    fn trait_is_object_safe_and_realos_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RealOs>();
        let api: Box<dyn OsApi> = Box::new(RealOs);
        // dyn dispatch reaches every method without panicking on this host.
        let _ = api.hypervisor();
    }

    #[test]
    fn seccomp_filter_dump_denied_for_own_pid() {
        // Unprivileged default is honest: attach isn't attempted pre-Task 12.
        assert_eq!(
            RealOs.seccomp_filter_dump(std::process::id()),
            Err(ProbeIo::PermissionDenied)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn is_root_matches_proc_euid() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let euid = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|f| f.split_whitespace().nth(1))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert_eq!(RealOs.is_root(), euid == 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn syscall0_ok_for_gettid_enosys_for_bogus_id() {
        assert!(RealOs.syscall0(libc::SYS_gettid as u32).is_ok());
        // Beyond the syscall table on x86_64/aarch64: sys_ni_syscall ⇒ ENOSYS.
        assert_eq!(RealOs.syscall0(4096), Err(libc::ENOSYS));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn landlock_abi_is_version_or_none_never_garbage() {
        // Environment-dependent (kernel ≥ 5.13 + CONFIG_SECURITY_LANDLOCK),
        // so only the mapping invariant is pinned: success ⇒ small positive
        // version; failure ⇒ None. (A dropped `r < 0` check would surface a
        // huge u64 here instead.)
        match RealOs.landlock_abi() {
            None => {}
            Some(v) => assert!(v > 0 && v < 64, "implausible landlock ABI {v}"),
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn seccomp_actions_baseline_support_and_honest_matrix() {
        let a = RealOs.seccomp_actions();
        // seccomp(2) KILL_THREAD/TRAP exist on every x86_64 kernel with seccomp
        // support (≥ 3.17); a wrong action constant would show EOPNOTSUPP here.
        assert!(a.kill_thread, "KILL_THREAD must be available");
        assert!(a.trap, "TRAP must be available");
        // KILL_PROCESS/ERRNO/LOG/TRACE (4.14+) and USER_NOTIF (5.0+) are true
        // on this host's kernel but are NOT pinned here: stripped/hardened
        // kernels may lack them; `probed_ok` stays the witness either way.
    }

    #[test]
    fn uds_probe_missing_socket_is_not_found() {
        let missing = std::path::Path::new("/tmp/amirus-absent-socket.sock");
        let err = RealOs
            .uds_probe(missing, Duration::from_millis(200))
            .expect_err("connect to an absent socket must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn uds_probe_parses_status_line_and_body() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("srv.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut chunk = [0u8; 64];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
                .unwrap();
            // dropping `stream` closes the socket ⇒ client's read_to_string hits EOF
        });
        let reply = RealOs.uds_probe(&sock, Duration::from_secs(2)).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "hello");
        server.join().unwrap();
    }
}
