//! `OsApi` — the syscall seam between probes and the real kernel.
//!
//! Every non-filesystem fact in the pipeline flows through this trait so
//! fixture-rooted tests (Tasks 8-18, 26) substitute fakes with these exact
//! signatures. `RealOs` is the production impl: it must never panic on
//! unexpected kernel responses — it degrades to `None`/`false`/`Err` instead.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::sys::fs::ProbeIo;
use serde::Serialize;

#[derive(Clone, Debug, Default)]
pub struct HypervisorInfo {
    pub present: bool,
    pub vendor: Option<String>,
}

/// Kernel support for each `SECCOMP_RET_*` action, probed via
/// `seccomp(SECCOMP_GET_ACTION_AVAIL)`. Serialized `camelCase` for the
/// `seccomp.actions` fact (Task 12 probe).
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug)]
pub struct UdsReply {
    pub status: u16,
    pub body: String,
}

pub trait OsApi: Send + Sync {
    fn hypervisor(&self) -> HypervisorInfo;
    fn landlock_abi(&self) -> Option<u64>; // None ⇒ syscall unsupported
    fn seccomp_actions(&self) -> SeccompActions;
    fn seccomp_filter_dump(&self, pid: u32) -> Result<Vec<u64>, ProbeIo>;
    #[allow(dead_code)] // Consumed by later probe tasks (15-17); allow until then.
    fn syscall0(&self, id: u32) -> Result<(), i32>; // raw arg-less syscall; Err = errno
    fn uds_probe(&self, path: &Path, timeout: Duration) -> std::io::Result<UdsReply>;
    #[allow(dead_code)] // Consumed by later probe tasks (15-17); allow until then.
    fn env(&self, key: &str) -> Option<String>;
    fn is_root(&self) -> bool; // geteuid() == 0
}

pub struct RealOs;

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
        // ONE cumulative deadline covers the whole exchange — connect, ping
        // read, and /info read share `timeout`. Socket read timeouts are
        // per-read: a hostile listener trickling one byte per interval
        // resets them forever, so every read re-arms with the time left and
        // exhaustion yields Err(TimedOut) — like any Err here (e.g.
        // WouldBlock stalls), it degrades to null info upstream, never a
        // panic and never an unbounded wait.
        let deadline = Instant::now() + timeout;
        let left = || deadline.saturating_duration_since(Instant::now());

        // Handshake step 1 (spec): GET /_ping for liveness, on its own
        // connection — dockerd/podman honor `Connection: close` and tear the
        // stream down after the ping reply, so /info cannot reuse it.
        let mut ping = connect_uds_timeout(path, left())?;
        ping.set_write_timeout(Some(left()))?;
        ping.write_all(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let status = read_status_code(&mut ping, deadline)?;
        if status != 200 {
            // Liveness failed: report the status verbatim, never send /info.
            return Ok(UdsReply {
                status,
                body: String::new(),
            });
        }
        drop(ping);
        // Step 2: GET /info on a fresh connection (Accept: */* is Docker API
        // etiquette; Podman ignores it). Reads stop at EOF or the 1 MiB cap —
        // a noisy listener cannot balloon the scan, the deadline bounds time.
        let mut s = connect_uds_timeout(path, left())?;
        s.set_write_timeout(Some(left()))?;
        s.write_all(
            b"GET /info HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        )?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let remain = left();
            if remain.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "uds cumulative deadline exhausted",
                ));
            }
            s.set_read_timeout(Some(remain))?;
            let n = s.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() >= 1 << 20 {
                buf.truncate(1 << 20);
                break; // 1 MiB read cap: all any fact could carry anyway
            }
        }
        Ok(UdsReply {
            status,
            body: http_body(&buf),
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

/// Read an HTTP status line (up to the first `\n`, capped at 4 KiB) and
/// parse its status code, re-arming the socket read timeout against the
/// cumulative `deadline` before every byte. Unparseable headlines report 0 —
/// probes treat 0 as "not 2xx" without needing to distinguish transport noise.
fn read_status_code(
    s: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
) -> std::io::Result<u16> {
    use std::io::Read;
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "uds cumulative deadline exhausted",
            ));
        }
        s.set_read_timeout(Some(left))?;
        if s.read(&mut byte)? == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 4096 {
            break; // absurd status line: stop buffering, parse what we have
        }
    }
    let line = String::from_utf8_lossy(&buf);
    Ok(line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0))
}

/// Extract an HTTP response body: strip headers, then de-chunk when
/// `Transfer-Encoding` declares `chunked` — Podman's /info always uses it —
/// else return the remainder verbatim (close-delimited identity, Docker's
/// /info). A 1 MiB read cap can truncate mid-chunk; the bytes framed so far
/// are all anyone gets, and a partial body fails JSON parse ⇒ null info.
fn http_body(response: &[u8]) -> String {
    let Some(sep) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        return String::new(); // no headers ⇒ no body
    };
    let head = String::from_utf8_lossy(&response[..sep]);
    let mut rest = &response[sep + 4..];
    let chunked = head.lines().skip(1).any(|h| {
        let (name, value) = h.split_once(':').unwrap_or(("", ""));
        name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|c| c.trim().eq_ignore_ascii_case("chunked"))
    });
    if !chunked {
        return String::from_utf8_lossy(rest).into_owned();
    }
    let mut body: Vec<u8> = Vec::new();
    // chunk = <hex-size>[";" ext] CRLF payload CRLF
    while let Some(size_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let hex = rest[..size_end]
            .split(|b| *b == b';')
            .next()
            .unwrap_or(&rest[..size_end]);
        let Ok(size) = usize::from_str_radix(std::str::from_utf8(hex).unwrap_or("").trim(), 16)
        else {
            break; // corrupted framing: return what was collected
        };
        rest = &rest[size_end + 2..];
        if size == 0 {
            break;
        }
        let take = size.min(rest.len());
        body.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
        if take < size {
            break; // truncated by the read cap
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// `UnixStream::connect_timeout` equivalent (std provides none): non-blocking
/// connect, `poll` for writability within `timeout`, surface a deferred
/// connect error, then restore blocking mode for the request/response path.
///
/// AF_UNIX caveat — NOT full parity with `TcpStream::connect_timeout`: a unix
/// `connect(2)` never reports EINPROGRESS; a full listener backlog returns
/// EAGAIN/WouldBlock immediately (propagated as an error, no timed wait) and
/// success returns 0 synchronously. The EINPROGRESS/poll branch is defensive,
/// kept so a hypothetical deferred-connect transport still honors `timeout`.
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
        // Round sub-millisecond timeouts UP so poll waits at least one tick
        // instead of truncating to 0 (Duration::ZERO stays an immediate check).
        let ms = (timeout.as_millis()
            + u128::from(!timeout.subsec_nanos().is_multiple_of(1_000_000)))
        .min(libc::c_int::MAX as u128) as libc::c_int;
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
        // SECCOMP_GET_ACTION_AVAIL itself is 4.14+, and a sandbox may also
        // ERRNO seccomp(2); in either case every probe fails — all seven
        // flags false — so the pin below is vacuous and the test passes on
        // kernels/sandboxes that never ran the mechanism. Whenever ANY action
        // probes available, the mechanism demonstrably worked, so the two
        // baseline actions must be among them: a wrong action constant
        // (EOPNOTSUPP on the TRAP/KILL_THREAD probe) trips this pin.
        let any_avail = a.kill_process
            || a.kill_thread
            || a.trap
            || a.errno
            || a.log
            || a.trace
            || a.user_notif;
        assert!(
            !any_avail || (a.kill_thread && a.trap),
            "GET_ACTION_AVAIL working yet baseline actions missing: {a:?}"
        );
        // KILL_PROCESS/ERRNO/LOG/TRACE (4.14+) and USER_NOTIF (5.0+) are true
        // on this host's kernel but are NOT pinned here: stripped/hardened
        // kernels may lack them; `probed_ok` stays the witness either way.
    }

    #[test]
    fn uds_probe_missing_socket_is_not_found() {
        // Fresh tempdir path: never created ⇒ guaranteed ENOENT, immune to
        // stale-socket collisions a fixed /tmp name would risk.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.sock");
        let err = RealOs
            .uds_probe(&missing, Duration::from_millis(200))
            .expect_err("connect to an absent socket must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// Read one request's headers off a stub-stream (until the blank line).
    fn read_head(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
        use std::io::Read;
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
        req
    }

    #[test]
    fn uds_probe_performs_ping_then_info_handshake() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("srv.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            // Realistic daemons honor `Connection: close`: one connection per
            // request. /_ping first, then — only on a 200 ping — /info.
            let (mut stream, _) = listener.accept().unwrap();
            let req = read_head(&mut stream);
            assert!(req.starts_with(b"GET /_ping"), "ping first: {req:?}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .unwrap();
            drop(stream);
            let (mut stream, _) = listener.accept().unwrap();
            let req = read_head(&mut stream);
            assert!(req.starts_with(b"GET /info"), "then /info: {req:?}");
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            ).unwrap();
            // dropping `stream` closes the socket ⇒ client's read-to-EOF completes
        });
        let reply = RealOs.uds_probe(&sock, Duration::from_secs(2)).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "hello");
        server.join().unwrap();
    }

    #[test]
    fn uds_probe_ping_failure_skips_info_request() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("srv.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            // Exactly one request is expected; a second GET would block the
            // client's accept-side assertions forever ⇒ test timeout catches it.
            let (mut stream, _) = listener.accept().unwrap();
            let req = read_head(&mut stream);
            assert!(req.starts_with(b"GET /_ping"));
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let reply = RealOs.uds_probe(&sock, Duration::from_secs(2)).unwrap();
        assert_eq!(reply.status, 404); // ping status passthrough
        assert!(reply.body.is_empty()); // /info never sent ⇒ no body
        server.join().unwrap();
    }

    #[test]
    fn uds_probe_cumulative_deadline_beats_trickling_listener() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("trickle.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            // Hostile listener: dribble 1 byte / 50 ms — enough to reset any
            // per-read timeout forever while never completing a status line.
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..1_000 {
                if stream.write_all(b"H").is_err() {
                    break; // the probe gave up and disconnected
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let budget = Duration::from_millis(300);
        let t0 = std::time::Instant::now();
        let err = RealOs
            .uds_probe(&sock, budget)
            .expect_err("trickling listener must hit the cumulative deadline");
        let elapsed = t0.elapsed();
        assert!(elapsed < budget * 3, "stalled {elapsed:?} > 3× {budget:?}");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        server.join().unwrap(); // trickler sees EPIPE once the probe socket drops
    }
    #[test]
    fn http_body_identity_and_chunked_framing() {
        // close-delimited identity (docker's /info shape):
        assert_eq!(http_body(b"HTTP/1.1 200 OK\r\n\r\nplain"), "plain");
        // chunked (podman's /info shape), multi-chunk + trailer:
        assert_eq!(
            http_body(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\n wo\r\n0\r\n\r\n"
            ),
            "hello wo"
        );
        // case-insensitive header, chunk extension, missing trailer CRLFs:
        assert_eq!(
            http_body(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n3;a=b\r\nabc\r\n0\r\n"
            ),
            "abc"
        );
        // no headers at all ⇒ no body; unparseable chunk size ⇒ collected so far:
        assert_eq!(http_body(b"none"), "");
        assert_eq!(
            http_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab"),
            "ab" // read cap truncated the 4-byte chunk after 2 bytes
        );
    }
}
