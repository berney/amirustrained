//! Empirical raw-device access probe (`--probe-device-open`, opt-in).
//!
//! The passive `kernel-surface` facts classify `/dev/mem`, `/dev/kmem` and
//! `/dev/port` with `access(2)` — a DAC bit check under the real uid. That
//! heuristic has a ground-truth gap in both directions: capability-bearing
//! processes pass `open()` where `access()` says no, and sandboxes present
//! DAC-readable nodes that **no driver implements**: gVisor's Sentry answers
//! `open()` with `ENXIO` (reproduced live: `docker --privileged`-style device
//! injection into a runsc sandbox produced `dev_mem: "accessible"` and the
//! AMR-025 Critical, while the actual `open(2)` failed). This probe performs
//! the syscall to close the gap.
//!
//! Non-destructive contract (AGENTS.md Tenet 4): `open()` with `O_RDONLY`
//! only — never `read()`, `write()`, `mmap()` — and the descriptor is closed
//! immediately in the worker child, so the parent's descriptor table is
//! untouched. `O_NONBLOCK` guards against a pathological driver `.open`
//! handler that would wait, and the worker runs under the same 5 s deadline
//! discipline as `kernel-exec`: pipe IPC, `poll`, `SIGKILL` on overrun.
//!
//! Off by default because the `open(2)` itself is the detection surface:
//! Falco ships rules that alert on `/dev/mem` opens regardless of read.
use serde::{Deserialize, Serialize};

use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;
use crate::probes::kernel_exec::errno_name;

pub const PROBE: &str = "device-open";
pub const FACT_PROBE: &str = "kernel.device_open";

/// Deadline for the forked worker, matching the kernel-exec probe.
const WORKER_DEADLINE_MS: u128 = 5000;

/// The raw memory / port I/O device nodes under test, as (fact key, path).
pub const DEVICES: [(&str, &str); 3] = [
    ("dev_mem", "/dev/mem"),
    ("dev_kmem", "/dev/kmem"),
    ("dev_port", "/dev/port"),
];

/// Empirical verdict of one `open(2)` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenStatus {
    /// `open(2)` returned a usable fd: the caller reaches the device.
    /// (Read range is still subject to STRICT_DEVMEM/lockdown; the probe
    /// proves the entry gate, which is what the boundary models.)
    Permitted,
    /// DAC/LSM refusal (`EACCES`/`EPERM`).
    Denied,
    /// No node at the path (`ENOENT`).
    Absent,
    /// Node exists and DAC allowed, but the device layer answers there is
    /// nothing behind it (`ENODEV`/`ENXIO`) — the sandbox signature: a
    /// gVisor pseudo-device is a node without a driver.
    Unsupported,
    /// Any other errno, including the worker-timeout and IPC-failure
    /// sentinels. Rules must treat this as *inconclusive*, never closed.
    Error,
}

impl OpenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OpenStatus::Permitted => "permitted",
            OpenStatus::Denied => "denied",
            OpenStatus::Absent => "absent",
            OpenStatus::Unsupported => "unsupported",
            OpenStatus::Error => "error",
        }
    }
}

/// One device verdict, shaped like `kernel_exec::SyscallResult` so machine
/// consumers parse the two opt-in probes with the same reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenResult {
    pub status: OpenStatus,
    pub errno: i32,
    pub error_name: String,
}

impl OpenResult {
    fn of(status: OpenStatus, errno: i32) -> Self {
        Self {
            status,
            errno,
            error_name: errno_name(errno),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceOpenPayload {
    pub dev_mem: OpenResult,
    pub dev_kmem: OpenResult,
    pub dev_port: OpenResult,
}

/// Decode an `open(2)` errno into a status. Pure, and the mapping the AMR-025
/// override keys on.
pub fn decode_open_errno(err: i32) -> OpenStatus {
    match err {
        libc::EACCES | libc::EPERM => OpenStatus::Denied,
        libc::ENOENT => OpenStatus::Absent,
        libc::ENODEV | libc::ENXIO => OpenStatus::Unsupported,
        _ => OpenStatus::Error,
    }
}

/// One real `open(2)`/`close()` round-trip. Runs only in the worker child.
pub fn open_one(path: &str) -> OpenResult {
    let Ok(c_path) = std::ffi::CString::new(path) else {
        // Static paths have no NUL; unreachable, and Error is the honest
        // inconclusive verdict if it ever were not.
        return OpenResult::of(OpenStatus::Error, 0);
    };
    // SAFETY: `c_path` is a valid NUL-terminated path. `O_RDONLY` asks only
    // for read permission (write access is never probed), `O_CLOEXEC` keeps
    // the fd out of any later exec, `O_NONBLOCK` prevents a blocking
    // `.open` handler from stalling the worker past its deadline. The fd is
    // closed immediately: no read, no write, no mmap, zero state mutation.
    let rc = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if rc >= 0 {
        unsafe {
            libc::close(rc);
        }
        return OpenResult::of(OpenStatus::Permitted, 0);
    }
    let err = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    OpenResult::of(decode_open_errno(err), err)
}

pub fn execute_open_probes() -> DeviceOpenPayload {
    let results: Vec<OpenResult> = DEVICES.iter().map(|(_, p)| open_one(p)).collect();
    DeviceOpenPayload {
        dev_mem: results[0].clone(),
        dev_kmem: results[1].clone(),
        dev_port: results[2].clone(),
    }
}

/// Map a passive `check_device` verdict onto the simulated fixture answer.
/// A fixture device stand-in is a regular file: it opens exactly when the
/// DAC leg permits, so `accessible ⇔ permitted` and there is nothing to
/// simulate beyond the DAC verdict itself. The driver-absent case cannot be
/// modelled by a plain tree; live sandboxes (the gVisor case) are covered by
/// the sandbox scenario + live matrix instead.
pub fn simulated_status(passive: &str) -> (OpenStatus, i32) {
    match passive {
        "accessible" => (OpenStatus::Permitted, 0),
        "denied" => (OpenStatus::Denied, libc::EPERM),
        _ => (OpenStatus::Absent, libc::ENOENT),
    }
}

/// Invert [`OpenStatus::as_str`]; an unknown label degrades to `Error`
/// (inconclusive), never to a closed verdict.
pub fn parse_open_status(label: &str) -> OpenStatus {
    match label {
        "permitted" => OpenStatus::Permitted,
        "denied" => OpenStatus::Denied,
        "absent" => OpenStatus::Absent,
        "unsupported" => OpenStatus::Unsupported,
        _ => OpenStatus::Error,
    }
}

/// Fixture simulation override: a plain file tree cannot express "node is
/// DAC-readable but `open(2)` fails" - exactly the gVisor pseudo-device the
/// probe exists to catch. The optional file `sys/kernel/device_open_simulation`
/// declares the kernel-side behaviour as JSON keyed by fact key:
/// `{"dev_mem": {"status": "unsupported", "errno": 6}, …}`. Keys that are
/// absent fall back to the DAC mapping.
fn simulated_override(fs: &crate::sys::fs::PseudoFs) -> serde_json::Map<String, serde_json::Value> {
    fs.read("/sys/kernel/device_open_simulation")
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn simulate_fixture(cx: &Ctx) -> ProbeOutcome {
    let overrides = simulated_override(cx.fs);
    let mut o = ProbeOutcome::empty(PROBE);
    for (key, path) in DEVICES {
        let (status, errno) = match overrides.get(key) {
            Some(entry) => {
                let status = entry
                    .get("status")
                    .and_then(|s| s.as_str())
                    .map(parse_open_status)
                    .unwrap_or(OpenStatus::Error);
                let errno = entry
                    .get("errno")
                    .and_then(|e| e.as_i64())
                    .unwrap_or(0)
                    .try_into()
                    .unwrap_or(0);
                (status, errno)
            }
            None => simulated_status(crate::probes::kernel_surface::check_device(cx.fs, path)),
        };
        o = o.with_fact(Fact::ok(
            FACT_PROBE,
            key,
            serde_json::json!({
                "status": status.as_str(),
                "errno": errno,
                "error_name": errno_name(errno),
            }),
            path.into(),
        ));
    }
    o
}

fn payload_facts(payload: &DeviceOpenPayload) -> Vec<(String, serde_json::Value)> {
    [
        ("dev_mem", &payload.dev_mem),
        ("dev_kmem", &payload.dev_kmem),
        ("dev_port", &payload.dev_port),
    ]
    .into_iter()
    .map(|(key, r)| {
        (
            key.into(),
            serde_json::json!({
                "status": r.status.as_str(),
                "errno": r.errno,
                "error_name": r.error_name,
            }),
        )
    })
    .collect()
}

/// Forked worker mirroring `kernel_exec::run_isolated_probe`: pipe IPC,
/// `poll` under a 5 s deadline, `SIGKILL` + reap on overrun.
fn run_isolated_probe() -> ProbeOutcome {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        let mut o = ProbeOutcome::empty(PROBE);
        o.availability = Availability::Degraded("pipe creation failed".into());
        return o;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let mut o = ProbeOutcome::empty(PROBE);
        o.availability = Availability::Degraded("fork failed".into());
        return o;
    }

    if pid == 0 {
        // Child worker: performs the opens, serializes, exits. `_exit` skips
        // atexit handlers inherited from the parent's runtime.
        unsafe {
            libc::close(fds[0]);
        }
        let payload = execute_open_probes();
        let json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let mut written = 0;
        while written < json_bytes.len() {
            let rc = unsafe {
                libc::write(
                    fds[1],
                    json_bytes[written..].as_ptr() as *const libc::c_void,
                    json_bytes.len() - written,
                )
            };
            if rc > 0 {
                written += rc as usize;
            } else if rc < 0 {
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if err != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }
        unsafe {
            libc::close(fds[1]);
            libc::_exit(0);
        }
    }

    // Parent supervisor.
    unsafe {
        libc::close(fds[1]);
    }

    let deadline = std::time::Duration::from_millis(WORKER_DEADLINE_MS as u64);
    let start = std::time::Instant::now();
    let mut pfd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let poll_res = loop {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            break 0;
        }
        let remaining_ms = (deadline - elapsed).as_millis().min(i32::MAX as u128) as libc::c_int;
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if err == libc::EINTR {
                continue;
            }
            break rc;
        }
        break rc;
    };

    if poll_res <= 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            libc::close(fds[0]);
        }
        let mut o = ProbeOutcome::empty(PROBE);
        o.timed_out = true;
        o.availability = Availability::Unavailable("timed out".into());
        // Inconclusive sentinel facts, same shape as kernel-exec's timeout
        // leg: `error` never satisfies a rule predicate.
        for (key, path) in DEVICES {
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                key,
                serde_json::json!({
                    "status": OpenStatus::Error.as_str(),
                    "errno": libc::ETIMEDOUT,
                    "error_name": errno_name(libc::ETIMEDOUT),
                }),
                path.into(),
            ));
        }
        return o;
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let rc =
            unsafe { libc::read(fds[0], chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if rc > 0 {
            buf.extend_from_slice(&chunk[..rc as usize]);
        } else if rc == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if err == libc::EINTR {
                continue;
            }
            break;
        }
    }
    unsafe {
        libc::close(fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }

    let mut o = ProbeOutcome::empty(PROBE);
    match serde_json::from_slice::<DeviceOpenPayload>(&buf) {
        Ok(payload) => {
            for (key, value) in payload_facts(&payload) {
                o = o.with_fact(Fact::ok(FACT_PROBE, &key, value, key_source(&key)));
            }
        }
        Err(_) => {
            o.availability = Availability::Degraded("worker response unreadable".into());
            for (key, path) in DEVICES {
                o = o.with_fact(Fact::degraded(
                    FACT_PROBE,
                    key,
                    serde_json::json!({
                        "status": OpenStatus::Error.as_str(),
                        "errno": 0,
                        "error_name": "",
                    }),
                    path.into(),
                ));
            }
        }
    }
    o
}

fn key_source(key: &str) -> String {
    DEVICES
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, p)| (*p).to_string())
        .unwrap_or_else(|| key.to_string())
}

pub struct DeviceOpen;

impl Probe for DeviceOpen {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        if !cx.opts.probe_device_open {
            return ProbeOutcome::empty(PROBE);
        }
        if cx.fs.is_fixture() {
            return simulate_fixture(cx);
        }
        run_isolated_probe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_open_errno_maps_the_boundary_signatures() {
        assert_eq!(decode_open_errno(libc::EACCES), OpenStatus::Denied);
        assert_eq!(decode_open_errno(libc::EPERM), OpenStatus::Denied);
        assert_eq!(decode_open_errno(libc::ENOENT), OpenStatus::Absent);
        // The sandbox signatures: Sentry answers ENXIO for unimplemented
        // char devices; a kernel without the driver answers ENODEV.
        assert_eq!(decode_open_errno(libc::ENXIO), OpenStatus::Unsupported);
        assert_eq!(decode_open_errno(libc::ENODEV), OpenStatus::Unsupported);
        // Anything else is inconclusive, never "closed".
        assert_eq!(decode_open_errno(libc::EIO), OpenStatus::Error);
        assert_eq!(decode_open_errno(libc::ETIMEDOUT), OpenStatus::Error);
    }

    #[test]
    fn parse_open_status_inverts_labels_and_fails_inconclusive() {
        assert_eq!(parse_open_status("permitted"), OpenStatus::Permitted);
        assert_eq!(parse_open_status("denied"), OpenStatus::Denied);
        assert_eq!(parse_open_status("absent"), OpenStatus::Absent);
        assert_eq!(parse_open_status("unsupported"), OpenStatus::Unsupported);
        // Unknown labels must degrade to inconclusive, never to a close.
        assert_eq!(parse_open_status("maybe"), OpenStatus::Error);
    }

    #[test]
    fn simulated_status_tracks_the_passive_dac_verdict() {
        assert_eq!(simulated_status("accessible"), (OpenStatus::Permitted, 0));
        assert_eq!(
            simulated_status("denied"),
            (OpenStatus::Denied, libc::EPERM)
        );
        assert_eq!(
            simulated_status("absent"),
            (OpenStatus::Absent, libc::ENOENT)
        );
    }

    #[test]
    fn gated_off_run_emits_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(dir.path().into());
        let os = crate::sys::os::RealOs;
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: false,
            compact: false,
            probe_ebpf: Vec::new(),
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let prior = crate::pipeline::Prior::default();
        let cx = crate::pipeline::Ctx {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            fs: &fs,
            os: &os,
            opts: &opts,
            prior,
        };
        let o = DeviceOpen.run(&cx);
        assert!(o.facts.is_empty(), "gated-off probe must emit no facts");
    }

    #[test]
    fn fixture_run_simulates_from_the_tree() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("dev")).unwrap();
        // A readable stand-in and a missing one; a mode-000 file would also
        // model denial, but DAC bits of test files are harness-dependent
        // under root CI, so assert the mapping on what `check_device` says.
        std::fs::write(dir.path().join("dev/mem").as_path(), b"").unwrap();
        let fs = crate::sys::fs::PseudoFs::new(dir.path().into());
        let os = crate::sys::os::RealOs;
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: true,
            compact: false,
            probe_ebpf: Vec::new(),
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let prior = crate::pipeline::Prior::default();
        let cx = crate::pipeline::Ctx {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            fs: &fs,
            os: &os,
            opts: &opts,
            prior,
        };
        let o = DeviceOpen.run(&cx);
        assert_eq!(o.facts.len(), 3);
        let dev_mem = o
            .facts
            .iter()
            .find(|f| f.key == "dev_mem")
            .expect("dev_mem fact");
        assert_eq!(dev_mem.value["status"], "permitted");
        let dev_kmem = o
            .facts
            .iter()
            .find(|f| f.key == "dev_kmem")
            .expect("dev_kmem fact");
        assert_eq!(dev_kmem.value["status"], "absent");
        assert_eq!(dev_kmem.value["error_name"], "ENOENT");
    }
}
