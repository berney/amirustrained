#[cfg(target_arch = "x86_64")]
const SYS_KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;
#[cfg(not(target_arch = "x86_64"))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = 294;
use serde::{Deserialize, Serialize};

use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::Probe;

pub const PROBE: &str = "kernel-exec";
pub const FACT_PROBE: &str = "kernel.exec";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Permitted,
    Denied,
    Unsupported,
    UnsupportedArch,
    Error,
}

impl Status {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Permitted => "permitted",
            Status::Denied => "denied",
            Status::Unsupported => "unsupported",
            Status::UnsupportedArch => "unsupported_arch",
            Status::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallResult {
    pub status: Status,
    pub errno: i32,
    pub error_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelExecPayload {
    pub finit_module: SyscallResult,
    pub init_module: SyscallResult,
    pub kexec_file_load: SyscallResult,
    pub kexec_load: SyscallResult,
    pub iopl: SyscallResult,
}

pub struct KernelExec;

impl Probe for KernelExec {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_kernel_exec(cx)
    }
}

pub fn probe_kernel_exec(cx: &Ctx) -> ProbeOutcome {
    if !cx.opts.probe_kernel_execution {
        return ProbeOutcome::empty(PROBE);
    }
    if cx.fs.is_fixture() {
        return simulate_fixture_probe(cx);
    }
    run_isolated_probe()
}

pub fn simulate_fixture_probe(cx: &Ctx) -> ProbeOutcome {
    let modules_disabled = cx
        .prior
        .facts
        .get("kernel.surface.modules_disabled")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            cx.fs
                .read("/proc/sys/kernel/modules_disabled")
                .ok()
                .and_then(|s| crate::probes::kernel_surface::parse_sysctl_bool(&s))
        })
        .unwrap_or(false);

    let kexec_load_disabled = cx
        .prior
        .facts
        .get("kernel.surface.kexec_load_disabled")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            cx.fs
                .read("/proc/sys/kernel/kexec_load_disabled")
                .ok()
                .and_then(|s| crate::probes::kernel_surface::parse_sysctl_bool(&s))
        })
        .unwrap_or(false);

    let is_locked_down = cx
        .prior
        .facts
        .get("kernel.surface.lockdown")
        .or_else(|| cx.prior.facts.get("lsm.lockdown"))
        .and_then(|v| v.as_str())
        .map(|s| matches!(s, "integrity" | "confidentiality"))
        .or_else(|| {
            cx.fs
                .read("/sys/kernel/security/lockdown")
                .ok()
                .and_then(|s| crate::probes::kernel_surface::parse_lockdown(&s))
                .map(|s| matches!(s.as_str(), "integrity" | "confidentiality"))
        })
        .unwrap_or(false);

    let has_cap_rawio = cx
        .prior
        .facts
        .get("capabilities.effective")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|c| c.as_str() == Some("cap_sys_rawio")))
        .unwrap_or_else(|| cx.os.is_root());

    let finit_module = if modules_disabled || is_locked_down {
        SyscallResult {
            status: Status::Denied,
            errno: libc::EPERM,
            error_name: "EPERM".to_string(),
        }
    } else {
        SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        }
    };

    let init_module = if modules_disabled || is_locked_down {
        SyscallResult {
            status: Status::Denied,
            errno: libc::EPERM,
            error_name: "EPERM".to_string(),
        }
    } else {
        SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        }
    };

    let kexec_file_load = if kexec_load_disabled || is_locked_down {
        SyscallResult {
            status: Status::Denied,
            errno: libc::EPERM,
            error_name: "EPERM".to_string(),
        }
    } else {
        SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        }
    };

    let kexec_load = if kexec_load_disabled || is_locked_down {
        SyscallResult {
            status: Status::Denied,
            errno: libc::EPERM,
            error_name: "EPERM".to_string(),
        }
    } else {
        SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        }
    };

    let iopl = if !is_locked_down && has_cap_rawio {
        SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        }
    } else {
        SyscallResult {
            status: Status::Denied,
            errno: libc::EPERM,
            error_name: "EPERM".to_string(),
        }
    };

    let mut o = ProbeOutcome::empty(PROBE);
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "finit_module",
        serde_json::to_value(&finit_module).expect("serializable"),
        "finit_module".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "init_module",
        serde_json::to_value(&init_module).expect("serializable"),
        "init_module".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "kexec_file_load",
        serde_json::to_value(&kexec_file_load).expect("serializable"),
        "kexec_file_load".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "kexec_load",
        serde_json::to_value(&kexec_load).expect("serializable"),
        "kexec_load".into(),
    ));
    o = o.with_fact(Fact::ok(
        FACT_PROBE,
        "iopl",
        serde_json::to_value(&iopl).expect("serializable"),
        "iopl".into(),
    ));
    o
}

pub fn errno_name(errno: i32) -> String {
    let name = match errno {
        0 => "",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::ENOEXEC => "ENOEXEC",
        libc::EBADF => "EBADF",
        libc::ECHILD => "ECHILD",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::ENOTBLK => "ENOTBLK",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::ETXTBSY => "ETXTBSY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK",
        libc::EPIPE => "EPIPE",
        libc::EDOM => "EDOM",
        libc::ERANGE => "ERANGE",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ETIMEDOUT => "ETIMEDOUT",
        _ => return format!("ERRNO_{errno}"),
    };
    name.to_string()
}

pub fn decode_finit_module(res: Result<(), i32>) -> SyscallResult {
    match res {
        Ok(()) => SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        },
        Err(libc::EBADF) => SyscallResult {
            status: Status::Permitted,
            errno: libc::EBADF,
            error_name: "EBADF".to_string(),
        },
        Err(e @ (libc::EPERM | libc::EACCES)) => SyscallResult {
            status: Status::Denied,
            errno: e,
            error_name: errno_name(e),
        },
        Err(libc::ENOSYS) => SyscallResult {
            status: Status::Unsupported,
            errno: libc::ENOSYS,
            error_name: "ENOSYS".to_string(),
        },
        Err(e) => SyscallResult {
            status: Status::Error,
            errno: e,
            error_name: errno_name(e),
        },
    }
}

pub fn decode_init_module(res: Result<(), i32>) -> SyscallResult {
    match res {
        Ok(()) => SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        },
        Err(e @ (libc::ENOEXEC | libc::EFAULT)) => SyscallResult {
            status: Status::Permitted,
            errno: e,
            error_name: errno_name(e),
        },
        Err(e @ (libc::EPERM | libc::EACCES)) => SyscallResult {
            status: Status::Denied,
            errno: e,
            error_name: errno_name(e),
        },
        Err(libc::ENOSYS) => SyscallResult {
            status: Status::Unsupported,
            errno: libc::ENOSYS,
            error_name: "ENOSYS".to_string(),
        },
        Err(e) => SyscallResult {
            status: Status::Error,
            errno: e,
            error_name: errno_name(e),
        },
    }
}

pub fn decode_kexec_file_load(res: Result<(), i32>) -> SyscallResult {
    match res {
        Ok(()) => SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        },
        Err(libc::EBADF) => SyscallResult {
            status: Status::Permitted,
            errno: libc::EBADF,
            error_name: "EBADF".to_string(),
        },
        Err(e @ (libc::EPERM | libc::EACCES)) => SyscallResult {
            status: Status::Denied,
            errno: e,
            error_name: errno_name(e),
        },
        Err(libc::ENOSYS) => SyscallResult {
            status: Status::Unsupported,
            errno: libc::ENOSYS,
            error_name: "ENOSYS".to_string(),
        },
        Err(e) => SyscallResult {
            status: Status::Error,
            errno: e,
            error_name: errno_name(e),
        },
    }
}

pub fn decode_kexec_load(res: Result<(), i32>) -> SyscallResult {
    match res {
        Ok(()) => SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        },
        Err(libc::EINVAL) => SyscallResult {
            status: Status::Permitted,
            errno: libc::EINVAL,
            error_name: "EINVAL".to_string(),
        },
        Err(e @ (libc::EPERM | libc::EACCES)) => SyscallResult {
            status: Status::Denied,
            errno: e,
            error_name: errno_name(e),
        },
        Err(libc::ENOSYS) => SyscallResult {
            status: Status::Unsupported,
            errno: libc::ENOSYS,
            error_name: "ENOSYS".to_string(),
        },
        Err(e) => SyscallResult {
            status: Status::Error,
            errno: e,
            error_name: errno_name(e),
        },
    }
}

#[allow(dead_code)]
pub fn decode_iopl(res: Result<(), i32>) -> SyscallResult {
    match res {
        Ok(()) => SyscallResult {
            status: Status::Permitted,
            errno: 0,
            error_name: String::new(),
        },
        Err(e @ (libc::EPERM | libc::EACCES)) => SyscallResult {
            status: Status::Denied,
            errno: e,
            error_name: errno_name(e),
        },
        Err(libc::ENOSYS) => SyscallResult {
            status: Status::Unsupported,
            errno: libc::ENOSYS,
            error_name: "ENOSYS".to_string(),
        },
        Err(e) => SyscallResult {
            status: Status::Error,
            errno: e,
            error_name: errno_name(e),
        },
    }
}

#[allow(dead_code)]
pub fn decode_iopl_unsupported_arch() -> SyscallResult {
    SyscallResult {
        status: Status::UnsupportedArch,
        errno: 0,
        error_name: String::new(),
    }
}

fn raw_syscall<F>(f: F) -> Result<(), i32>
where
    F: FnOnce() -> libc::c_long,
{
    let rc = f();
    if rc < 0 {
        let err = unsafe { *libc::__errno_location() };
        Err(err)
    } else {
        Ok(())
    }
}

pub fn execute_boundary_probes() -> KernelExecPayload {
    let finit_res =
        raw_syscall(|| unsafe { libc::syscall(libc::SYS_finit_module, -1i32, c"".as_ptr(), 0i32) });
    let finit_module = decode_finit_module(finit_res);

    let init_res = raw_syscall(|| unsafe {
        libc::syscall(
            libc::SYS_init_module,
            std::ptr::null::<libc::c_void>(),
            0usize,
            c"".as_ptr(),
        )
    });
    let init_module = decode_init_module(init_res);

    let kexec_file_res = raw_syscall(|| unsafe {
        libc::syscall(
            SYS_KEXEC_FILE_LOAD,
            -1i32,
            -1i32,
            0usize,
            std::ptr::null::<libc::c_char>(),
            0usize,
        )
    });
    let kexec_file_load = decode_kexec_file_load(kexec_file_res);

    let kexec_res = raw_syscall(|| unsafe {
        libc::syscall(
            libc::SYS_kexec_load,
            0usize,
            usize::MAX,
            std::ptr::null::<libc::c_void>(),
            0usize,
        )
    });
    let kexec_load = decode_kexec_load(kexec_res);

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let iopl = {
        let rc = unsafe { libc::iopl(3) };
        let iopl_res = if rc < 0 {
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(())
        };
        decode_iopl(iopl_res)
    };

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let iopl = decode_iopl_unsupported_arch();

    KernelExecPayload {
        finit_module,
        init_module,
        kexec_file_load,
        kexec_load,
        iopl,
    }
}

pub fn run_isolated_probe() -> ProbeOutcome {
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
        // Child worker
        unsafe {
            libc::close(fds[0]);
        }
        let payload = execute_boundary_probes();
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
                let err = unsafe { *libc::__errno_location() };
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

    // Parent supervisor
    unsafe {
        libc::close(fds[1]);
    }

    let timeout_ms = 5000;
    let mut pfd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };

    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_millis(timeout_ms as u64);

    let poll_res = loop {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            break 0;
        }
        let remaining_ms = (deadline - elapsed).as_millis().min(timeout_ms as u128) as libc::c_int;
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if rc < 0 {
            let err = unsafe { *libc::__errno_location() };
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
        for key in [
            "finit_module",
            "init_module",
            "kexec_file_load",
            "kexec_load",
            "iopl",
        ] {
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                key,
                serde_json::json!({
                    "status": "error",
                    "errno": libc::ETIMEDOUT,
                    "error_name": "ETIMEDOUT",
                }),
                key.into(),
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
            let err = unsafe { *libc::__errno_location() };
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

    match serde_json::from_slice::<KernelExecPayload>(&buf) {
        Ok(payload) => {
            let mut o = ProbeOutcome::empty(PROBE);
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "finit_module",
                serde_json::to_value(&payload.finit_module).expect("serializable"),
                "finit_module".into(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "init_module",
                serde_json::to_value(&payload.init_module).expect("serializable"),
                "init_module".into(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "kexec_file_load",
                serde_json::to_value(&payload.kexec_file_load).expect("serializable"),
                "kexec_file_load".into(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "kexec_load",
                serde_json::to_value(&payload.kexec_load).expect("serializable"),
                "kexec_load".into(),
            ));
            o = o.with_fact(Fact::ok(
                FACT_PROBE,
                "iopl",
                serde_json::to_value(&payload.iopl).expect("serializable"),
                "iopl".into(),
            ));
            o
        }
        Err(_) => {
            let mut o = ProbeOutcome::empty(PROBE);
            o.availability = Availability::Degraded("failed to read child payload".into());
            for key in [
                "finit_module",
                "init_module",
                "kexec_file_load",
                "kexec_load",
                "iopl",
            ] {
                o = o.with_fact(Fact::ok(
                    FACT_PROBE,
                    key,
                    serde_json::json!({
                        "status": "error",
                        "errno": libc::EIO,
                        "error_name": "EIO",
                    }),
                    key.into(),
                ));
            }
            o
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opts::Opts;
    use crate::pipeline::Prior;
    use crate::sys::fs::PseudoFs;
    use crate::sys::os::RealOs;

    #[test]
    fn finit_module_decoder_mappings() {
        let permitted = decode_finit_module(Err(libc::EBADF));
        assert_eq!(permitted.status, Status::Permitted);
        assert_eq!(permitted.errno, libc::EBADF);
        assert_eq!(permitted.error_name, "EBADF");

        let denied_eperm = decode_finit_module(Err(libc::EPERM));
        assert_eq!(denied_eperm.status, Status::Denied);
        assert_eq!(denied_eperm.errno, libc::EPERM);
        assert_eq!(denied_eperm.error_name, "EPERM");

        let denied_eacces = decode_finit_module(Err(libc::EACCES));
        assert_eq!(denied_eacces.status, Status::Denied);
        assert_eq!(denied_eacces.errno, libc::EACCES);
        assert_eq!(denied_eacces.error_name, "EACCES");

        let unsupported = decode_finit_module(Err(libc::ENOSYS));
        assert_eq!(unsupported.status, Status::Unsupported);
        assert_eq!(unsupported.errno, libc::ENOSYS);
        assert_eq!(unsupported.error_name, "ENOSYS");

        let error = decode_finit_module(Err(libc::EINVAL));
        assert_eq!(error.status, Status::Error);
        assert_eq!(error.errno, libc::EINVAL);
        assert_eq!(error.error_name, "EINVAL");
    }

    #[test]
    fn init_module_decoder_mappings() {
        let permitted_enoexec = decode_init_module(Err(libc::ENOEXEC));
        assert_eq!(permitted_enoexec.status, Status::Permitted);
        assert_eq!(permitted_enoexec.errno, libc::ENOEXEC);
        assert_eq!(permitted_enoexec.error_name, "ENOEXEC");

        let permitted_efault = decode_init_module(Err(libc::EFAULT));
        assert_eq!(permitted_efault.status, Status::Permitted);
        assert_eq!(permitted_efault.errno, libc::EFAULT);
        assert_eq!(permitted_efault.error_name, "EFAULT");

        let denied_eperm = decode_init_module(Err(libc::EPERM));
        assert_eq!(denied_eperm.status, Status::Denied);
        assert_eq!(denied_eperm.errno, libc::EPERM);

        let denied_eacces = decode_init_module(Err(libc::EACCES));
        assert_eq!(denied_eacces.status, Status::Denied);
        assert_eq!(denied_eacces.errno, libc::EACCES);

        let unsupported = decode_init_module(Err(libc::ENOSYS));
        assert_eq!(unsupported.status, Status::Unsupported);
        assert_eq!(unsupported.errno, libc::ENOSYS);

        let error = decode_init_module(Err(libc::EINVAL));
        assert_eq!(error.status, Status::Error);
        assert_eq!(error.errno, libc::EINVAL);
    }

    #[test]
    fn kexec_file_load_decoder_mappings() {
        let permitted = decode_kexec_file_load(Err(libc::EBADF));
        assert_eq!(permitted.status, Status::Permitted);
        assert_eq!(permitted.errno, libc::EBADF);
        assert_eq!(permitted.error_name, "EBADF");

        let denied_eperm = decode_kexec_file_load(Err(libc::EPERM));
        assert_eq!(denied_eperm.status, Status::Denied);
        assert_eq!(denied_eperm.errno, libc::EPERM);

        let denied_eacces = decode_kexec_file_load(Err(libc::EACCES));
        assert_eq!(denied_eacces.status, Status::Denied);
        assert_eq!(denied_eacces.errno, libc::EACCES);

        let unsupported = decode_kexec_file_load(Err(libc::ENOSYS));
        assert_eq!(unsupported.status, Status::Unsupported);
        assert_eq!(unsupported.errno, libc::ENOSYS);

        let error = decode_kexec_file_load(Err(libc::EINVAL));
        assert_eq!(error.status, Status::Error);
        assert_eq!(error.errno, libc::EINVAL);
    }

    #[test]
    fn kexec_load_decoder_mappings() {
        let permitted = decode_kexec_load(Err(libc::EINVAL));
        assert_eq!(permitted.status, Status::Permitted);
        assert_eq!(permitted.errno, libc::EINVAL);
        assert_eq!(permitted.error_name, "EINVAL");

        let denied_eperm = decode_kexec_load(Err(libc::EPERM));
        assert_eq!(denied_eperm.status, Status::Denied);
        assert_eq!(denied_eperm.errno, libc::EPERM);

        let denied_eacces = decode_kexec_load(Err(libc::EACCES));
        assert_eq!(denied_eacces.status, Status::Denied);
        assert_eq!(denied_eacces.errno, libc::EACCES);

        let unsupported = decode_kexec_load(Err(libc::ENOSYS));
        assert_eq!(unsupported.status, Status::Unsupported);
        assert_eq!(unsupported.errno, libc::ENOSYS);

        let error = decode_kexec_load(Err(libc::EBADF));
        assert_eq!(error.status, Status::Error);
        assert_eq!(error.errno, libc::EBADF);
    }

    #[test]
    fn iopl_decoder_mappings() {
        let permitted = decode_iopl(Ok(()));
        assert_eq!(permitted.status, Status::Permitted);
        assert_eq!(permitted.errno, 0);

        let denied = decode_iopl(Err(libc::EPERM));
        assert_eq!(denied.status, Status::Denied);
        assert_eq!(denied.errno, libc::EPERM);
        assert_eq!(denied.error_name, "EPERM");

        let unsupported = decode_iopl(Err(libc::ENOSYS));
        assert_eq!(unsupported.status, Status::Unsupported);
        assert_eq!(unsupported.errno, libc::ENOSYS);

        let unsupported_arch = decode_iopl_unsupported_arch();
        assert_eq!(unsupported_arch.status, Status::UnsupportedArch);
        assert_eq!(unsupported_arch.errno, 0);

        let error = decode_iopl(Err(libc::EINVAL));
        assert_eq!(error.status, Status::Error);
        assert_eq!(error.errno, libc::EINVAL);
    }

    #[test]
    fn probe_disabled_returns_empty_outcome() {
        let fs = PseudoFs::real();
        let os = RealOs;
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = Ctx {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: Prior::default(),
        };

        let probe = KernelExec;
        let outcome = probe.run(&cx);
        assert_eq!(outcome.name, PROBE);
        assert!(outcome.facts.is_empty());
    }

    #[test]
    fn probe_enabled_executes_isolated_boundary_probe() {
        let fs = PseudoFs::real();
        let os = RealOs;
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: true,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = Ctx {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: Prior::default(),
        };

        let probe = KernelExec;
        let outcome = probe.run(&cx);
        assert_eq!(outcome.name, PROBE);
        assert_eq!(outcome.facts.len(), 5);

        let find_fact = |key: &str| {
            outcome
                .facts
                .iter()
                .find(|f| f.probe == FACT_PROBE && f.key == key)
                .unwrap_or_else(|| panic!("missing fact {key}"))
        };

        for key in [
            "finit_module",
            "init_module",
            "kexec_file_load",
            "kexec_load",
            "iopl",
        ] {
            let f = find_fact(key);
            assert!(f.value.get("status").is_some());
            assert!(f.value.get("errno").is_some());
            assert!(f.value.get("error_name").is_some());
        }
    }

    #[test]
    fn probe_fixture_simulates_boundary_results_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let proc_sys = dir.path().join("proc/sys/kernel");
        std::fs::create_dir_all(&proc_sys).unwrap();
        std::fs::write(proc_sys.join("modules_disabled"), "1\n").unwrap();
        std::fs::write(proc_sys.join("kexec_load_disabled"), "1\n").unwrap();

        let fs = PseudoFs::new(dir.path().to_path_buf());
        let os = RealOs;
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: true,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = Ctx {
            pid: std::process::id(),
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: Prior::default(),
        };

        let probe = KernelExec;
        let outcome = probe.run(&cx);
        assert_eq!(outcome.name, PROBE);
        assert_eq!(outcome.facts.len(), 5);

        for key in [
            "finit_module",
            "init_module",
            "kexec_file_load",
            "kexec_load",
            "iopl",
        ] {
            let f = outcome
                .facts
                .iter()
                .find(|f| f.probe == FACT_PROBE && f.key == key)
                .unwrap();
            assert_eq!(
                f.value.get("status").and_then(|s| s.as_str()),
                Some("denied")
            );
            assert_eq!(
                f.value.get("errno").and_then(|s| s.as_i64()),
                Some(libc::EPERM as i64)
            );
        }
    }

    #[test]
    fn probe_fixture_simulates_permitted_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let proc_sys = dir.path().join("proc/sys/kernel");
        std::fs::create_dir_all(&proc_sys).unwrap();
        std::fs::write(proc_sys.join("modules_disabled"), "0\n").unwrap();
        std::fs::write(proc_sys.join("kexec_load_disabled"), "0\n").unwrap();

        let fs = PseudoFs::new(dir.path().to_path_buf());
        let os = RealOs;
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: true,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let mut prior = Prior::default();
        prior.facts.insert(
            "capabilities.effective".to_string(),
            serde_json::json!(["cap_sys_rawio"]),
        );
        let cx = Ctx {
            pid: std::process::id(),
            uid: 0,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior,
        };

        let probe = KernelExec;
        let outcome = probe.run(&cx);
        assert_eq!(outcome.name, PROBE);
        assert_eq!(outcome.facts.len(), 5);

        for key in [
            "finit_module",
            "init_module",
            "kexec_file_load",
            "kexec_load",
            "iopl",
        ] {
            let f = outcome
                .facts
                .iter()
                .find(|f| f.probe == FACT_PROBE && f.key == key)
                .unwrap();
            assert_eq!(
                f.value.get("status").and_then(|s| s.as_str()),
                Some("permitted"),
                "key {key} must be permitted"
            );
        }
    }
}
