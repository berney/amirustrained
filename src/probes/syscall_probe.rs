//! Opt-in EPERM sweep (spec §5 "Syscall enumeration policy"): invoke every
//! x86_64 syscall with all-zero args and read the errno. Only `EPERM`(1) and
//! `EACCES`(13) mean a seccomp filter terminated the call; every other errno
//! (`ENOENT`, `EFAULT`, `EINVAL`, `E2BIG`, `ENOSYS`…) is "not blocked /
//! indeterminate". Mirrors amicontained's sweep — parity over cleverness.
//!
//! SAFETY contract (security review 2026-10-01 + round-3 re-adjudication;
//! canonical SKIP supersedes amicontained's hang list): the null-arg premise
//! fails exactly where the guard (capability, ownership, or "object exists")
//! passes before/independently of argument validation and the NULL/zero
//! branch is a DOCUMENTED ACTION or a documented expense. SKIP classes:
//!   1. never-returns — hang / exit / self-modifying: rt_sigreturn, select,
//!      pause, pselect6, ppoll, exit, exit_group, clone, fork, vfork,
//!      seccomp, ptrace(TRACEME), umask reset, setsid/setpgid, setgroups(0).
//!   2. acts-on-root — NULL is the real action once caps are held:
//!      swapoff(NULL)=all swap off, delete_module(NULL,0)=rmmod -a,
//!      vhangup(ctty), acct(NULL)=accounting off,
//!      sethostname/setdomainname(len 0)=empty UTS name; kexec_load passes
//!      validation with nr_segments 0 (replaces the pending reboot image).
//!   3. acts-on-root-or-owner — shmctl/msgctl/semctl: IPC_RMID == 0 IGNORES
//!      the buffer, so the sweep destroys SysV id-0 objects (any user's as
//!      root, the invoker's own unprivileged; ids are reused, e.g.
//!      PostgreSQL's first segment).
//!   4. fd-0-relative — stdin is the state sink: close(0) poisons the slot
//!      for every later fd creator and dfd/read(0) probe; fchmod, fchown,
//!      ftruncate, finit_module act on stdin's file; shutdown(0, SHUT_RD)
//!      irreversibly read-shuts a socket stdin.
//!   5. conditional-delay — waits act when the object exists (wait4, waitid,
//!      msgrcv, accept, accept4); sync/syncfs write back unconditionally and
//!      can D-state past the ceiling.
//!   6. thread/process bookkeeping — set_tid_address(0) silently deadlocks
//!      pthread_join; alarm(0)/setitimer(NULL)/timer_settime(NULL)/
//!      timer_delete(0) cancel or destroy the caller's (or id 0's) timers.
//!
//! Registered ONLY with `--probe-syscalls`; without `--probe-timeout` the
//! CLI forces a 30 s ceiling (spec §5), so even a missed hazard degrades
//! instead of hanging the scan. Sweep = 289 pure sysenter round-trips.
//!
//! INVOCATION ASSUMPTION (residual review note 2026-10-01): the sweep
//! presumes DIRECT execution of the static binary. The credential family
//! (setuid/setgid/setreuid/setregid/setresuid/setresgid) is swept because
//! zero args is a no-op as root and EPERM unprivileged — but under a
//! setuid-root or file-capability launch (euid 0, ruid != 0) the zeroed
//! calls would succeed and permanently convert real+saved ids to root. If
//! packaging ever installs a setuid bit or setcap, move those six names
//! into class 2 of SKIP and drop them from AUDITED_SWEPT.

use crate::model::{Fact, ProbeOutcome};

/// Canonical SKIP (spec §5 syscall-probe row, security review 2026-10-01 +
/// round-3 re-adjudication same day): hang / exit / self-modifying /
/// NULL-arg acts-on-root / acts-on-root-or-owner / fd-0-relative /
/// conditional-delay / thread-process bookkeeping. Names grouped by class;
/// every entry must exist in NAMES and SKIP must EQUAL the canonical set
/// (pinned by test). The swept complement is separately frozen as an
/// allow-list in the test module (`AUDITED_SWEPT`): any regenerated NAMES
/// entry joins the sweep only after human review adds it there.
#[cfg(target_arch = "x86_64")]
pub const SKIP: &[&str] = &[
    // hang-class
    "rt_sigreturn",
    "select",
    "pause",
    "pselect6",
    "ppoll",
    // exit-class
    "exit",
    "exit_group",
    "clone",
    "fork",
    "vfork",
    // self-modifying
    "seccomp",
    "ptrace",
    "umask",
    "setsid",
    "setpgid",
    "setgroups",
    // NULL-arg acts-on-root (NULL is a documented action)
    "swapoff",
    "delete_module",
    "vhangup",
    "acct",
    "sethostname",
    "setdomainname",
    // acts-on-root-or-owner (review round 3, 2026-10-01; reverses the
    // earlier verified-errno-only verdict - the argument is ABI-derived and
    // skipping costs nothing): IPC_RMID == 0 is the one ctl command that
    // IGNORES the buffer (man's canonical form is shmctl(id, IPC_RMID,
    // NULL)), so the all-zero sweep becomes shmctl/msgctl(0, IPC_RMID,
    // NULL) / semctl(0, 0, IPC_RMID) and DESTROYS the SysV object with id
    // 0 - root destroys any user's, unprivileged passes ipcperms on its own
    // (owner-write). Ids start at 0 and are reused: PostgreSQL's first
    // shared segment, MySQL's semaphores.
    "shmctl",
    "msgctl",
    "semctl",
    // kexec_load with nr_segments == 0 passes validation after the
    // CAP_SYS_BOOT check (kernel enforces only an UPPER bound), so a
    // zero-segment load is well-formed and a root sweep would replace the
    // pending kexec image. kexec_file_load skipped for symmetry (its
    // unargued O_EXEC-EINVAL guard is not worth trusting).
    "kexec_load",
    "kexec_file_load",
    // fd-0-relative: stdin's file/pty is the state sink, no root needed.
    // close(0) is the trigger for fd-0 poisoning: it frees the slot, then
    // the sweep's own fd creators (inotify_init, timerfd_create, ...) claim
    // it, and any later dfd- or read(0)-based call acts on the replacement
    // (inotify_read with count 0 waits forever). shutdown(0, SHUT_RD = 0)
    // is legal and IRREVERSIBLE: it read-shuts stdin whenever fd 0 is a
    // socket (relay shells like `exec 0<>/dev/tcp/...` lose their input).
    "close",
    "fchmod",
    "fchown",
    "ftruncate",
    "finit_module",
    "shutdown",
    // conditional-delay: acts/blocks/delays when the object exists (wait4,
    // waitid, msgrcv, accept, accept4) or is unconditionally expensive -
    // sync() takes no args and writebacks the WHOLE host; syncfs(0) does
    // the same to fd 0's filesystem; both run in D state for unbounded
    // time on loaded/remote filesystems and can outlive the 30 s ceiling.
    "wait4",
    "waitid",
    "msgrcv",
    "accept",
    "accept4",
    "sync",
    "syncfs",
    // thread/process bookkeeping: null-arg calls that quietly cancel or
    // destroy the caller's (or id 0's) kernel bookkeeping objects.
    // set_tid_address(0) NULLs the caller's clear_child_tid, so the thread's
    // exit never fires the futex wake pthread_join waits on - the joined
    // thread vanishes from /proc while the joiner hangs forever (repro:
    // spawn + syscall(218, 0) + join). The pipeline itself is immune
    // (channel + recv_timeout), but the sweep must not poison other joiners
    // in the process. alarm(0) cancels any pending alarm; setitimer with a
    // NULL/zeroed value disarms ITIMER_REAL; timer_settime(0, .., NULL, ..)
    // disarms and timer_delete(0) destroys timer id 0.
    "set_tid_address",
    "alarm",
    "setitimer",
    "timer_settime",
    "timer_delete",
];

/// x86_64 number→name table. Generated ONCE, committed verbatim (pinned to
/// libc 0.2.189 in Cargo.lock). Generator — mechanical, zero decisions:
///
/// ```text
/// grep -oE 'pub const SYS_[a-z0-9_]+: c_long = [0-9]+' \
///   ~/.cargo/registry/src/*/libc-0.2.189/src/unix/linux_like/linux/gnu/b64/x86_64/not_x32.rs
/// ```
///
/// (libc ≥ 0.2.18x moved the gnu x86_64 table from `mod.rs` to `not_x32.rs`;
/// same unistd-64 constants.) Keep `nr <= SYS_rseq`, drop alias duplicates,
/// emit ("name", nr) ascending: 334 rows, strictly monotonic.
#[cfg(target_arch = "x86_64")]
pub const NAMES: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("open", 2),
    ("close", 3),
    ("stat", 4),
    ("fstat", 5),
    ("lstat", 6),
    ("poll", 7),
    ("lseek", 8),
    ("mmap", 9),
    ("mprotect", 10),
    ("munmap", 11),
    ("brk", 12),
    ("rt_sigaction", 13),
    ("rt_sigprocmask", 14),
    ("rt_sigreturn", 15),
    ("ioctl", 16),
    ("pread64", 17),
    ("pwrite64", 18),
    ("readv", 19),
    ("writev", 20),
    ("access", 21),
    ("pipe", 22),
    ("select", 23),
    ("sched_yield", 24),
    ("mremap", 25),
    ("msync", 26),
    ("mincore", 27),
    ("madvise", 28),
    ("shmget", 29),
    ("shmat", 30),
    ("shmctl", 31),
    ("dup", 32),
    ("dup2", 33),
    ("pause", 34),
    ("nanosleep", 35),
    ("getitimer", 36),
    ("alarm", 37),
    ("setitimer", 38),
    ("getpid", 39),
    ("sendfile", 40),
    ("socket", 41),
    ("connect", 42),
    ("accept", 43),
    ("sendto", 44),
    ("recvfrom", 45),
    ("sendmsg", 46),
    ("recvmsg", 47),
    ("shutdown", 48),
    ("bind", 49),
    ("listen", 50),
    ("getsockname", 51),
    ("getpeername", 52),
    ("socketpair", 53),
    ("setsockopt", 54),
    ("getsockopt", 55),
    ("clone", 56),
    ("fork", 57),
    ("vfork", 58),
    ("execve", 59),
    ("exit", 60),
    ("wait4", 61),
    ("kill", 62),
    ("uname", 63),
    ("semget", 64),
    ("semop", 65),
    ("semctl", 66),
    ("shmdt", 67),
    ("msgget", 68),
    ("msgsnd", 69),
    ("msgrcv", 70),
    ("msgctl", 71),
    ("fcntl", 72),
    ("flock", 73),
    ("fsync", 74),
    ("fdatasync", 75),
    ("truncate", 76),
    ("ftruncate", 77),
    ("getdents", 78),
    ("getcwd", 79),
    ("chdir", 80),
    ("fchdir", 81),
    ("rename", 82),
    ("mkdir", 83),
    ("rmdir", 84),
    ("creat", 85),
    ("link", 86),
    ("unlink", 87),
    ("symlink", 88),
    ("readlink", 89),
    ("chmod", 90),
    ("fchmod", 91),
    ("chown", 92),
    ("fchown", 93),
    ("lchown", 94),
    ("umask", 95),
    ("gettimeofday", 96),
    ("getrlimit", 97),
    ("getrusage", 98),
    ("sysinfo", 99),
    ("times", 100),
    ("ptrace", 101),
    ("getuid", 102),
    ("syslog", 103),
    ("getgid", 104),
    ("setuid", 105),
    ("setgid", 106),
    ("geteuid", 107),
    ("getegid", 108),
    ("setpgid", 109),
    ("getppid", 110),
    ("getpgrp", 111),
    ("setsid", 112),
    ("setreuid", 113),
    ("setregid", 114),
    ("getgroups", 115),
    ("setgroups", 116),
    ("setresuid", 117),
    ("getresuid", 118),
    ("setresgid", 119),
    ("getresgid", 120),
    ("getpgid", 121),
    ("setfsuid", 122),
    ("setfsgid", 123),
    ("getsid", 124),
    ("capget", 125),
    ("capset", 126),
    ("rt_sigpending", 127),
    ("rt_sigtimedwait", 128),
    ("rt_sigqueueinfo", 129),
    ("rt_sigsuspend", 130),
    ("sigaltstack", 131),
    ("utime", 132),
    ("mknod", 133),
    ("uselib", 134),
    ("personality", 135),
    ("ustat", 136),
    ("statfs", 137),
    ("fstatfs", 138),
    ("sysfs", 139),
    ("getpriority", 140),
    ("setpriority", 141),
    ("sched_setparam", 142),
    ("sched_getparam", 143),
    ("sched_setscheduler", 144),
    ("sched_getscheduler", 145),
    ("sched_get_priority_max", 146),
    ("sched_get_priority_min", 147),
    ("sched_rr_get_interval", 148),
    ("mlock", 149),
    ("munlock", 150),
    ("mlockall", 151),
    ("munlockall", 152),
    ("vhangup", 153),
    ("modify_ldt", 154),
    ("pivot_root", 155),
    ("_sysctl", 156),
    ("prctl", 157),
    ("arch_prctl", 158),
    ("adjtimex", 159),
    ("setrlimit", 160),
    ("chroot", 161),
    ("sync", 162),
    ("acct", 163),
    ("settimeofday", 164),
    ("mount", 165),
    ("umount2", 166),
    ("swapon", 167),
    ("swapoff", 168),
    ("reboot", 169),
    ("sethostname", 170),
    ("setdomainname", 171),
    ("iopl", 172),
    ("ioperm", 173),
    ("create_module", 174),
    ("init_module", 175),
    ("delete_module", 176),
    ("get_kernel_syms", 177),
    ("query_module", 178),
    ("quotactl", 179),
    ("nfsservctl", 180),
    ("getpmsg", 181),
    ("putpmsg", 182),
    ("afs_syscall", 183),
    ("tuxcall", 184),
    ("security", 185),
    ("gettid", 186),
    ("readahead", 187),
    ("setxattr", 188),
    ("lsetxattr", 189),
    ("fsetxattr", 190),
    ("getxattr", 191),
    ("lgetxattr", 192),
    ("fgetxattr", 193),
    ("listxattr", 194),
    ("llistxattr", 195),
    ("flistxattr", 196),
    ("removexattr", 197),
    ("lremovexattr", 198),
    ("fremovexattr", 199),
    ("tkill", 200),
    ("time", 201),
    ("futex", 202),
    ("sched_setaffinity", 203),
    ("sched_getaffinity", 204),
    ("set_thread_area", 205),
    ("io_setup", 206),
    ("io_destroy", 207),
    ("io_getevents", 208),
    ("io_submit", 209),
    ("io_cancel", 210),
    ("get_thread_area", 211),
    ("lookup_dcookie", 212),
    ("epoll_create", 213),
    ("epoll_ctl_old", 214),
    ("epoll_wait_old", 215),
    ("remap_file_pages", 216),
    ("getdents64", 217),
    ("set_tid_address", 218),
    ("restart_syscall", 219),
    ("semtimedop", 220),
    ("fadvise64", 221),
    ("timer_create", 222),
    ("timer_settime", 223),
    ("timer_gettime", 224),
    ("timer_getoverrun", 225),
    ("timer_delete", 226),
    ("clock_settime", 227),
    ("clock_gettime", 228),
    ("clock_getres", 229),
    ("clock_nanosleep", 230),
    ("exit_group", 231),
    ("epoll_wait", 232),
    ("epoll_ctl", 233),
    ("tgkill", 234),
    ("utimes", 235),
    ("vserver", 236),
    ("mbind", 237),
    ("set_mempolicy", 238),
    ("get_mempolicy", 239),
    ("mq_open", 240),
    ("mq_unlink", 241),
    ("mq_timedsend", 242),
    ("mq_timedreceive", 243),
    ("mq_notify", 244),
    ("mq_getsetattr", 245),
    ("kexec_load", 246),
    ("waitid", 247),
    ("add_key", 248),
    ("request_key", 249),
    ("keyctl", 250),
    ("ioprio_set", 251),
    ("ioprio_get", 252),
    ("inotify_init", 253),
    ("inotify_add_watch", 254),
    ("inotify_rm_watch", 255),
    ("migrate_pages", 256),
    ("openat", 257),
    ("mkdirat", 258),
    ("mknodat", 259),
    ("fchownat", 260),
    ("futimesat", 261),
    ("newfstatat", 262),
    ("unlinkat", 263),
    ("renameat", 264),
    ("linkat", 265),
    ("symlinkat", 266),
    ("readlinkat", 267),
    ("fchmodat", 268),
    ("faccessat", 269),
    ("pselect6", 270),
    ("ppoll", 271),
    ("unshare", 272),
    ("set_robust_list", 273),
    ("get_robust_list", 274),
    ("splice", 275),
    ("tee", 276),
    ("sync_file_range", 277),
    ("vmsplice", 278),
    ("move_pages", 279),
    ("utimensat", 280),
    ("epoll_pwait", 281),
    ("signalfd", 282),
    ("timerfd_create", 283),
    ("eventfd", 284),
    ("fallocate", 285),
    ("timerfd_settime", 286),
    ("timerfd_gettime", 287),
    ("accept4", 288),
    ("signalfd4", 289),
    ("eventfd2", 290),
    ("epoll_create1", 291),
    ("dup3", 292),
    ("pipe2", 293),
    ("inotify_init1", 294),
    ("preadv", 295),
    ("pwritev", 296),
    ("rt_tgsigqueueinfo", 297),
    ("perf_event_open", 298),
    ("recvmmsg", 299),
    ("fanotify_init", 300),
    ("fanotify_mark", 301),
    ("prlimit64", 302),
    ("name_to_handle_at", 303),
    ("open_by_handle_at", 304),
    ("clock_adjtime", 305),
    ("syncfs", 306),
    ("sendmmsg", 307),
    ("setns", 308),
    ("getcpu", 309),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("kcmp", 312),
    ("finit_module", 313),
    ("sched_setattr", 314),
    ("sched_getattr", 315),
    ("renameat2", 316),
    ("seccomp", 317),
    ("getrandom", 318),
    ("memfd_create", 319),
    ("kexec_file_load", 320),
    ("bpf", 321),
    ("execveat", 322),
    ("userfaultfd", 323),
    ("membarrier", 324),
    ("mlock2", 325),
    ("copy_file_range", 326),
    ("preadv2", 327),
    ("pwritev2", 328),
    ("pkey_mprotect", 329),
    ("pkey_alloc", 330),
    ("pkey_free", 331),
    ("statx", 332),
    ("rseq", 334),
];

/// Sweep 0..=SYS_rseq with null args; names whose call hit EPERM/EACCES,
/// ascending by syscall number (the order of NAMES is the output order).
#[cfg(target_arch = "x86_64")]
pub fn probe_blocked(os: &dyn crate::sys::os::OsApi) -> Vec<&'static str> {
    NAMES
        .iter()
        .filter(|(n, _)| !SKIP.contains(n))
        .filter(|(_, nr)| matches!(os.syscall0(*nr), Err(1) | Err(13))) // EPERM | EACCES
        .map(|(n, _)| *n)
        .collect()
}

/// Other architectures: no committed number table exists, and inventing one
/// would be unsound — the sweep compiles to nothing (spec §5).
#[cfg(not(target_arch = "x86_64"))]
pub fn probe_blocked(_os: &dyn crate::sys::os::OsApi) -> Vec<&'static str> {
    vec![]
}

/// Registered by `probes::registry` only when `opts.probe_syscalls`.
pub struct SyscallProbe;

impl crate::probes::Probe for SyscallProbe {
    fn name(&self) -> &'static str {
        "syscall-probe"
    }
    fn run(&self, cx: &crate::pipeline::Ctx) -> ProbeOutcome {
        #[cfg(not(target_arch = "x86_64"))]
        return ProbeOutcome {
            availability: crate::model::Availability::Degraded("unsupported arch".into()),
            ..ProbeOutcome::empty("syscall-probe")
        };
        #[cfg(target_arch = "x86_64")]
        {
            let blocked = probe_blocked(cx.os);
            // Coverage wording (review RESID-COVERAGE): the sweep is an
            // audited 289-number subset, not the full 0..=SYS_rseq range;
            // counts are derived so wording can never silently drift.
            let coverage = format!(
                "null-arg sweep of {} audited syscalls ({} skipped for safety)",
                NAMES.len() - SKIP.len(),
                SKIP.len()
            );
            ProbeOutcome::empty("syscall-probe")
                .with_fact(Fact::ok(
                    "syscall-probe",
                    "sweptCount",
                    serde_json::json!(NAMES.len() - SKIP.len()),
                    "audited sweep coverage; skipped names are in SKIP".into(),
                ))
                .with_fact(Fact::ok(
                    "syscall-probe",
                    "blocked",
                    serde_json::json!(blocked),
                    coverage.clone(),
                ))
                .with_fact(Fact::ok(
                    "syscall-probe",
                    "blockedCount",
                    serde_json::json!(blocked.len()),
                    coverage,
                ))
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::probes::Probe;

    /// Full-trait stub (Task 4 signatures). `syscall0` answers EPERM for
    /// the four picked numbers, EACCES for chroot, ENOSYS for everything
    /// else — the sweep must treat all other errnos as indeterminate.
    struct Stub;
    impl crate::sys::os::OsApi for Stub {
        fn hypervisor(&self) -> crate::sys::os::HypervisorInfo {
            Default::default()
        }
        fn landlock_abi(&self) -> Option<u64> {
            None
        }
        fn seccomp_actions(&self) -> crate::sys::os::SeccompActions {
            Default::default()
        }
        fn seccomp_filter_dump(&self, _p: u32) -> Result<Vec<u64>, crate::sys::fs::ProbeIo> {
            Err(crate::sys::fs::ProbeIo::PermissionDenied)
        }
        fn syscall0(&self, n: u32) -> Result<(), i32> {
            let eperm: [u32; 4] = [
                libc::SYS_mount,
                libc::SYS_reboot,
                libc::SYS_setns,
                libc::SYS_pause,
            ]
            .map(|x| x as u32);
            if eperm.contains(&n) {
                return Err(1); // EPERM
            }
            if n == libc::SYS_chroot as u32 {
                return Err(13); // EACCES
            }
            Err(38) // ENOSYS
        }
        fn uds_probe(
            &self,
            _p: &std::path::Path,
            _t: std::time::Duration,
        ) -> std::io::Result<crate::sys::os::UdsReply> {
            Err(std::io::Error::other("stub"))
        }
        fn env(&self, _k: &str) -> Option<String> {
            None
        }
        fn is_root(&self) -> bool {
            false
        }
    }

    #[test]
    fn enumeration_marks_eperm_blocked_and_skips_hang_list() {
        // Classification is errno-driven: only EPERM(1)/EACCES(13) count as
        // blocked; every other errno — and Ok — is indeterminate. The stub
        // forces both blocked arms deterministically. Which errnos a real
        // kernel returns for null args is not pinned here (e.g.
        // `reboot(0,0,0,0)` hits the CAP_SYS_BOOT check before the magic,
        // so non-root hosts report it blocked — observed live, amicontained
        // parity); the sweep just reports what the kernel said.
        //
        // pause(34) stubs EPERM but sits on SKIP (all-zero args would hang
        // the sweep), so it must NOT appear. Result ordered by syscall
        // number: chroot(161) < mount(165) < reboot(169) < setns(308).
        // The EACCES arm sits on chroot, not sethostname: sethostname is
        // now skipped (len 0 is a valid empty-UTS-name write on any run).
        let blocked = probe_blocked(&Stub);
        assert_eq!(blocked, ["chroot", "mount", "reboot", "setns"]);
    }

    #[test]
    fn names_table_is_strictly_ascending_and_pinned_to_libc() {
        // Mechanical pin for the committed table (libc 0.2.189, gnu x86_64):
        // 334 rows from read(0) to rseq(334), no alias duplicates.
        assert_eq!(NAMES.len(), 334);
        assert!(
            NAMES.windows(2).all(|w| w[0].1 < w[1].1),
            "NAMES must be strictly ascending by syscall number"
        );
        // Boundary rows cross-checked against the compiled libc constants.
        assert_eq!(
            NAMES.first().map(|&(n, nr)| (n, nr)),
            Some(("read", libc::SYS_read as u32))
        );
        assert_eq!(
            NAMES.last().map(|&(n, nr)| (n, nr)),
            Some(("rseq", libc::SYS_rseq as u32))
        );
    }

    #[test]
    fn skip_list_is_the_canonical_set_and_shrinks_the_sweep() {
        // Canonical list from spec §5 (security review 2026-10-01 + review
        // round 3): SKIP must EQUAL this set - nothing more (unreviewed
        // entries), nothing less (a regenerated NAMES must not silently
        // drop a protected name into the swept set). Every entry carries
        // dated review evidence in the SKIP class comments.
        const CANONICAL: &[&str] = &[
            // hang-class
            "rt_sigreturn",
            "select",
            "pause",
            "pselect6",
            "ppoll",
            // exit-class
            "exit",
            "exit_group",
            "clone",
            "fork",
            "vfork",
            // self-modifying
            "seccomp",
            "ptrace",
            "umask",
            "setsid",
            "setpgid",
            "setgroups",
            // NULL-arg acts-on-root
            "swapoff",
            "delete_module",
            "vhangup",
            "acct",
            "sethostname",
            "setdomainname",
            // acts-on-root-or-owner (review round 3)
            "shmctl",
            "msgctl",
            "semctl",
            "kexec_load",
            "kexec_file_load",
            // fd-0-relative
            "close",
            "fchmod",
            "fchown",
            "ftruncate",
            "finit_module",
            "shutdown",
            // conditional-delay
            "wait4",
            "waitid",
            "msgrcv",
            "accept",
            "accept4",
            "sync",
            "syncfs",
            // thread/process bookkeeping
            "set_tid_address",
            "alarm",
            "setitimer",
            "timer_settime",
            "timer_delete",
        ];
        assert_eq!(CANONICAL.len(), 45);
        for s in CANONICAL {
            assert!(SKIP.contains(s), "protected name {s} missing from SKIP");
            assert!(
                NAMES.iter().any(|(n, _)| n == s),
                "SKIP entry {s} missing from NAMES"
            );
        }
        assert_eq!(
            SKIP.len(),
            CANONICAL.len(),
            "SKIP gained unreviewed entries"
        );
        assert!(
            SKIP.iter().all(|s| CANONICAL.contains(s)),
            "SKIP diverged from the canonical spec §5 set"
        );
        assert_eq!(
            NAMES.iter().filter(|(n, _)| !SKIP.contains(n)).count(),
            289,
            "swept set must be NAMES minus the 45 skipped"
        );
        // Why the live smoke never tripped classes 2-3 on this host: single
        // process (no children ⇒ wait4/waitid inert), stdin was a pipe
        // (neither a listening socket for accept nor an owned file for
        // fchmod/fchown), no msg queue id 0 existed, and no capabilities
        // were held. The list is a contractual guarantee for arbitrary
        // (including root) runs, not an observation of one.
    }

    #[test]
    fn swept_set_equals_the_frozen_audit_allow_list() {
        // STRUCTURAL GUARD (review round 3, 2026-10-01): a test-time
        // allow-list, not only a runtime deny-list. SKIP alone grows
        // reactively, one review finding at a time; this freeze inverts the
        // default - the swept set (NAMES minus SKIP) must EQUAL the frozen
        // list below. Any regenerated NAMES entry (libc bump) joins the sweep
        // after a human reviews its null-arg safety and adds it here.
        // Grouping is by syscall-number chunk for diff readability only;
        // membership in this set IS the reviewed verdict ("audited safe").
        const AUDITED_SWEPT: &[&str] = &[
            // nr 0-27
            "read",
            "write",
            "open",
            "stat",
            "fstat",
            "lstat",
            "poll",
            "lseek",
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "rt_sigaction",
            "rt_sigprocmask",
            "ioctl",
            "pread64",
            "pwrite64",
            "readv",
            "writev",
            "access",
            "pipe",
            "sched_yield",
            "mremap",
            "msync",
            "mincore",
            // nr 28-63
            "madvise",
            "shmget",
            "shmat",
            "dup",
            "dup2",
            "nanosleep",
            "getitimer",
            "getpid",
            "sendfile",
            "socket",
            "connect",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "bind",
            "listen",
            "getsockname",
            "getpeername",
            "socketpair",
            "setsockopt",
            "getsockopt",
            "execve",
            "kill",
            "uname",
            // nr 64-94
            "semget",
            "semop",
            "shmdt",
            "msgget",
            "msgsnd",
            "fcntl",
            "flock",
            "fsync",
            "fdatasync",
            "truncate",
            "getdents",
            "getcwd",
            "chdir",
            "fchdir",
            "rename",
            "mkdir",
            "rmdir",
            "creat",
            "link",
            "unlink",
            "symlink",
            "readlink",
            "chmod",
            "chown",
            "lchown",
            // nr 96-124
            "gettimeofday",
            "getrlimit",
            "getrusage",
            "sysinfo",
            "times",
            "getuid",
            "syslog",
            "getgid",
            "setuid",
            "setgid",
            "geteuid",
            "getegid",
            "getppid",
            "getpgrp",
            "setreuid",
            "setregid",
            "getgroups",
            "setresuid",
            "getresuid",
            "setresgid",
            "getresgid",
            "getpgid",
            "setfsuid",
            "setfsgid",
            "getsid",
            // nr 125-149
            "capget",
            "capset",
            "rt_sigpending",
            "rt_sigtimedwait",
            "rt_sigqueueinfo",
            "rt_sigsuspend",
            "sigaltstack",
            "utime",
            "mknod",
            "uselib",
            "personality",
            "ustat",
            "statfs",
            "fstatfs",
            "sysfs",
            "getpriority",
            "setpriority",
            "sched_setparam",
            "sched_getparam",
            "sched_setscheduler",
            "sched_getscheduler",
            "sched_get_priority_max",
            "sched_get_priority_min",
            "sched_rr_get_interval",
            "mlock",
            // nr 150-181
            "munlock",
            "mlockall",
            "munlockall",
            "modify_ldt",
            "pivot_root",
            "_sysctl",
            "prctl",
            "arch_prctl",
            "adjtimex",
            "setrlimit",
            "chroot",
            "settimeofday",
            "mount",
            "umount2",
            "swapon",
            "reboot",
            "iopl",
            "ioperm",
            "create_module",
            "init_module",
            "get_kernel_syms",
            "query_module",
            "quotactl",
            "nfsservctl",
            "getpmsg",
            // nr 182-206
            "putpmsg",
            "afs_syscall",
            "tuxcall",
            "security",
            "gettid",
            "readahead",
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
            "tkill",
            "time",
            "futex",
            "sched_setaffinity",
            "sched_getaffinity",
            "set_thread_area",
            "io_setup",
            // nr 207-235
            "io_destroy",
            "io_getevents",
            "io_submit",
            "io_cancel",
            "get_thread_area",
            "lookup_dcookie",
            "epoll_create",
            "epoll_ctl_old",
            "epoll_wait_old",
            "remap_file_pages",
            "getdents64",
            "restart_syscall",
            "semtimedop",
            "fadvise64",
            "timer_create",
            "timer_gettime",
            "timer_getoverrun",
            "clock_settime",
            "clock_gettime",
            "clock_getres",
            "clock_nanosleep",
            "epoll_wait",
            "epoll_ctl",
            "tgkill",
            "utimes",
            // nr 236-262
            "vserver",
            "mbind",
            "set_mempolicy",
            "get_mempolicy",
            "mq_open",
            "mq_unlink",
            "mq_timedsend",
            "mq_timedreceive",
            "mq_notify",
            "mq_getsetattr",
            "add_key",
            "request_key",
            "keyctl",
            "ioprio_set",
            "ioprio_get",
            "inotify_init",
            "inotify_add_watch",
            "inotify_rm_watch",
            "migrate_pages",
            "openat",
            "mkdirat",
            "mknodat",
            "fchownat",
            "futimesat",
            "newfstatat",
            // nr 263-290
            "unlinkat",
            "renameat",
            "linkat",
            "symlinkat",
            "readlinkat",
            "fchmodat",
            "faccessat",
            "unshare",
            "set_robust_list",
            "get_robust_list",
            "splice",
            "tee",
            "sync_file_range",
            "vmsplice",
            "move_pages",
            "utimensat",
            "epoll_pwait",
            "signalfd",
            "timerfd_create",
            "eventfd",
            "fallocate",
            "timerfd_settime",
            "timerfd_gettime",
            "signalfd4",
            "eventfd2",
            // nr 291-318
            "epoll_create1",
            "dup3",
            "pipe2",
            "inotify_init1",
            "preadv",
            "pwritev",
            "rt_tgsigqueueinfo",
            "perf_event_open",
            "recvmmsg",
            "fanotify_init",
            "fanotify_mark",
            "prlimit64",
            "name_to_handle_at",
            "open_by_handle_at",
            "clock_adjtime",
            "sendmmsg",
            "setns",
            "getcpu",
            "process_vm_readv",
            "process_vm_writev",
            "kcmp",
            "sched_setattr",
            "sched_getattr",
            "renameat2",
            "getrandom",
            // nr 319-334
            "memfd_create",
            "bpf",
            "execveat",
            "userfaultfd",
            "membarrier",
            "mlock2",
            "copy_file_range",
            "preadv2",
            "pwritev2",
            "pkey_mprotect",
            "pkey_alloc",
            "pkey_free",
            "statx",
            "rseq",
        ];
        assert_eq!(AUDITED_SWEPT.len(), 289);
        let mut swept: Vec<&str> = NAMES
            .iter()
            .filter(|(n, _)| !SKIP.contains(n))
            .map(|(n, _)| *n)
            .collect();
        let mut audited = AUDITED_SWEPT.to_vec();
        swept.sort_unstable();
        audited.sort_unstable();
        assert_eq!(
            swept, audited,
            "swept set drifted from the frozen allow-list - review each new \
             syscall's null-arg safety before adding it here"
        );
    }

    #[test]
    fn fd_creating_sweep_calls_leak_only_process_scoped_fds() {
        // Pins the spec §5 "Benign accepted" clause: the sweep's fd creators
        // return immediately (never block) and their only residue is an fd
        // that lives until process exit. Anon-inode fds are never closed
        // during a run, so counting their links in /proc/self/fd is monotone
        // and immune to other tests' regular fd churn.
        use crate::sys::os::{OsApi, RealOs};
        let anon = |kinds: &[&str]| -> usize {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .map(|t| {
                            let t = t.to_string_lossy();
                            kinds.iter().any(|k| t.contains(k))
                        })
                        .unwrap_or(false)
                })
                .count()
        };
        const KINDS: &[&str] = &["[timerfd]", "[eventfd]", "inotify", "[eventpoll]"];
        let before = anon(KINDS);
        for name in [
            "timerfd_create",
            "eventfd2",
            "inotify_init",
            "epoll_create1",
        ] {
            let (_, nr) = *NAMES.iter().find(|(n, _)| *n == name).unwrap();
            assert!(!SKIP.contains(&name), "{name} must stay in the sweep");
            assert!(RealOs.syscall0(nr).is_ok(), "{name} must return, not block");
        }
        let after = anon(KINDS);
        assert!(
            after >= before + 4,
            "each swept fd creator must leave exactly its fd behind (benign, process-scoped)"
        );
    }

    #[test]
    fn probe_publishes_blocked_and_count_facts() {
        let dir = tempfile::tempdir().unwrap();
        let fs = crate::sys::fs::PseudoFs::new(dir.path().to_path_buf());
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: true,
            probe_ebpf: false,
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let cx = crate::pipeline::Ctx {
            pid: 4242,
            uid: 1000,
            fs: &fs,
            os: &Stub,
            opts: &opts,
            prior: crate::pipeline::Prior {
                signals: vec![],
                facts: std::collections::HashMap::new(),
            },
        };
        let o = SyscallProbe.run(&cx);
        assert_eq!(o.name, "syscall-probe");
        assert_eq!(o.availability, crate::model::Availability::Ok);
        let blocked = o.facts.iter().find(|f| f.key == "blocked").unwrap();
        assert_eq!(
            blocked.value,
            serde_json::json!(["chroot", "mount", "reboot", "setns"])
        );
        let count = o.facts.iter().find(|f| f.key == "blockedCount").unwrap();
        assert_eq!(count.value, serde_json::json!(4));
    }

    #[test]
    fn real_sweep_is_deterministic_in_process() {
        // ReviewT18 seam finding: `libc::syscall(id)` leaves arg registers
        // 2-6 carrying residual values, so blocked[] drifted between runs.
        // With the seam's all-zeroed-registers contract the same process
        // must observe the identical sweep twice.
        let a = probe_blocked(&crate::sys::os::RealOs);
        let b = probe_blocked(&crate::sys::os::RealOs);
        assert_eq!(a, b, "sweep must be deterministic in-process");
    }
}

#[cfg(all(test, not(target_arch = "x86_64")))]
mod tests {
    use super::*;

    #[test]
    fn sweep_compiles_to_empty_off_x86_64() {
        assert!(probe_blocked(&crate::sys::os::RealOs).is_empty());
    }
}
