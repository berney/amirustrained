//! Opt-in EPERM sweep (spec §5 "Syscall enumeration policy"): invoke every
//! syscall of the target arch's committed NAMES table with all-zero args
//! and read the errno. Only `EPERM`(1) and
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
//! instead of hanging the scan. Sweep size is per-arch (NAMES minus SKIP):
//! 289 round-trips on x86_64, 239 on aarch64, 238 on riscv64.
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
///
/// ARCH SCALING (multi-arch task 2026-10-02): the list keys BY NAME on
/// purpose — the same hazards carry different numbers per arch (mount 165
/// on x86_64 vs 40 on asm-generic; reboot 169 vs 142; seccomp 317 vs 277).
/// All supported arches share this one canonical list; names an arch's
/// table does not contain (select/pause/fork/vfork/alarm are absent from
/// asm-generic; kexec_file_load sits above its rseq ceiling) simply match
/// nothing, and the per-arch pin test freezes exactly which entries are
/// vacuous per arch.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
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

/// aarch64 (asm-generic) number→name table. Generated ONCE, committed
/// verbatim (pinned to libc 0.2.189). The musl module is the generator
/// because it is the release target; every name present in the gnu module
/// carries the SAME number there (cross-checked 1:1 — the only musl-only
/// in-range row is io_pgetevents(292), which the kernel asm-generic table
/// defines for all arches; the gnu modules' table just omits the constant).
/// Generator — mechanical, zero decisions:
///
/// ```text
/// grep -oE 'pub const SYS_[a-z0-9_]+: c_long = [0-9]+' \
///   ~/.cargo/registry/src/*/libc-0.2.189/src/unix/linux_like/linux/musl/b64/aarch64/mod.rs
/// ```
///
/// Keep `nr <= SYS_rseq` (293 on asm-generic — the same sweep-ceiling
/// policy as x86_64; landlock/futex_waitv/mseal sit above it on every
/// arch), drop alias duplicates, emit ("name", nr) ascending: 278 rows,
/// strictly monotonic. The 244..=259 asm-generic arch-specific
/// reservation is a real hole (no exported names). Numbers differ from
/// x86_64 by design: io_setup=0 (the table opens with the aio family, not
/// read), mount=40, reboot=142, seccomp=277, bpf=280, rseq=293.
#[cfg(target_arch = "aarch64")]
pub const NAMES: &[(&str, u32)] = &[
    ("io_setup", 0),
    ("io_destroy", 1),
    ("io_submit", 2),
    ("io_cancel", 3),
    ("io_getevents", 4),
    ("setxattr", 5),
    ("lsetxattr", 6),
    ("fsetxattr", 7),
    ("getxattr", 8),
    ("lgetxattr", 9),
    ("fgetxattr", 10),
    ("listxattr", 11),
    ("llistxattr", 12),
    ("flistxattr", 13),
    ("removexattr", 14),
    ("lremovexattr", 15),
    ("fremovexattr", 16),
    ("getcwd", 17),
    ("lookup_dcookie", 18),
    ("eventfd2", 19),
    ("epoll_create1", 20),
    ("epoll_ctl", 21),
    ("epoll_pwait", 22),
    ("dup", 23),
    ("dup3", 24),
    ("fcntl", 25),
    ("inotify_init1", 26),
    ("inotify_add_watch", 27),
    ("inotify_rm_watch", 28),
    ("ioctl", 29),
    ("ioprio_set", 30),
    ("ioprio_get", 31),
    ("flock", 32),
    ("mknodat", 33),
    ("mkdirat", 34),
    ("unlinkat", 35),
    ("symlinkat", 36),
    ("linkat", 37),
    ("renameat", 38),
    ("umount2", 39),
    ("mount", 40),
    ("pivot_root", 41),
    ("nfsservctl", 42),
    ("statfs", 43),
    ("fstatfs", 44),
    ("truncate", 45),
    ("ftruncate", 46),
    ("fallocate", 47),
    ("faccessat", 48),
    ("chdir", 49),
    ("fchdir", 50),
    ("chroot", 51),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchownat", 54),
    ("fchown", 55),
    ("openat", 56),
    ("close", 57),
    ("vhangup", 58),
    ("pipe2", 59),
    ("quotactl", 60),
    ("getdents64", 61),
    ("lseek", 62),
    ("read", 63),
    ("write", 64),
    ("readv", 65),
    ("writev", 66),
    ("pread64", 67),
    ("pwrite64", 68),
    ("preadv", 69),
    ("pwritev", 70),
    ("sendfile", 71),
    ("pselect6", 72),
    ("ppoll", 73),
    ("signalfd4", 74),
    ("vmsplice", 75),
    ("splice", 76),
    ("tee", 77),
    ("readlinkat", 78),
    ("newfstatat", 79),
    ("fstat", 80),
    ("sync", 81),
    ("fsync", 82),
    ("fdatasync", 83),
    ("sync_file_range", 84),
    ("timerfd_create", 85),
    ("timerfd_settime", 86),
    ("timerfd_gettime", 87),
    ("utimensat", 88),
    ("acct", 89),
    ("capget", 90),
    ("capset", 91),
    ("personality", 92),
    ("exit", 93),
    ("exit_group", 94),
    ("waitid", 95),
    ("set_tid_address", 96),
    ("unshare", 97),
    ("futex", 98),
    ("set_robust_list", 99),
    ("get_robust_list", 100),
    ("nanosleep", 101),
    ("getitimer", 102),
    ("setitimer", 103),
    ("kexec_load", 104),
    ("init_module", 105),
    ("delete_module", 106),
    ("timer_create", 107),
    ("timer_gettime", 108),
    ("timer_getoverrun", 109),
    ("timer_settime", 110),
    ("timer_delete", 111),
    ("clock_settime", 112),
    ("clock_gettime", 113),
    ("clock_getres", 114),
    ("clock_nanosleep", 115),
    ("syslog", 116),
    ("ptrace", 117),
    ("sched_setparam", 118),
    ("sched_setscheduler", 119),
    ("sched_getscheduler", 120),
    ("sched_getparam", 121),
    ("sched_setaffinity", 122),
    ("sched_getaffinity", 123),
    ("sched_yield", 124),
    ("sched_get_priority_max", 125),
    ("sched_get_priority_min", 126),
    ("sched_rr_get_interval", 127),
    ("restart_syscall", 128),
    ("kill", 129),
    ("tkill", 130),
    ("tgkill", 131),
    ("sigaltstack", 132),
    ("rt_sigsuspend", 133),
    ("rt_sigaction", 134),
    ("rt_sigprocmask", 135),
    ("rt_sigpending", 136),
    ("rt_sigtimedwait", 137),
    ("rt_sigqueueinfo", 138),
    ("rt_sigreturn", 139),
    ("setpriority", 140),
    ("getpriority", 141),
    ("reboot", 142),
    ("setregid", 143),
    ("setgid", 144),
    ("setreuid", 145),
    ("setuid", 146),
    ("setresuid", 147),
    ("getresuid", 148),
    ("setresgid", 149),
    ("getresgid", 150),
    ("setfsuid", 151),
    ("setfsgid", 152),
    ("times", 153),
    ("setpgid", 154),
    ("getpgid", 155),
    ("getsid", 156),
    ("setsid", 157),
    ("getgroups", 158),
    ("setgroups", 159),
    ("uname", 160),
    ("sethostname", 161),
    ("setdomainname", 162),
    ("getrlimit", 163),
    ("setrlimit", 164),
    ("getrusage", 165),
    ("umask", 166),
    ("prctl", 167),
    ("getcpu", 168),
    ("gettimeofday", 169),
    ("settimeofday", 170),
    ("adjtimex", 171),
    ("getpid", 172),
    ("getppid", 173),
    ("getuid", 174),
    ("geteuid", 175),
    ("getgid", 176),
    ("getegid", 177),
    ("gettid", 178),
    ("sysinfo", 179),
    ("mq_open", 180),
    ("mq_unlink", 181),
    ("mq_timedsend", 182),
    ("mq_timedreceive", 183),
    ("mq_notify", 184),
    ("mq_getsetattr", 185),
    ("msgget", 186),
    ("msgctl", 187),
    ("msgrcv", 188),
    ("msgsnd", 189),
    ("semget", 190),
    ("semctl", 191),
    ("semtimedop", 192),
    ("semop", 193),
    ("shmget", 194),
    ("shmctl", 195),
    ("shmat", 196),
    ("shmdt", 197),
    ("socket", 198),
    ("socketpair", 199),
    ("bind", 200),
    ("listen", 201),
    ("accept", 202),
    ("connect", 203),
    ("getsockname", 204),
    ("getpeername", 205),
    ("sendto", 206),
    ("recvfrom", 207),
    ("setsockopt", 208),
    ("getsockopt", 209),
    ("shutdown", 210),
    ("sendmsg", 211),
    ("recvmsg", 212),
    ("readahead", 213),
    ("brk", 214),
    ("munmap", 215),
    ("mremap", 216),
    ("add_key", 217),
    ("request_key", 218),
    ("keyctl", 219),
    ("clone", 220),
    ("execve", 221),
    ("mmap", 222),
    ("fadvise64", 223),
    ("swapon", 224),
    ("swapoff", 225),
    ("mprotect", 226),
    ("msync", 227),
    ("mlock", 228),
    ("munlock", 229),
    ("mlockall", 230),
    ("munlockall", 231),
    ("mincore", 232),
    ("madvise", 233),
    ("remap_file_pages", 234),
    ("mbind", 235),
    ("get_mempolicy", 236),
    ("set_mempolicy", 237),
    ("migrate_pages", 238),
    ("move_pages", 239),
    ("rt_tgsigqueueinfo", 240),
    ("perf_event_open", 241),
    ("accept4", 242),
    ("recvmmsg", 243),
    ("wait4", 260),
    ("prlimit64", 261),
    ("fanotify_init", 262),
    ("fanotify_mark", 263),
    ("name_to_handle_at", 264),
    ("open_by_handle_at", 265),
    ("clock_adjtime", 266),
    ("syncfs", 267),
    ("setns", 268),
    ("sendmmsg", 269),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("kcmp", 272),
    ("finit_module", 273),
    ("sched_setattr", 274),
    ("sched_getattr", 275),
    ("renameat2", 276),
    ("seccomp", 277),
    ("getrandom", 278),
    ("memfd_create", 279),
    ("bpf", 280),
    ("execveat", 281),
    ("userfaultfd", 282),
    ("membarrier", 283),
    ("mlock2", 284),
    ("copy_file_range", 285),
    ("preadv2", 286),
    ("pwritev2", 287),
    ("pkey_mprotect", 288),
    ("pkey_alloc", 289),
    ("pkey_free", 290),
    ("statx", 291),
    ("io_pgetevents", 292),
    ("rseq", 293),
];

/// riscv64 (asm-generic) number→name table. Identical ABI family to
/// aarch64 — but regenerated INDEPENDENTLY from the libc riscv64 module
/// and verified by a name-for-name diff against the aarch64 extraction:
/// within the sweep ceiling the two arches differ ONLY by libc's omission
/// of SYS_renameat (below). Generator — mechanical, zero decisions:
///
/// ```text
/// grep -oE 'pub const SYS_[a-z0-9_]+: c_long = [0-9]+' \
///   ~/.cargo/registry/src/*/libc-0.2.189/src/unix/linux_like/linux/musl/b64/riscv64/mod.rs
/// ```
///
/// Keep `nr <= SYS_rseq` (293), drop alias duplicates, ascending: 277 rows,
/// strictly monotonic. DOCUMENTED GAP: libc 0.2.189 (gnu AND musl) omits
/// SYS_renameat on riscv64 although the kernel asm-generic table numbers it
/// 38 (between linkat 37 and umount2 39); renameat2(276) IS swept, so the
/// coverage loss is exactly one legacy call. Re-check this row count on the
/// next libc bump — if libc gains the constant, regeneration must produce
/// 278 rows and the pin test here must be updated deliberately.
#[cfg(target_arch = "riscv64")]
pub const NAMES: &[(&str, u32)] = &[
    ("io_setup", 0),
    ("io_destroy", 1),
    ("io_submit", 2),
    ("io_cancel", 3),
    ("io_getevents", 4),
    ("setxattr", 5),
    ("lsetxattr", 6),
    ("fsetxattr", 7),
    ("getxattr", 8),
    ("lgetxattr", 9),
    ("fgetxattr", 10),
    ("listxattr", 11),
    ("llistxattr", 12),
    ("flistxattr", 13),
    ("removexattr", 14),
    ("lremovexattr", 15),
    ("fremovexattr", 16),
    ("getcwd", 17),
    ("lookup_dcookie", 18),
    ("eventfd2", 19),
    ("epoll_create1", 20),
    ("epoll_ctl", 21),
    ("epoll_pwait", 22),
    ("dup", 23),
    ("dup3", 24),
    ("fcntl", 25),
    ("inotify_init1", 26),
    ("inotify_add_watch", 27),
    ("inotify_rm_watch", 28),
    ("ioctl", 29),
    ("ioprio_set", 30),
    ("ioprio_get", 31),
    ("flock", 32),
    ("mknodat", 33),
    ("mkdirat", 34),
    ("unlinkat", 35),
    ("symlinkat", 36),
    ("linkat", 37),
    ("umount2", 39),
    ("mount", 40),
    ("pivot_root", 41),
    ("nfsservctl", 42),
    ("statfs", 43),
    ("fstatfs", 44),
    ("truncate", 45),
    ("ftruncate", 46),
    ("fallocate", 47),
    ("faccessat", 48),
    ("chdir", 49),
    ("fchdir", 50),
    ("chroot", 51),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchownat", 54),
    ("fchown", 55),
    ("openat", 56),
    ("close", 57),
    ("vhangup", 58),
    ("pipe2", 59),
    ("quotactl", 60),
    ("getdents64", 61),
    ("lseek", 62),
    ("read", 63),
    ("write", 64),
    ("readv", 65),
    ("writev", 66),
    ("pread64", 67),
    ("pwrite64", 68),
    ("preadv", 69),
    ("pwritev", 70),
    ("sendfile", 71),
    ("pselect6", 72),
    ("ppoll", 73),
    ("signalfd4", 74),
    ("vmsplice", 75),
    ("splice", 76),
    ("tee", 77),
    ("readlinkat", 78),
    ("newfstatat", 79),
    ("fstat", 80),
    ("sync", 81),
    ("fsync", 82),
    ("fdatasync", 83),
    ("sync_file_range", 84),
    ("timerfd_create", 85),
    ("timerfd_settime", 86),
    ("timerfd_gettime", 87),
    ("utimensat", 88),
    ("acct", 89),
    ("capget", 90),
    ("capset", 91),
    ("personality", 92),
    ("exit", 93),
    ("exit_group", 94),
    ("waitid", 95),
    ("set_tid_address", 96),
    ("unshare", 97),
    ("futex", 98),
    ("set_robust_list", 99),
    ("get_robust_list", 100),
    ("nanosleep", 101),
    ("getitimer", 102),
    ("setitimer", 103),
    ("kexec_load", 104),
    ("init_module", 105),
    ("delete_module", 106),
    ("timer_create", 107),
    ("timer_gettime", 108),
    ("timer_getoverrun", 109),
    ("timer_settime", 110),
    ("timer_delete", 111),
    ("clock_settime", 112),
    ("clock_gettime", 113),
    ("clock_getres", 114),
    ("clock_nanosleep", 115),
    ("syslog", 116),
    ("ptrace", 117),
    ("sched_setparam", 118),
    ("sched_setscheduler", 119),
    ("sched_getscheduler", 120),
    ("sched_getparam", 121),
    ("sched_setaffinity", 122),
    ("sched_getaffinity", 123),
    ("sched_yield", 124),
    ("sched_get_priority_max", 125),
    ("sched_get_priority_min", 126),
    ("sched_rr_get_interval", 127),
    ("restart_syscall", 128),
    ("kill", 129),
    ("tkill", 130),
    ("tgkill", 131),
    ("sigaltstack", 132),
    ("rt_sigsuspend", 133),
    ("rt_sigaction", 134),
    ("rt_sigprocmask", 135),
    ("rt_sigpending", 136),
    ("rt_sigtimedwait", 137),
    ("rt_sigqueueinfo", 138),
    ("rt_sigreturn", 139),
    ("setpriority", 140),
    ("getpriority", 141),
    ("reboot", 142),
    ("setregid", 143),
    ("setgid", 144),
    ("setreuid", 145),
    ("setuid", 146),
    ("setresuid", 147),
    ("getresuid", 148),
    ("setresgid", 149),
    ("getresgid", 150),
    ("setfsuid", 151),
    ("setfsgid", 152),
    ("times", 153),
    ("setpgid", 154),
    ("getpgid", 155),
    ("getsid", 156),
    ("setsid", 157),
    ("getgroups", 158),
    ("setgroups", 159),
    ("uname", 160),
    ("sethostname", 161),
    ("setdomainname", 162),
    ("getrlimit", 163),
    ("setrlimit", 164),
    ("getrusage", 165),
    ("umask", 166),
    ("prctl", 167),
    ("getcpu", 168),
    ("gettimeofday", 169),
    ("settimeofday", 170),
    ("adjtimex", 171),
    ("getpid", 172),
    ("getppid", 173),
    ("getuid", 174),
    ("geteuid", 175),
    ("getgid", 176),
    ("getegid", 177),
    ("gettid", 178),
    ("sysinfo", 179),
    ("mq_open", 180),
    ("mq_unlink", 181),
    ("mq_timedsend", 182),
    ("mq_timedreceive", 183),
    ("mq_notify", 184),
    ("mq_getsetattr", 185),
    ("msgget", 186),
    ("msgctl", 187),
    ("msgrcv", 188),
    ("msgsnd", 189),
    ("semget", 190),
    ("semctl", 191),
    ("semtimedop", 192),
    ("semop", 193),
    ("shmget", 194),
    ("shmctl", 195),
    ("shmat", 196),
    ("shmdt", 197),
    ("socket", 198),
    ("socketpair", 199),
    ("bind", 200),
    ("listen", 201),
    ("accept", 202),
    ("connect", 203),
    ("getsockname", 204),
    ("getpeername", 205),
    ("sendto", 206),
    ("recvfrom", 207),
    ("setsockopt", 208),
    ("getsockopt", 209),
    ("shutdown", 210),
    ("sendmsg", 211),
    ("recvmsg", 212),
    ("readahead", 213),
    ("brk", 214),
    ("munmap", 215),
    ("mremap", 216),
    ("add_key", 217),
    ("request_key", 218),
    ("keyctl", 219),
    ("clone", 220),
    ("execve", 221),
    ("mmap", 222),
    ("fadvise64", 223),
    ("swapon", 224),
    ("swapoff", 225),
    ("mprotect", 226),
    ("msync", 227),
    ("mlock", 228),
    ("munlock", 229),
    ("mlockall", 230),
    ("munlockall", 231),
    ("mincore", 232),
    ("madvise", 233),
    ("remap_file_pages", 234),
    ("mbind", 235),
    ("get_mempolicy", 236),
    ("set_mempolicy", 237),
    ("migrate_pages", 238),
    ("move_pages", 239),
    ("rt_tgsigqueueinfo", 240),
    ("perf_event_open", 241),
    ("accept4", 242),
    ("recvmmsg", 243),
    ("wait4", 260),
    ("prlimit64", 261),
    ("fanotify_init", 262),
    ("fanotify_mark", 263),
    ("name_to_handle_at", 264),
    ("open_by_handle_at", 265),
    ("clock_adjtime", 266),
    ("syncfs", 267),
    ("setns", 268),
    ("sendmmsg", 269),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("kcmp", 272),
    ("finit_module", 273),
    ("sched_setattr", 274),
    ("sched_getattr", 275),
    ("renameat2", 276),
    ("seccomp", 277),
    ("getrandom", 278),
    ("memfd_create", 279),
    ("bpf", 280),
    ("execveat", 281),
    ("userfaultfd", 282),
    ("membarrier", 283),
    ("mlock2", 284),
    ("copy_file_range", 285),
    ("preadv2", 286),
    ("pwritev2", 287),
    ("pkey_mprotect", 288),
    ("pkey_alloc", 289),
    ("pkey_free", 290),
    ("statx", 291),
    ("io_pgetevents", 292),
    ("rseq", 293),
];

/// Sweep the arch's committed NAMES table (nr 0..=SYS_rseq of that arch)
/// with null args; names whose call hit EPERM/EACCES,
/// ascending by syscall number (the order of NAMES is the output order).
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
pub fn probe_blocked(os: &dyn crate::sys::os::OsApi) -> Vec<&'static str> {
    NAMES
        .iter()
        .filter(|(n, _)| !SKIP.contains(n))
        .filter(|(_, nr)| matches!(os.syscall0(*nr), Err(1) | Err(13))) // EPERM | EACCES
        .map(|(n, _)| *n)
        .collect()
}

/// Arches without a committed number table (anything beyond x86_64 /
/// aarch64 / riscv64): inventing one would be unsound — the sweep compiles
/// to nothing, `SyscallProbe` reports Degraded("unsupported arch"), and the
/// scan itself is unaffected (spec §5). Compile proof:
/// `cargo check --target powerpc64-unknown-linux-gnu`.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
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
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )))]
        return ProbeOutcome {
            availability: crate::model::Availability::Degraded("unsupported arch".into()),
            ..ProbeOutcome::empty("syscall-probe")
        };
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
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

/// Frozen AUDITED-SWEPT allow-list (review round 3, 2026-10-01), lifted to
/// module scope by the multi-arch task (2026-10-02) so the aarch64/riscv64
/// pin test can assert its swept set never escapes the human-audited
/// universe. Grouping is by x86_64 syscall-number chunk for diff
/// readability only; membership in this set IS the reviewed verdict
/// ("audited safe" under the null-arg sweep contract at the top of this
/// module).
#[cfg(test)]
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
        // (The frozen list itself lives at module scope, cfg(test), lifted
        //  there so the per-arch audit test can check membership too.)
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

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "riscv64")))]
mod asm_generic_tests {
    use super::*;

    /// Full-trait stub (Task 4 signatures). EPERM for mount/reboot/setns —
    /// plus ptrace, the asm-generic stand-in for x86_64's pause as the
    /// "stubbed blocked but name-keyed skipped" witness (pause does not
    /// exist in the asm-generic table); EACCES for chroot; ENOSYS else.
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
                libc::SYS_ptrace,
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

    fn nr_of(name: &str) -> Option<u32> {
        NAMES.iter().find(|(n, _)| *n == name).map(|(_, nr)| *nr)
    }

    #[test]
    fn enumeration_marks_eperm_blocked_and_skips_hang_list() {
        // Same errno contract as x86_64; result ordered by THIS arch's
        // numbers: mount(40) < chroot(51) < reboot(142) < setns(268).
        // ptrace(117) is stubbed EPERM but sits on SKIP, so it must NOT
        // appear — the skip list filters BY NAME on numbers that bear no
        // relation to the x86_64 ones (that is the whole point).
        let blocked = probe_blocked(&Stub);
        assert_eq!(blocked, ["mount", "chroot", "reboot", "setns"]);
    }

    #[test]
    fn names_table_is_strictly_ascending_and_pinned_to_libc() {
        // Mechanical pin for the committed asm-generic table (libc 0.2.189):
        // aarch64 278 rows io_setup(0)..rseq(293); riscv64 277 rows — the
        // difference is ONLY libc's missing SYS_renameat on riscv64
        // (documented at the table), verified by diffing the two generated
        // extractions name-for-name.
        assert_eq!(
            NAMES.len(),
            if cfg!(target_arch = "aarch64") {
                278
            } else {
                277
            }
        );
        assert!(
            NAMES.windows(2).all(|w| w[0].1 < w[1].1),
            "NAMES must be strictly ascending by syscall number"
        );
        // Boundary rows cross-checked against the compiled libc constants:
        // asm-generic opens with the aio family (io_setup=0), not read, and
        // ends at rseq — 293 here vs 334 on x86_64.
        assert_eq!(
            NAMES.first().map(|&(n, nr)| (n, nr)),
            Some(("io_setup", libc::SYS_io_setup as u32))
        );
        assert_eq!(
            NAMES.last().map(|&(n, nr)| (n, nr)),
            Some(("rseq", libc::SYS_rseq as u32))
        );
    }

    #[test]
    fn asm_generic_spot_numbers_match_the_kernel_table() {
        // Values verified from libc 0.2.189 with three-way agreement (gnu
        // aarch64, gnu riscv64, musl both); deliberately NOT the x86_64
        // numbers (mount 165, reboot 169, seccomp 317).
        for (name, libc_nr, table_nr) in [
            ("mount", libc::SYS_mount as u32, 40),
            ("reboot", libc::SYS_reboot as u32, 142),
            ("seccomp", libc::SYS_seccomp as u32, 277),
            ("bpf", libc::SYS_bpf as u32, 280),
            ("rseq", libc::SYS_rseq as u32, 293),
        ] {
            assert_eq!(
                (nr_of(name), libc_nr),
                (Some(table_nr), table_nr),
                "{name} drifted"
            );
        }
        // io_pgetevents: the one in-range row the gnu libc modules omit but
        // musl (and the kernel asm-generic table) define — 292 on every
        // asm-generic arch.
        assert_eq!(nr_of("io_pgetevents"), Some(292));
        assert_eq!(nr_of("kexec_load"), Some(104));
        assert_eq!(nr_of("swapoff"), Some(225));
        if cfg!(target_arch = "aarch64") {
            assert_eq!(nr_of("renameat"), Some(38));
        } else {
            assert_eq!(nr_of("renameat"), None, "libc riscv64 documents the 38 gap");
            assert_eq!(nr_of("renameat2"), Some(276));
        }
    }

    #[test]
    fn skip_list_is_name_keyed_across_arches() {
        // The canonical 45-name SKIP is shared UNCHANGED across arches. The
        // names below exist on x86_64 but match nothing in the asm-generic
        // table (legacy select/pause/fork/vfork/alarm; kexec_file_load is
        // nr 294 > the 293 sweep ceiling on aarch64 and undefined on
        // riscv64). Pinning the vacuous set documents WHY the skip list
        // must key by NAME: numbers shift (mount 165→40, reboot 169→142,
        // seccomp 317→277), names do not.
        let mut missing: Vec<&str> = SKIP
            .iter()
            .filter(|s| !NAMES.iter().any(|(n, _)| n == *s))
            .copied()
            .collect();
        missing.sort_unstable();
        assert_eq!(
            missing,
            [
                "alarm",
                "fork",
                "kexec_file_load",
                "pause",
                "select",
                "vfork"
            ]
        );
        assert_eq!(SKIP.len() - missing.len(), 39);
        // swept = NAMES minus the 39 effective skips (riscv64 additionally
        // loses the never-listed renameat slot to the libc gap):
        assert_eq!(
            NAMES.iter().filter(|(n, _)| !SKIP.contains(n)).count(),
            if cfg!(target_arch = "aarch64") {
                239
            } else {
                238
            }
        );
    }

    #[test]
    fn swept_set_stays_inside_the_frozen_audit() {
        // STRUCTURAL GUARD, asm-generic flavor: the x86_64 hazard audit is
        // semantics-based (same name ⇒ same null-arg behavior on any arch),
        // so every swept name here must already sit in AUDITED_SWEPT — or
        // be explicitly reviewed below. A regenerated table that silently
        // sweeps a new name trips this test before it trips a production
        // host; the pinned swept counts (skip test above) make the subset
        // check an exact-equality guard for free.
        const ASM_GENERIC_REVIEWED: &[&str] = &[
            // io_pgetevents(292): same family as the audited io_getevents —
            // aio ctx id 0 cannot exist in-process (the sweep's own
            // io_setup(0, NULL) call on nr 0 fails EINVAL and allocates
            // nothing), and min_nr == 0 means the call can never wait.
            "io_pgetevents",
        ];
        for (n, _) in NAMES.iter().filter(|(n, _)| !SKIP.contains(n)) {
            assert!(
                AUDITED_SWEPT.contains(n) || ASM_GENERIC_REVIEWED.contains(n),
                "swept name {n} was never audited for null-arg safety"
            );
        }
    }

    #[test]
    fn real_sweep_is_deterministic_in_process() {
        // Same ReviewT18 seam contract as x86_64 (all six arg registers
        // zeroed): the same process must observe the identical sweep twice.
        let a = probe_blocked(&crate::sys::os::RealOs);
        let b = probe_blocked(&crate::sys::os::RealOs);
        assert_eq!(a, b, "sweep must be deterministic in-process");
    }
}

#[cfg(all(
    test,
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))
))]
mod tests {
    use super::*;

    /// Unknown arch: no number table is compiled in, the sweep returns
    /// empty, and `SyscallProbe::run` reports Degraded("unsupported arch")
    /// — degraded, never a panic (spec §5). This test cannot RUN on the
    /// supported dev hosts; the degraded run() path is compile-proven by
    /// `cargo check --target powerpc64-unknown-linux-gnu` (see README
    /// supported-arches).
    #[test]
    fn sweep_compiles_to_empty_on_unknown_arch() {
        assert!(probe_blocked(&crate::sys::os::RealOs).is_empty());
    }
}
