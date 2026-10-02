//! Raw `bpf(2)` plumbing shared by the opt-in eBPF probes.
//!
//! Deliberately NOT aya-obj's `Progs::load`: the pipeline is sync and
//! non-async, and every probe must degrade to a clean `ProbeOutcome`
//! without ever panicking. We hand-roll the two attr structs we need and
//! call `bpf(2)` via `libc::syscall`, which keeps the probe honest about
//! what the kernel itself says (errno + verifier log, nothing else).
//!
//! All entry points return `(Option<errno>, log)` instead of `Result`:
//! "the kernel refused" is DATA for a fingerprint tool, not an error.
//! A successful call closes the returned fd immediately — we never keep
//! programs or BTF objects loaded.

use std::ffi::CString;

use aya_obj::generated::bpf_cmd;
use serde_json::{Value, json};

/// Verifier log capacity per attempt (BPF_LOG_LEVEL1). The kernel writes a
/// NUL-terminated message; 4 KiB is more than enough and keeps the JSON
/// value bounded (we additionally cap what we store).
const LOG_CAP: usize = 4096;

/// `union bpf_attr` prefix for `BPF_PROG_LOAD`, mirroring the kernel's
/// `prog_load` member byte-for-byte (linux-6.8 `uapi/linux/bpf.h`
/// union bpf_attr: `func_info` needs no padding after `func_info_rec_size`
/// @76, so `attach_btf_id` is @108 and the attach union @112; the member
/// continues with the `core_relo*`/`fd_array` fields and ends padded to
/// `sizeof` 144). Getting any offset wrong here silently relocates
/// `attach_btf_id` — fentry loads then fail "must provide btf_id" while
/// every zero-fill field still looks fine.
#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,            // 0
    insn_cnt: u32,             // 4
    insns: u64,                // 8
    license: u64,              // 16
    log_level: u32,            // 24
    log_size: u32,             // 28
    log_buf: u64,              // 32
    kern_version: u32,         // 40
    prog_flags: u32,           // 44
    prog_name: [u8; 16],       // 48
    prog_ifindex: u32,         // 64
    expected_attach_type: u32, // 68
    prog_btf_fd: u32,          // 72
    func_info_rec_size: u32,   // 76
    func_info: u64,            // 80
    func_info_cnt: u32,        // 88
    line_info_rec_size: u32,   // 92
    line_info: u64,            // 96
    line_info_cnt: u32,        // 104
    attach_btf_id: u32,        // 108
    attach_prog_fd: u32,       // 112 (union with attach_btf_obj_fd)
    core_relo_cnt: u32,        // 116
    fd_array: u64,             // 120
    core_relos: u64,           // 128
    core_relo_rec_size: u32,   // 136
    _log_true_size_out: u32,   // 140 (kernel output; input stays 0)
} // 144 = sizeof the prog_load member

/// `union bpf_attr` prefix for `BPF_BTF_LOAD`.
#[repr(C)]
#[derive(Default)]
struct BtfLoadAttr {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
    // trailing kernel fields kept zeroed: btf_log_true_size, btf_flags,
    // btf_token_fd — the full 32-byte union member, all-zero past our fields.
    _pad: [u32; 3],
}

/// One eBPF instruction (`struct bpf_insn`).
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

/// `r0 = 0; exit` — the smallest program that passes the verifier.
static HELLO: [BpfInsn; 2] = [
    BpfInsn {
        code: 0xb7,
        regs: 0x00,
        off: 0,
        imm: 0,
    }, // mov r0, 0
    BpfInsn {
        code: 0x95,
        regs: 0x00,
        off: 0,
        imm: 0,
    }, // exit
];

/// Minimal valid BTF: header + PTR(id 1) -> INT(id 2) + the empty string
/// table. 45 bytes; the same shape aya uses for its own feature probing.
/// Used to test whether `BPF_BTF_LOAD` itself is permitted.
pub const MINIMAL_BTF: &[u8] = &[
    // header (24 B): magic 0xEB9F LE, version 1, flags 0, hdr_len 24,
    // type_off 0, type_len 28, str_off 28, str_len 1  →  53 B total
    0x9f, 0xeb, 0x01, 0x00, //
    24, 0, 0, 0, //
    0, 0, 0, 0, //
    28, 0, 0, 0, //
    28, 0, 0, 0, //
    1, 0, 0, 0, //
    // PTR, id 1 (12 B): name_off 0, info kind=PTR(2)<<24, type -> id 2
    0, 0, 0, 0, //
    0x00, 0x00, 0x00, 0x02, //
    2, 0, 0, 0, //
    // INT, id 2 (16 B): name_off 0, info kind=INT(1)<<24, size 4, int_data bits=32
    0, 0, 0, 0, //
    0x00, 0x00, 0x00, 0x01, //
    4, 0, 0, 0, //
    32, 0, 0, 0, //
    // strings (1 B): the mandatory leading NUL
    0,
];

fn errno() -> i32 {
    // SAFETY: thread-local errno location, always valid on Linux.
    unsafe { *libc::__errno_location() }
}

/// Extract the NUL-terminated verifier log the kernel wrote into `buf`.
fn take_log(buf: &[u8]) -> String {
    // SAFETY: the buffer is zero-initialised, so even if the kernel wrote
    // nothing there is a NUL to stop at within capacity.
    let c = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    String::from_utf8_lossy(c.to_bytes()).into_owned()
}

fn fill_name(slot: &mut [u8; 16], name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    slot[..n].copy_from_slice(&bytes[..n]);
    slot[n..].fill(0);
}

/// `bpf(BPF_PROG_LOAD)` a two-instruction program of `prog_type`.
/// `name` must stay in `[A-Za-z0-9_.]` — never a dash: Ubuntu's hardened
/// kernels reject dashes in `prog_name` with a pre-verifier EINVAL that
/// would masquerade as "type absent" in the sweep decode.
/// Returns `(None, "")` on success (the fd is closed immediately) or
/// `(Some(errno), verifier-log)`.
pub fn try_prog_load(
    prog_type: u32,
    expected_attach_type: u32,
    attach_btf_id: u32,
    name: &str,
) -> (Option<i32>, String) {
    let license = CString::new("GPL").expect("static GPL license");
    let mut log = vec![0u8; LOG_CAP];
    let mut attr = ProgLoadAttr {
        prog_type,
        insn_cnt: HELLO.len() as u32,
        insns: HELLO.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1, // BPF_LOG_LEVEL1
        log_size: LOG_CAP as u32,
        log_buf: log.as_mut_ptr() as u64,
        expected_attach_type,
        attach_btf_id,
        ..Default::default()
    };
    fill_name(&mut attr.prog_name, name);
    // SAFETY: attr/HELLO/license/log all outlive the syscall; the kernel
    // only reads the attr and the buffers it is told about.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_PROG_LOAD as u32,
            &attr as *const ProgLoadAttr,
            std::mem::size_of::<ProgLoadAttr>() as u32,
        )
    };
    if rc >= 0 {
        // SAFETY: rc is a fresh fd owned by us.
        unsafe { libc::close(rc as i32) };
        (None, String::new())
    } else {
        (Some(errno()), take_log(&log))
    }
}

/// `bpf(BPF_BTF_LOAD)` an in-memory BTF blob. Same contract as
/// [`try_prog_load`]: success closes the fd and yields `(None, "")`.
/// `log_level` selects the kernel's BTF log: 1 explains rejections of
/// small blobs; the vmlinux object must load with 0 — its verbose
/// success trace exceeds any sane buffer and the kernel fails the whole
/// load with ENOSPC when a requested log does not fit.
pub fn try_btf_load(blob: &[u8], log_level: u32) -> (Option<i32>, String) {
    let mut log = vec![0u8; LOG_CAP];
    let logging = log_level != 0;
    let attr = BtfLoadAttr {
        btf: blob.as_ptr() as u64,
        btf_size: blob.len() as u32,
        btf_log_level: log_level,
        btf_log_size: if logging { LOG_CAP as u32 } else { 0 },
        btf_log_buf: if logging { log.as_mut_ptr() as u64 } else { 0 },
        ..Default::default()
    };
    // SAFETY: as above; blob outlives the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_BTF_LOAD as u32,
            &attr as *const BtfLoadAttr,
            std::mem::size_of::<BtfLoadAttr>() as u32,
        )
    };
    if rc >= 0 {
        // SAFETY: rc is a fresh fd owned by us.
        unsafe { libc::close(rc as i32) };
        (None, String::new())
    } else {
        (Some(errno()), take_log(&log))
    }
}

// ---------------------------------------------------------------------------
// Prog-type sweep support
// ---------------------------------------------------------------------------

/// Every `BPF_PROG_TYPE_*` id with the `expected_attach_type` its load
/// requires, pinned to the generated uapi enums so an accidental
/// renumber is a compile error. Ids 1..=32 (kernel 6.1 set).
///
/// The kernel's load-time fixup only defaults `expected_attach_type`
/// for `cgroup-sock`/`sk-reuseport`; sock-addr, sockopt, sk-lookup and
/// netfilter reject a zero hint with a PRE-VERIFIER EINVAL (empty log)
/// that would otherwise be misread as "type absent" — so the sweep
/// passes a valid hook for each.
macro_rules! pt {
    ($v:ident) => {
        aya_obj::generated::bpf_prog_type::$v as u32
    };
}
macro_rules! at {
    ($v:ident) => {
        aya_obj::generated::bpf_attach_type::$v as u32
    };
}

pub const PROG_TYPES: &[(u32, &str, u32)] = &[
    (pt!(BPF_PROG_TYPE_SOCKET_FILTER), "socket-filter", 0),
    (pt!(BPF_PROG_TYPE_KPROBE), "kprobe", 0),
    (pt!(BPF_PROG_TYPE_SCHED_CLS), "sched-cls", 0),
    (pt!(BPF_PROG_TYPE_SCHED_ACT), "sched-act", 0),
    (pt!(BPF_PROG_TYPE_TRACEPOINT), "tracepoint", 0),
    (pt!(BPF_PROG_TYPE_XDP), "xdp", 0),
    (pt!(BPF_PROG_TYPE_PERF_EVENT), "perf-event", 0),
    (pt!(BPF_PROG_TYPE_CGROUP_SKB), "cgroup-skb", 0),
    (pt!(BPF_PROG_TYPE_CGROUP_SOCK), "cgroup-sock", 0),
    (pt!(BPF_PROG_TYPE_LWT_IN), "lwt-in", 0),
    (pt!(BPF_PROG_TYPE_LWT_OUT), "lwt-out", 0),
    (pt!(BPF_PROG_TYPE_LWT_XMIT), "lwt-xmit", 0),
    (pt!(BPF_PROG_TYPE_SOCK_OPS), "sock-ops", 0),
    (pt!(BPF_PROG_TYPE_SK_SKB), "sk-skb", 0),
    (pt!(BPF_PROG_TYPE_CGROUP_DEVICE), "cgroup-device", 0),
    (pt!(BPF_PROG_TYPE_SK_MSG), "sk-msg", 0),
    (pt!(BPF_PROG_TYPE_RAW_TRACEPOINT), "raw-tracepoint", 0),
    (
        pt!(BPF_PROG_TYPE_CGROUP_SOCK_ADDR),
        "cgroup-sock-addr",
        at!(BPF_CGROUP_INET4_CONNECT),
    ),
    (pt!(BPF_PROG_TYPE_LWT_SEG6LOCAL), "lwt-seg6local", 0),
    (pt!(BPF_PROG_TYPE_LIRC_MODE2), "lirc-mode2", 0),
    (pt!(BPF_PROG_TYPE_SK_REUSEPORT), "sk-reuseport", 0),
    (pt!(BPF_PROG_TYPE_FLOW_DISSECTOR), "flow-dissector", 0),
    (pt!(BPF_PROG_TYPE_CGROUP_SYSCTL), "cgroup-sysctl", 0),
    (
        pt!(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE),
        "raw-tracepoint-writable",
        0,
    ),
    (
        pt!(BPF_PROG_TYPE_CGROUP_SOCKOPT),
        "cgroup-sockopt",
        at!(BPF_CGROUP_SETSOCKOPT),
    ),
    (pt!(BPF_PROG_TYPE_TRACING), "tracing", 0),
    (pt!(BPF_PROG_TYPE_STRUCT_OPS), "struct-ops", 0),
    (pt!(BPF_PROG_TYPE_EXT), "ext", 0),
    (pt!(BPF_PROG_TYPE_LSM), "lsm", 0),
    (
        pt!(BPF_PROG_TYPE_SK_LOOKUP),
        "sk-lookup",
        at!(BPF_SK_LOOKUP),
    ),
    (pt!(BPF_PROG_TYPE_SYSCALL), "syscall", 0),
    (
        pt!(BPF_PROG_TYPE_NETFILTER),
        "netfilter",
        at!(BPF_NETFILTER),
    ),
];

/// What one prog-type load attempt says about the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeVerdict {
    /// Load succeeded (fd closed immediately).
    Loadable,
    /// `EINVAL` with an empty verifier log: the type does not exist in
    /// this kernel.
    Absent,
    /// The type may exist; the kernel refused the attempt on privilege
    /// or policy grounds (`EPERM`/`EACCES`/`EOPNOTSUPP`/other).
    Denied(String),
    /// `EINVAL` WITH a verifier log: the type exists, our trivial program
    /// failed its attach contract. Existence proven, loadability not.
    Rejected,
}

/// Pure verdict classifier for one sweep attempt. `errno` is `None` for a
/// successful load; `log` is the raw verifier log ("" when the kernel
/// wrote nothing).
pub fn type_verdict(errno: Option<i32>, log: &str, knob: Option<u8>) -> TypeVerdict {
    use TypeVerdict::*;
    let Some(e) = errno else { return Loadable };
    match e {
        libc::EPERM | libc::EACCES | libc::EOPNOTSUPP => Denied(super::ebpf_load::classify(
            e,
            (!log.is_empty()).then_some(log),
            knob,
        )),
        libc::EINVAL => {
            if log.is_empty() {
                Absent
            } else {
                Rejected
            }
        }
        other => Denied(super::ebpf_load::classify(
            other,
            (!log.is_empty()).then_some(log),
            knob,
        )),
    }
}

/// Aggregate sweep rows into the `ebpf.types` fact value. `rows` is
/// `(slug, verdict)` in table order.
pub fn types_value(rows: &[(&str, TypeVerdict)]) -> Value {
    use TypeVerdict::*;
    let mut loadable = Vec::new();
    let mut absent = Vec::new();
    let mut denied = serde_json::Map::new();
    let mut rejected = serde_json::Map::new();
    for (slug, v) in rows {
        match v {
            Loadable => loadable.push(json!(slug)),
            Absent => absent.push(json!(slug)),
            Denied(status) => {
                denied.insert((*slug).to_owned(), json!(status));
            }
            Rejected => {
                rejected.insert((*slug).to_owned(), json!("rejected"));
            }
        }
    }
    json!({
        "summary": format!(
            "loadable={} absent={} denied={} rejected={}",
            loadable.len(),
            absent.len(),
            denied.len(),
            rejected.len()
        ),
        "attempted": rows.len(),
        "loadable": loadable,
        "absent": absent,
        "denied": denied,
        "rejected": rejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_structs_match_uapi_layout() {
        // Offsets are the linux-6.8 uapi values; a drift silently moves
        // attach_btf_id and the kernel then refuses fentry loads with
        // "must provide btf_id" while zero-filled fields look fine.
        assert_eq!(std::mem::size_of::<ProgLoadAttr>(), 144);
        assert_eq!(std::mem::size_of::<BtfLoadAttr>(), 40);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, prog_type), 0);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, prog_name), 48);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, expected_attach_type), 68);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, func_info), 80);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, line_info), 96);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, attach_btf_id), 108);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, attach_prog_fd), 112);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, fd_array), 120);
        let attr = ProgLoadAttr::default();
        let raw: &[u8] = unsafe { std::slice::from_raw_parts(&attr as *const _ as *const u8, 144) };
        assert!(raw.iter().all(|&b| b == 0));
    }

    #[test]
    fn prog_types_are_unique_and_dense() {
        let ids: Vec<u32> = PROG_TYPES.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(ids.len(), 32);
        for (want, got) in (1u32..=32).zip(&ids) {
            assert_eq!(
                *got,
                want,
                "slug {}",
                PROG_TYPES[ids.iter().position(|i| i == got).unwrap()].1
            );
        }
        let mut slugs: Vec<&str> = PROG_TYPES.iter().map(|(_, s, _)| *s).collect();
        slugs.sort_unstable();
        let n = slugs.len();
        slugs.dedup();
        assert_eq!(slugs.len(), n);
    }

    #[test]
    fn minimal_btf_parses_offline() {
        // Offline proof the blob is structurally valid BTF: aya's own
        // parser must accept it (no kernel needed).
        assert_eq!(MINIMAL_BTF.len(), 53);
        let btf = aya_obj::btf::Btf::parse(MINIMAL_BTF, object::Endianness::Little)
            .expect("minimal BTF must parse");
        // 2 types parsed: PTR id 1 -> INT id 2, both name_off 0 ("");
        // a kind we never declared must miss.
        use aya_obj::btf::BtfKind;
        assert_eq!(btf.id_by_type_name_kind("", BtfKind::Ptr).unwrap(), 1);
        assert_eq!(btf.id_by_type_name_kind("", BtfKind::Int).unwrap(), 2);
        assert!(btf.id_by_type_name_kind("", BtfKind::Enum).is_err());
    }

    #[test]
    fn fill_name_bounds_and_nuls() {
        let mut slot = [0xffu8; 16];
        fill_name(&mut slot, "amir_types");
        assert_eq!(&slot[..10], b"amir_types");
        assert!(slot[10..].iter().all(|&b| b == 0));
        fill_name(&mut slot, "this-name-is-definitely-way-too-long");
        assert_eq!(&slot[..15], b"this-name-is-de");
        assert_eq!(slot[15], 0);
    }

    #[test]
    fn type_verdict_bands() {
        assert_eq!(type_verdict(None, "", None), TypeVerdict::Loadable);
        assert_eq!(
            type_verdict(Some(libc::EINVAL), "", Some(1)),
            TypeVerdict::Absent
        );
        assert_eq!(
            type_verdict(Some(libc::EINVAL), "R2 !read_ptr", None),
            TypeVerdict::Rejected
        );
        // eperm reuses the load-probe classifier (knob-aware)
        assert_eq!(
            type_verdict(Some(libc::EPERM), "", Some(1)),
            TypeVerdict::Denied("eperm-unpriv-disabled".into())
        );
        assert_eq!(
            type_verdict(Some(libc::EACCES), "", None),
            TypeVerdict::Denied("eacces-lsm".into())
        );
        assert_eq!(
            type_verdict(Some(libc::EOPNOTSUPP), "no jit", None),
            TypeVerdict::Denied("eopnotsupp".into())
        );
        // other errnos: no message -> errno-<N>
        assert_eq!(
            type_verdict(Some(libc::ENOMEM), "", None),
            TypeVerdict::Denied("enomem".into())
        );
    }

    #[test]
    fn types_value_shape() {
        let rows = vec![
            ("socket-filter", TypeVerdict::Loadable),
            ("lirc-mode2", TypeVerdict::Absent),
            ("lsm", TypeVerdict::Denied("eperm-unpriv-disabled".into())),
            ("tracing", TypeVerdict::Rejected),
        ];
        let v = types_value(&rows);
        assert_eq!(v["summary"], "loadable=1 absent=1 denied=1 rejected=1");
        assert_eq!(v["attempted"], 4);
        assert_eq!(v["loadable"][0], "socket-filter");
        assert_eq!(v["absent"][0], "lirc-mode2");
        assert_eq!(v["denied"]["lsm"], "eperm-unpriv-disabled");
        assert_eq!(v["rejected"]["tracing"], "rejected");
    }
}
