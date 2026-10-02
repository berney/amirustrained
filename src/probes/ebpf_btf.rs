//! `--probe-ebpf btf` — does the kernel accept BTF objects, and can BTF
//! take a program all the way to a real fentry attach-id load?
//!
//! Three layers, each answering an independent question (layer N+1 is only
//! attempted when layer N succeeded — a failure there is data, not a skip):
//!
//! 1. `btfSyscall` — `bpf(BPF_BTF_LOAD)` a 53-byte minimal BTF object.
//!    Answers: is the BTF facility itself permitted to this context?
//! 2. `vmlinuxBtf` — read `/sys/kernel/btf/vmlinux` and load it verbatim.
//!    Answers: is CONFIG_DEBUG_INFO_BTF built in, is the file readable, and
//!    does the real kernel BTF pass validation (a different, heavier
//!    question than 1: size + `bpf_btf_allow_load_load` policy).
//! 3. `fentry` — parse the vmlinux BTF (aya-obj, offline), resolve
//!    `vfs_read` (fallback `vfs_write`) to its func id, then
//!    `BPF_PROG_LOAD` a `BPF_PROG_TYPE_TRACING` program with
//!    `attach_btf_id = <id>`. Answers: the full fentry-availability chain
//!    — BTF + BTF-based attach + `perf_event`-class privileges — without
//!    ever attaching or executing anything (fd closed immediately).
//!
//! Every layer degrades to a status string; the probe never fails the run.
//! Status vocabulary per layer:
//!
//! - `btfSyscall`: `ok` | classify(errno × knob) | `reject`
//! - `vmlinuxBtf`: `ok` | classify(…) | `absent` | `read-denied`
//! - `fentry`: `ok` | `skipped` | `parse-failed` | `target-not-found` |
//!   `type-absent` | classify(…) | `rejected`

use std::io::ErrorKind;

use aya_obj::btf::{Btf, BtfKind};
use aya_obj::generated::{bpf_attach_type, bpf_prog_type};
use object::Endianness;
use serde_json::{Value, json};

use crate::model::{Fact, ProbeOutcome};
use crate::pipeline::Ctx;
use crate::probes::{Probe, ebpf_raw};

pub struct EbpfBtf;

const PROBE: &str = "ebpf-btf";
const FACT_PROBE: &str = "ebpf";
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
/// fentry targets: both are core VFS functions present in essentially every
/// kernel's vmlinux BTF; vfs_write covers the (vanishingly rare) case of a
/// kernel that stripped vfs_read.
const FENTRY_TARGETS: [&str; 2] = ["vfs_read", "vfs_write"];

/// A completed syscall attempt: `(errno, verifier log)` — `None` errno
/// means success.
pub type Attempt = (Option<i32>, String);

/// Outcome of reading the vmlinux BTF file, reduced to what matters.
#[derive(Debug)]
pub enum ReadOutcome {
    Ok(Vec<u8>),
    /// ENOENT: no BTF baked into the kernel.
    Missing,
    /// Exists but unreadable in this context (EACCES/EPERM/EISDIR/…).
    Unreadable(i32),
}

/// What the fentry layer got from the parsed vmlinux BTF.
#[derive(Debug)]
pub enum FentryAttempt {
    ParseFailed(String),
    TargetNotFound,
    Load {
        target: &'static str,
        attempt: Attempt,
    },
}

/// Cap a kernel/verifier message so one fact stays report-sized.
fn clip(s: &str) -> String {
    const MAX: usize = 220;
    let t = s.trim();
    if t.chars().count() <= MAX {
        return t.to_string();
    }
    let cut: String = t.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// Step shape shared by all three layers.
fn step(status: &str, errno: Option<i32>, message: Option<String>) -> Value {
    json!({ "status": status, "errno": errno, "message": message })
}

/// Status for a failed attempt, decoded exactly like the Task 29 load probe
/// (errno fused with the `unprivileged_bpf_disabled` knob posture).
fn denial_status(attempt: &Attempt, knob: Option<u8>) -> (String, Option<i32>, Option<String>) {
    let (errno, log) = attempt;
    let status = super::ebpf_load::classify(
        errno.unwrap_or(0),
        (!log.is_empty()).then_some(log.as_str()),
        knob,
    );
    (status, *errno, (!log.is_empty()).then(|| clip(log)))
}

/// Pure assembly of the `ebpf.btf` fact value. All kernel contact happens
/// in [`gather`]; this is the tested contract.
pub fn btf_value(
    sys: &Attempt,
    read: &ReadOutcome,
    load: Option<&Attempt>,
    fentry: Option<&FentryAttempt>,
    knob: Option<u8>,
) -> Value {
    // Layer 1
    let sys_step = match sys.0 {
        None => step("ok", None, None),
        Some(_) => {
            let (s, e, m) = denial_status(sys, knob);
            step(&s, e, m)
        }
    };
    // Layer 2
    let (vmlinux_step, layer2_ok) = match read {
        ReadOutcome::Missing => (step("absent", None, None), false),
        ReadOutcome::Unreadable(e) => (step("read-denied", Some(*e), None), false),
        ReadOutcome::Ok(_) => match load {
            None => (step("read-present-load-skipped", None, None), false),
            Some(a) => match a.0 {
                None => (step("ok", None, None), true),
                Some(_) => {
                    let (s, e, m) = denial_status(a, knob);
                    (step(&s, e, m), false)
                }
            },
        },
    };
    // Layer 3
    let fentry_step = match fentry {
        None => step("skipped", None, None),
        Some(FentryAttempt::ParseFailed(msg)) => step("parse-failed", None, Some(clip(msg))),
        Some(FentryAttempt::TargetNotFound) => step("target-not-found", None, None),
        Some(FentryAttempt::Load { target, attempt }) => {
            let verdict = ebpf_raw::type_verdict(attempt.0, &attempt.1, knob);
            let (status, errno, msg) = match verdict {
                ebpf_raw::TypeVerdict::Loadable => ("ok".to_string(), None, None),
                ebpf_raw::TypeVerdict::Absent => ("type-absent".to_string(), None, None),
                ebpf_raw::TypeVerdict::Rejected => (
                    "rejected".to_string(),
                    attempt.0,
                    (!attempt.1.is_empty()).then(|| clip(&attempt.1)),
                ),
                ebpf_raw::TypeVerdict::Denied(s) => (
                    s,
                    attempt.0,
                    (!attempt.1.is_empty()).then(|| clip(&attempt.1)),
                ),
            };
            let mut v = step(&status, errno, msg);
            v["target"] = json!(target);
            v
        }
    };
    let mut summary = format!(
        "btfSyscall={} vmlinuxBtf={} fentry={}",
        sys_step["status"].as_str().unwrap_or("?"),
        vmlinux_step["status"].as_str().unwrap_or("?"),
        fentry_step["status"].as_str().unwrap_or("?")
    );
    if !layer2_ok {
        summary.push_str(" (fentry needs loadable vmlinux BTF)");
    }
    json!({
        "summary": summary,
        "btfSyscall": sys_step,
        "vmlinuxBtf": vmlinux_step,
        "fentry": fentry_step,
    })
}

/// The only kernel-touching part: three syscalls + one file read + one
/// offline parse, every fd closed by [`ebpf_raw`].
fn gather(knob: Option<u8>) -> Value {
    let sys = ebpf_raw::try_btf_load(ebpf_raw::MINIMAL_BTF, 1);
    let read = match std::fs::read(VMLINUX_BTF) {
        Ok(bytes) => ReadOutcome::Ok(bytes),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound) => ReadOutcome::Missing,
        Err(e) => ReadOutcome::Unreadable(e.raw_os_error().unwrap_or(0)),
    };
    let mut load = None;
    let mut fentry = None;
    if let ReadOutcome::Ok(bytes) = &read {
        let a = ebpf_raw::try_btf_load(bytes, 0);
        let ok = a.0.is_none();
        load = Some(a);
        if ok {
            fentry = Some(match Btf::parse(bytes, Endianness::default()) {
                Err(e) => FentryAttempt::ParseFailed(e.to_string()),
                Ok(btf) => {
                    match FENTRY_TARGETS.iter().find_map(|t| {
                        btf.id_by_type_name_kind(t, BtfKind::Func)
                            .ok()
                            .map(|id| (*t, id))
                    }) {
                        None => FentryAttempt::TargetNotFound,
                        Some((target, id)) => FentryAttempt::Load {
                            target,
                            attempt: ebpf_raw::try_prog_load(
                                bpf_prog_type::BPF_PROG_TYPE_TRACING as u32,
                                bpf_attach_type::BPF_TRACE_FENTRY as u32,
                                id,
                                "amir_fentry",
                            ),
                        },
                    }
                }
            });
        }
    }
    btf_value(&sys, &read, load.as_ref(), fentry.as_ref(), knob)
}

impl Probe for EbpfBtf {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let knob = super::ebpf_load::knob_from_prior(&cx.prior);
        ProbeOutcome::empty(PROBE).with_fact(Fact::ok(
            FACT_PROBE,
            "btf",
            gather(knob),
            "raw bpf(BPF_BTF_LOAD) of minimal blob + /sys/kernel/btf/vmlinux; fentry load via BPF_PROG_TYPE_TRACING attach_btf_id, fds closed immediately".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> Attempt {
        (None, String::new())
    }
    fn err(e: i32, log: &str) -> Attempt {
        (Some(e), log.to_string())
    }

    #[test]
    fn probe_name_is_stable() {
        assert_eq!(EbpfBtf.name(), "ebpf-btf");
    }

    #[test]
    fn all_three_layers_ok() {
        let read = ReadOutcome::Ok(vec![1, 2, 3]);
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&FentryAttempt::Load {
                target: "vfs_read",
                attempt: ok(),
            }),
            Some(1),
        );
        assert_eq!(v["btfSyscall"]["status"], "ok");
        assert_eq!(v["vmlinuxBtf"]["status"], "ok");
        assert_eq!(v["fentry"]["status"], "ok");
        assert_eq!(v["fentry"]["target"], "vfs_read");
        assert_eq!(v["summary"], "btfSyscall=ok vmlinuxBtf=ok fentry=ok");
    }

    #[test]
    fn btf_syscall_denied_layers_down() {
        let v = btf_value(
            &err(libc::EPERM, ""),
            &ReadOutcome::Missing,
            None,
            None,
            Some(2),
        );
        assert_eq!(v["btfSyscall"]["status"], "eperm-unpriv-disabled");
        assert_eq!(v["btfSyscall"]["errno"], 1);
        assert_eq!(v["vmlinuxBtf"]["status"], "absent");
        assert_eq!(v["fentry"]["status"], "skipped");
        assert!(
            v["summary"]
                .as_str()
                .unwrap()
                .contains("fentry needs loadable vmlinux BTF")
        );
    }

    #[test]
    fn vmlinux_readable_but_load_denied_is_layer3_skipped() {
        let read = ReadOutcome::Ok(vec![0]);
        let v = btf_value(&ok(), &read, Some(&err(libc::EACCES, "")), None, None);
        assert_eq!(v["vmlinuxBtf"]["status"], "eacces-lsm");
        assert_eq!(v["fentry"]["status"], "skipped");
    }

    #[test]
    fn unreadable_vmlinux_is_not_absent() {
        let v = btf_value(&ok(), &ReadOutcome::Unreadable(13), None, None, None);
        assert_eq!(v["vmlinuxBtf"]["status"], "read-denied");
        assert_eq!(v["vmlinuxBtf"]["errno"], 13);
    }

    #[test]
    fn fentry_verdict_bands() {
        let read = ReadOutcome::Ok(vec![0]);
        let mk = |a: Attempt| FentryAttempt::Load {
            target: "vfs_write",
            attempt: a,
        };
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&mk(err(libc::EINVAL, ""))),
            None,
        );
        assert_eq!(v["fentry"]["status"], "type-absent");
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&mk(err(libc::EPERM, ""))),
            Some(0),
        );
        assert_eq!(v["fentry"]["status"], "eperm-no-caps");
        // verifier log present ⇒ type exists, program rejected
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&mk(err(libc::EINVAL, "tracing progs require..."))),
            None,
        );
        assert_eq!(v["fentry"]["status"], "rejected");
        // the verifier's own words must survive into the report
        assert_eq!(v["fentry"]["message"], "tracing progs require...");
        assert_eq!(v["fentry"]["errno"], libc::EINVAL);
    }

    #[test]
    fn parse_and_target_statuses() {
        let read = ReadOutcome::Ok(vec![0]);
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&FentryAttempt::ParseFailed("bad magic".into())),
            None,
        );
        assert_eq!(v["fentry"]["status"], "parse-failed");
        assert_eq!(v["fentry"]["message"], "bad magic");
        let v = btf_value(
            &ok(),
            &read,
            Some(&ok()),
            Some(&FentryAttempt::TargetNotFound),
            None,
        );
        assert_eq!(v["fentry"]["status"], "target-not-found");
    }

    #[test]
    fn messages_are_clipped() {
        let long = "x".repeat(500);
        let c = clip(&long);
        assert_eq!(c.chars().count(), 220);
        assert!(c.ends_with('…'));
        assert_eq!(clip("  short  "), "short");
    }
}
