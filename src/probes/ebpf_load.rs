//! `--probe-ebpf` — the REAL eBPF program load probe (Task 29). The always-on
//! `ebpf` knobs probe (Task 28) only senses posture; this one calls
//! `bpf(BPF_PROG_LOAD)` for real through aya, with the object embedded in the
//! binary, so one static ELF carries everything.
//!
//! WHAT IT RUNS: `bpf/prebuilt/hello.bpf.o` — a tracepoint program that
//! returns 0. Zero maps, zero helpers, never attached, so it never executes.
//! The verdict rests on one `bpf(BPF_PROG_LOAD)`; aya additionally runs a
//! lazy, once-per-process kernel feature detection on the first load — up to
//! nine BTF loads, five trivial probe prog-loads, three map creates and one
//! link-create attempt (plus an RLIMIT_MEMLOCK raise/retry dance on pre-5.11
//! kernels) — every fd it opens closes inside the call, so nothing outlives
//! the probe. Rebuild provenance: `bpf/build.sh` (nightly + bpf-linker);
//! committing the object keeps the default stable/musl build free of the BPF
//! toolchain.
//!
//! CLEANUP / CRASH-SAFETY (why there is no `--unload-orphans`): the probe
//! NEVER pins anything — no path under /sys/fs/bpf is ever created. Aya's
//! `Drop` for the typed program closes the prog fd (and an explicit `unload`
//! runs first on the happy path), and the kernel frees a program as soon as
//! its last fd drops. A crash or kill between load and drop is handled by the
//! kernel itself: process exit closes every fd, so a leftover program is
//! structurally impossible. Nothing to sweep, hence no unload CLI.
//!
//! OUTCOMES (`ebpf.load` fact, `status` codes): success is `ok`; denials are
//! decoded from the kernel errno fused with the Task 28 knob posture — see
//! [`classify`] for the exact table. A missing-capability denial is a fully
//! decoded answer (`availability: ok`), NOT a degraded one: the probe asked
//! the kernel the question and the kernel answered. Only a never-asked
//! question degrades (empty embedded artifact, or an object aya cannot parse
//! before the syscall).

use serde_json::{Value, json};

use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::{Ctx, Prior};
use crate::probes::Probe;

const PROBE: &str = "ebpf-load";
/// The fact namespace stays `ebpf` (spec fact key `ebpf.load`), shared with
/// the always-on knobs probe; the event name above distinguishes the stream
/// entry itself.
const FACT_PROBE: &str = "ebpf";
const PROGRAM_NAME: &str = "hello";

/// Result of one load attempt, reduced to what the report needs. Built by
/// [`attempt_load`] in production and by fixtures in tests — the probe
/// contract below is pure over this enum.
#[derive(Debug, Clone, PartialEq)]
pub enum LoadOutcome {
    /// `BPF_PROG_LOAD` succeeded — the program existed in the kernel until
    /// this fn returned (fd dropped immediately).
    Loaded,
    /// The syscall ran and the kernel refused: raw errno plus the verifier
    /// log body when the kernel produced one.
    Denied { errno: i32, message: Option<String> },
    /// aya failed before `BPF_PROG_LOAD` (object parse / relocation / missing
    /// program symbol): the question was never asked ⇒ degraded.
    ParseFailed(String),
    /// The embedded artifact slot is empty (a tree built with `prebuilt/`
    /// truncated to a placeholder): never exec anything, never panic.
    ArtifactMissing,
}

/// Decodes a denial into a stable status code. Table (spec §6 AMR-021 row +
/// Task 29 plan):
/// - `EPERM` + knob 1/2 — the unprivileged-bpf-disabled knob itself refused
///   the call ⇒ `eperm-unpriv-disabled`.
/// - `EPERM` otherwise (knob 0, or knob absent and the load is unprivileged
///   legacy) ⇒ `eperm-no-caps`: the caller lacks CAP_BPF/CAP_SYS_ADMIN.
/// - `EACCES` ⇒ `eacces-lsm` (LSM/SELinux denial; seccomp would have sent
///   EPERM/SIGSYS instead).
/// - `EOPNOTSUPP` ⇒ `eopnotsupp` (kernel/runtime cannot do it: lockdown
///   variants, disabled BPF JIT-less support corners, prog type unsupported).
/// - any other errno while the kernel wrote a verifier log ⇒ the verifier
///   itself rejected the program ⇒ `verifier-reject`.
/// - remaining errnos ⇒ `errno-<name>` so unknown refusals stay decodeable.
pub fn classify(errno: i32, message: Option<&str>, knob: Option<u8>) -> String {
    match errno {
        libc::EPERM => match knob {
            Some(1) | Some(2) => "eperm-unpriv-disabled".into(),
            _ => "eperm-no-caps".into(),
        },
        libc::EACCES => "eacces-lsm".into(),
        libc::EOPNOTSUPP => "eopnotsupp".into(),
        other => match errno_name(other) {
            Some(name) => {
                // The verifier ran (and wrote a log) exactly when the syscall
                // got past the capability/LSM gates: a log body with e.g.
                // EINVAL/E2BIG is the verifier's own rejection.
                if message.is_some_and(|m| !m.trim().is_empty()) {
                    "verifier-reject".into()
                } else {
                    name.into()
                }
            }
            None => format!("errno-{other}"),
        },
    }
}

/// Stable lowercase errno label; `None` for numbers worth printing raw.
fn errno_name(errno: i32) -> Option<&'static str> {
    Some(match errno {
        libc::EPERM => "eperm",
        libc::ENOENT => "enoent",
        libc::EACCES => "eacces",
        libc::EFAULT => "efault",
        libc::EINVAL => "einval",
        libc::EBADF => "ebadf",
        libc::ENOMEM => "enomem",
        libc::E2BIG => "e2big",
        libc::EBUSY => "ebusy",
        libc::EOVERFLOW => "eoverflow",
        libc::EOPNOTSUPP => "eopnotsupp",
        _ => return None,
    })
}

/// Caps the kernel-side verifier log that lands in the report; the leading
/// lines carry the rejection reason. Truncation is char-boundary safe.
fn cap_message(message: &str) -> Option<String> {
    const MAX: usize = 2048;
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().count() <= MAX {
        Some(trimmed.to_string())
    } else {
        let mut s: String = trimmed.chars().take(MAX).collect();
        s.push('…');
        Some(s)
    }
}

/// The `ebpf.load` fact value for one outcome + knob posture (knob = Task 28
/// `ebpf.knobs.unprivilegedBpfDisabled`, `None` when absent/unknown).
pub fn load_status_value(outcome: &LoadOutcome, knob: Option<u8>) -> Value {
    match outcome {
        LoadOutcome::Loaded => json!({"status": "ok", "errno": null, "message": null}),
        LoadOutcome::Denied { errno, message } => json!({
            "status": classify(*errno, message.as_deref(), knob),
            "errno": errno,
            "message": cap_message(message.as_deref().unwrap_or("")),
        }),
        LoadOutcome::ParseFailed(_) => {
            json!({"status": "parse-failed", "errno": null, "message": null})
        }
        LoadOutcome::ArtifactMissing => {
            json!({"status": "artifact-missing", "errno": null, "message": null})
        }
    }
}

/// Pure outcome builder: LoadOutcome (+ knob posture) → the whole
/// ProbeOutcome. Availability is `ok` for success AND for every decoded
/// denial; `degraded` only when the kernel was never asked (pre-syscall
/// failures), so a rule can never key on an unverified load.
pub fn build_outcome(outcome: &LoadOutcome, knob: Option<u8>) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(PROBE);
    let value = load_status_value(outcome, knob);
    match outcome {
        LoadOutcome::ArtifactMissing => {
            o.availability = Availability::Degraded("embedded eBPF object absent".into());
            o.with_fact(Fact::degraded(FACT_PROBE, "load", value, source_note()))
        }
        LoadOutcome::ParseFailed(detail) => {
            o.availability = Availability::Degraded(format!(
                "embedded eBPF object not loadable by aya: {detail}"
            ));
            o.with_fact(Fact::degraded(FACT_PROBE, "load", value, source_note()))
        }
        LoadOutcome::Loaded | LoadOutcome::Denied { .. } => {
            o.with_fact(Fact::ok(FACT_PROBE, "load", value, source_note()))
        }
    }
}

fn source_note() -> String {
    format!("bpf(BPF_PROG_LOAD) via aya, embedded object bpf/prebuilt/hello.bpf.o ({PROGRAM_NAME})")
}

/// Knob posture for the classification, from the Task 28 `ebpf.knobs` fact
/// (`null`/absent ⇒ `None`, i.e. decode without knob context).
pub fn knob_from_prior(prior: &Prior) -> Option<u8> {
    prior
        .facts
        .get("ebpf.knobs")
        .and_then(|k| k.get("unprivilegedBpfDisabled"))
        .and_then(Value::as_u64)
        .map(|v| v as u8)
}

/// The one place that talks to the kernel. Loads the embedded object with aya
/// (`Ebpf::load` parses + relocates, `TracePoint::load` is the single
/// `BPF_PROG_LOAD`), then drops everything: the explicit `unload` plus the
/// `Ebpf` drop close every fd, and a crash between the two is covered by
/// process exit (see module docs — nothing is pinned, ever).
pub fn attempt_load(object: &[u8]) -> LoadOutcome {
    if object.is_empty() {
        return LoadOutcome::ArtifactMissing;
    }
    let mut ebpf = match aya::Ebpf::load(object) {
        Ok(e) => e,
        Err(e) => return pre_syscall_failure(e),
    };
    let loaded = match ebpf.program_mut(PROGRAM_NAME) {
        Some(aya::programs::Program::TracePoint(prog)) => match prog.load() {
            Ok(()) => Ok(()),
            // The kernel answered the question; keep errno + verifier log.
            Err(aya::programs::ProgramError::LoadError {
                io_error,
                verifier_log,
            }) => {
                let log = verifier_log.to_string();
                Err((io_error.raw_os_error().unwrap_or(0), Some(log)))
            }
            Err(other) => return pre_syscall_failure(other),
        },
        // Object parsed but has no `hello` tracepoint — a broken artifact.
        Some(_) => {
            return LoadOutcome::ParseFailed(format!(
                "program `{PROGRAM_NAME}` is not a tracepoint"
            ));
        }
        None => return LoadOutcome::ParseFailed(format!("program `{PROGRAM_NAME}` absent")),
    };
    // Drop the whole Ebpf here (typed-program Drop unloads first): the verdict
    // was captured above; the kernel state lives no longer than this call.
    drop(ebpf);
    match loaded {
        Ok(()) => LoadOutcome::Loaded,
        Err((errno, log)) => LoadOutcome::Denied {
            errno,
            message: log,
        },
    }
}

/// Any failure before (or unrelated to) the load syscall: honest `ParseFailed`
/// with aya's message — never a panic, never an exec.
fn pre_syscall_failure(e: impl std::fmt::Display) -> LoadOutcome {
    LoadOutcome::ParseFailed(e.to_string())
}

pub struct EbpfLoad;

impl Probe for EbpfLoad {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, _cx: &Ctx) -> ProbeOutcome {
        // Aligned per the aya ELF requirement; embedded at compile time so
        // deployment stays ONE static binary.
        let object: &[u8] = aya::include_bytes_aligned!("../../bpf/prebuilt/hello.bpf.o");
        let knob = knob_from_prior(&_cx.prior);
        build_outcome(&attempt_load(object), knob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prior_with_knob(knob: Value) -> Prior {
        Prior {
            signals: vec![],
            facts: [(
                "ebpf.knobs".to_string(),
                json!({"unprivilegedBpfDisabled": knob, "lockdown": null}),
            )]
            .into_iter()
            .collect(),
        }
    }

    // ── decode table (plan Step 1 RED): errno × knob ⇒ status ──

    #[test]
    fn eperm_decodes_by_knob_posture() {
        assert_eq!(classify(libc::EPERM, None, Some(0)), "eperm-no-caps");
        assert_eq!(
            classify(libc::EPERM, None, Some(1)),
            "eperm-unpriv-disabled"
        );
        assert_eq!(
            classify(libc::EPERM, None, Some(2)),
            "eperm-unpriv-disabled"
        );
        // Knob absent/unparseable leaves no attribution to the knob: caps.
        assert_eq!(classify(libc::EPERM, None, None), "eperm-no-caps");
    }

    #[test]
    fn eacces_and_eopnotsupp_are_distinct_denials() {
        assert_eq!(classify(libc::EACCES, None, Some(2)), "eacces-lsm");
        assert_eq!(classify(libc::EOPNOTSUPP, None, Some(0)), "eopnotsupp");
        // EOPNOTSUPP is NOT folded into the LSM class despite the plan's
        // "lockdown" shorthand note; it is its own kernel answer.
        assert_ne!(
            classify(libc::EOPNOTSUPP, None, Some(2)),
            classify(libc::EACCES, None, Some(2))
        );
    }

    #[test]
    fn verifier_reject_needs_a_kernel_side_log() {
        let log = "0: (b4) r0 = 0\nR1 !read_ok";
        assert_eq!(
            classify(libc::EINVAL, Some(log), Some(0)),
            "verifier-reject"
        );
        assert_eq!(classify(libc::E2BIG, Some(log), None), "verifier-reject");
        // Blank log is no log: plain errno decode.
        assert_eq!(classify(libc::EINVAL, Some("   "), None), "einval");
        assert_eq!(classify(libc::EFAULT, None, None), "efault");
        // Capability/knob denials outrank the log heuristic: the kernel may
        // still hand back a (mostly empty) log buffer with EPERM.
        assert_eq!(
            classify(libc::EPERM, Some(log), Some(2)),
            "eperm-unpriv-disabled"
        );
    }

    #[test]
    fn unknown_errnos_stay_decodeable() {
        assert_eq!(classify(12345, None, None), "errno-12345");
        assert_eq!(classify(libc::ENOMEM, None, Some(1)), "enomem");
    }

    // ── fact/availability contract ──

    #[test]
    fn success_is_ok_and_carries_no_errno_or_message() {
        let o = build_outcome(&LoadOutcome::Loaded, Some(2));
        assert_eq!(o.availability, Availability::Ok);
        assert_eq!(
            o.facts[0].value,
            json!({"status": "ok", "errno": null, "message": null})
        );
        assert_eq!(o.facts[0].probe, "ebpf");
        assert_eq!(o.facts[0].key, "load");
    }

    #[test]
    fn decoded_denial_is_a_complete_answer_never_degraded() {
        // Requirement: capabilities missing => decoded denial, NOT degraded.
        let o = build_outcome(
            &LoadOutcome::Denied {
                errno: libc::EPERM,
                message: None,
            },
            None,
        );
        assert_eq!(o.availability, Availability::Ok);
        assert_eq!(o.facts[0].value["status"], "eperm-no-caps");
        assert_eq!(o.facts[0].value["errno"], 1);
    }

    #[test]
    fn verifier_message_survives_with_char_safe_capping() {
        let long = "é".repeat(3000);
        let o = build_outcome(
            &LoadOutcome::Denied {
                errno: libc::EINVAL,
                message: Some(long),
            },
            Some(0),
        );
        let msg = o.facts[0].value["message"].as_str().unwrap();
        assert_eq!(msg.chars().count(), 2049); // 2048 + ellipsis
        assert!(msg.ends_with('…'));
        assert_eq!(o.facts[0].value["status"], "verifier-reject");
    }

    #[test]
    fn artifact_missing_and_parse_failure_degrade_never_panic() {
        for (outcome, avail) in [
            (
                LoadOutcome::ArtifactMissing,
                Availability::Degraded("embedded eBPF object absent".into()),
            ),
            (
                LoadOutcome::ParseFailed("junk".into()),
                Availability::Degraded("embedded eBPF object not loadable by aya: junk".into()),
            ),
        ] {
            let o = build_outcome(&outcome, None);
            assert_eq!(o.availability, avail);
            // Degraded facts are Ok-status false for rules by construction.
            assert_ne!(o.facts[0].status, crate::model::FactStatus::Ok);
        }
    }

    #[test]
    fn empty_embedded_slot_is_the_only_artifact_missing_trigger() {
        // The committed artifact is real in every build of this tree; the
        // runtime guard covers truncated placeholders (forks, filters).
        assert_eq!(attempt_load(&[]), LoadOutcome::ArtifactMissing);
    }

    #[test]
    fn garbage_object_degrades_to_parse_failed_without_syscall() {
        // Real-aya path, but garbage cannot reach BPF_PROG_LOAD: parse fails
        // first. Deterministic across kernels — safe for `cargo test`.
        assert!(matches!(
            attempt_load(b"not an elf"),
            LoadOutcome::ParseFailed(_)
        ));
    }

    #[test]
    fn knob_context_reads_the_task28_fact() {
        assert_eq!(knob_from_prior(&prior_with_knob(json!(2))), Some(2));
        assert_eq!(knob_from_prior(&prior_with_knob(Value::Null)), None);
        assert_eq!(knob_from_prior(&Prior::default()), None);
    }

    // ── registry gating: the probe does not exist without --probe-ebpf ──

    fn opts(ebpf: bool) -> crate::opts::Opts {
        crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            probe_device_open: false,
            compact: false,
            probe_ebpf: if ebpf {
                vec![crate::opts::EbpfTarget::Load]
            } else {
                Vec::new()
            },
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        }
    }

    #[test]
    fn registry_membership_follows_the_flag() {
        let off: Vec<&str> = crate::probes::registry(&opts(false))
            .iter()
            .map(|p| p.name())
            .collect();
        let on: Vec<&str> = crate::probes::registry(&opts(true))
            .iter()
            .map(|p| p.name())
            .collect();
        assert!(
            !off.contains(&PROBE),
            "--probe-ebpf absent must not register the load probe: {off:?}"
        );
        // Same events as the default run, plus exactly this one, slotted
        // right after the knobs probe it fuses (`ebpf`).
        assert_eq!(on.len(), off.len() + 1);
        let at = on.iter().position(|n| *n == PROBE).unwrap();
        assert_eq!(on[at - 1], "ebpf");
        let mut without = on.clone();
        without.remove(at);
        assert_eq!(without, off);
    }
}
