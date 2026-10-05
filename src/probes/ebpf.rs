//! ebpf probe — read-only eBPF exposure posture: the kernel's
//! `unprivileged_bpf_disabled` knob and the lockdown mode from pseudo-fs
//! (`ebpf.knobs`), plus the computed reachability of `bpf()` for the scanned
//! process (`ebpf.reachability`). Zero syscalls, zero new deps: reachability
//! fuses the already-collected `capabilities.effective` and `lsm.lockdown`
//! facts from `cx.prior`. The REAL program-load probe is Task 29's opt-in
//! `--probe-ebpf`; nothing here ever calls `bpf(2)`.

use serde_json::Value;
use serde_json::json;

use crate::model::{Availability, Fact, ProbeOutcome};
use crate::pipeline::{Ctx, Prior};
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;

const PROBE: &str = "ebpf";
const KNOB_PATH: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";
const LOCKDOWN_PATH: &str = "/sys/kernel/security/lockdown";

/// Parses the `unprivileged_bpf_disabled` knob body: 0 (open), 1 (closed,
/// changeable), 2 (closed until reboot). `None` output is either the absent
/// file — legacy kernels simply lack the knob ("absent pre-5.13" in spec §6
/// AMR-019), which is a statement, not an error — or a body the kernel would
/// never write (garbage is never guessed into one of the three values).
pub fn parse_knob(raw: Option<&str>) -> Option<u8> {
    match raw.map(str::trim) {
        Some("0") => Some(0),
        Some("1") => Some(1),
        Some("2") => Some(2),
        _ => None,
    }
}

/// Parses the current lockdown mode. The real file has two forms: a
/// changeable stack lists every mode with the current one in brackets
/// (`[none] integrity/confidentiality`), while a locked kernel prints the
/// bare mode word only (`integrity`). Absent file / empty body / malformed
/// body ⇒ `None` (securityfs not mounted, or nothing decidable).
pub fn parse_lockdown(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.split_once('[').map(|(_, after)| after) {
        // Bracketed list: the mode between `[` and the next `]`; an empty
        // bracket pair decides nothing.
        let current = rest.split(']').next()?.trim();
        (!current.is_empty()).then(|| current.to_string())
    } else if s.split_whitespace().count() == 1 {
        // Locked kernel: a single bare mode word (`integrity`, …).
        Some(s.to_string())
    } else {
        None
    }
}

/// Computed `ebpf.reachability` value (see [`probe_ebpf`] for the contract).
/// `capPathOpen` asks for CAP_BPF only: CAP_PERFMON covers map access and
/// perf-attached probes, not program load (AMR-020's `why` carries the
/// nuance). `unprivilegedOpen` follows the Task 28 plan formula with Rust
/// precedence — `knob == 0 || (knob == null && lockdown != "integrity")` —
/// i.e. the lockdown conjunct scopes the null-knob (legacy kernel) heuristic,
/// and an explicit knob 0 opens regardless of lockdown.
fn reachability_value(knob: Option<u8>, lockdown: Option<&str>, caps: Option<&Value>) -> Value {
    let cap_path_open = caps
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|c| c.as_str() == Some("cap_bpf")));
    let unprivileged_open = knob == Some(0) || (knob.is_none() && lockdown != Some("integrity"));
    json!({"capPathOpen": cap_path_open, "unprivilegedOpen": unprivileged_open})
}

/// Builds the `ebpf` outcome. `knobs` is always Ok-status — every constituent
/// file may legitimately be absent and reads as `null` (not degraded).
/// `reachability` needs the capabilities probe's `effective` fact in `prior`;
/// without it the whole process-capability side is unknown, so the fact is a
/// degraded `null` and the probe's availability is `degraded`. The lockdown
/// input for the heuristic comes from the `lsm` probe's already-parsed
/// `lsm.lockdown` fact (registry order runs both before this probe), per the
/// plan's "reads capabilities.effective + lockdown from cx.prior".
pub fn probe_ebpf(fs: &PseudoFs, prior: &Prior) -> ProbeOutcome {
    let knob = parse_knob(fs.read(KNOB_PATH).ok().as_deref());
    let lockdown = parse_lockdown(fs.read(LOCKDOWN_PATH).ok().as_deref());
    let mut o = ProbeOutcome::empty(PROBE);
    // One fact, two source files: each value is independently null-able.
    o = o.with_fact(Fact::ok(
        PROBE,
        "knobs",
        json!({"unprivilegedBpfDisabled": knob, "lockdown": lockdown}),
        format!("{KNOB_PATH}+{LOCKDOWN_PATH}"),
    ));
    match prior.facts.get("capabilities.effective") {
        Some(caps) => {
            // An Ok-status `lsm.lockdown` fact carries JSON null exactly when
            // the file is absent; `as_str()` folds both to the same unknown.
            let prior_lockdown = prior.facts.get("lsm.lockdown").and_then(Value::as_str);
            o.with_fact(Fact::ok(
                PROBE,
                "reachability",
                reachability_value(knob, prior_lockdown, Some(caps)),
                "computed:capabilities.effective+lsm.lockdown".into(),
            ))
        }
        None => {
            o.availability = Availability::Degraded("capabilities facts absent".into());
            o.with_fact(Fact::degraded(
                PROBE,
                "reachability",
                Value::Null,
                "computed:capabilities.effective+lsm.lockdown".into(),
            ))
        }
    }
}

pub struct Ebpf;

impl Probe for Ebpf {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        probe_ebpf(cx.fs, &cx.prior)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FactStatus;
    use std::collections::HashMap;

    /// A mini fixture tree of absolute pseudo-paths.
    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (path, body) in files {
            let f = d.path().join(path.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        }
        d
    }

    /// A `Prior` carrying exactly the facts the probe consumes.
    fn prior(caps: Option<&[&str]>, lockdown: Option<&str>) -> Prior {
        let mut facts = HashMap::new();
        if let Some(c) = caps {
            facts.insert("capabilities.effective".to_string(), json!(c));
        }
        if let Some(l) = lockdown {
            facts.insert("lsm.lockdown".to_string(), json!(l));
        }
        Prior {
            signals: vec![],
            facts,
        }
    }

    fn fact<'a>(o: &'a ProbeOutcome, key: &str) -> &'a Fact {
        o.facts
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("missing fact {key}"))
    }

    fn reach(o: &ProbeOutcome) -> (&Value, &Value) {
        let r = fact(o, "reachability");
        assert_eq!(r.status, FactStatus::Ok);
        (&r.value["capPathOpen"], &r.value["unprivilegedOpen"])
    }

    // ── knobs parsing ───────────────────────────────────────────────────────

    #[test]
    fn knob_values_parse_exactly_and_garbage_is_null() {
        assert_eq!(parse_knob(Some("0\n")), Some(0));
        assert_eq!(parse_knob(Some("1")), Some(1));
        assert_eq!(parse_knob(Some("2\n")), Some(2));
        // Never a real value: null, never a guessed stand-in.
        assert_eq!(parse_knob(Some("3\n")), None);
        assert_eq!(parse_knob(Some("locked\n")), None);
        assert_eq!(parse_knob(Some("")), None);
        assert_eq!(parse_knob(None), None);
    }

    #[test]
    fn lockdown_parses_both_real_file_forms() {
        // Changeable: the kernel lists all modes, current one bracketed.
        assert_eq!(
            parse_lockdown(Some("[none] integrity/confidentiality\n")).as_deref(),
            Some("none")
        );
        assert_eq!(
            parse_lockdown(Some("[integrity] confidentiality")).as_deref(),
            Some("integrity")
        );
        // Locked kernel: bare mode word, no brackets.
        assert_eq!(
            parse_lockdown(Some("integrity\n")).as_deref(),
            Some("integrity")
        );
        assert_eq!(
            parse_lockdown(Some("confidentiality\n")).as_deref(),
            Some("confidentiality")
        );
        // Absent file, empty and malformed bodies are all null.
        assert_eq!(parse_lockdown(None), None);
        assert_eq!(parse_lockdown(Some("   ")), None);
        assert_eq!(parse_lockdown(Some("[] integrity")), None);
        assert_eq!(parse_lockdown(Some("foo bar")), None);
    }

    #[test]
    fn absent_knob_files_are_null_facts_not_degradation() {
        // Pre-5.8-style kernel: no knob file at all, no securityfs.
        let d = tree(&[]);
        let fs = PseudoFs::new(d.path().into());
        let o = probe_ebpf(&fs, &prior(Some(&["cap_chown"]), None));
        assert!(matches!(o.availability, Availability::Ok));
        let k = fact(&o, "knobs");
        assert_eq!(k.status, FactStatus::Ok);
        assert_eq!(
            k.value,
            json!({"unprivilegedBpfDisabled": null, "lockdown": null})
        );
    }

    #[test]
    fn knobs_fact_reports_present_files_verbatim() {
        let d = tree(&[
            (KNOB_PATH, "2\n"),
            (LOCKDOWN_PATH, "[none] integrity/confidentiality\n"),
        ]);
        let fs = PseudoFs::new(d.path().into());
        let o = probe_ebpf(&fs, &prior(Some(&[]), Some("none")));
        let k = fact(&o, "knobs");
        assert_eq!(k.status, FactStatus::Ok);
        assert_eq!(
            k.value,
            json!({"unprivilegedBpfDisabled": 2, "lockdown": "none"})
        );
        assert!(k.source.contains("unprivileged_bpf_disabled"));
        assert!(k.source.contains("lockdown"));
    }

    // ── reachability truth table ────────────────────────────────────────────

    #[test]
    fn reachability_truth_table() {
        // (knob file body — "" means the file is absent —, CapEff names,
        //  prior lockdown, expected capPathOpen, expected unprivilegedOpen)
        type ReachCase = (
            &'static str,
            &'static [&'static str],
            Option<&'static str>,
            bool,
            bool,
        );
        let cases: Vec<ReachCase> = vec![
            // Knob 0: unprivileged bpf() allowed. The plan formula gives the
            // `lockdown != "integrity"` conjunct to the null-knob branch only
            // (Rust `||`/`&&` precedence), so knob 0 opens under any lockdown.
            ("0\n", &["cap_chown"], None, false, true),
            ("0\n", &["cap_chown"], Some("none"), false, true),
            ("0\n", &["cap_chown"], Some("integrity"), false, true),
            // Knob 1/2: unprivileged path closed no matter what.
            ("1\n", &["cap_bpf"], None, true, false),
            ("1\n", &["cap_bpf"], Some("none"), true, false),
            (
                "2\n",
                &["cap_bpf", "cap_perfmon"],
                Some("none"),
                true,
                false,
            ),
            // Absent knob = pre-5.13 heuristic, gated by `!= "integrity"`.
            ("", &["cap_chown"], None, false, true),
            ("", &["cap_chown"], Some("none"), false, true),
            ("", &["cap_chown"], Some("integrity"), false, false),
            // The formula compares against "integrity" exactly (plan Task 28).
            ("", &["cap_chown"], Some("confidentiality"), false, true),
            // CAP_PERFMON alone is maps/probes access, not the load path.
            ("", &["cap_perfmon", "cap_chown"], Some("none"), false, true),
            ("1\n", &["cap_perfmon"], None, false, false),
            // CAP_BPF opens the privileged path regardless of the knob.
            ("2\n", &["cap_bpf"], Some("integrity"), true, false),
            ("", &[], None, false, true),
        ];
        for (body, caps, lockdown, cap_path, unpriv) in cases {
            let files: Vec<(&str, &str)> = if body.is_empty() {
                vec![]
            } else {
                vec![(KNOB_PATH, body)]
            };
            let d = tree(&files);
            let fs = PseudoFs::new(d.path().into());
            let o = probe_ebpf(&fs, &prior(Some(caps), lockdown));
            let (cp, up) = reach(&o);
            assert_eq!(cp, &json!(cap_path), "caps {caps:?} lockdown {lockdown:?}");
            assert_eq!(up, &json!(unpriv), "knob {body:?} lockdown {lockdown:?}");
        }
    }

    #[test]
    fn missing_capabilities_degrades_reachability_only() {
        // The capabilities probe never ran (or timed out): the caps input is
        // unknown, so reachability must not guess — degraded null, while the
        // directly-read knobs fact stays Ok.
        let d = tree(&[(KNOB_PATH, "0\n")]);
        let fs = PseudoFs::new(d.path().into());
        let o = probe_ebpf(&fs, &prior(None, None));
        assert!(matches!(o.availability, Availability::Degraded(_)));
        let r = fact(&o, "reachability");
        assert_eq!(r.status, FactStatus::Degraded);
        assert_eq!(r.value, Value::Null);
        let k = fact(&o, "knobs");
        assert_eq!(k.status, FactStatus::Ok);
        assert_eq!(k.value["unprivilegedBpfDisabled"], json!(0));
    }

    #[test]
    fn run_wires_fs_and_prior_from_the_ctx() {
        // The registry dispatch seam: `run` must feed `cx.fs` + `cx.prior`
        // into the outcome builder, exactly like the k8s probe's sibling test.
        struct NoOs;
        impl crate::sys::os::OsApi for NoOs {
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
            fn syscall0(&self, _n: u32) -> Result<(), i32> {
                Err(38)
            }
            fn uds_probe(
                &self,
                _p: &std::path::Path,
                _t: std::time::Duration,
            ) -> std::io::Result<crate::sys::os::UdsReply> {
                Err(std::io::Error::other("x"))
            }
            fn env(&self, _k: &str) -> Option<String> {
                None
            }
            fn is_root(&self) -> bool {
                false
            }
        }
        let d = tree(&[(KNOB_PATH, "0\n")]);
        let fs = PseudoFs::new(d.path().into());
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            compact: false,
            probe_ebpf: Vec::new(),
            probe_timeout: None,
            fail_on: None,
            dump_filters: false,
        };
        let os = NoOs;
        let cx = Ctx {
            pid: 7,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior: prior(Some(&["cap_bpf"]), Some("none")),
        };
        let o = Ebpf.run(&cx);
        assert_eq!(Ebpf.name(), "ebpf");
        assert!(matches!(o.availability, Availability::Ok));
        let (cp, up) = reach(&o);
        assert_eq!(cp, &json!(true));
        assert_eq!(up, &json!(true));
    }
}
