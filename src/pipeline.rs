use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::model::*;
use crate::opts::Opts;
use crate::probes::Probe;
use crate::sys::fs::PseudoFs;
use crate::sys::os::OsApi;

/// What earlier probes accumulated, snapshotted per dispatch (probes run one at
/// a time, so building it between dispatches is race-free).
#[derive(Clone, Default)]
pub struct Prior {
    pub signals: Vec<Signal>,
    /// keyed "{probe}.{factKey}", Ok-status facts only
    pub facts: std::collections::HashMap<String, serde_json::Value>,
}

/// Read-only context handed to a probe on its worker thread. The fields are
/// consumed by the concrete probes (Tasks 8+), not by the pipeline itself.
#[allow(dead_code)] // Still unread: the registered probes are stubs (Tasks 8+).
pub struct Ctx<'a> {
    pub pid: u32,
    pub uid: u32,
    pub fs: &'a PseudoFs,
    pub os: &'a dyn OsApi,
    pub opts: &'a Opts,
    pub prior: Prior,
}

#[derive(Debug)]
pub enum Event {
    Meta {
        tool: Tool,
        scan: ScanMeta,
    },
    Probe(ProbeOutcome),
    Summary {
        verdict: Option<Verdict>,
        findings: Vec<Finding>,
        counts: Counts,
        complete: bool,
        /// The finished report, cloned once at Summary-emit time so the bulk
        /// `Json` renderer can serialize it without re-walking the events.
        report: Box<Report>,
    },
}

/// Degraded outcome shared by every non-happy path (timeout, worker panic,
/// spawn failure).
fn degraded_outcome(name: &str) -> ProbeOutcome {
    let mut o = ProbeOutcome::empty(name);
    o.timed_out = true;
    o.availability = Availability::Unavailable("timed out".into());
    o
}

/// Runs one probe on its own thread. The thread captures `Arc` clones of the
/// shared seams, so an abandoned (hung) worker can never outlive its data —
/// `exit()` reaps it. First channel response wins; timeouts are not retried,
/// which keeps event order deterministic. A panicking worker drops its sender,
/// so `Disconnected` lands on the same degraded path instead of aborting the
/// scan (release builds use `panic = "abort"`, where a panic cannot unwind;
/// this covers every other profile, including tests).
#[allow(clippy::too_many_arguments)] // Signature fixed by the Task 5 brief.
fn run_probe_bounded(
    probe: Arc<dyn Probe>,
    fs: Arc<PseudoFs>,
    os: Arc<dyn OsApi>,
    opts: &Opts,
    pid: u32,
    uid: u32,
    prior: Prior,
    timeout: Option<Duration>,
) -> ProbeOutcome {
    let name = probe.name();
    let (tx, rx) = mpsc::channel();
    // Owned clone: `thread::Builder::spawn` requires `'static` captures.
    let opts = Arc::new(opts.clone());
    let spawned = std::thread::Builder::new()
        .name(format!("probe-{name}"))
        .spawn(move || {
            let cx = Ctx {
                pid,
                uid,
                fs: &fs,
                os: &*os,
                opts: &opts,
                prior,
            };
            let _ = tx.send(probe.run(&cx));
        });
    if spawned.is_err() {
        // Thread starvation: degrade this probe rather than hang or abort.
        return degraded_outcome(name);
    }
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        let result = match deadline {
            Some(dl) => {
                // `recv_deadline` is unstable; recompute the remaining wait each
                // iteration so the deadline stays exact.
                rx.recv_timeout(dl.saturating_duration_since(Instant::now()))
            }
            None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        match (result, deadline) {
            (Ok(outcome), _) => return outcome,
            (Err(mpsc::RecvTimeoutError::Disconnected), _) => return degraded_outcome(name),
            // Spurious wakeups happen on some platforms; only honor a timeout
            // once the deadline has truly passed.
            (Err(mpsc::RecvTimeoutError::Timeout), Some(dl)) if Instant::now() < dl => continue,
            (Err(mpsc::RecvTimeoutError::Timeout), _) => return degraded_outcome(name),
        }
    }
}

/// Runs `probes` in order, emitting `Meta` → one `Probe` event per outcome →
/// `Summary`, and returns the finished `Report`. Aggregation is single-threaded
/// between dispatches, so `Prior` snapshots and report assembly are deterministic.
pub fn scan_with_probes(
    fs: Arc<PseudoFs>,
    os: Arc<dyn OsApi>,
    opts: &Opts,
    probes: Vec<Arc<dyn Probe>>,
    sink: &mut dyn FnMut(&Event),
) -> Report {
    let target_pid = opts.pid.unwrap_or_else(std::process::id);
    let meta = ScanMeta {
        target_pid,
        uid: unsafe {
            // SAFETY: geteuid(2) takes no arguments and cannot fail.
            libc::geteuid()
        },
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default(),
        kernel: rustix::system::uname()
            .release()
            .to_string_lossy()
            .into_owned(),
        complete: false,
        probe_timeout_s: opts.probe_timeout.map(|d| d.as_secs()),
    };
    let mut report = Report::blank(meta.clone(), 1);
    sink(&Event::Meta {
        tool: report.tool.clone(),
        scan: meta.clone(),
    });
    let mut prior = Prior::default();
    for probe in probes {
        let mut o = run_probe_bounded(
            probe.clone(),
            fs.clone(),
            os.clone(),
            opts,
            target_pid,
            meta.uid,
            prior.clone(),
            opts.probe_timeout,
        );
        prior.signals.append(&mut o.signals);
        for f in o.facts.iter().filter(|f| f.status == FactStatus::Ok) {
            prior
                .facts
                .insert(format!("{}.{}", o.name, f.key), f.value.clone());
        }
        if o.name == "runtime"
            && let Some(f) = o
                .facts
                .iter()
                .find(|f| f.key == "verdict" && f.status == FactStatus::Ok)
        {
            report.verdict = serde_json::from_value(f.value.clone()).ok();
        }
        report.push_probe(o.clone());
        sink(&Event::Probe(o));
    }
    report.findings = crate::model::rules::evaluate_all(&report, os.is_root());
    report.compute_counts();
    // Spec §5: a timed-out probe leaves its data unknown, so the scan only
    // completes when no probe timed out. Degraded/unavailable facts (data
    // definitively absent) never flip the flag.
    report.scan.complete = !report.probes.iter().any(|p| p.timed_out);
    sink(&Event::Summary {
        verdict: report.verdict.clone(),
        findings: report.findings.clone(),
        counts: report.counts.clone(),
        complete: report.scan.complete,
        report: Box::new(report.clone()),
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::Probe;
    use crate::sys::os::RealOs;
    struct Slow;
    impl Probe for Slow {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome {
            std::thread::sleep(std::time::Duration::from_millis(300));
            ProbeOutcome::empty("slow")
        }
    }
    struct Fast;
    impl Probe for Fast {
        fn name(&self) -> &'static str {
            "fast"
        }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome {
            ProbeOutcome::empty("fast")
        }
    }

    #[test]
    fn timed_out_probe_is_marked_and_scan_continues() {
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: Some(std::time::Duration::from_millis(50)),
            fail_on: None,
        };
        let mut events = vec![];
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(Slow), Arc::new(Fast)];
        let report = scan_with_probes(fs, os, &opts, probes, &mut |e| {
            events.push(format!("{e:?}"))
        });
        let slow = report.probes.iter().find(|p| p.name == "slow").unwrap();
        assert!(slow.timed_out);
        assert!(matches!(slow.availability, Availability::Unavailable(_)));
        let fast = report.probes.iter().find(|p| p.name == "fast").unwrap();
        assert!(!fast.timed_out);
        // Spec §5: any timed_out probe marks the scan incomplete.
        assert!(!report.scan.complete);
        // The Summary event must carry the same flag as the returned report.
        assert!(
            events.last().unwrap().contains("complete: false"),
            "summary event must say complete:false: {:?}",
            events.last()
        );
    }
    #[test]
    fn events_are_emitted_in_meta_probe_summary_order() {
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let mut events = vec![];
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(Fast), Arc::new(Slow2)];
        scan_with_probes(fs, os, &opts, probes, &mut |e| {
            events.push(format!("{e:?}"))
        });
        assert!(events[0].starts_with("Meta"));
        assert!(events[1].starts_with(r#"Probe(ProbeOutcome { name: "fast""#));
        assert!(events[2].starts_with(r#"Probe(ProbeOutcome { name: "slow2""#));
        assert!(events[3].starts_with("Summary"));
    }
    struct Slow2;
    impl Probe for Slow2 {
        fn name(&self) -> &'static str {
            "slow2"
        }
        fn run(&self, _cx: &Ctx) -> ProbeOutcome {
            ProbeOutcome::empty("slow2")
        }
    }

    #[test]
    fn prior_snapshot_carries_ok_facts_and_signals_of_earlier_probes() {
        struct Seeder;
        impl Probe for Seeder {
            fn name(&self) -> &'static str {
                "seeder"
            }
            fn run(&self, _cx: &Ctx) -> ProbeOutcome {
                ProbeOutcome::empty("seeder")
                    .with_fact(Fact::ok(
                        "seeder",
                        "flag",
                        serde_json::json!(true),
                        "src".into(),
                    ))
                    .with_fact(Fact::unavailable(
                        "seeder",
                        "missing",
                        "src".into(),
                        Some(2),
                    ))
                    .with_signal(Signal {
                        runtime: crate::model::RuntimeKind::Podman,
                        weight: 1.0,
                        evidence: Fact::ok("seeder", "sig", serde_json::json!(1), "src".into()),
                        env_only: false,
                    })
            }
        }
        struct Reader;
        impl Probe for Reader {
            fn name(&self) -> &'static str {
                "reader"
            }
            fn run(&self, cx: &Ctx) -> ProbeOutcome {
                // Only Ok facts, keyed "{probe}.{key}"; signals accumulated so far.
                assert_eq!(cx.prior.facts["seeder.flag"], serde_json::json!(true));
                assert!(!cx.prior.facts.contains_key("seeder.missing"));
                assert_eq!(cx.prior.signals.len(), 1);
                ProbeOutcome::empty("reader")
            }
        }
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: Some(std::process::id()),
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let report = scan_with_probes(
            fs,
            os,
            &opts,
            vec![Arc::new(Seeder), Arc::new(Reader)],
            &mut |_| {},
        );
        assert!(report.probes.iter().all(|p| !p.timed_out));
        // The Reader worker asserted the prior snapshot mid-scan (a failed assert there
        // panics its worker, surfacing as timed_out below); pid must be honored as given.
        assert_eq!(report.scan.target_pid, std::process::id());
    }

    #[test]
    fn runtime_verdict_fact_populates_report() {
        struct FakeRuntime;
        impl Probe for FakeRuntime {
            fn name(&self) -> &'static str {
                "runtime"
            }
            fn run(&self, _cx: &Ctx) -> ProbeOutcome {
                ProbeOutcome::empty("runtime").with_fact(Fact::ok(
                    "runtime",
                    "verdict",
                    serde_json::json!({
                        "runtime": "podman",
                        "variant": null,
                        "confidence": "high",
                        "alternatives": [],
                        "evidence": ["cgroup: podman slice"]
                    }),
                    "test".into(),
                ))
            }
        }
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let report = scan_with_probes(fs, os, &opts, vec![Arc::new(FakeRuntime)], &mut |_| {});
        let verdict = report.verdict.expect("verdict set from runtime probe");
        assert_eq!(verdict.runtime, crate::model::RuntimeKind::Podman);
        assert_eq!(verdict.confidence, "high");
    }

    #[test]
    fn panicking_probe_degrades_without_aborting_scan() {
        struct Boom;
        impl Probe for Boom {
            fn name(&self) -> &'static str {
                "boom"
            }
            fn run(&self, _cx: &Ctx) -> ProbeOutcome {
                panic!("probe exploded")
            }
        }
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: Some(std::time::Duration::from_secs(5)),
            fail_on: None,
        };
        let report = scan_with_probes(
            fs,
            os,
            &opts,
            vec![Arc::new(Boom), Arc::new(Fast)],
            &mut |_| {},
        );
        let boom = report.probes.iter().find(|p| p.name == "boom").unwrap();
        assert!(boom.timed_out);
        assert!(matches!(boom.availability, Availability::Unavailable(_)));
        // Scan continues past the panicked probe.
        assert!(
            report
                .probes
                .iter()
                .any(|p| p.name == "fast" && !p.timed_out)
        );
        // The panic lands on the shared timed_out degraded path, so spec §5
        // marks the scan incomplete even though it ran through to the summary.
        assert!(!report.scan.complete);
    }

    #[test]
    fn degraded_only_scan_stays_complete() {
        struct Hushed;
        impl Probe for Hushed {
            fn name(&self) -> &'static str {
                "hushed"
            }
            fn run(&self, _cx: &Ctx) -> ProbeOutcome {
                // Data definitively absent: a degraded probe carrying an
                // unavailable fact is a complete scan — only timed_out flips it.
                ProbeOutcome {
                    availability: Availability::Degraded("comparison skipped".into()),
                    ..ProbeOutcome::empty("hushed")
                }
                .with_fact(Fact::unavailable(
                    "hushed",
                    "ns.pid",
                    "stat".into(),
                    Some(2),
                ))
            }
        }
        let fs = Arc::new(PseudoFs::real());
        let os: Arc<dyn OsApi> = Arc::new(RealOs);
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: Some(std::time::Duration::from_secs(5)),
            fail_on: None,
        };
        let report = scan_with_probes(fs, os, &opts, vec![Arc::new(Hushed)], &mut |_| {});
        let hushed = report.probes.iter().find(|p| p.name == "hushed").unwrap();
        assert!(matches!(hushed.availability, Availability::Degraded(_)));
        assert!(!hushed.timed_out);
        assert!(report.scan.complete);
    }

    #[test]
    fn registry_lists_probes_in_dispatch_order() {
        let opts = Opts {
            pid: None,
            probe_syscalls: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let names: Vec<&str> = crate::probes::registry(&opts)
            .iter()
            .map(|p| p.name())
            .collect();
        assert_eq!(
            names,
            [
                "namespaces",
                "uidmap",
                "capabilities",
                "seccomp",
                "lsm",
                "ebpf",
                "vmm",
                "sockets",
                "cgroup",
                "k8s",
                "runtime",
            ]
        );
    }

    #[test]
    fn registry_gates_syscall_probe_on_probe_syscalls() {
        // The sweep actively invokes syscalls, so it must NOT appear by
        // default (asserted by the sibling above) and must sit right after
        // `seccomp` in dispatch order when `--probe-syscalls` is given.
        let opts = Opts {
            pid: None,
            probe_syscalls: true,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let names: Vec<&str> = crate::probes::registry(&opts)
            .iter()
            .map(|p| p.name())
            .collect();
        assert_eq!(
            names,
            [
                "namespaces",
                "uidmap",
                "capabilities",
                "seccomp",
                "syscall-probe",
                "lsm",
                "ebpf",
                "vmm",
                "sockets",
                "cgroup",
                "k8s",
                "runtime",
            ]
        );
    }

    #[test]
    fn registry_gates_ebpf_probes_on_target_set() {
        // Active eBPF probes never run by default (sibling test above);
        // `--probe-ebpf` decides WHICH of them run, in load→btf→types slot
        // order right after the knobs probe (spec §6 AMR-021).
        let names = |targets: Vec<crate::opts::EbpfTarget>| -> Vec<&str> {
            let opts = Opts {
                pid: None,
                probe_syscalls: false,
                probe_ebpf: targets,
                dump_filters: false,
                probe_timeout: None,
                fail_on: None,
            };
            crate::probes::registry(&opts)
                .iter()
                .map(|p| p.name())
                .collect()
        };
        use crate::opts::EbpfTarget::*;
        let all = names(vec![Load, Btf, Types]);
        let at = all.iter().position(|n| *n == "ebpf").unwrap();
        assert_eq!(
            &all[at..at + 4],
            ["ebpf", "ebpf-load", "ebpf-btf", "ebpf-types"]
        );
        // A subset selects only its own probe, still slotted after `ebpf`.
        let subset = names(vec![Types]);
        let at = subset.iter().position(|n| *n == "ebpf").unwrap();
        assert_eq!(&subset[at..at + 2], ["ebpf", "ebpf-types"]);
        assert!(!subset.contains(&"ebpf-load") && !subset.contains(&"ebpf-btf"));
    }
}
