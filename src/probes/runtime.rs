//! runtime probe — the fusion layer. It reads no files and issues no syscalls:
//! everything it knows arrived as signals and facts from the probes before it,
//! and it turns them into the single verdict the report leads with.
//!
//! The scoring table is spec §7 (Task 17 brief): weights are summed per
//! `RuntimeKind`; the top score is the primary and its confidence (capped at
//! 1.0); anything above `0.1` is worth naming as an alternative; Kubernetes
//! overlays whatever container runtime is underneath it; an all-zero table
//! falls back to `host`, with the vmm hypervisor fact deciding how far that
//! claim reaches.
//!
//! Since the 2026-10-01 amendment (spec §5) those summed weights cover only
//! *self-containment* signals: env-only ones (a reachable control socket, a
//! rootless uidmap) prove what the machine runs, never where this process
//! runs; they are excluded from the ranking and appended as
//! `environment: <kind> present (<probe>.<key>)` evidence notes instead.
//! Inside-visible markers (`/.dockerenv`, `container=`) do score, and when
//! one names an outer runtime the verdict gains `nested-in-<outer>`.
//!
//! Two shapes differ from the brief sketch, because the shipped `model::Verdict`
//! (Task 2, and the report schema the pipeline deserializes against) fixes
//! `runtime: RuntimeKind` and `confidence: "high"|"medium"|"low"`:
//! - the numeric top score is reported through that ladder by
//!   [`confidence_of`], which keeps the brief's `0.5` primary bar a visible
//!   boundary;
//! - the brief's `underlying` runtime and its `"host (virtualized)"` note live
//!   in `variant`, the schema's only free-form qualifier.

use crate::model::{Candidate, Fact, ProbeOutcome, RuntimeKind, Signal, Verdict};
use crate::pipeline::Ctx;
use crate::probes::Probe;

const PROBE: &str = "runtime";

/// Runner-ups must clear this weight to be reported at all (spec §7).
const MEANINGFUL: f32 = 0.1;
/// A top score at or above this bar is a primary verdict rather than a guess.
const PRIMARY: f32 = 0.5;

/// Sums the scoring signals' weights per runtime, best first. Env-only
/// signals never enter the ranking (spec §5, amendment 2026-10-01).
fn rank(signals: &[Signal]) -> Vec<(RuntimeKind, f32)> {
    let mut totals: std::collections::HashMap<RuntimeKind, f32> = Default::default();
    for s in signals.iter().filter(|s| !s.env_only) {
        *totals.entry(s.runtime).or_default() += s.weight;
    }
    let mut ranked: Vec<(RuntimeKind, f32)> = totals.into_iter().collect();
    // Ties break on the runtime name: the pipeline assembles reports
    // deterministically, and a HashMap's iteration order must not leak into
    // the ranking or the alternatives list.
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.as_str().cmp(b.0.as_str()))
    });
    ranked
}

/// Numeric top score → the report's confidence ladder. `0.9` is where a
/// top-grade self-containment read lands (a `libpod-`/docker cgroup pattern
/// plus the marker that corroborates it, gVisor's `/proc/version`), so
/// `high` means "strongly evidenced"; `0.5` is the brief's primary bar,
/// hence `medium`; anything under it is a guess stated at its own weight.
fn confidence_of(score: f32) -> &'static str {
    if score >= 0.9 {
        "high"
    } else if score >= PRIMARY {
        "medium"
    } else {
        "low"
    }
}

/// Fuses the accumulated signals into the verdict, in spec §7 precedence
/// order: the Kubernetes overlay if the target is in a pod, else the
/// strongest runtime at or above the primary bar, else a weak guess stated
/// at its own weight, else the host fallback. `in_pod` is the raw
/// `k8s.inPod` fact (a non-boolean or null value is simply "not in a pod"),
/// `hv_present` the tri-state read of `vmm.hypervisor.present`, `markers`
/// the raw `namespaces.containerMarkers` fact (absent/null ⇒ no nesting
/// claim). Only self-scoring signals rank; env-only ones become trailing
/// `environment:` notes whatever the verdict ends up being.
pub fn score(
    signals: &[Signal],
    in_pod: serde_json::Value,
    hv_present: Option<bool>,
    markers: serde_json::Value,
) -> Verdict {
    let ranked = rank(signals);
    let mut evidence: Vec<String> = signals
        .iter()
        .filter(|s| !s.env_only)
        .map(|s| {
            format!(
                "{} {}.{} {:.2}",
                s.runtime.as_str(),
                s.evidence.probe,
                s.evidence.key,
                s.weight
            )
        })
        .collect();
    let in_pod = in_pod.as_bool().unwrap_or(false);
    let top = ranked.first().copied();
    let (runtime, confidence, variant) = if in_pod {
        let underlying = ranked
            .iter()
            .find(|(k, w)| {
                *k != RuntimeKind::Kubernetes && is_container_runtime(*k) && *w > MEANINGFUL
            })
            .map(|(k, _)| k.as_str().to_string());
        evidence.push("k8s: env/serviceaccount/hostname heuristics".into());
        (
            RuntimeKind::Kubernetes,
            top.map(|(_, w)| w.min(1.0)).unwrap_or(0.7),
            underlying,
        )
    } else if let Some((k, w)) = top.filter(|(_, w)| *w >= PRIMARY) {
        (k, w.min(1.0), None)
    } else if let Some((k, w)) = top.filter(|(_, w)| *w > 0.0) {
        // Weak evidence only — report the guess at its own weight.
        (k, w, None)
    } else {
        match hv_present {
            // Hypervisor ruled out: the strongest claim this probe can make.
            Some(false) => (RuntimeKind::Host, 1.0, None),
            // Hypervisor proven: still a host as far as runtimes go, but the
            // report must not hide that it is a virtual one.
            Some(true) => (RuntimeKind::Host, 0.9, Some("virtualized".to_string())),
            // The vmm probe never landed (failed outright, or reported the
            // presence fact as unreadable). `host` is still the best answer,
            // but the unverified half of it has to stay visible.
            None => {
                evidence.push("vmm: hypervisor presence unknown".into());
                (RuntimeKind::Host, 0.9, None)
            }
        }
    };
    // Nesting (spec §5): markers naming an outer runtime different from the
    // innermost container verdict qualify it. The Kubernetes branch keeps its
    // underlying-runtime variant only — no marker logic there.
    let variant = variant.or_else(|| match runtime {
        RuntimeKind::Docker
        | RuntimeKind::Podman
        | RuntimeKind::Containerd
        | RuntimeKind::CriO
        | RuntimeKind::Lxc
        | RuntimeKind::SystemdNspawn
        | RuntimeKind::Gvisor => {
            outer_runtime(&markers, runtime).map(|outer| format!("nested-in-{outer}"))
        }
        _ => None,
    });
    // Excluded env-only signals do not vanish: each becomes a presence note
    // after the scored evidence lines, deduped by the whole note string (two
    // writable sockets of one kind are one line).
    for s in signals.iter().filter(|s| s.env_only) {
        let note = format!(
            "environment: {} present ({}.{})",
            s.runtime.as_str(),
            s.evidence.probe,
            s.evidence.key
        );
        if !evidence.contains(&note) {
            evidence.push(note);
        }
    }
    let alternatives = ranked
        .iter()
        .filter(|(k, w)| *w > MEANINGFUL && *k != runtime)
        .map(|(k, w)| Candidate {
            runtime: *k,
            score: *w,
        })
        .collect();
    Verdict {
        runtime,
        variant,
        confidence: confidence_of(confidence).to_string(),
        alternatives,
        evidence,
    }
}

/// The outer runtime implied by inside-visible markers, when it differs from
/// the innermost verdict: `/.dockerenv` ⇒ docker (the docker-specific file
/// settles a `container=podman` clash — podman-in-docker);
/// `container=docker`/`container=podman` likewise. Any other value, and any
/// absent or malformed marker fact, implies nothing (spec §5 nesting).
fn outer_runtime(markers: &serde_json::Value, inner: RuntimeKind) -> Option<String> {
    if markers["dockerenv"].as_bool().unwrap_or(false) && "docker" != inner.as_str() {
        return Some("docker".to_string());
    }
    match markers["containerEnv"].as_str() {
        Some(v @ ("docker" | "podman")) if v != inner.as_str() => Some(v.to_string()),
        _ => None,
    }
}

/// The container runtimes that can sit *under* a pod (spec §5's "k8s pod on
/// containerd"). Sandbox kinds are the isolation layer rather than the runtime
/// managing the container, so they never fill the verdict's variant.
fn is_container_runtime(k: RuntimeKind) -> bool {
    matches!(
        k,
        RuntimeKind::Docker | RuntimeKind::Containerd | RuntimeKind::CriO | RuntimeKind::Podman
    )
}

/// Final probe of every scan: turns the signals the other probes raised into
/// one verdict. It reads no files and issues no syscalls, so it has no failure
/// mode of its own — a scan whose predecessors all failed is still reported as
/// a host, never as `Unavailable`.
pub struct Runtime;

impl Probe for Runtime {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> ProbeOutcome {
        let in_pod = cx
            .prior
            .facts
            .get("k8s.inPod")
            .cloned()
            .unwrap_or(serde_json::json!(false));
        // Absent (the vmm probe never ran or failed) and null (the fact was
        // unreadable) both mean "unknown", which is not the same claim as an
        // explicit `present: false`.
        let hv_present = cx
            .prior
            .facts
            .get("vmm.hypervisor")
            .and_then(|v| v["present"].as_bool());
        let markers = cx
            .prior
            .facts
            .get("namespaces.containerMarkers")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let verdict = score(&cx.prior.signals, in_pod, hv_present, markers);
        ProbeOutcome::empty(PROBE).with_fact(Fact::ok(
            PROBE,
            "verdict",
            serde_json::to_value(&verdict).expect("Verdict is serializable"),
            "signal aggregation".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(rt: RuntimeKind, w: f32) -> Signal {
        Signal {
            runtime: rt,
            weight: w,
            evidence: Fact::ok("x", "y", serde_json::json!(1), "test".into()),
            env_only: false,
        }
    }

    #[test]
    fn docker_wins_over_weaker_podman_alternatives() {
        let v = score(
            &[
                sig(RuntimeKind::Docker, 0.8),
                sig(RuntimeKind::Podman, 0.3),
                sig(RuntimeKind::Docker, 0.1),
            ],
            serde_json::json!(false),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Docker);
        // Brief numeric confidence 0.9 (0.8 + 0.1 summed): the shipped model
        // carries the string ladder, so 0.9 lands in the top band.
        assert_eq!(v.confidence, "high");
        assert_eq!(v.alternatives[0].runtime, RuntimeKind::Podman);
    }

    #[test]
    fn kubernetes_overlays_underlying() {
        let v = score(
            &[
                sig(RuntimeKind::Kubernetes, 0.7),
                sig(RuntimeKind::Docker, 0.0),
            ],
            serde_json::json!(true),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Kubernetes);
    }

    #[test]
    fn bare_host_fallback() {
        let v = score(
            &[],
            serde_json::json!(false),
            Some(false),
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Host);
        assert_eq!(v.confidence, "high");
    }

    #[test]
    fn vm_host_notes_virtualization() {
        let v = score(
            &[],
            serde_json::json!(false),
            Some(true),
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Host);
        assert_eq!(v.confidence, "high");
    }

    fn sig_at(rt: RuntimeKind, w: f32, probe: &str, key: &str) -> Signal {
        Signal {
            runtime: rt,
            weight: w,
            evidence: Fact::ok(probe, key, serde_json::json!("v"), "src".into()),
            env_only: false,
        }
    }

    fn env_sig(rt: RuntimeKind, w: f32, probe: &str, key: &str) -> Signal {
        Signal {
            runtime: rt,
            weight: w,
            evidence: Fact::ok(probe, key, serde_json::json!("v"), "src".into()),
            env_only: true,
        }
    }

    #[test]
    fn rank_sums_repeated_signals_and_sorts_best_first() {
        let r = rank(&[
            sig(RuntimeKind::Podman, 0.7),
            sig(RuntimeKind::Docker, 0.8),
            sig(RuntimeKind::Podman, 0.3),
            sig(RuntimeKind::Docker, 0.1),
        ]);
        assert_eq!(
            r.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["podman", "docker"]
        );
        assert!((r[0].1 - 1.0).abs() < 1e-6, "0.7 + 0.3 must sum");
        assert!((r[1].1 - 0.9).abs() < 1e-6, "0.8 + 0.1 must sum");
    }

    #[test]
    fn tied_scores_rank_in_name_order_so_scans_are_deterministic() {
        let signals = [
            sig(RuntimeKind::Podman, 0.5),
            sig(RuntimeKind::Docker, 0.5),
            sig(RuntimeKind::Containerd, 0.5),
        ];
        let first: Vec<&str> = rank(&signals).iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(first, ["containerd", "docker", "podman"]);
        assert_eq!(
            score(
                &signals,
                serde_json::json!(false),
                Some(false),
                serde_json::Value::Null,
            )
            .alternatives
            .len(),
            2
        );
    }

    #[test]
    fn alternatives_are_cited_in_score_order_and_noise_is_dropped() {
        let v = score(
            &[
                sig(RuntimeKind::Docker, 0.9),
                sig(RuntimeKind::Containerd, 0.11),
                sig(RuntimeKind::Lxc, 0.1),
                sig(RuntimeKind::Podman, 0.15),
            ],
            serde_json::json!(false),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Docker);
        assert_eq!(
            v.alternatives.iter().map(|c| c.runtime).collect::<Vec<_>>(),
            [RuntimeKind::Podman, RuntimeKind::Containerd]
        );
    }

    #[test]
    fn evidence_cites_runtime_probe_key_and_weight() {
        let v = score(
            &[sig_at(RuntimeKind::Docker, 0.8, "cgroup", "pattern")],
            serde_json::json!(false),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.evidence, ["docker cgroup.pattern 0.80"]);
    }

    #[test]
    fn confidence_ladder_keeps_the_primary_bar_visible() {
        let at = |w: f32| {
            score(
                &[sig(RuntimeKind::Docker, w)],
                serde_json::json!(false),
                Some(false),
                serde_json::Value::Null,
            )
            .confidence
        };
        assert_eq!(at(0.9), "high");
        assert_eq!(at(0.89), "medium");
        assert_eq!(at(PRIMARY), "medium");
        assert_eq!(at(0.49), "low");
    }

    #[test]
    fn pod_underlying_is_a_container_runtime_only() {
        let v = score(
            &[
                sig(RuntimeKind::Kubernetes, 0.7),
                sig(RuntimeKind::Containerd, 0.4),
            ],
            serde_json::json!(true),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Kubernetes);
        assert_eq!(v.variant.as_deref(), Some("containerd"));
        assert_eq!(
            v.alternatives.iter().map(|c| c.runtime).collect::<Vec<_>>(),
            [RuntimeKind::Containerd]
        );

        // A sandbox kind is the isolation layer, not the pod's container runtime.
        let v = score(
            &[
                sig(RuntimeKind::Kubernetes, 0.7),
                sig(RuntimeKind::Firecracker, 0.6),
            ],
            serde_json::json!(true),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.variant, None);
        assert_eq!(v.alternatives[0].runtime, RuntimeKind::Firecracker);
    }

    #[test]
    fn kubernetes_without_underlying_evidence_still_overlays() {
        let v = score(
            &[sig(RuntimeKind::Kubernetes, 0.7)],
            serde_json::json!(true),
            None,
            serde_json::Value::Null,
        );
        assert_eq!(v.variant, None);
        assert!(v.alternatives.is_empty());
        assert!(v.evidence.iter().any(|e| e.starts_with("k8s: ")));
    }

    #[test]
    fn virtualized_host_records_the_variant_bare_metal_does_not() {
        assert_eq!(
            score(
                &[],
                serde_json::json!(false),
                Some(true),
                serde_json::Value::Null,
            )
            .variant
            .as_deref(),
            Some("virtualized")
        );
        assert_eq!(
            score(
                &[],
                serde_json::json!(false),
                Some(false),
                serde_json::Value::Null,
            )
            .variant,
            None
        );
    }

    #[test]
    fn unknown_hypervisor_is_not_reported_as_bare_metal() {
        let v = score(&[], serde_json::json!(false), None, serde_json::Value::Null);
        assert_eq!(v.runtime, RuntimeKind::Host);
        assert_eq!(v.variant, None);
        assert!(
            v.evidence.iter().any(|e| e.starts_with("vmm: ")),
            "the missing virtualization check must be visible in the evidence: {:?}",
            v.evidence
        );
    }

    /// Builds a context holding only prior output — the fusion probe touches no
    /// filesystem or syscall seam.
    fn with_prior<R>(
        facts: &[(&str, serde_json::Value)],
        signals: Vec<Signal>,
        run: impl FnOnce(&crate::pipeline::Ctx) -> R,
    ) -> R {
        let fs = crate::sys::fs::PseudoFs::real();
        let os = crate::sys::os::RealOs;
        let opts = crate::opts::Opts {
            pid: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            compact: false,
            probe_ebpf: Vec::new(),
            dump_filters: false,
            probe_timeout: None,
            fail_on: None,
        };
        let prior = crate::pipeline::Prior {
            signals,
            facts: facts
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        };
        let cx = crate::pipeline::Ctx {
            pid: 1,
            uid: 1000,
            fs: &fs,
            os: &os,
            opts: &opts,
            prior,
        };
        run(&cx)
    }

    fn verdict_of(o: &crate::model::ProbeOutcome) -> crate::model::Verdict {
        let f = o
            .facts
            .iter()
            .find(|f| f.key == "verdict")
            .expect("runtime emits a `verdict` fact");
        assert_eq!(f.probe, "runtime");
        // The pipeline deserializes this very value into `model::Verdict`; a
        // shape drift would silently drop the verdict from every report.
        serde_json::from_value(f.value.clone()).expect("verdict fact round-trips into the model")
    }

    #[test]
    fn run_fuses_priors_into_one_verdict_fact() {
        with_prior(
            &[
                ("k8s.inPod", serde_json::json!(true)),
                (
                    "vmm.hypervisor",
                    serde_json::json!({ "present": true, "vendor": "KVMKVMKVM" }),
                ),
            ],
            vec![
                sig_at(RuntimeKind::Kubernetes, 0.7, "cgroup", "pattern"),
                sig_at(RuntimeKind::Containerd, 0.4, "sockets", "found"),
            ],
            |cx| {
                let o = Runtime.run(cx);
                assert_eq!(o.name, "runtime");
                assert_eq!(o.availability, crate::model::Availability::Ok);
                assert!(
                    o.signals.is_empty(),
                    "the fusion probe raises no signals of its own"
                );
                assert_eq!(o.facts.len(), 1);
                let v = verdict_of(&o);
                assert_eq!(v.runtime, RuntimeKind::Kubernetes);
                assert_eq!(v.variant.as_deref(), Some("containerd"));
                assert_eq!(v.confidence, "medium");
            },
        );
    }

    #[test]
    fn run_still_verdicts_when_no_prior_probe_produced_anything() {
        with_prior(&[], vec![], |cx| {
            let o = Runtime.run(cx);
            assert_eq!(
                o.availability,
                crate::model::Availability::Ok,
                "an empty scan is a bare host, never `Unavailable`"
            );
            let v = verdict_of(&o);
            assert_eq!(v.runtime, RuntimeKind::Host);
            assert!(v.evidence.iter().any(|e| e.starts_with("vmm: ")));
        });
    }

    #[test]
    fn null_priors_are_not_read_as_true() {
        with_prior(
            &[
                ("k8s.inPod", serde_json::Value::Null),
                ("vmm.hypervisor", serde_json::Value::Null),
            ],
            vec![sig_at(RuntimeKind::Podman, 0.7, "cgroup", "pattern")],
            |cx| {
                let v = verdict_of(&Runtime.run(cx));
                assert_eq!(v.runtime, RuntimeKind::Podman);
                assert_eq!(v.confidence, "medium");
            },
        );
    }

    // ── Self-containment verdict (spec §5, amendment 2026-10-01) ──────────

    /// Scenario (a): a bare host that merely *runs* podman. The socket and
    /// the rootless uidmap prove the environment, not the process's own
    /// containment; the verdict stays `host` and the signals become notes.
    #[test]
    fn host_running_podman_verdicts_host_with_environment_notes() {
        let v = score(
            &[
                env_sig(RuntimeKind::Podman, 0.9, "sockets", "found"),
                env_sig(RuntimeKind::Podman, 0.3, "uidmap", "rootless"),
            ],
            serde_json::json!(false),
            Some(false),
            serde_json::Value::Null,
        );
        assert_ne!(v.runtime, RuntimeKind::Podman);
        assert_eq!(v.runtime, RuntimeKind::Host);
        assert_eq!(v.confidence, "high");
        assert!(
            v.evidence
                .contains(&"environment: podman present (sockets.found)".to_string()),
            "{:?}",
            v.evidence
        );
        assert!(
            v.evidence
                .contains(&"environment: podman present (uidmap.rootless)".to_string()),
            "{:?}",
            v.evidence
        );
        assert!(
            v.alternatives.is_empty(),
            "env_only signals are evidence, not candidates: {:?}",
            v.alternatives
        );
    }

    /// Scenario (b): `/.dockerenv` alone is containment evidence — enough
    /// to verdict docker, but only at its own (medium) confidence.
    #[test]
    fn dockerenv_marker_alone_verdicts_docker_at_medium() {
        let v = score(
            &[sig_at(
                RuntimeKind::Docker,
                0.6,
                "namespaces",
                "containerMarkers",
            )],
            serde_json::json!(false),
            Some(false),
            serde_json::json!({ "dockerenv": true, "containerEnv": null }),
        );
        assert_eq!(v.runtime, RuntimeKind::Docker);
        assert_eq!(v.confidence, "medium");
        // The only outer marker *is* the verdict: nothing nests inside itself.
        assert_eq!(v.variant, None);
    }

    /// Scenario (c): `libpod-` cgroup inside a docker host — innermost wins,
    /// docker is named as the outer layer, and its marker stays a candidate.
    #[test]
    fn podman_in_docker_verdicts_podman_nested_in_docker() {
        let v = score(
            &[
                sig_at(RuntimeKind::Podman, 0.7, "cgroup", "pattern"),
                sig_at(RuntimeKind::Podman, 0.6, "namespaces", "containerMarkers"),
                sig_at(RuntimeKind::Docker, 0.6, "namespaces", "containerMarkers"),
            ],
            serde_json::json!(false),
            Some(false),
            serde_json::json!({ "dockerenv": true, "containerEnv": "podman" }),
        );
        assert_eq!(v.runtime, RuntimeKind::Podman);
        assert_eq!(v.confidence, "high", "0.7 + 0.6 = 1.3 capped to 1.0");
        assert_eq!(v.variant.as_deref(), Some("nested-in-docker"));
        let docker = v
            .alternatives
            .iter()
            .find(|c| c.runtime == RuntimeKind::Docker)
            .expect("docker marker must remain an alternative");
        assert!((docker.score - 0.6).abs() < 1e-6, "alternatives score raw");
    }

    /// Scenario (d): a contained podman that also *runs* podman services —
    /// the cgroup verdict is unchanged and the socket note stays visible.
    #[test]
    fn contained_podman_with_writable_socket_notes_the_environment() {
        let v = score(
            &[
                sig_at(RuntimeKind::Podman, 0.7, "cgroup", "pattern"),
                env_sig(RuntimeKind::Podman, 0.9, "sockets", "found"),
            ],
            serde_json::json!(false),
            Some(false),
            serde_json::Value::Null,
        );
        assert_eq!(v.runtime, RuntimeKind::Podman);
        assert_eq!(v.confidence, "medium", "only the 0.7 cgroup scores");
        assert!(
            v.evidence
                .contains(&"environment: podman present (sockets.found)".to_string()),
            "{:?}",
            v.evidence
        );
        // Notes come after the scored evidence lines.
        let scored = v
            .evidence
            .iter()
            .position(|e| e == "podman cgroup.pattern 0.70")
            .expect("scored line present");
        let note = v
            .evidence
            .iter()
            .position(|e| e == "environment: podman present (sockets.found)")
            .expect("note present");
        assert!(scored < note);
    }

    #[test]
    fn environment_notes_dedup_by_their_whole_string() {
        // Two writable podman sockets ⇒ two signals, one note.
        let v = score(
            &[
                env_sig(RuntimeKind::Podman, 0.9, "sockets", "found"),
                env_sig(RuntimeKind::Podman, 0.9, "sockets", "found"),
            ],
            serde_json::json!(false),
            Some(false),
            serde_json::Value::Null,
        );
        assert_eq!(
            v.evidence
                .iter()
                .filter(|e| *e == "environment: podman present (sockets.found)")
                .count(),
            1
        );
    }

    #[test]
    fn kubernetes_branch_takes_no_marker_nesting() {
        // Spec: the k8s branch keeps the underlying-runtime variant only.
        let v = score(
            &[sig_at(RuntimeKind::Kubernetes, 0.7, "k8s", "inPod")],
            serde_json::json!(true),
            None,
            serde_json::json!({ "dockerenv": true, "containerEnv": null }),
        );
        assert_eq!(v.runtime, RuntimeKind::Kubernetes);
        assert_eq!(v.variant, None);
    }

    #[test]
    fn markers_absent_or_null_never_nest() {
        for markers in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({ "dockerenv": null, "containerEnv": null }),
            serde_json::json!("garbage"),
        ] {
            let v = score(
                &[sig_at(RuntimeKind::Podman, 0.7, "cgroup", "pattern")],
                serde_json::json!(false),
                Some(false),
                markers.clone(),
            );
            assert_eq!(v.runtime, RuntimeKind::Podman, "{markers}");
            assert_eq!(v.variant, None, "{markers}");
        }
    }

    #[test]
    fn run_plumbs_the_prior_marker_fact_into_the_nested_variant() {
        with_prior(
            &[(
                "namespaces.containerMarkers",
                serde_json::json!({ "dockerenv": true, "containerEnv": "podman" }),
            )],
            vec![
                sig_at(RuntimeKind::Podman, 0.7, "cgroup", "pattern"),
                sig_at(RuntimeKind::Podman, 0.6, "namespaces", "containerMarkers"),
                sig_at(RuntimeKind::Docker, 0.6, "namespaces", "containerMarkers"),
            ],
            |cx| {
                let v = verdict_of(&Runtime.run(cx));
                assert_eq!(v.runtime, RuntimeKind::Podman);
                assert_eq!(v.variant.as_deref(), Some("nested-in-docker"));
            },
        );
    }
}
