use super::Renderer;
use crate::model::{Availability, Finding, ProbeOutcome, Report, Severity};
use crate::pipeline::Event;

/// Markdown document renderer (spec §7 `markdown`): like `json`, the whole
/// output hangs off `Event::Summary`; streaming events are dropped.
pub struct Markdown;

impl Renderer for Markdown {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        if let Event::Summary { report, .. } = ev {
            document(w, report)?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

fn section_title(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Spec §9 markdown document: title, an incomplete banner when the scan did
/// not complete (spec §5: only ever timed-out probes), verdict table,
/// degraded-probe list, one `## SEVERITY` section per non-empty group
/// (findings keep registry order inside a section), counts line.
fn document(w: &mut dyn std::io::Write, r: &Report) -> std::io::Result<()> {
    writeln!(w, "# amirustrained report")?;
    writeln!(w)?;
    // Spec §5: an incomplete scan only ever means timed-out probes; state it
    // rather than leaving readers to infer it from the degraded list.
    if !r.scan.complete {
        let timed_out = r.probes.iter().filter(|p| p.timed_out).count();
        writeln!(w, "scan incomplete: {timed_out} probe(s) timed out")?;
        writeln!(w)?;
    }
    if let Some(v) = &r.verdict {
        writeln!(w, "| runtime | variant | confidence |")?;
        writeln!(w, "|---|---|---|")?;
        writeln!(
            w,
            "| {} | {} | {} |",
            v.runtime.as_str(),
            v.variant.as_deref().unwrap_or("-"),
            v.confidence
        )?;
        writeln!(w)?;
    }
    let degraded: Vec<&ProbeOutcome> = r
        .probes
        .iter()
        .filter(|p| p.availability != Availability::Ok)
        .collect();
    if !degraded.is_empty() {
        writeln!(w, "## Degraded probes")?;
        for p in degraded {
            let detail = match &p.availability {
                Availability::Degraded(d) => format!("degraded: {d}"),
                Availability::Unavailable(d) => format!("unavailable: {d}"),
                Availability::Ok => continue,
            };
            writeln!(w, "- {}: {detail}", p.name)?;
        }
        writeln!(w)?;
    }
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let group: Vec<&Finding> = r.findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        writeln!(w, "## {}", section_title(sev))?;
        writeln!(w)?;
        for f in group {
            writeln!(w, "### {} — {}", f.rule, f.summary)?;
            writeln!(w)?;
            writeln!(w, "- why: {}", f.why)?;
            writeln!(w, "- fix: {}", f.remediation)?;
            if !f.evidence.is_empty() {
                writeln!(w, "- evidence:")?;
                for ev in &f.evidence {
                    let value = serde_json::to_string(&ev.value).map_err(std::io::Error::other)?;
                    writeln!(w, "  - {}.{} = {} ({})", ev.probe, ev.key, value, ev.source)?;
                }
            }
            writeln!(w)?;
        }
    }
    writeln!(
        w,
        "{} findings (c{} h{} m{} l{} i{})",
        r.counts.critical + r.counts.high + r.counts.medium + r.counts.low + r.counts.info,
        r.counts.critical,
        r.counts.high,
        r.counts.medium,
        r.counts.low,
        r.counts.info
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Availability, ProbeOutcome, Report, RuntimeKind, ScanMeta, Severity, Verdict, test_finding,
    };

    fn fixture() -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(Verdict {
            runtime: RuntimeKind::Docker,
            variant: None,
            confidence: "high".into(),
            alternatives: vec![],
            evidence: vec![],
        });
        r.probes = vec![
            ProbeOutcome::empty("capabilities"),
            ProbeOutcome {
                availability: Availability::Degraded("apparmor fs not mounted".into()),
                ..ProbeOutcome::empty("lsm")
            },
        ];
        // Emission order pins section ordering AND registry order within the
        // HIGH group (AMR-022 precedes AMR-007 in the RULES slice).
        r.findings = vec![
            test_finding("AMR-002", Severity::High),
            test_finding("AMR-005", Severity::Medium),
            test_finding("AMR-022", Severity::High),
            test_finding("AMR-009", Severity::Info),
        ];
        r.compute_counts();
        r
    }

    #[test]
    fn markdown_structure_snapshot() {
        let r = fixture();
        let mut buf = vec![];
        Markdown
            .on_event(
                &mut buf,
                &Event::Summary {
                    verdict: r.verdict.clone(),
                    findings: r.findings.clone(),
                    counts: r.counts.clone(),
                    complete: true,
                    report: Box::new(r),
                },
            )
            .unwrap();
        insta::assert_snapshot!(String::from_utf8(buf).unwrap(), @r#"
        # amirustrained report

        | runtime | variant | confidence |
        |---|---|---|
        | docker | - | high |

        ## Degraded probes
        - lsm: degraded: apparmor fs not mounted

        ## HIGH

        ### AMR-002 — Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement

        - why: This is the `--privileged` signature: CAP_SYS_ADMIN plus no seccomp filter plus nothing confining the task with mandatory access control — an explicit AppArmor `unconfined` profile, or no AppArmor while SELinux is permissive or absent from the active LSM stack. Mount filesystems, reach raw devices, drive cgroup release_agent — the container boundary is nominal and kernel-interface exploits run unopposed by every mitigation the runtime would provide.
        - fix: Drop `--privileged` and CAP_SYS_ADMIN; keep the runtime's default seccomp and AppArmor profiles and add back only the specific capabilities the workload needs.
        - evidence:
          - capabilities.effective = ["cap_sys_admin"] (test)

        ### AMR-022 — Rootless container runtime API socket is reachable and writable

        - why: A rootless runtime daemon serves this socket as an ordinary unprivileged host user: whoever can write to it launches containers as that uid — read access to its home directory, keys, cron, and any sudo grant it holds. That is a container-to-host-user escape, not a host-root promise.
        - fix: Remove the socket mount from the workload and broker the API through a least-privilege proxy; treat the owning user account like any other interactive host account.
        - evidence:
          - capabilities.effective = ["cap_sys_admin"] (test)

        ## MEDIUM

        ### AMR-005 — Seccomp filter disabled inside a container

        - why: With seccomp mode 0 every syscall the kernel implements is reachable from container processes; the mitigation that normally removes the kernel entry points behind container escapes (fsconfig/af_packet class, CVE-2022-0185 and friends) is switched off.
        - fix: Start the container with the runtime's default seccomp profile (`--security-opt seccomp=runtime/default`) and extend a custom profile only for calls the workload genuinely needs.
        - evidence:
          - capabilities.effective = ["cap_sys_admin"] (test)

        ## INFO

        ### AMR-009 — Container runs on the legacy cgroup v1 hierarchy

        - why: cgroup v1 carries the `release_agent`/`notify_on_release` host-exec interfaces behind the classic container escapes (CVE-2022-0492 and family): a task that can reach or remount a writable v1 hierarchy while holding CAP_SYS_ADMIN runs helpers on the host. v1 also lacks the userns-aware delegation that makes v2 safe to hand container slices over.
        - fix: Boot/migrate the host to the unified hierarchy (cgroup v2 is the default on every current distribution); where v1 is unavoidable, mount the container's cgroupfs read-only.
        - evidence:
          - capabilities.effective = ["cap_sys_admin"] (test)

        4 findings (c0 h2 m1 l0 i1)
        "#);
    }

    #[test]
    fn markdown_ignores_non_summary_events() {
        let mut buf = vec![];
        Markdown
            .on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn markdown_flags_timed_out_scan_as_incomplete() {
        let mut r = fixture();
        r.scan.complete = false;
        r.probes.push(ProbeOutcome {
            timed_out: true,
            availability: Availability::Unavailable("timed out".into()),
            ..ProbeOutcome::empty("slow")
        });
        let mut buf = vec![];
        Markdown
            .on_event(
                &mut buf,
                &Event::Summary {
                    verdict: r.verdict.clone(),
                    findings: r.findings.clone(),
                    counts: r.counts.clone(),
                    complete: false,
                    report: Box::new(r),
                },
            )
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.lines()
                .any(|l| l == "scan incomplete: 1 probe(s) timed out"),
            "incomplete scan must state the timed-out count: {s}"
        );
    }
}
