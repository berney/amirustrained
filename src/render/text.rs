use super::Renderer;
use crate::model::{Counts, Finding, Severity, Verdict};
use crate::pipeline::Event;

#[cfg(test)]
use crate::model::{ProbeOutcome, Report, RuntimeKind, ScanMeta, test_finding}; // via `use super::*`

pub struct Text {
    pub verbose: bool,
    /// ANSI paint only when true (`make` derives it from tty/`--no-color`).
    pub color: bool,
}

impl Renderer for Text {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        match ev {
            Event::Meta { tool, scan } if self.verbose => writeln!(
                w,
                "{} {} scanning pid {} (uid {})",
                tool.name, tool.version, scan.target_pid, scan.uid
            )?,
            // Probe status lines are always on (the minimal-text contract);
            // `verbose` only adds the Meta header above.
            Event::Probe(o) => writeln!(
                w,
                "probe {}: {}",
                o.name,
                match &o.availability {
                    crate::model::Availability::Ok => "ok".into(),
                    crate::model::Availability::Degraded(d) => format!("degraded: {d}"),
                    crate::model::Availability::Unavailable(d) => format!("unavailable: {d}"),
                }
            )?,
            Event::Summary {
                verdict,
                findings,
                counts,
                complete,
                report,
            } => summary_block(
                w,
                verdict.as_ref(),
                findings,
                counts,
                *complete,
                // Spec §5: a non-complete scan only ever means timed-out probes.
                report.probes.iter().filter(|p| p.timed_out).count(),
                self.color,
            )?,
            _ => {}
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

/// Gutter label with its per-severity ANSI foreground (spec §9: bright-red,
/// red, yellow, blue, cyan), wrapped only when color is enabled.
fn gutter(sev: Severity, color: bool) -> String {
    let (label, ansi) = match sev {
        Severity::Critical => ("CRIT", "\x1b[91m"),
        Severity::High => ("HIGH", "\x1b[31m"),
        Severity::Medium => ("MED", "\x1b[33m"),
        Severity::Low => ("LOW", "\x1b[34m"),
        Severity::Info => ("INFO", "\x1b[36m"),
    };
    if color {
        format!("{ansi}{label}\x1b[0m")
    } else {
        label.to_string()
    }
}

/// Slug lookup so a line reads `AMR-xxx slug: summary`; findings only ever
/// come from the RULES registry, but the renderer never panics on a foreign id.
fn slug_of(id: &str) -> &'static str {
    crate::model::rules::RULES
        .iter()
        .find(|r| r.id == id)
        .map_or("-", |r| r.slug)
}

/// Spec §9 summary layout: verdict line, timeout-count INCOMPLETE banner
/// directly below it when the scan did not complete (spec §5: that only ever
/// means timed-out probes), findings severity-descending (the sort is stable,
/// so registry order survives within a group), each finding preceded by a
/// blank line, then the counts footer and — only for a complete scan — the
/// completion line.
fn summary_block(
    w: &mut dyn std::io::Write,
    verdict: Option<&Verdict>,
    findings: &[Finding],
    counts: &Counts,
    complete: bool,
    timed_out: usize,
    color: bool,
) -> std::io::Result<()> {
    if let Some(v) = verdict {
        writeln!(
            w,
            "runtime {} (confidence {})",
            v.runtime.as_str(),
            v.confidence
        )?;
    }
    if !complete {
        writeln!(w, "!! INCOMPLETE SCAN — {timed_out} probe(s) timed out !!")?;
    }
    let mut order: Vec<&Finding> = findings.iter().collect();
    // Stable sort keeps registry order inside each severity group.
    order.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in &order {
        writeln!(w)?;
        writeln!(
            w,
            "{} {} {}: {}",
            gutter(f.severity, color),
            f.rule,
            slug_of(f.rule),
            f.summary
        )?;
        writeln!(w, "  why: {}", f.why)?;
        writeln!(w, "  fix: {}", f.remediation)?;
        for ev in &f.evidence {
            let value = serde_json::to_string(&ev.value).map_err(std::io::Error::other)?;
            writeln!(
                w,
                "    - {}.{} = {} ({})",
                ev.probe, ev.key, value, ev.source
            )?;
        }
    }
    if !order.is_empty() {
        writeln!(w)?;
    }
    writeln!(
        w,
        "{} findings (c{} h{} m{} l{} i{})",
        counts.critical + counts.high + counts.medium + counts.low + counts.info,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    )?;
    if complete {
        writeln!(w, "scan complete")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimal_text_emits_probe_lines_and_summary() {
        let mut buf = vec![];
        let mut r = Text {
            verbose: false,
            color: false,
        };
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        r.on_event(
            &mut buf,
            &Event::Summary {
                verdict: None,
                findings: vec![],
                counts: Counts::default(),
                complete: true,
                report: Box::new(Report::blank(ScanMeta::stub(), 1)),
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("probe uidmap: ok"));
        assert!(s.contains("scan complete"));
    }

    fn docker_verdict() -> Verdict {
        Verdict {
            runtime: RuntimeKind::Docker,
            variant: None,
            confidence: "high".into(),
            alternatives: vec![],
            evidence: vec![],
        }
    }

    /// Findings in registry emission order (AMR-022 precedes AMR-007 in the
    /// RULES slice); the two Infos pin order-stability within a group.
    fn summary_report(complete: bool) -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(docker_verdict());
        r.findings = vec![
            test_finding("AMR-002", Severity::Critical),
            test_finding("AMR-022", Severity::Info),
            test_finding("AMR-007", Severity::Info),
        ];
        if !complete {
            // Spec §5: incompleteness is driven by timed-out probes; the
            // banner below counts them.
            r.probes.push(ProbeOutcome {
                timed_out: true,
                availability: crate::model::Availability::Unavailable("timed out".into()),
                ..ProbeOutcome::empty("slow")
            });
        }
        r.scan.complete = complete;
        r.compute_counts();
        r
    }

    fn summary_event(r: &Report) -> Event {
        Event::Summary {
            verdict: r.verdict.clone(),
            findings: r.findings.clone(),
            counts: r.counts.clone(),
            complete: r.scan.complete,
            report: Box::new(r.clone()),
        }
    }

    fn render_text(r: &Report, color: bool) -> String {
        let mut buf = vec![];
        Text {
            verbose: false,
            color,
        }
        .on_event(&mut buf, &summary_event(r))
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn text_full_layout_snapshot() {
        insta::assert_snapshot!(render_text(&summary_report(true), false), @r#"
        runtime docker (confidence high)

        CRIT AMR-002 privileged-container: Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement
          why: This is the `--privileged` signature: CAP_SYS_ADMIN plus no seccomp filter plus nothing confining the task with mandatory access control — an explicit AppArmor `unconfined` profile, or no AppArmor while SELinux is permissive or absent from the active LSM stack. Mount filesystems, reach raw devices, drive cgroup release_agent — the container boundary is nominal and kernel-interface exploits run unopposed by every mitigation the runtime would provide.
          fix: Drop `--privileged` and CAP_SYS_ADMIN; keep the runtime's default seccomp and AppArmor profiles and add back only the specific capabilities the workload needs.
            - capabilities.effective = ["cap_sys_admin"] (test)

        INFO AMR-022 rootless-socket-exposed: Rootless container runtime API socket is reachable and writable
          why: A rootless runtime daemon serves this socket as an ordinary unprivileged host user: whoever can write to it launches containers as that uid — read access to its home directory, keys, cron, and any sudo grant it holds. That is a container-to-host-user escape, not a host-root promise.
          fix: Remove the socket mount from the workload and broker the API through a least-privilege proxy; treat the owning user account like any other interactive host account.
            - capabilities.effective = ["cap_sys_admin"] (test)

        INFO AMR-007 selinux-permissive-in-container: SELinux context present while the policy runs permissive
          why: Permissive SELinux logs denials but enforces none of them: the task's label is decorative, and every containment assumption that rests on mandatory access control is void — on RHEL-family hosts SELinux is the only active LSM, so permissive here means no MAC layer at all, while the audit log quietly accumulates the attacks that were not stopped.
          fix: Return SELinux to enforcing (`setenforce 1`, `enforcing=1` on the kernel command line) and resolve the logged denials through an `audit2allow` policy review instead of leaving the system permissive; per-domain permissive is a debugging tool, not a deployment mode.
            - capabilities.effective = ["cap_sys_admin"] (test)

        3 findings (c1 h0 m0 l0 i2)
        scan complete
        "#);
    }

    #[test]
    fn text_incomplete_variant_snapshot() {
        insta::assert_snapshot!(render_text(&summary_report(false), false), @r#"
        runtime docker (confidence high)
        !! INCOMPLETE SCAN — 1 probe(s) timed out !!

        CRIT AMR-002 privileged-container: Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement
          why: This is the `--privileged` signature: CAP_SYS_ADMIN plus no seccomp filter plus nothing confining the task with mandatory access control — an explicit AppArmor `unconfined` profile, or no AppArmor while SELinux is permissive or absent from the active LSM stack. Mount filesystems, reach raw devices, drive cgroup release_agent — the container boundary is nominal and kernel-interface exploits run unopposed by every mitigation the runtime would provide.
          fix: Drop `--privileged` and CAP_SYS_ADMIN; keep the runtime's default seccomp and AppArmor profiles and add back only the specific capabilities the workload needs.
            - capabilities.effective = ["cap_sys_admin"] (test)

        INFO AMR-022 rootless-socket-exposed: Rootless container runtime API socket is reachable and writable
          why: A rootless runtime daemon serves this socket as an ordinary unprivileged host user: whoever can write to it launches containers as that uid — read access to its home directory, keys, cron, and any sudo grant it holds. That is a container-to-host-user escape, not a host-root promise.
          fix: Remove the socket mount from the workload and broker the API through a least-privilege proxy; treat the owning user account like any other interactive host account.
            - capabilities.effective = ["cap_sys_admin"] (test)

        INFO AMR-007 selinux-permissive-in-container: SELinux context present while the policy runs permissive
          why: Permissive SELinux logs denials but enforces none of them: the task's label is decorative, and every containment assumption that rests on mandatory access control is void — on RHEL-family hosts SELinux is the only active LSM, so permissive here means no MAC layer at all, while the audit log quietly accumulates the attacks that were not stopped.
          fix: Return SELinux to enforcing (`setenforce 1`, `enforcing=1` on the kernel command line) and resolve the logged denials through an `audit2allow` policy review instead of leaving the system permissive; per-domain permissive is a debugging tool, not a deployment mode.
            - capabilities.effective = ["cap_sys_admin"] (test)

        3 findings (c1 h0 m0 l0 i2)
        "#);
    }

    #[test]
    fn text_color_wraps_gutters_only_when_enabled() {
        let s = render_text(&summary_report(true), true);
        assert!(
            s.contains("\x1b[91mCRIT\x1b[0m"),
            "critical gutter must be bright red: {s}"
        );
        assert!(s.contains("\x1b[36mINFO\x1b[0m"), "info must be cyan: {s}");
        assert!(
            !render_text(&summary_report(true), false).contains('\x1b'),
            "color=false must emit no escape bytes"
        );
    }
}
