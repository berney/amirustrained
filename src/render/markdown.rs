use super::Renderer;
use super::style::{self, ColorSupport};
use crate::model::{Availability, Finding, ProbeOutcome, Report, Severity};
use crate::pipeline::Event;

/// Markdown document renderer (spec §7 `markdown`): like `json`, the whole
/// output hangs off `Event::Summary`; streaming events are dropped.
///
/// Titanium paint (off ⇒ byte-identical plain text): headings electricBlue
/// (H1 additionally underlined), list bullets electricBlue, the verdict
/// runtime by kind ([`style::verdict_fg`]), table borders subtleGray, the
/// `## SEVERITY` headers in the severity colour (Critical bold, the same
/// ladder as the text gutters), evidence values readoutGreen (the inline
/// code role), evidence sources dimAluminum. The document carries no links,
/// so OMP's OSC-8 link handling does not apply here.
pub struct Markdown {
    pub color: ColorSupport,
}

impl Renderer for Markdown {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        if let Event::Summary { report, .. } = ev {
            document(w, report, self.color)?;
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
fn document(w: &mut dyn std::io::Write, r: &Report, color: ColorSupport) -> std::io::Result<()> {
    let pipe = || color.fg(style::DIM_ALUMINUM, "|");
    let dash = color.fg(style::ELECTRIC_BLUE, "-");
    let h1 = format!(
        "{}{}{}",
        style::fg(style::ELECTRIC_BLUE),
        style::BOLD,
        style::UNDERLINE
    );
    let h2 = format!("{}{}", style::fg(style::ELECTRIC_BLUE), style::BOLD);
    writeln!(w, "{}", color.wrap(&h1, "# amirustrained report"))?;
    writeln!(w)?;
    // Spec §5: an incomplete scan only ever means timed-out probes; state it
    // rather than leaving readers to infer it from the degraded list.
    if !r.scan.complete {
        let timed_out = r.probes.iter().filter(|p| p.timed_out).count();
        let banner = format!("scan incomplete: {timed_out} probe(s) timed out");
        let alarm = format!("{}{}", style::fg(style::ALERT_RED), style::BOLD);
        writeln!(w, "{}", color.wrap(&alarm, &banner))?;
        writeln!(w)?;
    }
    if let Some(v) = &r.verdict {
        writeln!(
            w,
            "{} runtime {} variant {} confidence {}",
            pipe(),
            pipe(),
            pipe(),
            pipe()
        )?;
        writeln!(
            w,
            "{}",
            color.wrap(&style::fg(style::SUBTLE_GRAY), "|---|---|---|")
        )?;
        writeln!(
            w,
            "{} {} {} {} {} {} {}",
            pipe(),
            color.fg(style::verdict_fg(v.runtime), v.runtime.as_str()),
            pipe(),
            v.variant.as_deref().unwrap_or("-"),
            pipe(),
            v.confidence,
            pipe()
        )?;
        writeln!(w)?;
    }
    let degraded: Vec<&ProbeOutcome> = r
        .probes
        .iter()
        .filter(|p| p.availability != Availability::Ok)
        .collect();
    if !degraded.is_empty() {
        writeln!(w, "{}", color.wrap(&h2, "## Degraded probes"))?;
        for p in degraded {
            let detail = match &p.availability {
                Availability::Degraded(d) => format!("degraded: {d}"),
                Availability::Unavailable(d) => format!("unavailable: {d}"),
                Availability::Ok => continue,
            };
            writeln!(w, "{} {}: {detail}", dash, p.name)?;
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
        let sec = format!("## {}", section_title(sev));
        let sec_prefix = format!(
            "{}{}",
            style::fg(style::severity_fg(sev)),
            if style::severity_bold(sev) {
                style::BOLD
            } else {
                ""
            }
        );
        writeln!(w, "{}", color.wrap(&sec_prefix, &sec))?;
        writeln!(w)?;
        for f in group {
            writeln!(
                w,
                "{}",
                color.wrap(&h2, &format!("### {} — {}", f.rule, f.summary))
            )?;
            writeln!(w)?;
            writeln!(w, "{} why: {}", dash, f.why)?;
            writeln!(w, "{} fix: {}", dash, f.remediation)?;
            if !f.evidence.is_empty() {
                writeln!(w, "{} evidence:", dash)?;
                for ev in &f.evidence {
                    let value = serde_json::to_string(&ev.value).map_err(std::io::Error::other)?;
                    writeln!(
                        w,
                        "  {} {}.{} = {} {}",
                        dash,
                        ev.probe,
                        ev.key,
                        color.fg(style::READOUT_GREEN, &value),
                        color.fg(style::DIM_ALUMINUM, &format!("({})", ev.source))
                    )?;
                }
            }
            writeln!(w)?;
        }
    }
    let tok = |label: &str, n: usize, sev: Severity| {
        color.wrap(&style::fg(style::severity_fg(sev)), &format!("{label}{n}"))
    };
    writeln!(
        w,
        "{} findings ({} {} {} {} {})",
        r.counts.critical + r.counts.high + r.counts.medium + r.counts.low + r.counts.info,
        tok("c", r.counts.critical, Severity::Critical),
        tok("h", r.counts.high, Severity::High),
        tok("m", r.counts.medium, Severity::Medium),
        tok("l", r.counts.low, Severity::Low),
        tok("i", r.counts.info, Severity::Info),
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
        insta::assert_snapshot!(render_md(r, ColorSupport::Off), @r#"
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
        Markdown {
            color: ColorSupport::Off,
        }
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
        let s = render_md(r, ColorSupport::Off);
        assert!(
            s.lines()
                .any(|l| l == "scan incomplete: 1 probe(s) timed out"),
            "incomplete scan must state the timed-out count: {s}"
        );
    }

    /// One render path for every markdown test (Off keeps snapshots plain).
    fn render_md(r: Report, color: ColorSupport) -> String {
        let complete = r.scan.complete;
        let mut buf = vec![];
        Markdown { color }
            .on_event(
                &mut buf,
                &Event::Summary {
                    verdict: r.verdict.clone(),
                    findings: r.findings.clone(),
                    counts: r.counts.clone(),
                    complete,
                    report: Box::new(r),
                },
            )
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn markdown_paints_headings_bullets_and_severity_under_forced_colour() {
        let on = render_md(fixture(), ColorSupport::TrueColor);
        // H1: electricBlue + bold + underline.
        assert!(
            on.contains(&format!(
                "{}{}{}# amirustrained report{}",
                style::fg(style::ELECTRIC_BLUE),
                style::BOLD,
                style::UNDERLINE,
                style::RESET
            )),
            "H1 painted: {on}"
        );
        // HIGH section header carries the severity ladder (warningAmber).
        assert!(
            on.contains(&format!(
                "{}## HIGH{}",
                style::fg(style::WARNING_AMBER),
                style::RESET
            )),
            "HIGH header amber: {on}"
        );
        // Bullets electricBlue; verdict runtime by kind (docker → blue).
        assert!(on.contains(&format!(
            "{}-{}",
            style::fg(style::ELECTRIC_BLUE),
            style::RESET
        )));
        assert!(on.contains(&format!(
            "{}docker{}",
            style::fg(style::ELECTRIC_BLUE),
            style::RESET
        )));
        // Evidence value in the inline-code role (readoutGreen).
        assert!(on.contains(&style::fg(style::READOUT_GREEN)));
        // Structured content survives the paint: stripping SGR reproduces
        // the exact plain document the snapshot pins.
        let stripped: String = {
            let mut out = String::with_capacity(on.len());
            let mut it = on.chars().peekable();
            while let Some(c) = it.next() {
                if c == '\x1b' {
                    if it.peek() == Some(&'[') {
                        it.next();
                        for t in it.by_ref() {
                            if t == 'm' {
                                break;
                            }
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(stripped, render_md(fixture(), ColorSupport::Off));
    }
}
