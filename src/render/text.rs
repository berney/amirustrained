use super::Renderer;
use super::style::{self, ColorSupport};
use crate::model::{Counts, Finding, Severity, Verdict};
use crate::pipeline::Event;

#[cfg(test)]
use crate::model::{ProbeOutcome, Report, RuntimeKind, ScanMeta, test_finding}; // via `use super::*`

pub struct Text {
    pub verbose: bool,
    /// Titanium ANSI paint only when on (`make` derives it from
    /// `style::detect`: tty stdout, no `--no-color`/`NO_COLOR`/`TERM=dumb`).
    pub color: ColorSupport,
    /// Probe event names the user opted into (`--probe-syscalls`,
    /// `--probe-ebpf`): their fact lines print even without `--verbose`,
    /// clipped to a report-sized summary (the full value lives in the
    /// machine formats).
    pub optins: Vec<&'static str>,
}

/// One fact as a clipped compact-JSON tail: `probe.key: {…}`. The JSON body
/// rides the titanium tokeniser ([`super::json::highlight`]) so opt-in probe
/// output reads like the `--format json` document. Clip happens on the RAW
/// body first — the `…` sentinel must land outside any SGR run, and a string
/// cut mid-token is total: `string_end` runs to end-of-buffer.
fn fact_line(f: &crate::model::Fact, color: ColorSupport) -> String {
    const MAX: usize = 220;
    let body = match serde_json::to_string(&f.value) {
        Ok(s) => s,
        Err(_) => "<unserializable>".to_string(),
    };
    let shown = if body.chars().count() <= MAX {
        super::json::highlight(&body, color)
    } else {
        let cut: String = body.chars().take(MAX - 1).collect();
        format!("{}…", super::json::highlight(&cut, color))
    };
    format!("  {}.{}: {shown}", f.probe, f.key)
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
            // `verbose` adds the Meta header and every fact line, an opt-in
            // adds just the opted probe's facts.
            Event::Probe(o) => {
                writeln!(
                    w,
                    "probe {}: {}",
                    o.name,
                    match &o.availability {
                        crate::model::Availability::Ok => "ok".into(),
                        crate::model::Availability::Degraded(d) => format!("degraded: {d}"),
                        crate::model::Availability::Unavailable(d) => format!("unavailable: {d}"),
                    }
                )?;
                if self.verbose || self.optins.contains(&o.name.as_str()) {
                    for f in &o.facts {
                        writeln!(w, "{}", fact_line(f, self.color))?;
                    }
                }
            }
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

/// Gutter label in the titanium severity colour ([`style`] table; Critical
/// additionally bold), wrapped only when color is on.
fn gutter(sev: Severity, color: ColorSupport) -> String {
    let label = match sev {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    };
    let prefix = format!(
        "{}{}",
        style::fg(style::severity_fg(sev)),
        if style::severity_bold(sev) {
            style::BOLD
        } else {
            ""
        }
    );
    color.wrap(&prefix, label)
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
    color: ColorSupport,
) -> std::io::Result<()> {
    if let Some(v) = verdict {
        writeln!(
            w,
            "runtime {} (confidence {})",
            color.fg(style::verdict_fg(v.runtime), v.runtime.as_str()),
            v.confidence
        )?;
    }
    if !complete {
        let prefix = format!("{}{}", style::fg(style::ALERT_RED), style::BOLD);
        writeln!(
            w,
            "{}",
            color.wrap(
                &prefix,
                &format!("!! INCOMPLETE SCAN — {timed_out} probe(s) timed out !!")
            )
        )?;
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
            color: ColorSupport::Off,
            optins: vec![],
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

    fn render_text(r: &Report, color: ColorSupport) -> String {
        let mut buf = vec![];
        Text {
            verbose: false,
            color,
            optins: vec![],
        }
        .on_event(&mut buf, &summary_event(r))
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn text_full_layout_snapshot() {
        insta::assert_snapshot!(render_text(&summary_report(true), ColorSupport::Off), @r#"
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
        insta::assert_snapshot!(render_text(&summary_report(false), ColorSupport::Off), @r#"
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
    fn text_color_wraps_gutters_and_verdict_only_when_on() {
        let s = render_text(&summary_report(true), ColorSupport::TrueColor);
        assert!(
            s.contains(&format!(
                "{}{}CRIT{}",
                style::fg(style::ALERT_RED),
                style::BOLD,
                style::RESET
            )),
            "critical gutter: bold alertRed: {s}"
        );
        assert!(
            s.contains(&format!(
                "{}INFO{}",
                style::fg(style::DIM_ALUMINUM),
                style::RESET
            )),
            "info gutter: dimAluminum: {s}"
        );
        assert!(
            s.contains(&format!(
                "{}docker{}",
                style::fg(style::ELECTRIC_BLUE),
                style::RESET
            )),
            "docker verdict must be painted electricBlue: {s}"
        );
        assert!(
            !render_text(&summary_report(true), ColorSupport::Off).contains('\x1b'),
            "Off must emit no escape bytes"
        );
    }

    mod fact_lines {
        use super::*;
        use crate::model::Fact;
        use serde_json::json;

        fn outcome(probe: &str, ns: &str, key: &str, value: serde_json::Value) -> Event {
            let mut o = ProbeOutcome::empty(probe);
            o.facts.push(Fact::ok(ns, key, value, "test".to_string()));
            Event::Probe(o)
        }

        #[test]
        fn optin_probe_facts_print_at_default_verbosity() {
            let mut r = Text {
                verbose: false,
                color: ColorSupport::Off,
                optins: vec!["ebpf-btf"],
            };
            let mut buf = vec![];
            r.on_event(
                &mut buf,
                &outcome(
                    "ebpf-btf",
                    "ebpf",
                    "btf",
                    json!({"summary": "btfSyscall=ok"}),
                ),
            )
            .unwrap();
            let s = String::from_utf8(buf).unwrap();
            assert!(s.contains("probe ebpf-btf: ok\n"), "{s}");
            assert!(
                s.contains("  ebpf.btf: {\"summary\":\"btfSyscall=ok\"}"),
                "{s}"
            );
            // A probe the user did not opt into stays a single status line.
            let mut buf = vec![];
            r.on_event(&mut buf, &outcome("ebpf", "ebpf", "knobs", json!({"x": 1})))
                .unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), "probe ebpf: ok\n");
        }

        #[test]
        fn verbose_prints_every_fact_and_clips_long_values() {
            let mut r = Text {
                verbose: true,
                color: ColorSupport::Off,
                optins: vec![],
            };
            let mut buf = vec![];
            r.on_event(
                &mut buf,
                &outcome(
                    "seccomp",
                    "seccomp",
                    "mode",
                    json!({"blob": "z".repeat(400)}),
                ),
            )
            .unwrap();
            let line = String::from_utf8(buf)
                .unwrap()
                .lines()
                .find(|l| l.starts_with("  seccomp.mode:"))
                .expect("fact line")
                .to_string();
            // body clipped to exactly 220 chars ending in the ellipsis
            assert!(line.ends_with('…'), "must clip: {line}");
            let body = line.split_once(": ").unwrap().1;
            assert_eq!(body.chars().count(), 220);
        }

        fn fact_event(value: serde_json::Value) -> Event {
            outcome("ebpf-btf", "ebpf", "load", value)
        }

        #[test]
        fn fact_json_is_titanium_highlighted_when_color_on() {
            let mut r = Text {
                verbose: false,
                color: ColorSupport::TrueColor,
                optins: vec!["ebpf-btf"],
            };
            let mut buf = vec![];
            r.on_event(
                &mut buf,
                &fact_event(serde_json::json!({"status": "ok", "fd": 7, "errno": null})),
            )
            .unwrap();
            let s = String::from_utf8(buf).unwrap();
            // key electricBlue, string value gold, number amber, null green;
            // every SGR run is reset, and the token text survives untouched.
            assert!(
                s.contains(&format!(
                    "{}\"status\"{}",
                    style::fg(style::ELECTRIC_BLUE),
                    style::RESET
                )),
                "key must be electricBlue: {s}"
            );
            assert!(s.contains(&format!(
                "{}\"ok\"{}",
                style::fg(style::TITANIUM_GOLD),
                style::RESET
            )));
            assert!(s.contains(&format!(
                "{}7{}",
                style::fg(style::WARNING_AMBER),
                style::RESET
            )));
            assert!(s.contains(&format!(
                "{}null{}",
                style::fg(style::READOUT_GREEN),
                style::RESET
            )));
            // Off on the same payload: zero escape bytes (piped contract).
            let mut r = Text {
                verbose: false,
                color: ColorSupport::Off,
                optins: vec!["ebpf-btf"],
            };
            let mut buf = vec![];
            r.on_event(
                &mut buf,
                &fact_event(serde_json::json!({"status": "ok", "fd": 7, "errno": null})),
            )
            .unwrap();
            let plain = String::from_utf8(buf).unwrap();
            assert!(!plain.contains('\x1b'), "Off emits no escapes: {plain}");
            assert!(plain.contains("  ebpf.load: {\"status\":\"ok\",\"fd\":7,\"errno\":null}"));
        }

        #[test]
        fn clipped_fact_ends_with_ellipsis_outside_any_sgr_run() {
            let mut r = Text {
                verbose: true,
                color: ColorSupport::TrueColor,
                optins: vec![],
            };
            let mut buf = vec![];
            r.on_event(
                &mut buf,
                &fact_event(serde_json::json!({"blob": "z".repeat(400)})),
            )
            .unwrap();
            let line = String::from_utf8(buf)
                .unwrap()
                .lines()
                .find(|l| l.starts_with("  ebpf.load:"))
                .expect("fact line")
                .to_string();
            assert!(line.ends_with('…'), "clip sentinel last: {line}");
            // The gold string token is still open (no closing quote after the
            // cut) and must be reset before the sentinel, not swallow it.
            assert!(line.ends_with(&format!("{}…", style::RESET)), "{line}");
            let visible: String = {
                let mut v = String::new();
                let mut it = line.chars();
                while let Some(c) = it.next() {
                    if c == '\x1b' {
                        for t in it.by_ref() {
                            if t == 'm' {
                                break;
                            }
                        }
                    } else {
                        v.push(c);
                    }
                }
                v
            };
            let body = visible.split_once(": ").unwrap().1;
            assert_eq!(
                body.chars().count(),
                220,
                "visible body stays 220: {visible}"
            );
        }
    }
}
