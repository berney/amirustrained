use super::Renderer;
use super::style::{self, ColorSupport};
use crate::model::{Finding, Report, Severity, Verdict};
use crate::pipeline::Event;

#[cfg(test)]
use crate::model::{Counts, ProbeOutcome, RuntimeKind, ScanMeta, test_finding}; // via `use super::*`

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
    /// Single-line diffable finding mode (`--compact` / `--terse`).
    pub compact: bool,
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
            // Suppress probe <name>: ok unless verbose. Degraded/unavailable
            // probes emit single-line notices to stderr.
            Event::Probe(o) => {
                if self.verbose {
                    writeln!(
                        w,
                        "probe {}: {}",
                        o.name,
                        match &o.availability {
                            crate::model::Availability::Ok => "ok".into(),
                            crate::model::Availability::Degraded(d) => format!("degraded: {d}"),
                            crate::model::Availability::Unavailable(d) =>
                                format!("unavailable: {d}"),
                        }
                    )?;
                    for f in &o.facts {
                        writeln!(w, "{}", fact_line(f, self.color))?;
                    }
                } else {
                    match &o.availability {
                        crate::model::Availability::Degraded(d) => {
                            eprintln!("probe {}: degraded: {d}", o.name);
                        }
                        crate::model::Availability::Unavailable(d) => {
                            eprintln!("probe {}: unavailable: {d}", o.name);
                        }
                        crate::model::Availability::Ok => {}
                    }
                    if self.optins.contains(&o.name.as_str()) {
                        for f in &o.facts {
                            writeln!(w, "{}", fact_line(f, self.color))?;
                        }
                    }
                }
            }
            Event::Summary { report, .. } => summary_block(w, report, self.color, self.compact)?,
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

/// Formats the 5-line Environment & Identity Header at the top of the report:
///
/// Host:       Linux <release> (<arch>) | distro: <distro> | runtime: <runtime> (confidence <conf>)
/// Identity:   uid=<uid>(<user>) gid=<gid>(<group>) groups=<groups>
/// Caps:       <eff_hex> (<count> caps) [eff=<eff_hex> bnd=<bnd_hex> inh=<inh_hex>]
/// Sandboxing: no_new_privs=<0|1> seccomp=<mode> lockdown=<mode>
/// Visibility: pid_ns=<isolated|host> (<N> procs visible, pid 1="<cmd>", procfs hidepid=<val>)
fn format_identity_header(
    w: &mut dyn std::io::Write,
    report: &Report,
    verdict: Option<&Verdict>,
    color: ColorSupport,
) -> std::io::Result<()> {
    let pipe = color.fg(style::DIM_ALUMINUM, "|");

    // Line 1: Host
    let kernel = if report.scan.kernel.is_empty() {
        "unknown"
    } else {
        &report.scan.kernel
    };
    let linux_str = if kernel.starts_with("Linux") {
        kernel.to_string()
    } else {
        format!("Linux {kernel}")
    };
    let arch = if report.scan.arch.is_empty() {
        "unknown"
    } else {
        &report.scan.arch
    };
    let host_os = format!("{linux_str} ({arch})");
    let distro = report.scan.distro.as_deref().unwrap_or("unknown");
    let (runtime_str, conf) = match verdict {
        Some(v) => (
            color.fg(style::verdict_fg(v.runtime), v.runtime.as_str()),
            v.confidence.as_str(),
        ),
        None => ("unknown".to_string(), "none"),
    };
    writeln!(
        w,
        "{}{} {} distro: {} {} runtime: {} (confidence {})",
        color.fg(style::ELECTRIC_BLUE, "Host:       "),
        host_os,
        pipe,
        distro,
        pipe,
        runtime_str,
        conf
    )?;

    // Line 2: Identity
    let uid = report
        .fact("uidmap", "uid")
        .and_then(|f| f.value.as_u64())
        .map_or(report.scan.uid, |u| u as u32);
    let user = report
        .fact("uidmap", "user")
        .and_then(|f| f.value.as_str())
        .unwrap_or(if uid == 0 { "root" } else { "unknown" });
    let gid = report
        .fact("uidmap", "gid")
        .and_then(|f| f.value.as_u64())
        .unwrap_or(0) as u32;
    let group = report
        .fact("uidmap", "group")
        .and_then(|f| f.value.as_str())
        .unwrap_or(if gid == 0 { "root" } else { "unknown" });
    let groups_formatted = report
        .fact("uidmap", "groupsFormatted")
        .and_then(|f| f.value.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            report
                .fact("uidmap", "groups")
                .and_then(|f| f.value.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| {
            if uid == 0 {
                "0(root)".into()
            } else {
                "none".into()
            }
        });
    writeln!(
        w,
        "{}uid={}({}) gid={}({}) groups={}",
        color.fg(style::ELECTRIC_BLUE, "Identity:   "),
        uid,
        user,
        gid,
        group,
        groups_formatted
    )?;

    // Line 3: Caps
    let eff_hex = report
        .fact("capabilities", "hex.effective")
        .and_then(|f| f.value.as_str())
        .unwrap_or("0000000000000000");
    let bnd_hex = report
        .fact("capabilities", "hex.bounding")
        .and_then(|f| f.value.as_str())
        .unwrap_or("0000000000000000");
    let inh_hex = report
        .fact("capabilities", "hex.inheritable")
        .and_then(|f| f.value.as_str())
        .unwrap_or("0000000000000000");
    let count = report
        .fact("capabilities", "effective")
        .and_then(|f| f.value.as_array())
        .map_or(0, |a| a.len());
    let caps_count_str = if count == 41 {
        "all 41 caps".to_string()
    } else {
        format!("{count} caps")
    };
    writeln!(
        w,
        "{}{} ({}) [eff={} bnd={} inh={}]",
        color.fg(style::ELECTRIC_BLUE, "Caps:       "),
        eff_hex,
        caps_count_str,
        eff_hex,
        bnd_hex,
        inh_hex
    )?;

    // Line 4: Sandboxing
    let nnp = report
        .fact("capabilities", "noNewPrivs")
        .and_then(|f| f.value.as_u64())
        .unwrap_or(0);
    let seccomp_str = report
        .fact("seccomp", "mode")
        .and_then(|f| f.value.as_str())
        .map(|m| match m {
            "disabled" => "0(disabled)",
            "strict" => "1(strict)",
            "filter" => "2(filter)",
            other => other,
        })
        .unwrap_or("unknown");
    let lockdown = report
        .fact("lsm", "lockdown")
        .or_else(|| report.fact("kernel.surface", "lockdown"))
        .and_then(|f| f.value.as_str())
        .unwrap_or("none");
    writeln!(
        w,
        "{}no_new_privs={} seccomp={} lockdown={}",
        color.fg(style::ELECTRIC_BLUE, "Sandboxing: "),
        nnp,
        seccomp_str,
        lockdown
    )?;

    // Line 5: Visibility
    let pid_ns = report
        .fact("namespaces", "isolated")
        .and_then(|f| f.value.get("pid"))
        .and_then(|v| v.as_bool())
        .map(|b| if b { "isolated" } else { "host" })
        .unwrap_or("unknown");
    let procs = report
        .fact("namespaces", "visibleProcs")
        .and_then(|f| f.value.as_u64())
        .unwrap_or(0);
    let pid1 = report
        .fact("namespaces", "pid1Cmdline")
        .and_then(|f| f.value.as_str())
        .unwrap_or("unknown");
    let hidepid = report
        .fact("namespaces", "hidepid")
        .and_then(|f| f.value.as_str())
        .unwrap_or("0");
    writeln!(
        w,
        "{}pid_ns={} ({} procs visible, pid 1=\"{}\", procfs hidepid={})",
        color.fg(style::ELECTRIC_BLUE, "Visibility: "),
        pid_ns,
        procs,
        pid1,
        hidepid
    )?;

    Ok(())
}

/// Spec §9 summary layout: identity header, timeout-count INCOMPLETE banner
/// directly below it when the scan did not complete (spec §5: that only ever
/// means timed-out probes), findings severity-descending (the sort is stable,
/// so registry order survives within a group), each finding preceded by a
/// blank line, then the counts footer and — only for a complete scan — the
/// completion line.
fn summary_block(
    w: &mut dyn std::io::Write,
    report: &Report,
    color: ColorSupport,
    compact: bool,
) -> std::io::Result<()> {
    format_identity_header(w, report, report.verdict.as_ref(), color)?;
    if !report.scan.complete {
        let timed_out = report.probes.iter().filter(|p| p.timed_out).count();
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
    let mut order: Vec<&Finding> = report.findings.iter().collect();
    // Stable sort keeps registry order inside each severity group.
    order.sort_by_key(|f| std::cmp::Reverse(f.severity));
    if compact {
        if !order.is_empty() {
            writeln!(w)?;
            for f in &order {
                writeln!(
                    w,
                    "{} {} {}: {}",
                    gutter(f.severity, color),
                    f.rule,
                    slug_of(f.rule),
                    f.summary
                )?;
            }
            writeln!(w)?;
        }
        writeln!(
            w,
            "{} findings (c{} h{} m{} l{} i{})",
            report.counts.critical
                + report.counts.high
                + report.counts.medium
                + report.counts.low
                + report.counts.info,
            report.counts.critical,
            report.counts.high,
            report.counts.medium,
            report.counts.low,
            report.counts.info
        )?;
        return Ok(());
    }
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
        report.counts.critical
            + report.counts.high
            + report.counts.medium
            + report.counts.low
            + report.counts.info,
        report.counts.critical,
        report.counts.high,
        report.counts.medium,
        report.counts.low,
        report.counts.info
    )?;
    if report.scan.complete {
        writeln!(w, "scan complete")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GroupEntry;
    #[test]
    fn minimal_text_suppresses_probe_ok_lines() {
        let mut buf = vec![];
        let mut r = Text {
            verbose: false,
            color: ColorSupport::Off,
            optins: vec![],
            compact: false,
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
        assert!(!s.contains("probe uidmap: ok"));
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
            compact: false,
        }
        .on_event(&mut buf, &summary_event(r))
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn render_text_compact(r: &Report, color: ColorSupport) -> String {
        let mut buf = vec![];
        Text {
            verbose: false,
            color,
            optins: vec![],
            compact: true,
        }
        .on_event(&mut buf, &summary_event(r))
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_test_report(
        kernel: &str,
        arch: &str,
        distro: Option<&str>,
        verdict: Option<Verdict>,
        uid: u32,
        user: &str,
        gid: u32,
        group: &str,
        groups: Vec<&str>,
        eff_hex: &str,
        bnd_hex: &str,
        inh_hex: &str,
        caps_count: usize,
        no_new_privs: u64,
        seccomp_mode: &str,
        lockdown: &str,
        pid_ns_isolated: bool,
        visible_procs: usize,
        pid1_cmd: &str,
        hidepid: &str,
    ) -> Report {
        let mut r = Report::blank(
            ScanMeta {
                target_pid: 1,
                uid,
                user: Some(if uid == 0 {
                    "root".into()
                } else {
                    "user".into()
                }),
                full_name: None,
                gid: 0,
                group: Some("root".into()),
                groups: vec![GroupEntry {
                    gid: 0,
                    name: Some("root".into()),
                }],
                timestamp: "123".into(),
                kernel: kernel.into(),
                arch: arch.into(),
                distro: distro.map(String::from),
                complete: true,
                probe_timeout_s: None,
            },
            1,
        );
        r.verdict = verdict;

        let mut uidmap = ProbeOutcome::empty("uidmap");
        uidmap = uidmap.with_fact(crate::model::Fact::ok(
            "uidmap",
            "uid",
            serde_json::json!(uid),
            "/proc/1/status".into(),
        ));
        uidmap = uidmap.with_fact(crate::model::Fact::ok(
            "uidmap",
            "user",
            serde_json::json!(user),
            "/etc/passwd".into(),
        ));
        uidmap = uidmap.with_fact(crate::model::Fact::ok(
            "uidmap",
            "gid",
            serde_json::json!(gid),
            "/proc/1/status".into(),
        ));
        uidmap = uidmap.with_fact(crate::model::Fact::ok(
            "uidmap",
            "group",
            serde_json::json!(group),
            "/etc/group".into(),
        ));
        uidmap = uidmap.with_fact(crate::model::Fact::ok(
            "uidmap",
            "groups",
            serde_json::json!(groups),
            "/proc/1/status".into(),
        ));
        r.push_probe(uidmap);

        let mut caps = ProbeOutcome::empty("capabilities");
        caps = caps.with_fact(crate::model::Fact::ok(
            "capabilities",
            "hex.effective",
            serde_json::json!(eff_hex),
            "/proc/1/status".into(),
        ));
        caps = caps.with_fact(crate::model::Fact::ok(
            "capabilities",
            "hex.bounding",
            serde_json::json!(bnd_hex),
            "/proc/1/status".into(),
        ));
        caps = caps.with_fact(crate::model::Fact::ok(
            "capabilities",
            "hex.inheritable",
            serde_json::json!(inh_hex),
            "/proc/1/status".into(),
        ));
        let eff_vec: Vec<serde_json::Value> = (0..caps_count)
            .map(|_| serde_json::json!("cap_test"))
            .collect();
        caps = caps.with_fact(crate::model::Fact::ok(
            "capabilities",
            "effective",
            serde_json::json!(eff_vec),
            "/proc/1/status".into(),
        ));
        caps = caps.with_fact(crate::model::Fact::ok(
            "capabilities",
            "noNewPrivs",
            serde_json::json!(no_new_privs),
            "/proc/1/status".into(),
        ));
        r.push_probe(caps);

        let mut seccomp = ProbeOutcome::empty("seccomp");
        seccomp = seccomp.with_fact(crate::model::Fact::ok(
            "seccomp",
            "mode",
            serde_json::json!(seccomp_mode),
            "/proc/1/status".into(),
        ));
        r.push_probe(seccomp);

        let mut lsm = ProbeOutcome::empty("lsm");
        lsm = lsm.with_fact(crate::model::Fact::ok(
            "lsm",
            "lockdown",
            serde_json::json!(lockdown),
            "/sys/kernel/security/lockdown".into(),
        ));
        r.push_probe(lsm);

        let mut namespaces = ProbeOutcome::empty("namespaces");
        namespaces = namespaces.with_fact(crate::model::Fact::ok(
            "namespaces",
            "isolated",
            serde_json::json!({"pid": pid_ns_isolated}),
            "/proc/1/ns".into(),
        ));
        namespaces = namespaces.with_fact(crate::model::Fact::ok(
            "namespaces",
            "visibleProcs",
            serde_json::json!(visible_procs),
            "/proc".into(),
        ));
        namespaces = namespaces.with_fact(crate::model::Fact::ok(
            "namespaces",
            "pid1Cmdline",
            serde_json::json!(pid1_cmd),
            "/proc/1/cmdline".into(),
        ));
        namespaces = namespaces.with_fact(crate::model::Fact::ok(
            "namespaces",
            "hidepid",
            serde_json::json!(hidepid),
            "/proc/mounts".into(),
        ));
        r.push_probe(namespaces);

        r
    }

    #[test]
    fn identity_header_root() {
        let r = make_test_report(
            "6.8.0-142-generic",
            "x86_64",
            Some("Ubuntu 22.04.4 LTS"),
            Some(docker_verdict()),
            0,
            "root",
            0,
            "root",
            vec!["0(root)", "10(wheel)", "998(docker)"],
            "000001ffffffffff",
            "000001ffffffffff",
            "0000000000000000",
            41,
            0,
            "disabled",
            "none",
            true,
            59,
            "/sbin/fireworks-init",
            "0",
        );
        let s = render_text(&r, ColorSupport::Off);
        let expected_header = "\
Host:       Linux 6.8.0-142-generic (x86_64) | distro: Ubuntu 22.04.4 LTS | runtime: docker (confidence high)
Identity:   uid=0(root) gid=0(root) groups=0(root),10(wheel),998(docker)
Caps:       000001ffffffffff (all 41 caps) [eff=000001ffffffffff bnd=000001ffffffffff inh=0000000000000000]
Sandboxing: no_new_privs=0 seccomp=0(disabled) lockdown=none
Visibility: pid_ns=isolated (59 procs visible, pid 1=\"/sbin/fireworks-init\", procfs hidepid=0)";
        assert!(
            s.starts_with(expected_header),
            "header missing or incorrect:\n{s}"
        );
    }

    #[test]
    fn identity_header_unprivileged() {
        let r = make_test_report(
            "6.8.0-142-generic",
            "x86_64",
            Some("Debian GNU/Linux 12 (bookworm)"),
            Some(Verdict {
                runtime: RuntimeKind::Host,
                variant: None,
                confidence: "high".into(),
                alternatives: vec![],
                evidence: vec![],
            }),
            1000,
            "user",
            1000,
            "user",
            vec!["1000(user)"],
            "0000000000000000",
            "000001ffffffffff",
            "0000000000000000",
            0,
            1,
            "filter",
            "integrity",
            false,
            120,
            "/usr/lib/systemd/systemd",
            "2",
        );
        let s = render_text(&r, ColorSupport::Off);
        let expected_header = "\
Host:       Linux 6.8.0-142-generic (x86_64) | distro: Debian GNU/Linux 12 (bookworm) | runtime: host (confidence high)
Identity:   uid=1000(user) gid=1000(user) groups=1000(user)
Caps:       0000000000000000 (0 caps) [eff=0000000000000000 bnd=000001ffffffffff inh=0000000000000000]
Sandboxing: no_new_privs=1 seccomp=2(filter) lockdown=integrity
Visibility: pid_ns=host (120 procs visible, pid 1=\"/usr/lib/systemd/systemd\", procfs hidepid=2)";
        assert!(
            s.starts_with(expected_header),
            "header missing or incorrect:\n{s}"
        );
    }

    #[test]
    fn identity_header_color_styling() {
        let r = make_test_report(
            "6.8.0-142-generic",
            "x86_64",
            Some("Ubuntu 22.04.4 LTS"),
            Some(docker_verdict()),
            0,
            "root",
            0,
            "root",
            vec!["0(root)"],
            "000001ffffffffff",
            "000001ffffffffff",
            "0000000000000000",
            41,
            0,
            "disabled",
            "none",
            true,
            59,
            "/sbin/init",
            "0",
        );
        let s = render_text(&r, ColorSupport::TrueColor);
        assert!(
            s.contains(&style::ColorSupport::TrueColor.fg(style::ELECTRIC_BLUE, "Host:       "))
        );
        assert!(
            s.contains(&style::ColorSupport::TrueColor.fg(style::ELECTRIC_BLUE, "Identity:   "))
        );
        assert!(
            s.contains(&style::ColorSupport::TrueColor.fg(style::ELECTRIC_BLUE, "Caps:       "))
        );
        assert!(
            s.contains(&style::ColorSupport::TrueColor.fg(style::ELECTRIC_BLUE, "Sandboxing: "))
        );
        assert!(
            s.contains(&style::ColorSupport::TrueColor.fg(style::ELECTRIC_BLUE, "Visibility: "))
        );
        assert!(s.contains(&style::ColorSupport::TrueColor.fg(style::DIM_ALUMINUM, "|")));
    }

    #[test]
    fn text_full_layout_snapshot() {
        insta::assert_snapshot!(render_text(&summary_report(true), ColorSupport::Off), @r#"
        Host:       Linux K (A) | distro: unknown | runtime: docker (confidence high)
        Identity:   uid=0(root) gid=0(root) groups=0(root)
        Caps:       0000000000000000 (0 caps) [eff=0000000000000000 bnd=0000000000000000 inh=0000000000000000]
        Sandboxing: no_new_privs=0 seccomp=unknown lockdown=none
        Visibility: pid_ns=unknown (0 procs visible, pid 1="unknown", procfs hidepid=0)

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
        Host:       Linux K (A) | distro: unknown | runtime: docker (confidence high)
        Identity:   uid=0(root) gid=0(root) groups=0(root)
        Caps:       0000000000000000 (0 caps) [eff=0000000000000000 bnd=0000000000000000 inh=0000000000000000]
        Sandboxing: no_new_privs=0 seccomp=unknown lockdown=none
        Visibility: pid_ns=unknown (0 procs visible, pid 1="unknown", procfs hidepid=0)
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
    fn text_compact_layout_snapshot() {
        insta::assert_snapshot!(render_text_compact(&summary_report(true), ColorSupport::Off), @r#"
        Host:       Linux K (A) | distro: unknown | runtime: docker (confidence high)
        Identity:   uid=0(root) gid=0(root) groups=0(root)
        Caps:       0000000000000000 (0 caps) [eff=0000000000000000 bnd=0000000000000000 inh=0000000000000000]
        Sandboxing: no_new_privs=0 seccomp=unknown lockdown=none
        Visibility: pid_ns=unknown (0 procs visible, pid 1="unknown", procfs hidepid=0)

        CRIT AMR-002 privileged-container: Privileged container: CAP_SYS_ADMIN, seccomp disabled, no MAC confinement
        INFO AMR-022 rootless-socket-exposed: Rootless container runtime API socket is reachable and writable
        INFO AMR-007 selinux-permissive-in-container: SELinux context present while the policy runs permissive

        3 findings (c1 h0 m0 l0 i2)
        "#);
    }

    #[test]
    fn text_compact_color_wraps_gutters() {
        let s = render_text_compact(&summary_report(true), ColorSupport::TrueColor);
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
            !s.contains("  why:"),
            "compact mode must omit why block: {s}"
        );
        assert!(
            !s.contains("  fix:"),
            "compact mode must omit fix block: {s}"
        );
        assert!(
            !s.contains("scan complete"),
            "compact mode must omit scan complete: {s}"
        );
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

    #[test]
    fn format_identity_header_falls_back_to_kernel_surface_lockdown() {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        let mut surface = ProbeOutcome::empty("kernel-surface");
        surface = surface.with_fact(crate::model::Fact::ok(
            "kernel.surface",
            "lockdown",
            serde_json::json!("confidentiality"),
            "/sys/kernel/security/lockdown".into(),
        ));
        r.push_probe(surface);
        let mut buf = Vec::new();
        format_identity_header(&mut buf, &r, None, ColorSupport::Off).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("lockdown=confidentiality"),
            "header must show fallback lockdown: {s}"
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
                compact: false,
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
            assert!(!s.contains("probe ebpf-btf: ok"));
            assert!(
                s.contains("  ebpf.btf: {\"summary\":\"btfSyscall=ok\"}"),
                "{s}"
            );
            // An un-opted probe's ok status is suppressed when not verbose.
            let mut buf = vec![];
            r.on_event(&mut buf, &outcome("ebpf", "ebpf", "knobs", json!({"x": 1})))
                .unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), "");
        }

        #[test]
        fn verbose_prints_every_fact_and_clips_long_values() {
            let mut r = Text {
                verbose: true,
                color: ColorSupport::Off,
                optins: vec![],
                compact: false,
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
                compact: false,
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
                compact: false,
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
                compact: false,
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
