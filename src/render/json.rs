use super::Renderer;
use crate::pipeline::Event;

/// Bulk JSON renderer (spec §7 `json`): the whole report is the output, so
/// streaming events are dropped and the single pretty document lands on
/// `Summary`.
pub struct Json;

impl Renderer for Json {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // One document, one write: `to_string_pretty` renders the whole report
        // in memory, so no partial/invalid JSON can reach the consumer even if
        // the write is interrupted. Serde errors fold into IO (exit 2), the
        // same contract the other renderers use.
        if let Event::Summary { report, .. } = ev {
            let mut s = serde_json::to_string_pretty(&**report).map_err(std::io::Error::other)?;
            s.push('\n');
            w.write_all(s.as_bytes())?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Candidate, Fact, Finding, ProbeOutcome, Report, Rule, RuntimeKind, ScanMeta, Severity,
        Verdict,
    };

    static RULE: Rule = Rule {
        id: "AMR-098",
        slug: "json-render-shape",
        severity: Severity::High,
        summary: "s",
        why: "w",
        remediation: "r",
        references: &["https://example.test/doc"],
        requires_root: false,
        container_only: false,
        check: |_| Some(vec![]),
    };

    /// Fixture mirroring spec §7: scan complete, high-confidence verdict with
    /// one alternative, one finding carrying evidence, two probe outcomes.
    fn fixture_report() -> Report {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.verdict = Some(Verdict {
            runtime: RuntimeKind::Podman,
            variant: None,
            confidence: "high".into(),
            alternatives: vec![Candidate {
                runtime: RuntimeKind::Docker,
                score: 0.2,
            }],
            evidence: vec!["cgroup: podman slice".into()],
        });
        r.push_probe(ProbeOutcome::empty("namespaces"));
        r.push_probe(ProbeOutcome::empty("sockets"));
        r.findings = vec![Finding::new(
            &RULE,
            vec![Fact::ok(
                "sockets",
                "found",
                serde_json::json!(true),
                "/run/podman/podman.sock".into(),
            )],
        )];
        r.compute_counts();
        r
    }

    fn render(r: Report) -> String {
        let complete = r.scan.complete;
        let mut buf = vec![];
        Json.on_event(
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
        Json.finish(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn json_full_report_shape() {
        let out = render(fixture_report());
        assert!(out.ends_with('\n'), "pretty JSON must end with a newline");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "schemaVersion",
                "tool",
                "scan",
                "verdict",
                "probes",
                "findings",
                "counts"
            ]
        );
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["tool"]["name"], "amirustrained");
        assert_eq!(v["scan"]["complete"], true);
        // Confidence is the report-schema string ladder, not a number.
        assert_eq!(v["verdict"]["confidence"], "high");
        // serde emits struct field order (preserve_order), so this pins the
        // spec §7 finding layout: evidence before remediation.
        let fkeys: Vec<&str> = v["findings"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fkeys,
            [
                "rule",
                "severity",
                "summary",
                "why",
                "evidence",
                "remediation",
                "references"
            ]
        );
        assert_eq!(v["findings"][0]["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(v["probes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_ignores_non_summary() {
        let mut buf = vec![];
        let mut r = Json;
        r.on_event(
            &mut buf,
            &Event::Meta {
                tool: fixture_report().tool.clone(),
                scan: ScanMeta::stub(),
            },
        )
        .unwrap();
        r.on_event(&mut buf, &Event::Probe(ProbeOutcome::empty("uidmap")))
            .unwrap();
        r.finish(&mut buf).unwrap();
        assert!(
            buf.is_empty(),
            "bulk JSON must buffer nothing before Summary"
        );
    }

    #[test]
    fn json_counts_match_finding_severity_tally() {
        let mut r = fixture_report();
        r.findings.push(Finding::new(
            &RULE,
            vec![Fact::ok("p", "k", serde_json::json!(1), "src".into())],
        ));
        // Second finding demoted to Info so the tally is not single-severity.
        r.findings[1].severity = Severity::Info;
        r.compute_counts();
        let v: serde_json::Value = serde_json::from_str(&render(r)).unwrap();
        let tally = |sev: &str| {
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["severity"] == sev)
                .count()
        };
        assert_eq!(v["counts"]["high"].as_u64().unwrap(), tally("high") as u64);
        assert_eq!(v["counts"]["info"].as_u64().unwrap(), tally("info") as u64);
        assert_eq!(
            v["counts"]["medium"].as_u64().unwrap(),
            tally("medium") as u64
        );
        let total = v["findings"].as_array().unwrap().len() as u64;
        let emitted: u64 = ["critical", "high", "medium", "low", "info"]
            .iter()
            .map(|k| v["counts"][k].as_u64().unwrap())
            .sum();
        assert_eq!(emitted, total, "counts must tally every finding");
    }
}
