use super::Renderer;
use crate::model::{Finding, Severity, rules::RULES};
use crate::pipeline::Event;

/// SARIF 2.1.0 renderer (spec §7 `sarif`): one pretty document on `Summary`,
/// other events ignored — a bulk format like `json`.
pub struct Sarif;

impl Renderer for Sarif {
    fn on_event(&mut self, w: &mut dyn std::io::Write, ev: &Event) -> std::io::Result<()> {
        // One document, one write (same bulk contract as `json`): the whole
        // envelope is serialized in memory, so no partial JSON reaches the
        // consumer. Serde errors fold into IO (exit 2).
        if let Event::Summary { findings, .. } = ev {
            let doc = envelope(findings);
            let text = serde_json::to_string_pretty(&doc).map_err(std::io::Error::other)?;
            writeln!(w, "{text}")?;
        }
        Ok(())
    }
    fn finish(&mut self, _w: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }
}

/// SARIF result/report level for a severity: crit/high error, medium
/// warning, low/info note.
fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// One registry rule as a SARIF reportingDescriptor. `helpUri` only when the
/// rule cites a reference (no empty-string keys in the document).
fn rule_descriptor(rule: &'static crate::model::Rule) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": rule.id,
        "shortDescription": { "text": rule.summary },
        "fullDescription": { "text": rule.why },
        "defaultConfiguration": { "level": level(rule.severity) },
    });
    if let Some(url) = rule.references.first() {
        v["helpUri"] = serde_json::Value::String((*url).to_string());
    }
    v
}

/// Full SARIF 2.1.0 envelope: the driver always carries the whole RULES
/// registry (viewers resolve `ruleIndex` against it), while `results` maps
/// the actual findings — position = index in RULES, level from the finding's
/// severity. No locations: findings describe the process, not source files.
fn envelope(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut v = serde_json::json!({
                "ruleId": f.rule,
                "level": level(f.severity),
                "message": { "text": f.summary },
            });
            if let Some(idx) = RULES.iter().position(|r| r.id == f.rule) {
                v["ruleIndex"] = serde_json::json!(idx);
            }
            v
        })
        .collect();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "amirustrained",
                    "informationUri": "https://github.com/berney/amirustrained",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": RULES.iter().map(rule_descriptor).collect::<Vec<_>>(),
                }
            },
            "results": results,
        }],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Report, ScanMeta, Severity, test_finding};

    fn render(r: Report) -> serde_json::Value {
        let mut buf = vec![];
        Sarif
            .on_event(
                &mut buf,
                &Event::Summary {
                    verdict: None,
                    findings: r.findings.clone(),
                    counts: r.counts.clone(),
                    complete: true,
                    report: Box::new(r),
                },
            )
            .unwrap();
        serde_json::from_slice(&buf).expect("summary must emit exactly one JSON document")
    }

    #[test]
    fn sarif_envelope_and_levels() {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.findings = vec![
            test_finding("AMR-001", Severity::Critical),
            test_finding("AMR-009", Severity::Low),
        ];
        r.compute_counts();
        let v = render(r);
        assert_eq!(v["version"], "2.1.0");
        assert!(
            v["$schema"].as_str().unwrap().contains("sarif-2.1.0"),
            "$schema: {}",
            v["$schema"]
        );
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "amirustrained");
        assert_eq!(
            driver["informationUri"],
            "https://github.com/berney/amirustrained"
        );
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            driver["rules"].as_array().unwrap().len(),
            crate::model::rules::RULES.len(),
            "driver rules must list the whole registry"
        );
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        // ruleIndex = position in RULES (AMR-022's id-space append shifts 007+).
        assert_eq!(results[0]["ruleId"], "AMR-001");
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["message"]["text"],
            crate::model::rules::RULES[0].summary
        );
        assert_eq!(results[1]["ruleId"], "AMR-009");
        assert_eq!(results[1]["ruleIndex"], 9);
        assert_eq!(results[1]["level"], "note");
        assert!(results[0].get("locations").is_none(), "no locations");
    }

    #[test]
    fn sarif_rule_entries_carry_descriptions_and_default_level() {
        let v = render(Report::blank(ScanMeta::stub(), 1));
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        let r0 = &rules[0];
        assert_eq!(r0["id"], "AMR-001");
        assert_eq!(
            r0["shortDescription"]["text"],
            "Container runtime API socket is reachable and writable"
        );
        assert_eq!(
            r0["fullDescription"]["text"],
            crate::model::rules::RULES[0].why
        );
        assert_eq!(
            r0["helpUri"],
            "https://docs.docker.com/engine/security/socket-proxy/"
        );
        assert_eq!(r0["defaultConfiguration"]["level"], "error");
        // Medium -> warning, High -> error over the whole registry, consistently.
        for (rule, entry) in crate::model::rules::RULES.iter().zip(rules) {
            let want = match rule.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };
            assert_eq!(entry["defaultConfiguration"]["level"], want, "{}", rule.id);
            assert_eq!(entry["shortDescription"]["text"], rule.summary);
        }
    }

    #[test]
    fn sarif_empty_findings_still_emit_a_valid_run() {
        let v = render(Report::blank(ScanMeta::stub(), 1));
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn sarif_ignores_non_summary_events() {
        let mut buf = vec![];
        Sarif
            .on_event(
                &mut buf,
                &Event::Probe(crate::model::ProbeOutcome::empty("uidmap")),
            )
            .unwrap();
        assert!(buf.is_empty());
    }
}
