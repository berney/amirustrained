use serde::Serialize;

use super::{Fact, Rule, Severity};

// No `Deserialize`: `&'static` fields cannot be reconstructed from runtime input data.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    /// Owned: a privilege-demotion suffix is appended at evaluation time.
    pub summary: String,
    pub why: &'static str,
    pub evidence: Vec<Fact>,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

impl Finding {
    pub fn new(rule: &'static Rule, evidence: Vec<Fact>) -> Finding {
        Finding {
            rule: rule.id,
            severity: rule.severity,
            summary: rule.summary.into(),
            why: rule.why,
            remediation: rule.remediation,
            references: rule.references,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Rule, Severity};

    static SHAPE: Rule = Rule {
        id: "AMR-099",
        slug: "shape-pin",
        severity: Severity::Medium,
        summary: "s",
        why: "w",
        remediation: "r",
        references: &["https://example.test/doc"],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        check: |_| Some(vec![]),
    };

    #[test]
    fn finding_serializes_spec_shape() {
        let f = Finding::new(
            &SHAPE,
            vec![Fact::ok("p", "k", serde_json::json!(1), "src".into())],
        );
        let j = serde_json::to_value(&f).unwrap();
        let keys: Vec<&str> = j.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
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
        assert_eq!(j["rule"], "AMR-099");
        assert_eq!(j["severity"], "medium");
        assert_eq!(j["references"][0], "https://example.test/doc");
        assert_eq!(j["evidence"].as_array().unwrap().len(), 1);
    }
}
