use serde::Serialize;

use super::{Fact, Rule, Severity};

// No `Deserialize`: `&'static` fields cannot be reconstructed from runtime input data.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    pub evidence: Vec<Fact>,
}

impl Finding {
    pub fn new(rule: &'static Rule, evidence: Vec<Fact>) -> Finding {
        Finding {
            rule: rule.id,
            severity: rule.severity,
            summary: rule.summary,
            why: rule.why,
            remediation: rule.remediation,
            references: rule.references,
            evidence,
        }
    }
}
