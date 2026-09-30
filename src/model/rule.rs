use serde::{Deserialize, Serialize};

use super::{Fact, Finding, Report};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub struct Rule {
    pub id: &'static str,
    pub slug: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    /// true → an unprivileged run emits an Info downgrade instead of evaluating `check`.
    pub requires_root: bool,
    pub check: fn(report: &Report, privileged: bool) -> Option<Vec<Fact>>,
}

impl Rule {
    pub fn evaluate(&self, report: &Report, privileged: bool) -> Option<Finding> {
        if self.requires_root && !privileged {
            let mut e = vec![Fact::degraded(
                self.id,
                "assessment",
                serde_json::json!({ "insufficientPrivilege": true }),
                "probe".into(),
            )];
            e.extend(self.downgrade_evidence(report));
            return Some(Finding {
                rule: self.id,
                severity: Severity::Info,
                summary: "insufficient privilege to assess",
                why: self.why,
                remediation: self.remediation,
                references: self.references,
                evidence: e,
            });
        }
        (self.check)(report, privileged).map(|ev| Finding {
            rule: self.id,
            severity: self.severity,
            summary: self.summary,
            why: self.why,
            remediation: self.remediation,
            references: self.references,
            evidence: ev,
        })
    }
    fn downgrade_evidence(&self, report: &Report) -> Vec<Fact> {
        let _ = report;
        vec![]
    }
}
