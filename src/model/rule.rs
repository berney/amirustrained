use serde::{Deserialize, Serialize};

use super::{Fact, Finding, Report, RuntimeKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Everything a rule check may read: the aggregated report and whether the
/// run had root. Checks are pure predicates over facts — they never read the
/// system themselves, so a finding is always explainable from the report.
pub struct Assess<'r> {
    pub report: &'r Report,
    pub privileged: bool,
}

impl<'r> Assess<'r> {
    /// Ok-status facts only: a degraded or unavailable fact never satisfies a
    /// predicate (spec §8 — probes degrade honestly, rules stay silent).
    pub fn fact(&self, probe: &str, key: &str) -> Option<&'r Fact> {
        self.report.fact(probe, key)
    }
    /// True when the fusion verdict attributes this process to a container
    /// runtime. Environment-only socket/uidmap evidence deliberately does not
    /// move the verdict (Task 17b), so this stays self-containment-only.
    pub fn containerized(&self) -> bool {
        self.report
            .verdict
            .as_ref()
            .is_some_and(|v| v.runtime != RuntimeKind::Host)
    }
    /// Ok-status string equality on a fact value.
    pub fn is(&self, probe: &str, key: &str, s: &str) -> bool {
        self.fact(probe, key)
            .is_some_and(|f| f.value.as_str() == Some(s))
    }
    /// Ok-status array membership on a fact value (capability names etc.).
    pub fn arr_has(&self, probe: &str, key: &str, s: &str) -> bool {
        self.fact(probe, key).is_some_and(|f| {
            f.value
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(s)))
        })
    }
}

pub struct Rule {
    pub id: &'static str,
    /// Stable kebab name for SARIF `fullRule` rendering (Task 22+).
    #[allow(dead_code)] // Read only by the later SARIF renderer.
    pub slug: &'static str,
    pub severity: Severity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    /// true → an unprivileged run cannot fully read the inputs: every
    /// evaluation then emits an Info finding with the summary suffixed
    /// " (insufficient privilege to assess)" — fired keeps its evidence,
    /// unfired reports an empty-evidence blind-spot note (spec §6 F4, §8).
    pub requires_root: bool,
    /// `Some(evidence)` fires the rule; `None` stays silent.
    pub check: fn(&Assess) -> Option<Vec<Fact>>,
}

impl Rule {
    pub fn evaluate(&self, report: &Report, privileged: bool) -> Option<Finding> {
        let a = Assess { report, privileged };
        let evidence = (self.check)(&a);
        if self.requires_root && !a.privileged {
            // Spec §6 erratum F4: the downgrade must be reachable — the note is
            // emitted whether or not the root-gated inputs happened to be readable.
            return Some(Finding {
                rule: self.id,
                severity: Severity::Info,
                summary: format!("{} (insufficient privilege to assess)", self.summary),
                why: self.why,
                remediation: self.remediation,
                references: self.references,
                evidence: evidence.unwrap_or_default(),
            });
        }
        Some(Finding {
            rule: self.id,
            severity: self.severity,
            summary: self.summary.into(),
            why: self.why,
            remediation: self.remediation,
            references: self.references,
            evidence: evidence?,
        })
    }
}
