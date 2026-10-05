pub mod fact;
pub mod finding;
pub mod outcome;
pub mod report;
pub mod rule;
pub mod rules;
pub mod runtime;

pub use fact::{Fact, FactStatus};
pub use finding::Finding;
pub use outcome::{Availability, ProbeOutcome};
pub use report::{Counts, GroupEntry, Report, ReportMeta, ScanMeta, Tool};
pub use rule::{Assess, Rule, Severity};
pub use runtime::{Candidate, PriorSignals, RuntimeKind, Signal, Verdict};

/// Shared render-test fixture: a finding built from the real registry entry
/// `id` with one deterministic evidence fact; `sev` overrides the rule's own
/// severity so renderer tests drive grouping without registry coupling.
#[cfg(test)]
pub(crate) fn test_finding(id: &str, sev: Severity) -> Finding {
    let rule = rules::RULES
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("test_finding: {id} is not a RULES id"));
    Finding {
        rule: rule.id,
        severity: sev,
        summary: rule.summary.into(),
        why: rule.why,
        evidence: vec![Fact::ok(
            "capabilities",
            "effective",
            serde_json::json!(["cap_sys_admin"]),
            "test".into(),
        )],
        remediation: rule.remediation,
        references: rule.references,
    }
}
