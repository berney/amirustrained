pub use super::rule::Rule;
use super::{Finding, Report};

/// Rule registry; Tasks 19-21 append entries in id order.
pub static RULES: &[Rule] = &[];

pub fn evaluate_all(report: &Report, privileged: bool) -> Vec<Finding> {
    RULES
        .iter()
        .filter_map(|r| r.evaluate(report, privileged))
        .collect()
}
