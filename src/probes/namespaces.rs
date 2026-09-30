use super::Probe;
use crate::model::ProbeOutcome;
use crate::pipeline::Ctx;

/// Compiling stub; Task 8 lands the real namespace inspection.
pub struct Namespaces;

impl Probe for Namespaces {
    fn name(&self) -> &'static str {
        "namespaces"
    }
    fn run(&self, _cx: &Ctx) -> ProbeOutcome {
        ProbeOutcome::empty(self.name())
    }
}
