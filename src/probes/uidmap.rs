use super::Probe;
use crate::model::ProbeOutcome;
use crate::pipeline::Ctx;

/// Compiling stub; Task 9 lands the real uid-map inspection.
pub struct Uidmap;

impl Probe for Uidmap {
    fn name(&self) -> &'static str {
        "uidmap"
    }
    fn run(&self, _cx: &Ctx) -> ProbeOutcome {
        ProbeOutcome::empty(self.name())
    }
}
