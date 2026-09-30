use serde::{Deserialize, Serialize};

use super::{Fact, Signal};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state", content = "detail")]
pub enum Availability {
    Ok,
    Degraded(String),
    Unavailable(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutcome {
    pub name: String,
    pub availability: Availability,
    pub facts: Vec<Fact>,
    #[serde(skip)]
    pub signals: Vec<Signal>,
    pub timed_out: bool,
}

impl ProbeOutcome {
    pub fn empty(name: &str) -> Self {
        Self {
            name: name.into(),
            availability: Availability::Ok,
            facts: vec![],
            signals: vec![],
            timed_out: false,
        }
    }
    pub fn with_fact(mut self, f: Fact) -> Self {
        self.facts.push(f);
        self
    }
    pub fn with_signal(mut self, s: Signal) -> Self {
        self.signals.push(s);
        self
    }
}
