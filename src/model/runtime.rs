use serde::{Deserialize, Serialize};

use super::Fact;

// NOTE: the brief writes `rename_all = "kebab-lowercase"`, which is not a valid
// serde rule; "kebab-case" is serde's lower-kebab transform (CriO -> "cri-o").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    Docker,
    Containerd,
    CriO,
    Podman,
    Kubernetes,
    Lxc,
    SystemdNspawn,
    Firecracker,
    Gvisor,
    Kata,
    Host,
}

#[derive(Clone, Debug)]
pub struct Signal {
    pub runtime: RuntimeKind,
    pub weight: f32,
    pub evidence: Fact,
}

/// Signals accumulated by the pipeline before the `runtime` probe runs.
#[derive(Default)]
pub struct PriorSignals(pub Vec<Signal>);
impl PriorSignals {
    pub fn extend(&mut self, sigs: Vec<Signal>) {
        self.0.extend(sigs);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub runtime: RuntimeKind,
    pub score: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub runtime: RuntimeKind,
    pub variant: Option<String>,
    pub confidence: String,
    pub alternatives: Vec<Candidate>,
    pub evidence: Vec<String>,
}
