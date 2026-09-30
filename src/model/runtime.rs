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

impl RuntimeKind {
    /// Stable lowercase name, used in verdict evidence strings. Kept in
    /// lockstep with the serde (`kebab-case`) spelling the report schema emits,
    /// so an evidence citation and the `runtime` field never disagree;
    /// `as_str_matches_the_serde_name` pins that.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeKind::Docker => "docker",
            RuntimeKind::Containerd => "containerd",
            RuntimeKind::CriO => "cri-o",
            RuntimeKind::Podman => "podman",
            RuntimeKind::Kubernetes => "kubernetes",
            RuntimeKind::Lxc => "lxc",
            RuntimeKind::SystemdNspawn => "systemd-nspawn",
            RuntimeKind::Firecracker => "firecracker",
            RuntimeKind::Gvisor => "gvisor",
            RuntimeKind::Kata => "kata",
            RuntimeKind::Host => "host",
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `as_str` is what verdict evidence cites and what the pod's underlying
    /// runtime is reported as; serde is what the report wire format carries. If
    /// they ever drift (a rename, a new variant), evidence would name a runtime
    /// the `runtime` field could not deserialize back to.
    #[test]
    fn as_str_matches_the_serde_name() {
        for k in [
            RuntimeKind::Docker,
            RuntimeKind::Containerd,
            RuntimeKind::CriO,
            RuntimeKind::Podman,
            RuntimeKind::Kubernetes,
            RuntimeKind::Lxc,
            RuntimeKind::SystemdNspawn,
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
            RuntimeKind::Host,
        ] {
            let wire = serde_json::to_value(k).unwrap();
            assert_eq!(wire.as_str(), Some(k.as_str()), "{k:?}");
        }
    }
}
