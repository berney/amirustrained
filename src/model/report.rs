use serde::{Deserialize, Serialize};

use super::{Fact, Finding, ProbeOutcome, Verdict};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanMeta {
    pub target_pid: u32,
    pub uid: u32,
    pub timestamp: String,
    pub kernel: String,
    pub arch: String,
    pub distro: Option<String>,
    pub complete: bool,
    pub probe_timeout_s: Option<u64>,
}

pub type ReportMeta = ScanMeta;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

// No `Deserialize` on Report: its `Vec<Finding>` holds `&'static` fields that cannot
// be reconstructed from runtime input; Report is an output-only artifact.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub scan: ScanMeta,
    pub verdict: Option<Verdict>,
    pub probes: Vec<ProbeOutcome>,
    pub findings: Vec<Finding>,
    pub counts: Counts,
}

impl ScanMeta {
    pub fn stub() -> Self {
        ScanMeta {
            target_pid: 0,
            uid: 0,
            timestamp: "T".into(),
            kernel: "K".into(),
            arch: "A".into(),
            distro: None,
            complete: true,
            probe_timeout_s: None,
        }
    }
}

impl Report {
    pub fn blank(scan: ScanMeta, schema_version: u32) -> Self {
        Self {
            schema_version,
            tool: Tool {
                name: "amirustrained".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            scan,
            verdict: None,
            probes: vec![],
            findings: vec![],
            counts: Counts::default(),
        }
    }
    pub fn push_probe(&mut self, o: ProbeOutcome) {
        self.probes.push(o);
    }
    pub fn fact(&self, probe: &str, key: &str) -> Option<&Fact> {
        self.probes
            .iter()
            .flat_map(|p| &p.facts)
            .find(|f| f.probe == probe && f.key == key && f.status == super::FactStatus::Ok)
    }
    pub fn compute_counts(&mut self) {
        self.counts = Default::default();
        for f in &self.findings {
            match f.severity {
                super::Severity::Critical => self.counts.critical += 1,
                super::Severity::High => self.counts.high += 1,
                super::Severity::Medium => self.counts.medium += 1,
                super::Severity::Low => self.counts.low += 1,
                super::Severity::Info => self.counts.info += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fact_lookup_skips_non_ok() {
        let mut r = Report::blank(ScanMeta::stub(), 1);
        r.push_probe(ProbeOutcome::empty("uidmap").with_fact(Fact::unavailable(
            "uidmap",
            "uidMap",
            "/x".into(),
            Some(13),
        )));
        assert!(r.fact("uidmap", "uidMap").is_none());
    }
    #[test]
    fn scan_meta_serializes_arch_and_distro() {
        let meta = ScanMeta {
            target_pid: 1234,
            uid: 1000,
            timestamp: "1234567890".into(),
            kernel: "6.8.0".into(),
            arch: "x86_64".into(),
            distro: Some("Ubuntu 22.04.4 LTS".into()),
            complete: true,
            probe_timeout_s: None,
        };
        let val = serde_json::to_value(&meta).unwrap();
        assert_eq!(val["arch"], "x86_64");
        assert_eq!(val["distro"], "Ubuntu 22.04.4 LTS");
    }
}
