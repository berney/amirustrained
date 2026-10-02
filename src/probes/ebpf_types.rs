//! `--probe-ebpf types` — per-prog-type capability sweep.
//!
//! One trivial `bpf(BPF_PROG_LOAD)` per `BPF_PROG_TYPE_*` (ids 1..=32):
//! `mov r0, 0; exit`, license GPL, every fd closed immediately, nothing
//! pinned or attached. The answer per type:
//!
//! - rc ≥ 0            → `loadable` (the kernel really accepts this type)
//! - EINVAL, no log    → `absent`   (type id unknown to this kernel)
//! - EINVAL + log      → `rejected` (type exists; our trivial program fails
//!   its attach contract — existence proven, loadability not; counted as a
//!   denial in the summary)
//! - EPERM/EACCES/…    → `denied`, decoded through the Task 29 classify
//!   table fused with the `ebpf.knobs` posture
//!
//! The sweep never executes attached programs and holds nothing open, so its
//! blast radius per attempt is one verifier run. Registered ONLY under
//! `--probe-ebpf` (spec §6 AMR-021 posture: active probing stays opt-in).

use crate::model::Fact;
use crate::pipeline::Ctx;
use crate::probes::{Probe, ebpf_raw};

pub struct EbpfTypes;

const PROBE: &str = "ebpf-types";
/// Fact namespace stays `ebpf` (spec keys `ebpf.types`).
const FACT_PROBE: &str = "ebpf";

impl Probe for EbpfTypes {
    fn name(&self) -> &'static str {
        PROBE
    }

    fn run(&self, cx: &Ctx) -> crate::model::ProbeOutcome {
        let knob = super::ebpf_load::knob_from_prior(&cx.prior);
        let rows: Vec<(&'static str, ebpf_raw::TypeVerdict)> = ebpf_raw::PROG_TYPES
            .iter()
            .map(|(id, slug, eat)| {
                let (errno, log) = ebpf_raw::try_prog_load(*id, *eat, 0, "amir_types");
                (*slug, ebpf_raw::type_verdict(errno, &log, knob))
            })
            .collect();
        crate::model::ProbeOutcome::empty(PROBE).with_fact(Fact::ok(
            FACT_PROBE,
            "types",
            ebpf_raw::types_value(&rows),
            "raw bpf(BPF_PROG_LOAD) per prog type: 2-insn mov r0,0; exit, GPL, fds closed immediately"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn probe_name_is_stable() {
        assert_eq!(EbpfTypes.name(), "ebpf-types");
    }

    // The kernel-facing sweep is a thin map over `ebpf_raw::try_prog_load`;
    // its decision logic is pure and tested in `ebpf_raw` (type_verdict,
    // types_value). Running it here would require a BPF-capable host and
    // would only re-pin the kernel's answer, not our contract.
    #[test]
    fn sweep_rows_feed_value_via_pure_layer() {
        let rows = vec![
            ("socket-filter", ebpf_raw::TypeVerdict::Loadable),
            ("lirc-mode2", ebpf_raw::TypeVerdict::Absent),
        ];
        let v = ebpf_raw::types_value(&rows);
        assert_eq!(v["summary"], "loadable=1 absent=1 denied=0 rejected=0");
        assert_eq!(v["attempted"], 2);
        let _ = json!({});
    }
}
