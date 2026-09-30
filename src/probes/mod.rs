use std::sync::Arc;

use crate::model::ProbeOutcome;
use crate::opts::Opts;
use crate::pipeline::Ctx;

/// One self-contained inspection. Runs on a pipeline worker thread; `Ctx`
/// borrows the shared seams and the accumulated output of earlier probes.
pub trait Probe: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, cx: &Ctx) -> ProbeOutcome;
}

// Probe modules are appended here by their own tasks; rustfmt keeps these
// declarations sorted alphabetically. The dispatch order (spec Global
// Constraints: namespaces, uidmap, capabilities, seccomp, [syscall-probe], lsm,
// vmm, cgroup, sockets, k8s, runtime) lives in `registry()` below.
pub mod capabilities;
pub mod cgroup;
pub mod namespaces;
pub mod uidmap;

/// Probes in dispatch order. The syscall probe (gated on `opts.probe_syscalls`)
/// is appended here when its task lands.
pub fn registry(_opts: &Opts) -> Vec<Arc<dyn Probe>> {
    vec![
        Arc::new(namespaces::Namespaces),
        Arc::new(uidmap::Uidmap),
        Arc::new(capabilities::Capabilities),
        Arc::new(cgroup::Cgroup),
    ]
}
