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
// ebpf, vmm, sockets, cgroup, k8s, runtime) lives in `registry()` below.
pub mod capabilities;
pub mod cgroup;
pub mod ebpf;
pub mod ebpf_load;
pub mod k8s;
pub mod lsm;
pub mod namespaces;
pub mod runtime;
pub mod seccomp;
pub mod sockets;
pub mod syscall_probe;
pub mod uidmap;
pub mod vmm;

/// Probes in dispatch order. The syscall probe is conditional: registered
/// only with `--probe-syscalls`, since it actively invokes syscalls (spec §5).
pub fn registry(opts: &Opts) -> Vec<Arc<dyn Probe>> {
    let mut probes: Vec<Arc<dyn Probe>> = vec![
        Arc::new(namespaces::Namespaces),
        Arc::new(uidmap::Uidmap),
        Arc::new(capabilities::Capabilities),
        Arc::new(seccomp::Seccomp),
    ];
    if opts.probe_syscalls {
        probes.push(Arc::new(syscall_probe::SyscallProbe));
    }
    probes.push(Arc::new(lsm::Lsm));
    // Reads the eBPF knobs files directly and fuses the capabilities and
    // lockdown facts the probes above already accumulated (`cx.prior`).
    probes.push(Arc::new(ebpf::Ebpf));
    // The REAL load probe is opt-in (spec §6 AMR-021: "--probe-ebpf only"):
    // one BPF_PROG_LOAD with the embedded object, nothing pinned. Slotted
    // right after the knobs probe so its classification can read the fresh
    // `ebpf.knobs` fact from `cx.prior`.
    if opts.probe_ebpf {
        probes.push(Arc::new(ebpf_load::EbpfLoad));
    }
    let rest: Vec<Arc<dyn Probe>> = vec![
        Arc::new(vmm::Vmm),
        Arc::new(sockets::Sockets),
        Arc::new(cgroup::Cgroup),
        Arc::new(k8s::K8s),
        // Last: it only fuses what the probes above accumulated.
        Arc::new(runtime::Runtime),
    ];
    probes.extend(rest);
    probes
}
