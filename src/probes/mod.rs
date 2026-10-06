use std::sync::Arc;

use crate::model::ProbeOutcome;
use crate::opts::{EbpfTarget, Opts};
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
pub mod device_open;
pub mod ebpf;
pub mod ebpf_btf;
pub mod ebpf_load;
pub mod ebpf_raw;
pub mod ebpf_types;
pub mod k8s;
pub mod kernel_config;
pub mod kernel_exec;
pub mod kernel_surface;
pub mod lsm;
pub mod mounts;
pub mod namespaces;
pub mod runtime;
pub mod seccomp;
pub mod sockets;
pub mod syscall_probe;
pub mod uidmap;
pub mod vmm;

/// Probes in dispatch order. The syscall probe is conditional: registered
/// only with `--probe-syscalls`, since it actively invokes syscalls (spec §5).
/// The active eBPF probes (`ebpf-load`, `ebpf-btf`, `ebpf-types`) are gated
/// on the `--probe-ebpf` target set (spec §6 AMR-021).
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
    // The REAL probes are opt-in (spec §6 AMR-021: "--probe-ebpf only").
    // Slotted right after the knobs probe so their classification can read
    // the fresh `ebpf.knobs` fact from `cx.prior`.
    if opts.probe_ebpf.contains(&EbpfTarget::Load) {
        probes.push(Arc::new(ebpf_load::EbpfLoad));
    }
    if opts.probe_ebpf.contains(&EbpfTarget::Btf) {
        probes.push(Arc::new(ebpf_btf::EbpfBtf));
    }
    if opts.probe_ebpf.contains(&EbpfTarget::Types) {
        probes.push(Arc::new(ebpf_types::EbpfTypes));
    }
    let rest: Vec<Arc<dyn Probe>> = vec![
        Arc::new(vmm::Vmm),
        Arc::new(sockets::Sockets),
        Arc::new(cgroup::Cgroup),
        Arc::new(mounts::Mounts),
        Arc::new(k8s::K8s),
        Arc::new(kernel_config::KernelConfig),
        Arc::new(kernel_surface::KernelSurface),
    ];
    probes.extend(rest);
    // The empirical raw-device open test is opt-in (HIDS-visible `open(2)`;
    // `--probe-device-open`). Slotted right after `kernel-surface` so its
    // facts sit beside the passive `dev_*` verdicts they can override.
    if opts.probe_device_open {
        probes.push(Arc::new(device_open::DeviceOpen));
    }
    if opts.probe_kernel_execution {
        probes.push(Arc::new(kernel_exec::KernelExec));
    }
    // Last: it only fuses what the probes above accumulated.
    probes.push(Arc::new(runtime::Runtime));
    probes
}
