//! Minimal verifier-clean eBPF program for the `--probe-ebpf` load verdict
//! (Task 29). A tracepoint that immediately returns 0: zero maps, no helpers,
//! no tail calls, no network/fs access, never attached — the ONLY observable
//! effect is one `BPF_PROG_LOAD` syscall. The verdict is the load itself; the
//! loader drops the program fd right away and never pins anything.
#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, EbpfContext};

/// Explicit `name`/`category` derive section `tracepoint/sched/sched_yield`:
/// a syntactically valid tracepoint label whose attach point never matters
/// here, since the loader loads the program and drops it without ever
/// attaching — it never executes.
#[tracepoint(name = "sched_yield", category = "sched")]
pub fn hello(ctx: TracePointContext) -> u32 {
    let _ = ctx.as_ptr();
    0
}

/// BPF programs cannot unwind; a panic is structurally impossible in a
/// function with no branches, but core still demands the symbol.
/// `unreachable_unchecked` compiles to nothing: if it were ever reachable the
/// JIT'ed code would just fall through, and the program runs nowhere anyway
/// (never attached).
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
