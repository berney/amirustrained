use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, FromArgMatches};

// `pub` keeps the not-yet-consumed model helpers (Tasks 8+) lint-clean in the
// bin target; nothing outside the crate can reach them.
pub mod model;
mod opts;
mod pipeline;
mod probes;
mod render;
mod sys;

/// Process exit codes (spec Global Constraints):
///
/// | code | meaning |
/// |------|---------|
/// | 0 | scan completed |
/// | 1 | `--fail-on` threshold tripped |
/// | 2 | CLI misuse (bad `--format` / `--fail-on`, clap parse error) or output IO failure |
/// | 3 | internal error |
///
/// `3` has no reachable path yet: the only non-CLI faults are renderer writes
/// and the serde failures the renderers fold into them, which the contract
/// assigns to `2`. Keeping the row documented is what pins the contract until
/// a real internal-error source appears.
fn main() -> ExitCode {
    // clap owns the help/error stream, so titanium rides its styles hook
    // instead of our tokeniser. `--no-color` must silence that stream too:
    // when clap prints help or a parse error the flag is not parsed yet, so
    // prescan argv (`NO_COLOR`/`TERM=dumb` anstream honours on its own).
    // `get_matches` keeps the exit-code-2-on-misuse / 0-on-help contract.
    let mut cmd = opts::Cli::command().styles(render::style::clap_styles());
    if std::env::args().any(|a| a == "--no-color") {
        cmd = cmd.color(clap::ColorChoice::Never);
    }
    let cli = opts::Cli::from_arg_matches(&cmd.get_matches()).unwrap_or_else(|e| e.exit());
    // Misuse (unknown format, unknown fail-on level) is decided before any
    // probe runs, so `--help`-style errors cost nothing.
    let (fmt, opts) = match opts::Opts::from_cli(&cli) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let fs = Arc::new(match &cli.fixture_root {
        Some(r) => sys::fs::PseudoFs::new(r.clone()),
        None => sys::fs::PseudoFs::real(),
    });
    let os: Arc<dyn sys::os::OsApi> = Arc::new(sys::os::RealOs);
    // ANSI paint only for an interactive stdout that asked for it (spec §9):
    // `--no-color` is the explicit switch, then the chalk.ts environment
    // predicate (`NO_COLOR` presence, `TERM=dumb`), then the tty test. A
    // non-tty consumer gets byte-identical plain bytes. `-o file` is never an
    // interactive sink (ReviewT2324): folding it into `tty` keeps escape
    // codes out of the report file.
    let color = render::style::detect(
        cli.no_color,
        cli.output.is_none() && std::io::stdout().is_terminal(),
        &|key| std::env::var(key).ok(),
    );
    // The opt-in probes exist *for* their answers: text shows their fact
    // lines even without `--verbose` (src/render/text.rs).
    let mut optins: Vec<&'static str> = Vec::new();
    if opts.probe_syscalls {
        optins.push("syscall-probe");
    }
    optins.extend(opts.probe_ebpf.iter().map(|t| t.probe_name()));
    let mut renderer = render::make(fmt, cli.verbose, color, optins, opts.compact);
    let mut out: Box<dyn std::io::Write> = match &cli.output {
        Some(p) => match std::fs::File::create(p) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("error: cannot write {}: {e}", p.display());
                return ExitCode::from(2);
            }
        },
        None => Box::new(std::io::stdout()),
    };
    // Streaming contract: every event is rendered the moment the pipeline
    // produces it. A failed write means the consumer is gone (stdout closed,
    // disk full); finish the process here rather than running probes whose
    // output nobody will read. `exit` reaps any abandoned probe worker, which
    // is safe because workers only hold `Arc` clones of the seams.
    let mut sink = |ev: &pipeline::Event| {
        if let Err(e) = renderer.on_event(&mut out, ev) {
            eprintln!("error: output failed: {e}");
            std::process::exit(2);
        }
    };
    let report = pipeline::scan_with_probes(fs, os, &opts, probes::registry(&opts), &mut sink);
    if let Err(e) = renderer.finish(&mut out) {
        eprintln!("error: output failed: {e}");
        return ExitCode::from(2);
    }
    if tripped(&report.findings, opts.fail_on) {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// `--fail-on` decision: exit 1 as soon as one finding reaches the configured
/// level (`Severity` is ordered, so the comparison is the whole contract).
fn tripped(findings: &[model::Finding], fail_on: Option<model::Severity>) -> bool {
    fail_on.is_some_and(|lvl| findings.iter().any(|f| f.severity >= lvl))
}

#[cfg(test)]
mod tests {
    use super::tripped;
    use crate::model::{Finding, Rule, Severity};

    static LOW: Rule = Rule {
        id: "AMR-TEST",
        slug: "test",
        severity: Severity::Low,
        summary: "s",
        why: "w",
        remediation: "r",
        references: &[],
        requires_root: false,
        container_only: false,
        verbose_only: false,
        severity_of: None,
        check: |_a| Some(vec![]),
    };

    #[test]
    fn fail_on_trips_at_or_above_its_level_only() {
        let findings = [Finding::new(&LOW, vec![])]; // severity: Low
        for lvl in [Severity::Info, Severity::Low] {
            assert!(
                tripped(&findings, Some(lvl)),
                "a Low finding must trip {lvl:?}"
            );
        }
        for lvl in [Severity::Medium, Severity::High, Severity::Critical] {
            assert!(
                !tripped(&findings, Some(lvl)),
                "a Low finding must not trip {lvl:?}"
            );
        }
    }

    #[test]
    fn no_threshold_and_no_findings_never_trip() {
        let findings = [Finding::new(&LOW, vec![])];
        assert!(!tripped(&findings, None));
        assert!(!tripped(&[], Some(Severity::Info)));
    }
}
