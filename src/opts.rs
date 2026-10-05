use std::time::Duration;

use crate::model::Severity;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "amirustrained",
    version,
    about = "Runtime introspection & LPE-posture reporter"
)]
pub struct Cli {
    // Flags are wired for real in Task 7; parse them now so --help is stable.
    /// text | markdown | json | yaml | sarif | jsonl
    #[arg(long, default_value = "text")]
    pub format: String,
    #[arg(long, short)]
    pub output: Option<std::path::PathBuf>,
    #[arg(long)]
    pub probe_syscalls: bool,
    /// Probe kernel-mode execution boundaries (finit_module, kexec, raw memory/IO).
    #[arg(
        long = "probe-kernel-execution",
        alias = "probe-kernel",
        visible_alias = "probe-kernel"
    )]
    pub probe_kernel_execution: bool,

    /// Render concise single-line findings (ideal for diffing privilege states).
    #[arg(long = "compact", alias = "terse", visible_alias = "terse")]
    pub compact: bool,
    /// Opt-in ACTIVE eBPF probes; a bare flag runs all three, an optional
    /// comma list picks a subset: `load` (aya, embedded object: one
    /// verdict-bearing BPF_PROG_LOAD), `btf` (BPF_BTF_LOAD of a minimal
    /// blob + /sys/kernel/btf/vmlinux, then a BTF-referencing fentry load),
    /// `types` (one trivial BPF_PROG_LOAD per BPF_PROG_TYPE_* id). All fds
    /// close immediately; nothing is pinned, attached, or executed. Succeeds
    /// only when the caller can load programs (CAP_BPF/CAP_SYS_ADMIN -
    /// effectively root); every denial is decoded (src/probes/ebpf_*.rs).
    #[arg(
        long,
        value_name = "WHAT",
        num_args = 0..=1,
        default_missing_value = "all",
        value_parser = parse_ebpf_targets
    )]
    pub probe_ebpf: Option<EbpfTargets>,
    /// Seconds; 0 is rejected (would degrade every probe instantly while
    /// the forced-ceiling sweep thread runs with no consumer).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub probe_timeout: Option<u64>,
    #[arg(long)]
    pub pid: Option<u32>,
    #[arg(long)]
    pub fail_on: Option<String>,
    #[arg(long)]
    pub no_color: bool,
    #[arg(long, short)]
    pub verbose: bool,
    /// Dumps raw seccomp filter programs (root only, ptrace attach).
    #[arg(long, hide = true)]
    pub dump_filters: bool,
    #[arg(long, hide = true)]
    pub fixture_root: Option<std::path::PathBuf>,
}

/// Internal derived view of `Cli`; [`Opts::from_cli`] is the only place clap
/// meets the pipeline, so nothing downstream depends on clap.
#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub pid: Option<u32>,
    pub probe_syscalls: bool,
    #[allow(dead_code)]
    pub probe_kernel_execution: bool,
    #[allow(dead_code)]
    pub compact: bool,
    /// Selected active eBPF probes; empty = none (default). Duplicates from
    /// repeated/comma-mixed flag uses are collapsed at parse time.
    pub probe_ebpf: Vec<EbpfTarget>,
    pub probe_timeout: Option<Duration>,
    pub fail_on: Option<Severity>,
    pub dump_filters: bool,
}

/// One opt-in active eBPF probe, selectable via `--probe-ebpf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EbpfTarget {
    Load,
    Btf,
    Types,
}

impl EbpfTarget {
    /// Pipeline event name of the probe this target selects.
    pub fn probe_name(self) -> &'static str {
        match self {
            EbpfTarget::Load => "ebpf-load",
            EbpfTarget::Btf => "ebpf-btf",
            EbpfTarget::Types => "ebpf-types",
        }
    }
}

/// Parsed `--probe-ebpf` value: one CLI token may expand to several targets
/// (comma list, or `all`), so the value parser returns the whole set as a
/// single clap value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfTargets(pub Vec<EbpfTarget>);

/// `--probe-ebpf` value parser: `all` (what a bare flag expands to via
/// `default_missing_value`) or a comma-separated subset of
/// `load|btf|types`. Order is preserved, duplicates collapse.
fn parse_ebpf_targets(s: &str) -> Result<EbpfTargets, String> {
    let parse_one = |p: &str| match p.trim() {
        "load" => Ok(EbpfTarget::Load),
        "btf" => Ok(EbpfTarget::Btf),
        "types" => Ok(EbpfTarget::Types),
        other => Err(format!(
            "unknown eBPF probe target '{other}' (expected load, btf, types or all)"
        )),
    };
    match s.trim() {
        "all" => Ok(EbpfTargets(vec![
            EbpfTarget::Load,
            EbpfTarget::Btf,
            EbpfTarget::Types,
        ])),
        "" => {
            Err("empty value; use load, btf, types (comma list) or omit the value for all".into())
        }
        list => {
            let mut out: Vec<EbpfTarget> = Vec::new();
            for part in list.split(',') {
                let t = parse_one(part)?;
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            Ok(EbpfTargets(out))
        }
    }
}
/// CLI misuse: a flag value the pipeline cannot honor. Maps to exit code 2.
#[derive(Debug)]
pub enum CliError {
    BadFormat(String),
    BadFailOn(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::BadFormat(s) => write!(f, "unknown format '{s}'"),
            CliError::BadFailOn(s) => write!(f, "unknown fail-on level '{s}'"),
        }
    }
}

/// Ceiling for `--probe-timeout`, in seconds. The pipeline's deadline math is
/// `Instant::now() + timeout`, and `Duration::from_secs(u64::MAX)` overflows
/// that sum (panic), so the CLI clamps first. A day is orders of magnitude
/// beyond any legitimate probe budget, so the clamp never bites in practice.
const MAX_PROBE_TIMEOUT_SECS: u64 = 86_400;

/// Ceiling forced on `--probe-syscalls` when no explicit `--probe-timeout`
/// is given (spec §5, security review 2026-10-01): the canonical SKIP list
/// is the primary protection; this is the backstop so the sweep can never
/// run the scan unbounded.
const SWEEP_TIMEOUT_SECS: u64 = 30;

impl Opts {
    /// Translates parsed flags into the pipeline's view. `Err` means misuse:
    /// the process exits `2` without running a probe.
    pub fn from_cli(c: &Cli) -> Result<(Format, Opts), CliError> {
        let fmt: Format = c
            .format
            .parse()
            .map_err(|_| CliError::BadFormat(c.format.clone()))?;
        let fail_on = match c.fail_on.as_deref() {
            None => None,
            Some(s) => Some(match s {
                "any" => Severity::Info,
                "info" => Severity::Info,
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::Critical,
                _ => return Err(CliError::BadFailOn(s.into())),
            }),
        };
        Ok((
            fmt,
            Opts {
                pid: c.pid,
                probe_syscalls: c.probe_syscalls,
                probe_kernel_execution: c.probe_kernel_execution,
                compact: c.compact,
                probe_ebpf: c.probe_ebpf.clone().map(|t| t.0).unwrap_or_default(),
                probe_timeout: match (c.probe_syscalls, c.probe_timeout) {
                    // An explicit value stays authoritative; the sweep
                    // alone never runs without a ceiling (spec §5).
                    (true, None) => Some(Duration::from_secs(SWEEP_TIMEOUT_SECS)),
                    (_, secs) => secs.map(|s| Duration::from_secs(s.min(MAX_PROBE_TIMEOUT_SECS))),
                },
                fail_on,
                dump_filters: c.dump_filters,
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    Text,
    Markdown,
    Json,
    Yaml,
    Sarif,
    Jsonl,
}

impl std::str::FromStr for Format {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s {
            "text" => Format::Text,
            "markdown" => Format::Markdown,
            "json" => Format::Json,
            "yaml" => Format::Yaml,
            "sarif" => Format::Sarif,
            "jsonl" => Format::Jsonl,
            _ => return Err(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(format: &str, fail_on: Option<&str>, probe_timeout: Option<u64>) -> Cli {
        Cli {
            format: format.to_owned(),
            output: None,
            probe_syscalls: false,
            probe_kernel_execution: false,
            compact: false,
            probe_ebpf: None,
            probe_timeout,
            pid: Some(7),
            fail_on: fail_on.map(str::to_owned),
            no_color: false,
            verbose: false,
            dump_filters: false,
            fixture_root: None,
        }
    }

    #[test]
    fn fail_on_levels_map_onto_the_severity_ladder() {
        for (name, want) in [
            ("any", Severity::Info), // "any" is the floor alias
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            let (_, opts) = Opts::from_cli(&cli("jsonl", Some(name), None))
                .unwrap_or_else(|e| panic!("--fail-on {name} must parse: {e}"));
            assert_eq!(opts.fail_on, Some(want), "--fail-on {name}");
        }
        assert_eq!(
            Opts::from_cli(&cli("text", None, None)).unwrap().1.fail_on,
            None
        );
    }

    #[test]
    fn misuse_names_the_offending_value() {
        // These strings are the exit-2 stderr contract; `--fail-on` value
        // parsing grows in Task 25, so the wording is load-bearing.
        let err = Opts::from_cli(&cli("xml", None, None)).unwrap_err();
        assert_eq!(err.to_string(), "unknown format 'xml'");
        let err = Opts::from_cli(&cli("text", Some("apocalypse"), None)).unwrap_err();
        assert_eq!(err.to_string(), "unknown fail-on level 'apocalypse'");
    }

    #[test]
    fn probe_timeout_is_clamped_below_instant_overflow() {
        // Passing `u64::MAX` seconds through to `Instant::now() + timeout`
        // panics; the value the pipeline sees must stay bounded.
        let (_, opts) = Opts::from_cli(&cli("text", None, Some(u64::MAX))).unwrap();
        assert_eq!(opts.probe_timeout, Some(Duration::from_secs(86_400)));
        let (_, opts) = Opts::from_cli(&cli("text", None, Some(5))).unwrap();
        assert_eq!(opts.probe_timeout, Some(Duration::from_secs(5)));
        let (_, opts) = Opts::from_cli(&cli("text", None, None)).unwrap();
        assert_eq!(opts.probe_timeout, None);
    }

    #[test]
    fn probe_syscalls_forces_the_sweep_ceiling() {
        // Spec §5 (amended 2026-10-01): the EPERM sweep must never run
        // unbounded. `--probe-syscalls` without `--probe-timeout` forces a
        // 30 s ceiling; an explicit value stays authoritative; without the
        // flag nothing changes.
        let flag = |c: Cli| Cli {
            probe_syscalls: true,
            ..c
        };
        let (_, opts) = Opts::from_cli(&flag(cli("text", None, None))).unwrap();
        assert_eq!(opts.probe_timeout, Some(Duration::from_secs(30)));
        let (_, opts) = Opts::from_cli(&flag(cli("text", None, Some(5)))).unwrap();
        assert_eq!(opts.probe_timeout, Some(Duration::from_secs(5)));
        let (_, opts) = Opts::from_cli(&cli("text", None, None)).unwrap();
        assert_eq!(opts.probe_timeout, None);
    }

    #[test]
    fn probe_ebpf_bare_flag_selects_all_three_targets() {
        // Default off: no active probe without the flag.
        let (_, opts) = Opts::from_cli(&cli("text", None, None)).unwrap();
        assert!(opts.probe_ebpf.is_empty());
        // Bare `--probe-ebpf` = all three (load, btf, types).
        let parsed = Cli::try_parse_from(["amirustrained", "--probe-ebpf"]).unwrap();
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert_eq!(
            opts.probe_ebpf,
            [EbpfTarget::Load, EbpfTarget::Btf, EbpfTarget::Types]
        );
        // An optional value must not swallow the NEXT flag as its value.
        let parsed =
            Cli::try_parse_from(["amirustrained", "--probe-ebpf", "--format", "json"]).unwrap();
        assert_eq!(parsed.format, "json");
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert_eq!(opts.probe_ebpf.len(), 3);
        // Explicit subset + dedup + order preservation.
        let parsed =
            Cli::try_parse_from(["amirustrained", "--probe-ebpf", "types,load,types"]).unwrap();
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert_eq!(opts.probe_ebpf, [EbpfTarget::Types, EbpfTarget::Load]);
        assert_eq!(
            opts.probe_ebpf
                .iter()
                .map(|t| t.probe_name())
                .collect::<Vec<_>>(),
            ["ebpf-types", "ebpf-load"]
        );
        // The load probe needs no ceiling machinery (a handful of syscalls)
        // and must not disturb the sweep rules: timeout stays None.
        assert_eq!(opts.probe_timeout, None);
    }

    #[test]
    fn probe_ebpf_rejects_unknown_targets_at_parse_time() {
        use clap::error::ErrorKind;
        let err = Cli::try_parse_from(["amirustrained", "--probe-ebpf", "kprobes"])
            .expect_err("unknown target must not parse");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.to_string()
                .contains("unknown eBPF probe target 'kprobes'")
        );
        // Empty value is misuse too (`--probe-ebpf ""`).
        assert!(Cli::try_parse_from(["amirustrained", "--probe-ebpf", ""]).is_err());
    }

    #[test]
    fn yaml_is_a_first_class_format() {
        // User 2026-10-02: `yaml` is a real format everywhere - parse,
        // mapping, and the --help value list (cli test guards help).
        assert_eq!(
            Opts::from_cli(&cli("yaml", None, None)).unwrap().0,
            Format::Yaml
        );
    }

    #[test]
    fn probe_timeout_zero_is_rejected_as_misuse() {
        // `--probe-timeout 0` would degrade every probe instantly while the
        // forced-ceiling sweep thread keeps firing syscalls with no consumer
        // left reading its deadline. clap must reject it at parse time
        // (exit 2 = misuse channel); 1 s must still parse.
        use clap::error::ErrorKind;
        let err = Cli::try_parse_from(["amirustrained", "--probe-timeout", "0"])
            .expect_err("0 is not a legal probe timeout");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
        assert_eq!(err.exit_code(), 2);
        assert!(Cli::try_parse_from(["amirustrained", "--probe-timeout", "1"]).is_ok());
    }

    #[test]
    fn probe_kernel_execution_flag_and_alias() {
        let parsed = Cli::try_parse_from(["amirustrained", "--probe-kernel-execution"]).unwrap();
        assert!(parsed.probe_kernel_execution);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(opts.probe_kernel_execution);

        let parsed = Cli::try_parse_from(["amirustrained", "--probe-kernel"]).unwrap();
        assert!(parsed.probe_kernel_execution);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(opts.probe_kernel_execution);

        let parsed = Cli::try_parse_from(["amirustrained"]).unwrap();
        assert!(!parsed.probe_kernel_execution);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(!opts.probe_kernel_execution);
    }

    #[test]
    fn compact_flag_and_alias() {
        let parsed = Cli::try_parse_from(["amirustrained", "--compact"]).unwrap();
        assert!(parsed.compact);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(opts.compact);

        let parsed = Cli::try_parse_from(["amirustrained", "--terse"]).unwrap();
        assert!(parsed.compact);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(opts.compact);

        let parsed = Cli::try_parse_from(["amirustrained"]).unwrap();
        assert!(!parsed.compact);
        let (_, opts) = Opts::from_cli(&parsed).unwrap();
        assert!(!opts.compact);
    }
}
