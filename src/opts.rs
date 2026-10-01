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
    /// Opt-in REAL eBPF program load via aya (embedded object, one
    /// BPF_PROG_LOAD). Succeeds only when the caller can load programs
    /// (CAP_BPF/CAP_SYS_ADMIN — effectively root); every denial is decoded
    /// into `ebpf.load`. Nothing is pinned; loaded state dies with the
    /// process (src/probes/ebpf_load.rs).
    #[arg(long)]
    pub probe_ebpf: bool,
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
#[derive(Debug, Clone)]
pub struct Opts {
    pub pid: Option<u32>,
    pub probe_syscalls: bool,
    pub probe_ebpf: bool,
    pub probe_timeout: Option<Duration>,
    pub fail_on: Option<Severity>,
    pub dump_filters: bool,
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
                probe_ebpf: c.probe_ebpf,
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
            probe_ebpf: false,
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
    fn probe_ebpf_is_a_pure_opt_in_flag() {
        // The load probe needs no ceiling machinery (a single syscall) and
        // must not disturb the sweep rules: default off, flag maps through,
        // and with the flag alone the timeout stays None.
        let (_, opts) = Opts::from_cli(&cli("text", None, None)).unwrap();
        assert!(!opts.probe_ebpf);
        let c = Cli {
            probe_ebpf: true,
            ..cli("text", None, None)
        };
        let (_, opts) = Opts::from_cli(&c).unwrap();
        assert!(opts.probe_ebpf);
        assert_eq!(opts.probe_timeout, None);
        // The public long form really is `--probe-ebpf`.
        let parsed = Cli::try_parse_from(["amirustrained", "--probe-ebpf"]).unwrap();
        assert!(parsed.probe_ebpf);
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
}
