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
    /// text | markdown | json | sarif | jsonl
    #[arg(long, default_value = "text")]
    pub format: String,
    #[arg(long, short)]
    pub output: Option<std::path::PathBuf>,
    #[arg(long)]
    pub probe_syscalls: bool,
    #[arg(long)]
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
                probe_timeout: c
                    .probe_timeout
                    .map(|s| Duration::from_secs(s.min(MAX_PROBE_TIMEOUT_SECS))),
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
        let err = Opts::from_cli(&cli("yaml", None, None)).unwrap_err();
        assert_eq!(err.to_string(), "unknown format 'yaml'");
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
}
