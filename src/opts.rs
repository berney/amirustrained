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
    #[arg(long, hide = true)]
    pub fixture_root: Option<std::path::PathBuf>,
}

/// Internal derived view of `Cli`; Task 7 converts `Cli` → `Opts` so the
/// pipeline never depends on clap.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are read as Task 7/12+/17 wire each consumer.
pub struct Opts {
    pub pid: Option<u32>,
    pub probe_syscalls: bool,
    pub probe_timeout: Option<Duration>,
    pub fail_on: Option<Severity>,
    pub dump_filters: bool,
}
