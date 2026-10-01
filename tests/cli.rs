use std::fs;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use serde_json::Value;

#[test]
fn version_flag_prints_semver() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("amirustrained 0.1.0"));
}

// ---------------------------------------------------------------------------
// Process contract helpers.
//
// The probes run for real against this host, so nothing here may assert
// host-specific fact/finding values — only exit codes, stream structure, and
// the relationship between the reported counts and the exit code.
// ---------------------------------------------------------------------------

/// Runs the binary and returns `(exit code, stdout)`.
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::cargo_bin("amirustrained")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or_else(|| {
        panic!(
            "killed by signal: {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (code, String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parses the trailing `summary` line of a jsonl stream.
fn summary(stdout: &str) -> Value {
    let line = stdout.lines().last().expect("at least one jsonl line");
    let v: Value = serde_json::from_str(line).expect("summary line is JSON");
    assert_eq!(v["type"], "summary", "last line must be the summary");
    v
}

/// `--fail-on` level -> the count keys that count as tripping it. Mirrors
/// `model::Severity`'s ordering (`Info` is the lowest, so `any` trips on all).
const LEVELS: &[(&str, &[&str])] = &[
    ("any", &["critical", "high", "medium", "low", "info"]),
    ("info", &["critical", "high", "medium", "low", "info"]),
    ("low", &["critical", "high", "medium", "low"]),
    ("medium", &["critical", "high", "medium"]),
    ("high", &["critical", "high"]),
    ("critical", &["critical"]),
];

#[test]
fn bogus_format_exits_2() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["--format", "yaml"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("unknown format"));
}

#[test]
fn jsonl_stream_has_meta_first_and_summary_last() {
    let out = Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["--format", "jsonl"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    assert!(lines.next().unwrap().contains(r#""type":"meta""#));
    assert!(lines.last().unwrap().contains(r#""type":"summary""#));
}

#[test]
fn unwritable_output_exits_2() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["-o", "/nonexistent-dir-xyz/out.json"])
        .assert()
        .code(2);
}

#[test]
fn output_error_names_the_path_on_stderr() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["-o", "/nonexistent-dir-xyz/out.json"])
        .assert()
        .code(2)
        .stderr(contains("cannot write").and(contains("/nonexistent-dir-xyz/out.json")));
}

#[test]
fn bad_fail_on_level_exits_2() {
    Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["--fail-on", "apocalypse"])
        .assert()
        .code(2)
        .stderr(contains("unknown fail-on level"));
}

#[test]
fn fail_on_exit_code_matches_reported_counts() {
    for (level, at_or_above) in LEVELS {
        let (code, stdout) = run(&["--format", "jsonl", "--fail-on", level]);
        let summary = summary(&stdout);
        assert_eq!(summary["complete"], Value::Bool(true), "scan completed");
        let counts = &summary["counts"];
        let tripped = at_or_above
            .iter()
            .any(|k| counts[k].as_u64().unwrap_or(0) > 0);
        assert_eq!(
            code,
            if tripped { 1 } else { 0 },
            "--fail-on {level}, counts {counts}"
        );
    }
}

#[test]
fn meta_line_reflects_pid_and_probe_timeout() {
    let (code, stdout) = run(&["--format", "jsonl", "--pid", "4242", "--probe-timeout", "5"]);
    assert_eq!(code, 0);
    let first: Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(first["type"], "meta");
    assert_eq!(first["scan"]["targetPid"], 4242);
    assert_eq!(first["scan"]["probeTimeoutS"], 5);
}

#[test]
fn huge_probe_timeout_is_clamped_not_overflowing() {
    // `Duration::from_secs(u64::MAX) + Instant::now()` overflows and panics;
    // the CLI must clamp before the pipeline does any deadline math.
    let (code, stdout) = run(&[
        "--format",
        "jsonl",
        "--probe-timeout",
        "18446744073709551615",
    ]);
    assert_eq!(code, 0);
    let first: Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(first["scan"]["probeTimeoutS"], 86_400);
}

#[test]
fn output_file_gets_the_report_and_stdout_stays_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.jsonl");
    let out = Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["--format", "jsonl", "-o", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "nothing may reach stdout with -o");
    let file = fs::read_to_string(&path).unwrap();
    let mut lines = file.lines();
    assert!(lines.next().unwrap().contains(r#""type":"meta""#));
    assert!(lines.last().unwrap().contains(r#""type":"summary""#));
    // Same registry, same event count through either output path.
    let (_, stdout) = run(&["--format", "jsonl"]);
    assert_eq!(file.lines().count(), stdout.lines().count());
}

#[test]
fn verbose_text_adds_the_meta_header() {
    let (code, stdout) = run(&["--verbose"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("amirustrained 0.1.0 scanning pid"));
    assert!(stdout.contains("scan complete"));
}

#[test]
fn quiet_text_omits_the_meta_header() {
    let (code, stdout) = run(&[]);
    assert_eq!(code, 0);
    assert!(!stdout.contains("scanning pid"));
    assert!(stdout.contains("scan complete"));
}

#[test]
fn markdown_format_renders_the_report_document() {
    let (code, stdout) = run(&["--format", "markdown"]);
    assert_eq!(code, 0);
    // Bulk contract: the document owns stdout start-to-finish — no streaming
    // probe lines before or after it.
    assert!(
        stdout.starts_with("# amirustrained report"),
        "markdown output: {stdout}"
    );
    assert!(
        stdout.ends_with("scan complete\n") || stdout.ends_with(")\n"),
        "markdown output must end on the counts line: {stdout}"
    );
}

#[test]
fn sarif_format_not_yet_renders_text_and_exits_0() {
    // Task 24 replaces the sarif fallback; until then misuse-safe text output.
    let (code, stdout) = run(&["--format", "sarif"]);
    assert_eq!(code, 0, "sarif must not fail");
    assert!(stdout.contains("scan complete"), "sarif output: {stdout}");
}

#[test]
fn json_format_emits_one_pretty_report_document() {
    let (code, stdout) = run(&["--format", "json"]);
    assert_eq!(code, 0);
    // Bulk contract: stdout is exactly one document (from_str rejects trailing
    // non-whitespace), carrying the report root — not jsonl streaming lines.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json stdout must be one JSON document");
    assert_eq!(v["schemaVersion"], 1);
    assert_eq!(v["tool"]["name"], "amirustrained");
    assert_eq!(v["scan"]["complete"], true);
    for key in ["verdict", "probes", "findings", "counts"] {
        assert!(v.get(key).is_some(), "missing root key {key}: {v}");
    }
    assert!(
        !stdout.contains(r#""type":"#),
        "no jsonl stream lines in bulk json"
    );
}
