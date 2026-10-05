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

#[test]
fn help_lists_every_format_including_yaml() {
    // User 2026-10-02: `--format yaml` is a first-class, advertised option -
    // the whole value list must be visible in --help, never hidden.
    let (code, out) = run(&["--help"]);
    assert_eq!(code, 0);
    for f in ["text", "markdown", "json", "yaml", "sarif", "jsonl"] {
        assert!(out.contains(f), "--help must advertise format {f}: {out}");
    }
    assert!(
        out.contains("--no-color"),
        "--help must advertise the colour override: {out}"
    );
}

#[test]
fn forced_color_paints_help_and_no_color_silences_it() {
    // clap owns the help stream; titanium rides its Styles hook. CLICOLOR_FORCE
    // emulates "colour wanted" for a piped test harness; truecolor triples are
    // the palette (electricBlue headers, readoutGreen literals, gold
    // placeholders, alertRed errors, warningAmber invalid tokens).
    let (code, out) = run_env(&["--help"], &[("CLICOLOR_FORCE", "1")]);
    assert_eq!(code, 0);
    assert!(out.contains("38;2;0;180;255"), "blue section header: {out}");
    assert!(out.contains("38;2;0;255;136"), "green flag literal: {out}");
    assert!(out.contains("38;2;212;192;144"), "gold placeholder: {out}");
    // --no-color is honoured even against CLICOLOR_FORCE (explicit flag wins).
    let (code, out) = run_env(&["--no-color", "--help"], &[("CLICOLOR_FORCE", "1")]);
    assert_eq!(code, 0);
    assert!(
        !out.contains('\x1b'),
        "--no-color must strip help styles: {out}"
    );
    // Parse errors on the same stream: red label, amber offending token.
    let (code, err) = run_env_stderr(&["--bogus"], &[("CLICOLOR_FORCE", "1")]);
    assert_eq!(code, 2);
    assert!(err.contains("38;2;255;71;87"), "red error label: {err}");
    assert!(
        err.contains("38;2;255;179;71"),
        "amber invalid token: {err}"
    );
    // The unpainted default (test harness, no force) stays escape-free, which
    // is what the byte-exact help test above relies on.
    let (_, plain) = run(&["--help"]);
    assert!(!plain.contains('\x1b'));
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

/// [`run`] with extra env; `NO_COLOR` is stripped so a forcing variable
/// (anstream honours it over tty detection) is not shadowed by the harness.
fn run_env(args: &[&str], envs: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::cargo_bin("amirustrained").unwrap();
    cmd.env_remove("NO_COLOR").args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// [`run_env`] capturing stderr (clap writes help-errors there).
fn run_env_stderr(args: &[&str], envs: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::cargo_bin("amirustrained").unwrap();
    cmd.env_remove("NO_COLOR").args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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
        .args(["--format", "xml"])
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
fn output_file_never_receives_ansi_escapes() {
    // ReviewT2324: the tty probe answers for stdout, so `color` must be off
    // whenever the sink is a `-o` file — even from a terminal run, the report
    // file must hold plain bytes. (Under the harness stdout is a pipe anyway;
    // this pins the sink-aware precedence against regressions.)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.txt");
    let out = Command::cargo_bin("amirustrained")
        .unwrap()
        .args(["-o", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = fs::read(&path).unwrap();
    assert!(
        !bytes.contains(&0x1b),
        "text report file must contain no ESC bytes"
    );
    assert!(String::from_utf8_lossy(&bytes).contains("scan complete"));
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
fn piped_text_stdout_carries_no_ansi_escapes() {
    // The harness gives the child a pipe: `is_terminal()` is false, so the
    // renderer must emit plain bytes — `--no-color`/`NO_COLOR` change nothing
    // about that, and neither does the verbosity level.
    for args in [&[] as &[&str], &["--verbose"]] {
        let (code, stdout) = run(args);
        assert_eq!(code, 0);
        assert!(
            !stdout.contains('\x1b'),
            "piped text stdout must contain no ESC bytes: {args:?}"
        );
    }
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
        stdout.ends_with(")\n"),
        "markdown output must end on the counts line: {stdout}"
    );
}

#[test]
fn sarif_format_emits_one_valid_envelope() {
    let (code, stdout) = run(&["--format", "sarif"]);
    assert_eq!(code, 0, "sarif must not fail");
    // Bulk contract: stdout is exactly one JSON document (from_str rejects
    // trailing non-whitespace) — the SARIF envelope, not text.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format sarif stdout must be one JSON document");
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "amirustrained");
    assert!(v["runs"][0]["results"].is_array());
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

// ---------------------------------------------------------------------------
// Fixture-root end-to-end (Task 25).
//
// Under `--fixture-root` the path probes see only the fixture: a regular-file
// `docker.sock` stand-in yields a writable entry (fixture mode tests O_WRONLY
// on the joined path), its handshake fails so `info` is null, and AMR-001
// fires fail-loud (unknown peer treated as root). The verdict stays `host`,
// which keeps every `container_only` rule silent, so nothing but the fixture
// decides the fail-on boundary below. The single host input is the uds
// handshake against the literal `/run/docker.sock`; its outcome only fills
// `info` and cannot demote AMR-001 (no root daemon declares rootless there).
// ---------------------------------------------------------------------------

/// `run` with the fixture root prepended.
fn in_fixture(root: &std::path::Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["--fixture-root", root.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn fail_on_trips_against_fixture_socket() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("run")).unwrap();
    fs::write(dir.path().join("run/docker.sock"), "").unwrap();

    // Plain scan: exit 0 regardless of findings (spec exit-code table), and
    // the finding severity is the rule's ACTUAL Critical — AMR-001 is not
    // `requires_root`, so no privilege demotion touches it.
    let (code, stdout) = in_fixture(dir.path(), &["--format", "json"]);
    assert_eq!(code, 0, "a completed scan exits 0 even with findings");
    let v: Value = serde_json::from_str(&stdout).expect("one json document");
    let findings = v["findings"].as_array().unwrap();
    let amr001 = findings
        .iter()
        .find(|f| f["rule"] == "AMR-001")
        .unwrap_or_else(|| panic!("writable docker.sock must induce AMR-001: {findings:?}"));
    assert_eq!(
        amr001["severity"], "critical",
        "fail-on compares final severities; the fixture finding stays Critical"
    );

    // Reality check against the plan sketch: AMR-001 is Critical, not High,
    // so `--fail-on high` trips it — and `--fail-on critical` trips too, the
    // boundary met EXACTLY (`f.severity >= lvl` on the finding's final
    // severity; Critical >= Critical). The exit-0 side of that boundary is
    // pinned by the clean fixture below.
    let (code, _) = in_fixture(dir.path(), &["--fail-on", "high"]);
    assert_eq!(code, 1, "a Critical finding must trip --fail-on high");
    let (code, _) = in_fixture(dir.path(), &["--fail-on", "critical"]);
    assert_eq!(
        code, 1,
        "a Critical finding meets the critical threshold exactly"
    );
}

#[test]
fn clean_fixture_stays_under_the_fail_on_thresholds() {
    // The exit-0 side of the critical boundary: no socket stand-in means no
    // AMR-001, and the host verdict keeps every High-or-worse
    // (`container_only`) rule silent — only sub-High findings can appear, so
    // both thresholds pass.
    let dir = tempfile::tempdir().unwrap();
    let (code, stdout) = in_fixture(dir.path(), &["--format", "json"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("one json document");
    let findings = v["findings"].as_array().unwrap();
    assert!(
        !findings.iter().any(|f| f["rule"] == "AMR-001"),
        "no socket in the fixture, no AMR-001: {findings:?}"
    );
    for level in ["high", "critical"] {
        let (code, _) = in_fixture(dir.path(), &["--fail-on", level]);
        assert_eq!(code, 0, "the clean fixture must not trip --fail-on {level}");
    }
}

#[test]
fn flag_probe_kernel_execution_and_alias() {
    let (code, _) = run(&["--probe-kernel-execution"]);
    assert_eq!(code, 0, "--probe-kernel-execution should be accepted");

    let (code, _) = run(&["--probe-kernel"]);
    assert_eq!(code, 0, "--probe-kernel alias should be accepted");
}

#[test]
fn flag_compact_and_terse_alias() {
    let (code, _) = run(&["--compact"]);
    assert_eq!(code, 0, "--compact should be accepted");

    let (code, _) = run(&["--terse"]);
    assert_eq!(code, 0, "--terse alias should be accepted");
}

#[test]
fn help_lists_kernel_execution_and_compact_with_aliases() {
    let (code, stdout) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--probe-kernel-execution"),
        "help must list --probe-kernel-execution:\n{stdout}"
    );
    assert!(
        stdout.contains("probe-kernel"),
        "help must list probe-kernel alias:\n{stdout}"
    );
    assert!(
        stdout.contains("--compact"),
        "help must list --compact:\n{stdout}"
    );
    assert!(
        stdout.contains("terse"),
        "help must list terse alias:\n{stdout}"
    );
}
