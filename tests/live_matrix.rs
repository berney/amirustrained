//! Live runtime matrix: the test binary runs inside real isolation runtimes
//! via the `scripts/live/<env>.sh` leaves. `#[ignore]`d because they need
//! container engines, gVisor, KVM, etc.:
//!
//!   cargo test --test live_matrix -- --ignored            # every env available here
//!   cargo test --test live_matrix -- --ignored gvisor     # one env (name filter)
//!
//! An env whose leaf reports itself unavailable (exit 3) is skipped with a
//! note on stderr, unless `AMR_LIVE_REQUIRE=1`, which turns skips into
//! failures (use where the runtime is known to be provisioned).

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// Shared-kernel-container rules (AGENTS.md "Container Gating"): they must stay
/// silent whenever the verdict is host or a VM-isolated runtime.
const CONTAINER_ONLY_RULES: [&str; 6] = [
    "AMR-002", "AMR-005", "AMR-019", "AMR-031", "AMR-032", "AMR-033",
];

/// Runs the leaf for `env` with `--format json`; `None` when unavailable here.
fn scan(env: &str) -> Option<Value> {
    let leaf = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("scripts/live/{env}.sh"));
    let out = Command::new(&leaf)
        .args(["--format", "json"])
        .env("BIN", env!("CARGO_BIN_EXE_amirustrained"))
        .output()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", leaf.display()));
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.code() == Some(3) {
        assert!(
            std::env::var_os("AMR_LIVE_REQUIRE").is_none(),
            "{env} required but unavailable: {stderr}"
        );
        eprintln!("SKIP {env}: {}", stderr.trim());
        return None;
    }
    assert!(
        out.status.success(),
        "{env} exited {:?}: {stderr}",
        out.status
    );
    Some(
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{env} JSON: {e}\n{stderr}")),
    )
}

fn rules(report: &Value) -> Vec<&str> {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| f["rule"].as_str().expect("finding rule id"))
        .collect()
}

/// Contract every env must meet; returns the verdict runtime.
fn check_common<'a>(env: &str, report: &'a Value) -> &'a str {
    assert_eq!(report["schemaVersion"], 1, "{env}");
    assert_eq!(
        report["scan"]["complete"], true,
        "{env}: no probe may time out"
    );
    report["verdict"]["runtime"]
        .as_str()
        .unwrap_or_else(|| panic!("{env}: verdict.runtime missing"))
}

fn assert_runtime(env: &str, allowed: &[&str]) {
    let Some(report) = scan(env) else { return };
    let runtime = check_common(env, &report);
    assert!(
        allowed.contains(&runtime),
        "{env}: verdict {runtime}, expected one of {allowed:?}"
    );
    let fired = rules(&report);
    let isolated = matches!(runtime, "host" | "gvisor" | "firecracker" | "kata");
    if isolated {
        for r in CONTAINER_ONLY_RULES {
            assert!(
                !fired.contains(&r),
                "{env}: {r} must stay silent under {runtime}"
            );
        }
    }
    if matches!(runtime, "gvisor" | "firecracker") {
        assert!(
            fired.contains(&"AMR-014"),
            "{env}: strong-isolation finding missing"
        );
    }
}

macro_rules! live {
    ($($name:ident => $env:literal : [$($rt:literal),+];)+) => {$(
        #[test]
        #[ignore = "live runtime; run with --ignored"]
        fn $name() {
            assert_runtime($env, &[$($rt),+]);
        }
    )+};
}

// Verdicts the binary must reach in each env. `docker-*` run under whichever
// engine `docker` resolves to, so podman is an equally correct answer there.
// bwrap/unshare are bare namespaces without container markers: host.
live! {
    host => "host": ["host"];
    docker_default => "docker-default": ["docker", "podman"];
    docker_privileged => "docker-privileged": ["docker", "podman"];
    bubblewrap => "bubblewrap": ["host"];
    unshare => "unshare": ["host"];
    gvisor => "gvisor": ["gvisor"];
    gvisor_privileged => "gvisor-privileged": ["gvisor"];
    gvisor_rootless => "gvisor-rootless": ["gvisor"];
    gvisor_sudo => "gvisor-sudo": ["gvisor"];
    firecracker => "firecracker": ["firecracker"];
}
