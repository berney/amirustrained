#!/usr/bin/env bash
# Live smoke: run the real binary against the real host. Never destructive:
# the default probes are read-only, and the opt-in --probe-syscalls sweep is
# the EPERM-safe null-arg kind (spec §5/§8). Passes unprivileged.
#
# Honest scan.complete contract (verified in pipeline.rs): `scan.complete`
# becomes true once the scan reaches Summary; degraded/unavailable probe
# facts (e.g. `namespaces` degraded when pid-1 namespaces are unreadable on a
# hardened host) and even timed-out probes NEVER flip it back. So the assert
# below — complete == true — holds on any successful run, degraded probes or
# not; probe quality is visible in each probe's `availability`, not here.
#
# Usage: scripts/live-smoke.sh [PATH_TO_BINARY]
#   or:  PROFILE=release scripts/live-smoke.sh
#   or:  BIN=/some/other/amirustrained scripts/live-smoke.sh
# Defaults to the musl target dir because .cargo/config.toml makes plain
# `cargo build` emit target/x86_64-unknown-linux-musl/{debug,release}/.
set -euo pipefail

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PROFILE="${PROFILE:-debug}"
BIN="${1:-${BIN:-target/${TARGET}/${PROFILE}/amirustrained}}"

if [[ ! -x "$BIN" ]]; then
  echo "# $BIN missing; building ${PROFILE} for $TARGET" >&2
  if [[ "$PROFILE" == "release" ]]; then cargo build --release; else cargo build; fi
fi
[[ -x "$BIN" ]] || { echo "ERROR: no executable at $BIN" >&2; exit 1; }
echo "# binary: $BIN"
file "$BIN" || true

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- formats run clean, exit 0 under `set -e` -------------------------------
"$BIN" --format json     > "$TMP/amr.json"
"$BIN" --format jsonl    > "$TMP/amr.jsonl"
"$BIN" --format sarif    > "$TMP/amr.sarif"
"$BIN" --format markdown > "$TMP/amr.md"
"$BIN" --probe-syscalls --format jsonl -o "$TMP/amr-sys.jsonl"

# --- exit-code contract (this host) ------------------------------------------
# Plain scan: 0 (findings alone never change the exit code). --fail-on high: 1
# here because AMR-022 (rootless podman socket) is High on this host;
# --fail-on critical: 0 (no Critical finding). On a different host these two
# depend on local posture — this script is the THIS-host smoke, not portable CI.
"$BIN" --format json -o /dev/null
rc=0; "$BIN" --fail-on high --format json -o /dev/null || rc=$?
[[ $rc -eq 1 ]] || { echo "FAIL: --fail-on high expected exit 1 on this host, got $rc" >&2; exit 1; }
rc=0; "$BIN" --fail-on critical --format json -o /dev/null || rc=$?
[[ $rc -eq 0 ]] || { echo "FAIL: --fail-on critical expected exit 0 on this host, got $rc" >&2; exit 1; }
echo "# exit codes OK (0 / high=1 / critical=0)"

# --- content assertions -------------------------------------------------------
python3 - "$TMP" <<'EOF'
import json, sys

t = sys.argv[1]
r = json.load(open(f"{t}/amr.json"))
assert r["schemaVersion"] == 1
assert r["scan"]["complete"] is True  # honest contract: see header comment
names = [p["name"] for p in r["probes"]]
expected = {"namespaces", "uidmap", "capabilities", "seccomp",
            "lsm", "vmm", "cgroup", "sockets", "k8s", "runtime"}
assert expected <= set(names), f"missing default probes: {expected - set(names)}"
assert "syscall-probe" not in names, "syscall-probe must only run with --probe-syscalls"
runtime = next(p for p in r["probes"] if p["name"] == "runtime")
assert any(f["key"] == "verdict" for f in runtime["facts"]), "runtime probe must emit verdict"
assert r["verdict"] is not None and r["verdict"]["runtime"], "report verdict present"

for line in open(f"{t}/amr.jsonl"):
    assert json.loads(line)["schemaVersion"] == 1
sarif = json.load(open(f"{t}/amr.sarif"))
assert sarif["version"] == "2.1.0"

sysl = [json.loads(l) for l in open(f"{t}/amr-sys.jsonl")
        if json.loads(l).get("name") == "syscall-probe"]
assert sysl and sysl[0]["name"] == "syscall-probe", "syscalls sweep event missing"

print(f'live smoke OK (verdict={r["verdict"]["runtime"]}/{r["verdict"]["confidence"]}, '
      f'{len(r["findings"])} findings, complete={r["scan"]["complete"]})')
EOF
