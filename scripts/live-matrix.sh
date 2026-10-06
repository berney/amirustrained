#!/usr/bin/env bash
# Live runtime matrix: drive the scripts/live/<env>.sh leaves. Shared by local
# runs, `cargo test --test live_matrix`, and .github/workflows/live-matrix.yml.
# For a single environment call the leaf directly, e.g.
#   scripts/live/gvisor.sh --compact
#
#   scripts/live-matrix.sh list                          # env, status, label, reason (aligned; TSV when piped)
#   scripts/live-matrix.sh run [--skip-unavailable] <env>...|all
#                                                        # full sweep -> $OUT/<env>/
#   scripts/live-matrix.sh summary [DIR]                 # markdown comparison tables
#   scripts/live-matrix.sh setup [--system] <env>...|all # forward to each leaf's setup
#   scripts/live-matrix.sh oracle [env]...               # ground-truth drop/exec audit vs AMR-030
#     Disposable runtimes only (enforced: firecracker). Writes $OUT/<env>/
#     {result.json, oracle.tsv, oracle-verdict.txt}; exit 1 on any mismatch.
#
# OUT defaults to target/live-matrix. BIN/PROFILE/etc.: see scripts/live/lib.sh.
# `run` writes per env: status (ok | skipped: <why> | failed: <why>), one file
# per MODES view (+ .stderr), and result.json (--format json, must parse).
set -euo pipefail

# lib.sh: ROOT, resolve_bin (build once, export BIN so leaves reuse it).
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/live/lib.sh"
LIVE="$LIVE_DIR"
OUT="${OUT:-$ROOT/target/live-matrix}"

# Matrix order == summary column order.
ENVS=(host docker-default docker-privileged bubblewrap unshare gvisor gvisor-privileged gvisor-rootless gvisor-sudo firecracker)

# output-file|title|args. Human views are best-effort; result.json is the gate.
MODES=(
  "standard.txt|1. Standard Output (Card View with Why / Fix / Evidence)|"
  "compact.txt|2. Compact Output (--compact)|--compact"
  "verbose.txt|3. Verbose Output (--verbose)|--verbose"
  "active.txt|4. Active Probes Sweep (--probe-kernel-execution --probe-syscalls)|--compact --probe-kernel-execution --probe-syscalls"
  "report.md|5. Markdown Report (--format markdown)|--format markdown"
  "report.yaml|6. YAML Report (--format yaml)|--format yaml"
  "yolo.txt|7. Maximum-Info Sweep (--compact --yolo)|--compact --yolo"
)

die() { echo "live-matrix: $*" >&2; exit 2; }

leaf() {
  [[ -x "$LIVE/$1.sh" ]] || die "unknown env '$1' (known: ${ENVS[*]})"
  echo "$LIVE/$1.sh"
}

expand_envs() {
  local e
  for e in "$@"; do
    if [[ "$e" == all ]]; then printf '%s\n' "${ENVS[@]}"; else leaf "$e" >/dev/null; echo "$e"; fi
  done
}

group_start() { if [[ "${GITHUB_ACTIONS:-}" == true ]]; then echo "::group::$1"; else echo "── $1 ──"; fi; }
group_end() { if [[ "${GITHUB_ACTIONS:-}" == true ]]; then echo "::endgroup::"; else echo; fi; }

# Aligned columns on a terminal; TSV when piped (stable for scripts/agents).
cmd_list() {
  local e st i
  local -a ids=(ENV) status=(STATUS) label=(LABEL) reason=(REASON)
  for e in "${ENVS[@]}"; do
    st="$("$LIVE/$e.sh" check || true)"
    ids+=("$e"); label+=("$("$LIVE/$e.sh" label)")
    if [[ "$st" == available ]]; then status+=(available); reason+=("")
    else status+=(unavailable); reason+=("${st#unavailable: }"); fi
  done
  if [[ -t 1 ]]; then
    local we=0 ws=0 wl=0
    for i in "${!ids[@]}"; do
      (( ${#ids[i]} > we )) && we=${#ids[i]}
      (( ${#status[i]} > ws )) && ws=${#status[i]}
      (( ${#label[i]} > wl )) && wl=${#label[i]}
    done
    for i in "${!ids[@]}"; do
      printf '%-*s  %-*s  %-*s%s\n' "$we" "${ids[i]}" "$ws" "${status[i]}" "$wl" "${label[i]}" \
        "${reason[i]:+  ${reason[i]}}"
    done
  else
    for i in "${!ids[@]}"; do printf '%s\t%s\t%s\t%s\n' "${ids[i]}" "${status[i]}" "${label[i]}" "${reason[i]}"; done
  fi
}

run_one() {
  local env="$1" dir="$OUT/$1" l st mode file title args rc
  l="$(leaf "$env")"
  rm -rf "$dir"; mkdir -p "$dir"
  if ! st="$("$l" check)"; then
    echo "skipped: ${st#unavailable: }" > "$dir/status"
    echo "live-matrix: $env $(cat "$dir/status")" >&2
    return 3
  fi
  for mode in "${MODES[@]}"; do
    IFS='|' read -r file title args <<<"$mode"
    group_start "[$env] $title"
    rc=0
    # shellcheck disable=SC2086 # args is a fixed word list from MODES
    "$l" $args > "$dir/$file" 2> "$dir/${file%.*}.stderr" || rc=$?
    cat "$dir/$file" "$dir/${file%.*}.stderr"
    (( rc == 0 )) || echo "(exit $rc)"
    group_end
  done
  if "$l" --format json > "$dir/result.json" 2> "$dir/result.stderr" \
      && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$dir/result.json" 2>/dev/null; then
    echo ok > "$dir/status"
    echo "[$env] result.json OK -> $dir"
  else
    echo "failed: --format json did not produce a JSON report" > "$dir/status"
    echo "live-matrix: $env failed; stderr:" >&2
    cat "$dir/result.stderr" >&2
    return 1
  fi
}

cmd_run() {
  local skip=0 rc=0 r env
  local -a args=()
  for r in "$@"; do
    case "$r" in
      --skip-unavailable) skip=1 ;;
      all) skip=1; args+=(all) ;;
      -*) die "unknown flag $r" ;;
      *) args+=("$r") ;;
    esac
  done
  (( ${#args[@]} )) || die "usage: run [--skip-unavailable] <env>...|all"
  local -a envs; mapfile -t envs < <(expand_envs "${args[@]}")
  resolve_bin
  echo "# binary: $BIN"
  for env in "${envs[@]}"; do
    r=0; run_one "$env" || r=$?
    (( r == 3 && skip )) && continue
    (( r == 0 )) || rc=1
  done
  return "$rc"
}

cmd_summary() {
  local e
  local -a pairs=()
  for e in "${ENVS[@]}"; do pairs+=("$e=$("$LIVE/$e.sh" label)"); done
  python3 "$ROOT/scripts/live-matrix-summary.py" "${1:-$OUT}" "${pairs[@]}"
}

# A leaf still unavailable after setup (exit 3) is reported, not fatal: `run`
# decides whether a skip is acceptable. Download/sudo errors fail.
cmd_setup() {
  local -a flag=()
  [[ "${1:-}" == --system ]] && { flag=(--system); shift; }
  (( $# )) || die "usage: setup [--system] <env>...|all"
  local -a envs; mapfile -t envs < <(expand_envs "$@")
  local env r rc=0
  for env in "${envs[@]}"; do
    r=0; "$LIVE/$env.sh" setup "${flag[@]}" || r=$?
    (( r == 0 || r == 3 )) || rc=1
  done
  return "$rc"
}

# ── oracle: ground-truth drop-and-exec audit ────────────────────────────────
# Only VM-isolated envs are safe to mutate: containers share the host kernel
# (their /proc, /sys are host-kernel interfaces), and host/bwrap/unshare
# share the filesystem itself. Widen ORACLE_ENVS only after verifying that
# nothing escapes; the probe itself is create-only (never truncates existing
# files, never mkdirs) as a second line of defense.
ORACLE_ENVS=(firecracker)

# Guest root, dash. Per mount: create-only copy of /bin/true, execute it,
# mknod + read a null node, remove both. Columns: mount fstype write exec
# mknod devread. Mountinfo escapes whitespace in paths, so plain splitting
# is safe; escaped paths are emitted as fstype `escaped` and not tested.
# shellcheck disable=SC2016 # deliberately unevaluated: runs in the guest's dash
ORACLE_PROBE='
while read -r _ _ _ _ mp rest; do
  case $mp in *\\*) echo "$mp escaped skip skip skip skip"; continue;; esac
  set -- $rest; while [ "$1" != "-" ]; do shift; done; fs=$2
  f="$mp/.amr-oracle"; d="$f.dev"
  w=ok x=no m=no r=no
  if [ -e "$f" ] || [ -e "$d" ]; then
    echo "$mp $fs present skip skip skip"; continue
  fi
  if cp /bin/true "$f" 2>/dev/null; then
    "$f" >/dev/null 2>&1 && x=ok
  else w=fail; fi
  if mknod "$d" c 1 3 2>/dev/null; then
    m=ok; dd if="$d" bs=1 count=1 >/dev/null 2>&1 && r=ok
  fi
  rm -f "$f" "$d"
  echo "$mp $fs $w $x $m $r"
done < /proc/self/mountinfo
'

cmd_oracle() {
  local env l dir rc=0
  local -a envs=("$@")
  (( ${#envs[@]} )) || envs=("${ORACLE_ENVS[0]}")
  for env in "${envs[@]}"; do
    [[ " ${ORACLE_ENVS[*]} " == *" $env "* ]] ||
      die "oracle: env '$env' is not fully disposable; allowed: ${ORACLE_ENVS[*]}"
  done
  resolve_bin
  for env in "${envs[@]}"; do
    l="$(leaf "$env")"
    "$l" check >/dev/null || die "oracle: $env unavailable"
    dir="$OUT/$env"; mkdir -p "$dir"
    "$l" --format json > "$dir/result.json" || die "oracle: $env scan failed"
    "$l" shell -- sh -c "$ORACLE_PROBE" > "$dir/oracle.tsv" 2> "$dir/oracle.stderr" ||
      die "oracle: $env probe run failed (see $dir/oracle.stderr)"
    echo "# $env: passive AMR-030 verdicts vs drop-and-exec oracle"
    python3 - "$dir" <<'PY' | tee "$dir/oracle-verdict.txt" || rc=1
import json, os, sys

d = sys.argv[1]
res = json.load(open(os.path.join(d, "result.json")))
staging, caps = {}, []
for p in res["probes"]:
    if p["name"] == "mounts":
        for f in p["facts"]:
            if f["key"] == "staging" and f["value"]:
                staging = {s["mount_point"]: s for s in f["value"]}
    if p["name"] == "capabilities":
        for f in p["facts"]:
            if f["key"] == "effective" and f["value"]:
                caps = f["value"]
can_mknod = "cap_mknod" in caps

print(f"{'MOUNT':28} {'FSTYPE':12} {'PREDICTED':10} {'WRITE':7} {'EXEC':4} {'MKNOD':5} {'DEVREAD':7} VERDICT")
lines = [ln for ln in open(os.path.join(d, "oracle.tsv")) if ln.strip()]
bad = seen = 0
for ln in lines:
    seen += 1
    mp, fst, w, x, m, r = ln.split()
    st = staging.get(mp)
    p_exec = st is not None
    p_dev = p_exec and "nodev" in st["missing_flags"] and can_mknod
    t_exec, t_dev = x == "ok", r == "ok"
    v = []
    if w in ("present", "skip"):
        v.append("ERR(unprobed)")
    if p_exec != t_exec:
        v.append("FP-exec" if p_exec else "FN-exec")
    if p_dev != t_dev:
        v.append("FP-dev" if p_dev else "FN-dev")
    verdict = " ".join(v) if v else "ok"
    if verdict != "ok":
        bad += 1
    pred = ("exec" if p_exec else "-") + ("/dev" if p_dev else "")
    print(f"{mp:28} {fst:12} {pred:10} {w:7} {x:4} {m:5} {r:7} {verdict}")
tokens = set(t for ln in lines for t in ln.split())
for mp in sorted(staging):
    if mp not in tokens:
        print(f"{mp:28} {'?':12} {'exec?':10} {'absent':7} {'':4} {'':5} {'':7} ERR(not probed)")
        bad += 1

print()
if bad:
    print(f"MISMATCH: {bad} of {seen} mounts disagree with the oracle")
else:
    print(f"OK: {seen} mounts; passive verdicts agree with the drop-and-exec oracle")
sys.exit(1 if bad else 0)
PY
  done
  return "$rc"
}

case "${1:-}" in
  list) cmd_list ;;
  run) shift; cmd_run "$@" ;;
  summary) shift; cmd_summary "$@" ;;
  setup) shift; cmd_setup "$@" ;;
  oracle) shift; cmd_oracle "$@" ;;
  help|-h|--help|'') sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}" ;;
  *) die "unknown command '$1' (try: $0 help)" ;;
esac
