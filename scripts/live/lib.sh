# shellcheck shell=bash
# Shared plumbing for scripts/live/<env>.sh leaves. A leaf defines:
#   LABEL         human name
#   env_check     print a reason (and nothing else) when the env cannot run here
#   env_setup     fetch user-level assets (optional); $SYSTEM=1 also allows sudo host prep
#   env_launch    run "$BIN" "$@" inside the env, passing stdio + exit code through
# then calls `leaf_main "$@"`.
#
# Leaf CLI (amirustrained takes no positional args, so these words are free):
#   <leaf> [AMIRUSTRAINED ARGS...]   build latest (unless BIN is set) and run in the env
#   <leaf> check                     "available" (exit 0) | "unavailable: <why>" (exit 3)
#   <leaf> setup [--system]          fetch assets; --system: sudo host prep (CI runners)
#   <leaf> label                     print LABEL
#
# Environment: BIN, PROFILE (debug|release, default debug), TARGET,
# AMR_LIVE_CACHE, CONTAINER_ENGINE (docker|podman), IMAGE (default alpine:latest).
set -euo pipefail

LIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LIVE_DIR/../.." && pwd)"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PROFILE="${PROFILE:-debug}"
CACHE="${AMR_LIVE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/amirustrained/live-matrix}"
IMAGE="${IMAGE:-alpine:latest}"
SYSTEM=0
ENV_ID="$(basename "$0" .sh)"

GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/gvisor.tar.zstd"

note() { echo "live/$ENV_ID: $*" >&2; }
die() { note "$*"; exit 2; }

# Unset BIN => (re)build the working tree so every run tests the latest code;
# cargo's no-op rebuild is sub-second.
resolve_bin() {
  if [[ -z "${BIN:-}" ]]; then
    local -a flags=(--quiet --target "$TARGET")
    [[ "$PROFILE" == release ]] && flags+=(--release)
    (cd "$ROOT" && cargo build "${flags[@]}" >&2)
    BIN="$ROOT/target/$TARGET/$PROFILE/amirustrained"
  fi
  [[ -x "$BIN" ]] || die "no executable at $BIN"
  BIN="$(realpath "$BIN")"
  export BIN
}

sysctl_userns() { sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 || true; }

# ── container engines ────────────────────────────────────────────────────────
engine() {
  if [[ -n "${CONTAINER_ENGINE:-}" ]]; then echo "$CONTAINER_ENGINE"
  elif command -v docker >/dev/null; then echo docker
  elif command -v podman >/dev/null; then echo podman
  else return 1; fi
}
# `docker` is frequently a podman shim; their flags differ, so ask the binary.
engine_flavor() { if "$1" --version 2>/dev/null | grep -qi podman; then echo podman; else echo docker; fi; }

check_engine() {
  local eng
  eng="$(engine)" || { echo "no docker/podman"; return; }
  "$eng" info >/dev/null 2>&1 || echo "$eng unreachable ($eng info failed)"
}

# $1: extra engine flags (word-split); rest: amirustrained args. The binary is
# staged into a private dir mounted `:z` so SELinux hosts relabel the copy, not
# the build output, and the container keeps its normal confinement.
container_run() {
  local -a extra; read -r -a extra <<<"$1"; shift
  local stage rc=0
  stage="$(mktemp -d "${TMPDIR:-/tmp}/amr-ctr.XXXXXX")"
  cp "$BIN" "$stage/amirustrained"
  "$(engine)" run --rm "${extra[@]}" -v "$stage:/opt/amr:ro,z" "$IMAGE" /opt/amr/amirustrained "$@" || rc=$?
  rm -rf "$stage"
  return "$rc"
}

# ── gVisor ───────────────────────────────────────────────────────────────────
runsc_bin() {
  if command -v runsc >/dev/null; then command -v runsc
  elif [[ -x "$CACHE/bin/runsc" ]]; then echo "$CACHE/bin/runsc"
  else return 1; fi
}

setup_runsc() {
  if (( SYSTEM )); then
    # Container daemons exec the runtime as root: install system-wide.
    command -v runsc >/dev/null || curl -fsSL "$GVISOR_URL" | sudo tar --zstd -xf - -C /usr/local/bin
    sysctl_userns
  elif ! runsc_bin >/dev/null; then
    mkdir -p "$CACHE/bin"
    curl -fsSL "$GVISOR_URL" | tar --zstd -xf - -C "$CACHE/bin"
  fi
}

# ── entrypoint ───────────────────────────────────────────────────────────────
env_setup() { :; }

leaf_main() {
  local why
  case "${1:-}" in
    check)
      why="$(env_check)"
      if [[ -z "$why" ]]; then echo available; else echo "unavailable: $why"; exit 3; fi ;;
    setup)
      [[ "${2:-}" == --system ]] && SYSTEM=1
      env_setup
      why="$(env_check)"
      if [[ -z "$why" ]]; then note "ready"; else note "still unavailable: $why"; exit 3; fi ;;
    label) echo "$LABEL" ;;
    *)
      why="$(env_check)"
      [[ -z "$why" ]] || { note "unavailable: $why (try: $0 setup)"; exit 3; }
      resolve_bin
      env_launch "$@" ;;
  esac
}
