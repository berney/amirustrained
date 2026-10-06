#!/usr/bin/env bash
# gVisor as the OCI runtime of the container engine (docker --runtime=runsc / podman --runtime=<runsc>).
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="gVisor (container runtime)"

env_check() {
  local why; why="$(check_engine)"; [[ -z "$why" ]] || { echo "$why"; return; }
  runsc_bin >/dev/null || { echo "runsc not found"; return; }
  local eng; eng="$(engine)"
  if [[ "$(engine_flavor "$eng")" == docker ]]; then
    "$eng" info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"' \
      || echo "runsc not registered with docker (setup --system)"
  fi
}
env_setup() {
  setup_runsc
  if (( SYSTEM )) && [[ "$(engine_flavor "$(engine)")" == docker ]]; then
    sudo "$(command -v runsc)" install
    sudo systemctl restart docker
  fi
}
env_launch() {
  if [[ "$(engine_flavor "$(engine)")" == podman ]]; then
    # Rootless podman: runsc can apply neither SELinux labels nor systemd cgroups.
    container_run "--runtime=$(runsc_bin) --runtime-flag=ignore-cgroups --security-opt label=disable" "$@"
  else
    container_run "--runtime=runsc" "$@"
  fi
}

leaf_main "$@"
