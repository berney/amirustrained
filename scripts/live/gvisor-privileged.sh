#!/usr/bin/env bash
# `--privileged` container with gVisor as the engine's OCI runtime
# (docker run --privileged --runtime=runsc).
# Rootless podman cannot mknod, so --privileged bind-mounts every host device
# node (~270 extra mounts); runsc's sandbox then runs out of low FDs
# ("unable to remap stdios, FD 253 is already in use"). That combination is
# reported unavailable rather than silently weakened; rootful docker works.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="gVisor Privileged (container runtime)"

env_check() {
  local why; why="$(gvisor_container_check)"; [[ -z "$why" ]] || { echo "$why"; return; }
  local eng; eng="$(engine)"
  if [[ "$(engine_flavor "$eng")" == podman && "$("$eng" info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" == true ]]; then
    echo "rootless podman --privileged bind-mounts every host device; runsc fails (FD 253 in use). Needs rootful docker/podman"
  fi
}
env_setup() { gvisor_container_setup; }
env_launch() { gvisor_container_run "--privileged" "$@"; }

leaf_main "$@"
