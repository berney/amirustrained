#!/usr/bin/env bash
# gVisor as the OCI runtime of the container engine (docker --runtime=runsc / podman --runtime=<runsc>).
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="gVisor (container runtime)"

env_check() { gvisor_container_check; }
env_setup() { gvisor_container_setup; }
env_launch() { gvisor_container_run "" "$@"; }

leaf_main "$@"
