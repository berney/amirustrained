#!/usr/bin/env bash
# Default unprivileged container (docker, or podman when `docker` is podman).
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Docker Default"

env_check() { check_engine; }
env_launch() { container_run "" "$@"; }

leaf_main "$@"
