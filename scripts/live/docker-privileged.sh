#!/usr/bin/env bash
# --privileged container.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Docker Privileged"

env_check() { check_engine; }
env_launch() { container_run "--privileged" "$@"; }

leaf_main "$@"
