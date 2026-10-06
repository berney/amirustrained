#!/usr/bin/env bash
# The bare host: no isolation layer.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Host"

env_check() { :; }
env_launch() { "$BIN" "$@"; }

leaf_main "$@"
