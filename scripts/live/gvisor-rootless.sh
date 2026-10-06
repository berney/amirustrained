#!/usr/bin/env bash
# Standalone rootless gVisor sandbox (runsc --rootless do).
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="gVisor (runsc --rootless do)"

env_check() { runsc_bin >/dev/null || echo "runsc not found"; }
env_setup() { setup_runsc; }
env_launch() { inner_cmd "$BIN" "$@"; "$(runsc_bin)" --rootless --network=none "do" "${CMD[@]}"; }

leaf_main "$@"
