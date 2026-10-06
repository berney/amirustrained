#!/usr/bin/env bash
# Standalone root gVisor sandbox (sudo runsc do). Needs passwordless sudo.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="gVisor (sudo runsc do)"

env_check() {
  runsc_bin >/dev/null || { echo "runsc not found"; return; }
  sudo -n true 2>/dev/null || echo "passwordless sudo unavailable"
}
env_setup() { setup_runsc; }
env_launch() { sudo -n "$(runsc_bin)" --network=none "do" "$BIN" "$@"; }

leaf_main "$@"
