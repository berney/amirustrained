#!/usr/bin/env bash
# bwrap sandbox: read-only host root, fresh tmp/proc/dev, every namespace unshared.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Bubblewrap"

env_check() {
  command -v bwrap >/dev/null || { echo "bwrap not installed"; return; }
  bwrap --ro-bind / / --unshare-all true 2>/dev/null || echo "bwrap cannot create namespaces (userns restricted?)"
}
env_setup() {
  (( SYSTEM )) || return 0
  command -v bwrap >/dev/null || { sudo apt-get update && sudo apt-get install -y bubblewrap; }
  sysctl_userns
}
env_launch() { inner_cmd "$BIN" "$@"; bwrap --ro-bind / / --tmpfs /tmp --proc /proc --dev /dev --unshare-all "${CMD[@]}"; }

leaf_main "$@"
