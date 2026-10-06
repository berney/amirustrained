#!/usr/bin/env bash
# Raw unprivileged user+pid+mount namespace, mapped root.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Raw User-NS"

env_check() { unshare --user --map-root-user true 2>/dev/null || echo "unprivileged user namespaces denied"; }
env_setup() { (( SYSTEM )) && sysctl_userns; return 0; }
env_launch() { unshare --user --pid --mount --fork --map-root-user "$BIN" "$@"; }

leaf_main "$@"
