#!/usr/bin/env bash
# Firecracker microVM, rootless given a read/writable /dev/kvm. One boot per
# invocation on a throwaway reflink copy of the cached Ubuntu rootfs (the
# cache is never mutated); the guest script, the binary, and the result
# tarball travel over raw scratch drives (vdb/vdc/vdd), so no loop mounts or
# sudo are needed. PID 1 is /bin/sh, but it rebuilds the mount table of a
# stock systemd Ubuntu Firecracker guest (GUEST_MOUNTS), so mount-hygiene
# findings reflect a realistic microVM, not a bare-init worst case.
# Usage: see scripts/live/lib.sh header.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck disable=SC2034 # read by lib.sh
LABEL="Firecracker MicroVM"

# Mount table of a systemd Ubuntu 22.04 Firecracker guest (captured from a
# real uVM's /proc/self/mountinfo); devtmpfs on /dev is the kernel automount.
# Mounts the guest kernel lacks are skipped silently. Not reproduced: the
# systemd autofs trigger under binfmt_misc (binfmt_misc is mounted directly).
GUEST_MOUNTS='
m() { mount "$@" 2>/dev/null || true; }
mount --make-rshared /
m -t proc -o rw,nosuid,nodev,noexec,relatime proc /proc
m -t sysfs -o rw,nosuid,nodev,noexec,relatime sysfs /sys
m -t securityfs -o rw,nosuid,nodev,noexec,relatime securityfs /sys/kernel/security
m -t selinuxfs -o rw,nosuid,noexec,relatime selinuxfs /sys/fs/selinux
mkdir -p /dev/shm /dev/pts /dev/hugepages /dev/mqueue /var/lib/systemd
m -t tmpfs -o rw,nosuid,nodev,strictatime tmpfs /dev/shm
m -t devpts -o rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 devpts /dev/pts
m -t tmpfs -o rw,nosuid,nodev,strictatime,size=20%,nr_inodes=800k,mode=755 tmpfs /run
mkdir -p /run/lock
m -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size=5120k tmpfs /run/lock
m -t cgroup2 -o rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot cgroup2 /sys/fs/cgroup
m -t pstore -o rw,nosuid,nodev,noexec,relatime pstore /sys/fs/pstore
m -t bpf -o rw,nosuid,nodev,noexec,relatime,mode=700 bpf /sys/fs/bpf
m -t hugetlbfs -o rw,nosuid,nodev,relatime,pagesize=2M hugetlbfs /dev/hugepages
m -t mqueue -o rw,nosuid,nodev,noexec,relatime mqueue /dev/mqueue
m -t debugfs -o rw,nosuid,nodev,noexec,relatime debugfs /sys/kernel/debug
m -t tmpfs -o rw,nosuid,nodev,strictatime,size=50%,nr_inodes=1m tmpfs /tmp
m -t tmpfs -o rw,nosuid,nodev,strictatime,size=50%,nr_inodes=10k tmpfs /var/lib/systemd
m -t fusectl -o rw,nosuid,nodev,noexec,relatime fusectl /sys/fs/fuse/connections
m -t binfmt_misc -o rw,nosuid,nodev,noexec,relatime binfmt_misc /proc/sys/fs/binfmt_misc
'

FC_VERSION=v1.17.0
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz"
FC_KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260722-38359b8055fc-0/x86_64/debug/vmlinux-6.1.176"
FC_ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts-20230601/x86_64/ubuntu-22.04.ext4"
FC_TIMEOUT="${FC_TIMEOUT:-120}"
KERNEL="$CACHE/firecracker/vmlinux"
ROOTFS="$CACHE/firecracker/rootfs.ext4"

fc_bin() {
  if command -v firecracker >/dev/null; then command -v firecracker
  elif [[ -x "$CACHE/bin/firecracker" ]]; then echo "$CACHE/bin/firecracker"
  else return 1; fi
}

env_check() {
  [[ -e /dev/kvm ]] || { echo "/dev/kvm absent"; return; }
  [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm not read/writable (setup --system)"; return; }
  fc_bin >/dev/null || { echo "firecracker not found"; return; }
  [[ -s "$KERNEL" && -s "$ROOTFS" ]] || echo "guest kernel/rootfs not cached"
}

fetch() {
  [[ -s "$2" ]] && return
  mkdir -p "$(dirname "$2")"
  curl -fsSL -o "$2.part" "$1" && mv "$2.part" "$2"
}

env_setup() {
  if ! fc_bin >/dev/null; then
    local rel="release-${FC_VERSION}-x86_64"
    mkdir -p "$CACHE/bin"
    curl -fsSL "$FC_URL" | tar -xz -C "$CACHE" "$rel/firecracker-${FC_VERSION}-x86_64"
    mv "$CACHE/$rel/firecracker-${FC_VERSION}-x86_64" "$CACHE/bin/firecracker"
    rmdir "$CACHE/$rel"
  fi
  fetch "$FC_KERNEL_URL" "$KERNEL"
  fetch "$FC_ROOTFS_URL" "$ROOTFS"
  if (( SYSTEM )) && [[ -e /dev/kvm && ! -w /dev/kvm ]]; then sudo chmod 666 /dev/kvm; fi
}

# Single-quote for the guest's /bin/sh (dash).
shq() { local s=${1//\'/\'\\\'\'}; printf "'%s'" "$s"; }

env_launch() {
  local work vmm_rc=0 size arg interactive=0 quiet=""
  work="$(mktemp -d "${TMPDIR:-/tmp}/amr-fc.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: $work is local
  trap "rm -rf '$work'" EXIT
  (( SHELL_MODE && $# == 0 )) && { interactive=1; quiet=" quiet"; }
  inner_cmd /run/amr/amirustrained "$@"

  size=$(stat -c %s "$BIN")
  cp "$BIN" "$work/bin.img"
  truncate -s $(( (size + 511) / 512 * 512 )) "$work/bin.img"
  truncate -s 64M "$work/out.img"
  cp --reflink=auto "$ROOTFS" "$work/rootfs.ext4"
  {
    echo "$GUEST_MOUNTS"
    echo 'mkdir -p /run/amr'
    echo "head -c $size /dev/vdc > /run/amr/amirustrained; chmod +x /run/amr/amirustrained"
    if (( interactive )); then
      # Shell on the serial console, which firecracker wires to our terminal;
      # setsid -c makes ttyS0 its controlling tty so job control and ^C work.
      printf 'setsid -c'
      for arg in "${CMD[@]}"; do printf ' %s' "$(shq "$arg")"; done
      echo ' < /dev/ttyS0 > /dev/ttyS0 2>&1'
    else
      for arg in "${CMD[@]}"; do printf '%s ' "$(shq "$arg")"; done
      echo '> /run/amr/stdout 2> /run/amr/stderr; echo $? > /run/amr/rc'
      echo 'tar -cf /dev/vdd -C /run/amr stdout stderr rc; sync'
    fi
    echo 'echo b > /proc/sysrq-trigger'
    echo 'exit 0'
  } > "$work/init.sh"
  # Pad to a sector with newlines: the guest shell never parses NUL bytes.
  while (( $(stat -c %s "$work/init.sh") % 512 )); do echo >> "$work/init.sh"; done

  cat > "$work/vm.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off rw$quiet init=/bin/sh -- /dev/vdb"
  },
  "drives": [
    {"drive_id": "rootfs", "path_on_host": "$work/rootfs.ext4", "is_root_device": true, "is_read_only": false},
    {"drive_id": "script", "path_on_host": "$work/init.sh", "is_root_device": false, "is_read_only": true},
    {"drive_id": "binary", "path_on_host": "$work/bin.img", "is_root_device": false, "is_read_only": true},
    {"drive_id": "result", "path_on_host": "$work/out.img", "is_root_device": false, "is_read_only": false}
  ],
  "machine-config": {"vcpu_count": 2, "mem_size_mib": 2048}
}
EOF
  if (( interactive )); then
    "$(fc_bin)" --no-api --config-file "$work/vm.json" --api-sock "$work/fc.sock"
    exit
  fi
  timeout "$FC_TIMEOUT" "$(fc_bin)" --no-api --config-file "$work/vm.json" --api-sock "$work/fc.sock" \
    > "$work/console.log" 2>&1 < /dev/null || vmm_rc=$?
  mkdir "$work/res"
  if ! tar -xf "$work/out.img" -C "$work/res" 2>/dev/null || [[ ! -s "$work/res/rc" ]]; then
    note "guest produced no result (firecracker exit $vmm_rc); console tail:"
    tail -n 40 "$work/console.log" >&2
    exit 125
  fi
  [[ -n "${AMR_FC_CONSOLE:-}" ]] && cat "$work/console.log" >&2
  cat "$work/res/stdout"
  cat "$work/res/stderr" >&2
  exit "$(cat "$work/res/rc")"
}

leaf_main "$@"
