#!/bin/sh
set -eu
# The Docker cgroup namespace must be private. Never mount a host cgroup tree.
setup_cgroups() {
    [ "$(cat /proc/self/cgroup)" = '0::/' ] || return 1
    mount -o remount,rw /sys/fs/cgroup || return 1
    mkdir -p /sys/fs/cgroup/daemon || return 1
    echo $$ > /sys/fs/cgroup/daemon/cgroup.procs || return 1
    echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control || return 1
    mkdir -p /sys/fs/cgroup/agents || return 1
    echo '+cpu +memory +pids' > /sys/fs/cgroup/agents/cgroup.subtree_control || return 1
    chown 10001:10001 /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/agents \
      /sys/fs/cgroup/agents/cgroup.procs /sys/fs/cgroup/agents/cgroup.subtree_control || return 1
}
if ! setup_cgroups; then
    echo 'SECURITY: cgroup delegation unavailable; sandbox self-test will disable tools' >&2
fi
# Root setup ends here. Both bounding and ambient capability sets are empty.
exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all \
  --ambient-caps=-all --bounding-set=-all --no-new-privs "$@"
