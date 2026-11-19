#!/bin/sh
# Undo what a1-prepare.sh (and the later steps) changed on the host. Run as root.
set -u
[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
rm -f /etc/sudoers.d/probe-svc /etc/sudoers.d/.probe-svc.new
rm -f /usr/local/bin/probe
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
rm -rf /var/lib/probe /run/probe-stage1-run.*
# Stage A's files in the directory only root can write; nothing is read or removed from it unless it is root's alone. (Stage B's
# marker is undone by undo-b.sh; the directory itself goes when it is empty.)
if exists "$STATEDIR"; then
  if root_only "$STATEDIR" d; then
    rm -f "$STATEDIR"/check.log* "$STATEDIR"/sudoers.*
  else
    echo "note: $STATEDIR is not a directory of root's that only root can write: left alone; look at it"
  fi
fi
if root_only "$STATEDIR" d && [ -e "$STATEDIR/account-existed" ]; then
  rm -f "$STATEDIR/account-existed"
  echo "note: the account probe-svc existed before; it was not removed"
else
  userdel -r probe-svc 2>/dev/null && echo "removed the account probe-svc and its home"
fi
root_only "$STATEDIR" d && rmdir "$STATEDIR" 2>/dev/null
# Leftovers of runs made before the files moved out of the world-writable temporary directory are not touched here (a name in
# such a directory is not root's to obey): the runbook says how to look for them and remove them by hand.
echo "left alone: the audit lines already in syslog or the journal (they are history), /etc/probe (Stage B), anything under your own checkout"
