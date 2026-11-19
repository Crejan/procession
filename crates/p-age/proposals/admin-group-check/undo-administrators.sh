#!/bin/sh
# Undo check-administrators.sh. Run as root:   sh undo-administrators.sh
# Only what the marker says the check made is removed. The marker is read only if it is a regular file of root's that
# nobody else can write, in a directory of the same kind.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
need_root
exists "$STATEDIR" || { echo "nothing to undo: $STATEDIR does not exist (the check did not run, or this was undone)"; exit 0; }
root_only "$STATEDIR" d || { echo "STOP: $STATEDIR is not a directory of root's that only root can write: not read, not removed; look at it"; exit 1; }
[ -e "$MARKER" ] || { echo "STOP: $MARKER is missing: nothing says what the check made, so nothing is removed; look at $STATEDIR"; exit 1; }
root_only "$MARKER" f || { echo "STOP: $MARKER is not a regular file of root's that only root can write: not read; look at it"; exit 1; }

# the broker, if it still runs (only the account the marker says was made here)
for name in $(marker_values ACCOUNT_MADE); do
  case "$name" in "$BROKER"|"$MEMBER"|"$OTHER") ;; *) echo "STOP: the marker names an account this check does not make: not touched"; exit 1 ;; esac
done
if marked ACCOUNT_MADE && getent passwd "$BROKER" >/dev/null; then
  pkill -u "$BROKER" -x page 2>/dev/null
  n=0; while pgrep -u "$BROKER" -x page >/dev/null 2>&1 && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
  pgrep -u "$BROKER" -x page >/dev/null 2>&1 && { echo "STOP: the broker still runs after ten seconds: stop it, then run this again"; exit 1; }
fi
for d in $(marker_values ROOTDIR_MADE) $(marker_values BINDIR_MADE); do
  sane_path "$d" || { echo "STOP: the marker has a path that is not one: $d"; exit 1; }
  case "$d" in "$ROOTDIR"|"$BINDIR") rm -rf "$d" && echo "removed $d" ;; *) echo "STOP: the marker names $d, which this check does not make: not removed"; exit 1 ;; esac
done
for name in $(marker_values ACCOUNT_MADE); do
  userdel "$name" 2>/dev/null && echo "removed the account $name" || echo "note: could not remove the account $name (already gone?)"
done
for g in $(marker_values GROUP_MADE); do
  [ "$g" = "$GROUP" ] || { echo "STOP: the marker names a group this check does not make"; exit 1; }
  groupdel "$g" 2>/dev/null && echo "removed the group $g" || echo "note: could not remove the group $g (already gone?)"
done
rm -rf "$STATEDIR" && echo "removed $STATEDIR"
echo "left alone: the build in the checkout"
