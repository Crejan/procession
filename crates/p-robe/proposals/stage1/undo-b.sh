#!/bin/sh
# Undo Stage B: what b1, b2 and b3 changed. Run as root. Stage A (a1, a2, a3: the account, the rule, /usr/local/bin/probe)
# is undone by undo.sh, and not here. Only what the marker says b1 made is removed (a group, a membership, a host key, a
# directory that existed before are left alone). Stop pledge first (Ctrl-C in its terminal).
#   sh undo-b.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
need_root
[ -e "$MARKER" ] || { echo "nothing to undo: $MARKER does not exist (b1 did not run, or this was undone)"; exit 0; }

PERSON=$(marker_value PERSON)
[ -z "$PERSON" ] || RUNDIR=/run/pledge-$PERSON
# pledge must not be running: its socket directory is what it holds open.
if [ -n "$PERSON" ] && [ -S "$RUNDIR/control.sock" ] && [ -n "$(command -v fuser)" ] && fuser "$RUNDIR/control.sock" >/dev/null 2>&1; then
  echo "STOP: pledge is still running for $PERSON: press Ctrl-C in its terminal, then run this again"; exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now probe-serve.service >/dev/null 2>&1
  systemctl disable --now probe-setup.timer >/dev/null 2>&1
  systemctl stop probe-setup.service >/dev/null 2>&1
fi
rm -f /etc/systemd/system/probe-serve.service /etc/systemd/system/probe-setup.service /etc/systemd/system/probe-setup.timer
rm -rf /etc/systemd/system/probe-serve.service.d /etc/systemd/system/probe-setup.service.d
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && systemctl daemon-reload
echo "removed the units"

# (the settings and the units are removed whether or not the marker says so: SETTINGS_MADE, UNITS_MADE)
rm -f "$SETTINGS"
rm -rf /var/lib/probe/used/* 2>/dev/null
# The key directory: the service's key, its certificate and the person's two public keys, all made by b2.
marked KEYDIR_MADE && rm -rf "$KEYDIR" && echo "removed $KEYDIR"

for f in $(sed -n 's/^CALLER_MADE=//p' "$MARKER"); do rm -f "$f"; done
for f in $(sed -n 's/^BUNDLE_MADE=//p' "$MARKER"); do rm -f "$f"; done
rm -f /var/tmp/probe-stage1.pact-call.sh /var/tmp/probe-stage1.pledge-config.* /var/tmp/probe-stage1.key.* /var/tmp/probe-stage1.settings.*

# pledge's state (its keys, its record) and the socket directory, only if b1 made them.
for d in $(sed -n 's/^STATE_MADE=//p' "$MARKER"); do rm -rf "$d" && echo "removed pledge's state $d (its keys and record)"; done
for d in $(sed -n 's/^RUNDIR_MADE=//p' "$MARKER"); do rm -rf "$d" && echo "removed $d"; done
# parents of the state directory b1 made, only if empty now.
for d in $(sed -n 's/^PARENT_MADE=//p' "$MARKER" | sort -r); do rmdir "$d" 2>/dev/null; done

# The group and its members, as b1 found them.
for member in $(sed -n 's/^ADDED_\(.*\)=1$/\1/p' "$MARKER"); do
  gpasswd -d "$member" "$GROUP" >/dev/null 2>&1 && echo "removed $member from $GROUP"
done
marked GROUP_MADE && groupdel "$GROUP" 2>/dev/null && echo "removed the group $GROUP"
marked HOSTKEY_MADE && rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub && echo "removed the host key b1 made"

rm -f "$MARKER"
echo "left alone: the audit lines already in the journal (history), Stage A (undo.sh), the build in your checkout"
