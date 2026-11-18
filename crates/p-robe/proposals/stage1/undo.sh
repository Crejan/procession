#!/bin/sh
# Undo what a1-prepare.sh (and the later steps) changed on the host. Run as root.
set -u
[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
rm -f /etc/sudoers.d/probe-svc /etc/sudoers.d/.probe-svc.new
rm -f /usr/local/bin/probe
rm -rf /var/lib/probe /var/tmp/probe-stage1-run /var/tmp/probe-stage1.check.log*
if [ -e /var/tmp/probe-stage1.account-existed ]; then
  rm -f /var/tmp/probe-stage1.account-existed
  echo "note: the account probe-svc existed before; it was not removed"
else
  userdel -r probe-svc 2>/dev/null && echo "removed the account probe-svc and its home"
fi
echo "left alone: the audit lines already in syslog or the journal (they are history), /etc/probe (Stage B), anything under your own checkout"
