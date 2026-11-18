#!/bin/sh
# Stage A, step 2: does the sudo rule do what the runbook says? Run as root, after a1-prepare.sh.
# It runs `sudo -n /usr/local/bin/probe ...` as the account probe-svc, the way the service will.
set -u

SVC=probe-svc
PROBE=/usr/local/bin/probe
FAILED=0
LOG=/var/tmp/probe-stage1.check.log
: > "$LOG"

U1=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11
U2=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a12
U3=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a13
U4=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a14

[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }

# run NAME EXPECTED_RC COMMAND...   (as probe-svc; stdout to $LOG.out, stderr to $LOG.err)
run() {
  name=$1; want=$2; shift 2
  su -s /bin/sh -c "$*" "$SVC" > "$LOG.out" 2> "$LOG.err"
  rc=$?
  cat "$LOG.out" >> "$LOG"; cat "$LOG.err" >> "$LOG"
  if [ "$rc" = "$want" ]; then
    echo "PASS: $name (exit $rc)"
  else
    echo "FAIL: $name: exit $rc, expected $want"; sed 's/^/    /' "$LOG.err"; FAILED=1
  fi
}

run "a verb of the table runs as root through the rule" 0 \
  "sudo -n $PROBE --within open,none,none --call $U1 sys kit"
if grep -q '"euid":0' "$LOG.out"; then echo "PASS: sys kit says it ran as euid 0"; else echo "FAIL: sys kit did not say euid 0"; FAILED=1; fi
# sys kit was the last to write $LOG.out; the next run overwrites it.

run "above the approved rating: refused (64)" 64 \
  "sudo -n $PROBE --within open,none,none --call $U2 test peak"
run "at the approved rating: runs" 0 \
  "sudo -n $PROBE --within open,none,outage --call $U3 test peak"
run "run command is refused by the dispatcher (64)" 64 \
  "sudo -n $PROBE --within secret,lasting,outage --call $U4 run command"
run "the same flag twice is refused by the dispatcher (64)" 64 \
  "sudo -n $PROBE --within open,none,none --call $U4 --call $U4 sys kit"
run "the form without --within is not in the rule (sudo refuses, 1)" 1 \
  "sudo -n $PROBE sys kit"
run "another program is not in the rule (sudo refuses, 1)" 1 \
  "sudo -n /bin/true"

# The audit lines: tag probe, joined by the call's identifier.
sleep 1
if command -v journalctl >/dev/null 2>&1; then
  journalctl -t probe --no-pager -n 200 > "$LOG.syslog" 2>/dev/null
else
  : > "$LOG.syslog"
fi
for f in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do
  [ -r "$f" ] && grep ' probe\[\| probe:' "$f" >> "$LOG.syslog" 2>/dev/null
done
for pair in "$U1:event=start" "$U1:event=done" "$U2:event=refused" "$U3:event=start" "$U4:event=refused"; do
  id=${pair%%:*}; what=${pair#*:}
  if grep "$what" "$LOG.syslog" | grep -q "call=$id"; then
    echo "PASS: syslog has $what with call=$id"
  else
    echo "FAIL: no syslog line with $what and call=$id (looked in journalctl -t probe and /var/log)"; FAILED=1
  fi
done
if grep "call=$U2" "$LOG.syslog" | grep -q 'above-approved'; then
  echo "PASS: the refusal line says above-approved"
else
  echo "FAIL: the refusal of $U2 does not say above-approved"; FAILED=1
fi

if [ "$FAILED" = 0 ]; then
  echo "ALL PASSED: the sudo rule lets probe-svc run exactly the dispatcher, as root, and the audit lines carry the call identifiers."
else
  echo "SOMETHING FAILED: see above; full output in $LOG and $LOG.syslog"
  exit 1
fi
