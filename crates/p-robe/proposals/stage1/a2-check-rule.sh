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
U5=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a15
U6=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a16
U7=3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a17
LOCK=/var/lib/probe/locks/probe-svc.lock

[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
# Nothing is checked unless a1-prepare.sh has passed: without the rule every "sudo refuses" check would pass for the
# wrong reason (sudo -n says the same thing when no rule matches as when none exists).
for need in /etc/sudoers.d/probe-svc /usr/local/bin/probe; do
  [ -e "$need" ] || { echo "STOP: $need is absent: a1-prepare.sh has not passed, so nothing was checked. Run a1 first and read its last line."; exit 1; }
done
id "$SVC" >/dev/null 2>&1 || { echo "STOP: the account $SVC does not exist: a1-prepare.sh has not passed, so nothing was checked."; exit 1; }

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
  "sudo -n $PROBE --within open,none,none --call $U1 --until $(( $(date +%s) + 300 )) sys kit"
if grep -q '"euid":0' "$LOG.out"; then echo "PASS: sys kit says it ran as euid 0"; else echo "FAIL: sys kit did not say euid 0"; FAILED=1; fi
# sys kit was the last to write $LOG.out; the next run overwrites it.
# The positive control: if this first call did not run through the rule, none of the refusals below means anything
# (sudo -n refuses a call that no rule matches in the same words as a call the rule forbids), so stop here.
if [ "$FAILED" != 0 ]; then
  echo "STOP: the first call, which the rule must allow, did not run through it. The refusals are not checked: they would pass for the wrong reason. Look at the FAIL line above ('sudo -l -U probe-svc' shows what sudo thinks the rule is)."
  exit 1
fi

run "above the approved rating: refused (64)" 64 \
  "sudo -n $PROBE --within open,none,none --call $U2 --until $(( $(date +%s) + 300 )) test peak"
run "at the approved rating: runs" 0 \
  "sudo -n $PROBE --within open,none,outage --call $U3 --until $(( $(date +%s) + 300 )) test peak"
run "run command is refused by the dispatcher (64)" 64 \
  "sudo -n $PROBE --within secret,lasting,outage --call $U4 --until $(( $(date +%s) + 300 )) run command"
run "the same flag twice is refused by the dispatcher (64)" 64 \
  "sudo -n $PROBE --within open,none,none --call $U4 --until $(( $(date +%s) + 300 )) --call $U4 sys kit"
run "the form without --within is not in the rule (sudo refuses, 1)" 1 \
  "sudo -n $PROBE sys kit"
run "the form without --until is not in the rule (sudo refuses, 1)" 1 \
  "sudo -n $PROBE --within open,none,none --call $U4 sys kit"
run "a deadline more than ten minutes ahead is refused, so that it cannot park a process (64)" 64 \
  "sudo -n $PROBE --within open,none,none --call $U5 --until $(( $(date +%s) + 3600 )) sys kit"
run "a deadline already past: the verb is not started (76)" 76 \
  "sudo -n $PROBE --within open,none,none --call $U5 --until 1 sys kit"

# The lock: held by someone else (flock, as root) for 3 seconds. A call with --call waits for it and runs.
flock "$LOCK" sleep 3 &
sleep 1
run "a call waits for the identity's lock and then runs (0)" 0 \
  "sudo -n $PROBE --within open,none,none --call $U6 --until $(( $(date +%s) + 300 )) sys kit"
wait
# Held for 6 seconds, the deadline 2 seconds away: the wait is cut at the deadline and the verb is not started.
flock "$LOCK" sleep 6 &
sleep 1
DEADLINE=$(( $(date +%s) + 2 ))
run "the deadline passes while waiting for the lock: expired, not started (76)" 76 \
  "sudo -n $PROBE --within open,none,none --call $U7 --until $DEADLINE sys kit"
wait
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
for pair in "$U1:event=start" "$U1:event=done" "$U2:event=refused" "$U3:event=start" "$U4:event=refused" "$U5:event=expired" "$U6:event=start" "$U7:event=expired"; do
  id=${pair%%:*}; what=${pair#*:}
  if grep "$what" "$LOG.syslog" | grep -q "call=$id"; then
    echo "PASS: syslog has $what with call=$id"
  else
    echo "FAIL: no syslog line with $what and call=$id (looked in journalctl -t probe and /var/log)"; FAILED=1
  fi
done
if grep "call=$U6" "$LOG.syslog" | grep -q 'waited=[1-9]\|waited=[0-9]*\.[5-9]\|waited=[2-9]'; then
  echo "PASS: the line of the call that waited says for how long (waited=...)"
else
  echo "FAIL: the line of $U6 does not say how long it waited"; FAILED=1
fi
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
