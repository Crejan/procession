#!/bin/sh
# Stage A, step 1: prepare a Linux host for the sudo part of stage 1. Run as root.
#   sh a1-prepare.sh /path/to/probe
# where /path/to/probe is the `probe` built with `--features test-verbs`.
# Everything it changes is listed in RUNBOOK-stage1-linux.md, section 3, and undone by undo.sh.
set -eu
# Order matters: everything that can fail is checked, and the rule is checked with `visudo -cf`, BEFORE the
# first change to the machine. A run that stops leaves nothing behind.

PROBE_SRC="${1:?usage: sh a1-prepare.sh /path/to/probe}"
SVC=probe-svc
RULE=/etc/sudoers.d/probe-svc
INSTALLED=/usr/local/bin/probe

[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
[ -x "$PROBE_SRC" ] || { echo "FAIL: $PROBE_SRC is not an executable"; exit 1; }
command -v visudo >/dev/null || { echo "FAIL: visudo is not installed"; exit 1; }
command -v logger >/dev/null || { echo "FAIL: logger (util-linux) is not installed; the dispatcher cannot write its audit line"; exit 1; }
command -v ssh-keygen >/dev/null || { echo "FAIL: ssh-keygen is not installed"; exit 1; }
[ -e "$RULE" ] && { echo "FAIL: $RULE exists; run undo.sh first or remove it"; exit 1; }
[ -e "$INSTALLED" ] && { echo "FAIL: $INSTALLED exists; run undo.sh first or remove it"; exit 1; }
[ -e /var/lib/probe ] && { echo "FAIL: /var/lib/probe exists, and undo.sh removes that directory whole; look at it, move what you want to keep, remove it, and run this again"; exit 1; }

# 0. The sudoers rule, written to a temporary file and checked with visudo -cf BEFORE anything is changed.
# `\,` is the comma escaped: sudoers(5) says that , : = and \ must be escaped in command arguments (a comma
# separates commands in a list). THIS LINE IS NOT YET CONFIRMED by a run on the target host; if visudo says
# otherwise, nothing has been changed and the message is the finding.
CHECK=/var/tmp/probe-svc.sudoers.check
cat > "$CHECK" <<'RULE'
# probe-svc may run the dispatcher of probe, as root, in exactly this form: --within <rating>
# --call <uuid> --until <seconds> <noun> <verb> [arguments]. --call is the waiting form (the dispatcher waits
# up to 10 s for its lock); --until is the call's deadline, after which the verb is not started. The
# dispatcher refuses everything that is not a verb of its table, `run command` among it, and anything above
# the rating after --within. Sudoers wildcards match anything, spaces included (`*` any string, `?` any
# character, `[a-z]` one letter); the dispatcher is what checks the words.
Defaults:probe-svc !lecture
Defaults:probe-svc env_reset
probe-svc ALL=(root) NOPASSWD: /usr/local/bin/probe --within [a-z]*\,[a-z]*\,[a-z]* --call ????????-????-????-????-???????????? --until [0-9]* [a-z]* [a-z]*
RULE
chmod 0440 "$CHECK"
if visudo -cf "$CHECK"; then
  echo "PASS: visudo -cf accepts the rule (nothing has been changed yet)"
else
  rm -f "$CHECK"
  echo "FAIL: visudo -cf rejected the rule; NOTHING WAS CHANGED on this machine"
  exit 1
fi

# 1. The service's account: no login, no shell, its own home.
if id "$SVC" >/dev/null 2>&1; then
  echo "note: the account $SVC exists already; it is left as it is, and undo.sh will not remove it"
  : > /var/tmp/probe-stage1.account-existed
else
  useradd --system --create-home --home-dir /var/lib/probe-svc --shell /usr/sbin/nologin "$SVC"
  echo "made the account $SVC"
fi

# 2. The program, owned by root and writable by nobody else: sudo runs it as root.
install -o root -g root -m 0755 "$PROBE_SRC" "$INSTALLED"

# 3. The dispatcher's lock directory (root's) and the service's directory for used identifiers.
install -d -o root -g root -m 0755 /var/lib/probe /var/lib/probe/locks
install -d -o "$SVC" -g "$SVC" -m 0700 /var/lib/probe/used

# 4. The rule, in place; the whole configuration is checked once more, and the rule is taken out again if that fails.
install -o root -g root -m 0440 "$CHECK" "$RULE"
rm -f "$CHECK"
if visudo -c >/dev/null 2>&1; then
  echo "PASS: $RULE installed, and the whole sudoers configuration checks"
else
  rm -f "$RULE"
  echo "FAIL: the sudoers configuration does not check with the rule in place; the rule was removed again (the account and the files of steps 1 to 3 stay: run undo.sh)"
  exit 1
fi
echo "PASS: prepared. Next, ONE AT A TIME and reading the last line of each: sh a2-check-rule.sh"
