#!/bin/sh
# Stage A, step 1: prepare a Linux host for the sudo part of stage 1. Run as root.
#   sh a1-prepare.sh /path/to/CHECKOUT
# CHECKOUT is the checkout of the repository, owned by the person who builds it (as for a3 and b1 to b3). a1 BUILDS
# `probe` with `--features test-verbs` there, as that user, takes the path of the binary from cargo's own messages and
# installs that: no binary is named by hand, so none can be an old one.
# Everything it changes is listed in RUNBOOK-stage1-linux.md, section 3, and undone by undo.sh.
set -eu
# Order matters: everything that can fail, the build and the rule's `visudo -cf` included, is checked BEFORE the first change
# to the machine. If a run stops after a change, it takes back what it did (the EXIT trap below): it leaves nothing behind.

HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
SVC=probe-svc
RULE=/etc/sudoers.d/probe-svc
INSTALLED=/usr/local/bin/probe

ARG="${1:-}"
[ -n "$ARG" ] || stop "usage: sh a1-prepare.sh /path/to/CHECKOUT   (the checkout of the repository; a1 builds probe there)"
[ -f "$ARG" ] && stop "$ARG is a file: a1 now takes the CHECKOUT (the directory of the repository, owned by the person who builds it) and builds probe itself; it does not take a binary"
need_root
identify "$ARG"
command -v visudo >/dev/null || stop "visudo is not installed"
command -v logger >/dev/null || stop "logger (util-linux) is not installed; the dispatcher cannot write its audit line"
command -v ssh-keygen >/dev/null || stop "ssh-keygen is not installed"
command -v useradd >/dev/null || stop "useradd (shadow-utils) is not installed"
as_owner "command -v cargo >/dev/null" || stop "cargo is not on the PATH of $PERSON (a login shell): the owner builds the checkout"
exists "$RULE" && stop "$RULE exists; run undo.sh first or remove it"
exists "$INSTALLED" && stop "$INSTALLED exists; run undo.sh first or remove it"
exists /var/lib/probe && stop "/var/lib/probe exists, and undo.sh removes that directory whole; look at it, move what you want to keep, remove it, and run this again"
# The build, as the checkout's owner, before anything on the machine is touched. The path is cargo's, never a guess.
commit_of_checkout
echo "checkout $CHECKOUT at $COMMIT, built by $PERSON: building probe with the test verbs (this may take a while)..."
find_probe
{ [ -f "$PROBE_SRC" ] && [ -x "$PROBE_SRC" ]; } || stop "cargo named $PROBE_SRC, which is not an executable file"
echo "probe: $PROBE_SRC"

# What this run has done, for the EXIT trap: if it stops before "prepared", it takes these back.
MADE_STATEDIR=0; MADE_ACCOUNT=0; MADE_PROBE=0; MADE_LIB=0; MADE_RULE=0; MADE_FLAG=0; DONE=0; CHECK=
rollback() {
  [ "$DONE" = 1 ] && return 0
  echo "STOPPED: taking back what this run changed"
  [ -z "$CHECK" ] || rm -f "$CHECK"
  [ "$MADE_RULE" = 1 ] && rm -f "$RULE"
  [ "$MADE_PROBE" = 1 ] && rm -f "$INSTALLED"
  [ "$MADE_LIB" = 1 ] && rm -rf /var/lib/probe
  [ "$MADE_FLAG" = 1 ] && rm -f "$STATEDIR/account-existed"
  [ "$MADE_ACCOUNT" = 1 ] && userdel -r "$SVC" >/dev/null 2>&1 && echo "removed the account $SVC again"
  [ "$MADE_STATEDIR" = 1 ] && rmdir "$STATEDIR" 2>/dev/null
  return 0
}
trap rollback EXIT

# 0. The sudoers rule, written to a temporary file and checked with visudo -cf BEFORE anything is changed.
# `\,` is the comma escaped: sudoers(5) says that , : = and \ must be escaped in command arguments (a comma
# separates commands in a list). Confirmed on Debian 13: visudo -cf accepts this line, and sudo matched a real
# call of this form (the owner's run of 2026-11-18). If visudo says otherwise on another host, nothing has been
# changed and the message is the finding.
exists "$STATEDIR" || MADE_STATEDIR=1
ensure_statedir
CHECK=$(mktemp "$STATEDIR/sudoers.XXXXXX")
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
  echo "FAIL: visudo -cf rejected the rule; NOTHING WAS CHANGED on this machine"
  exit 1
fi

# 1. The service's account: no login, no shell, its own home.
if id "$SVC" >/dev/null 2>&1; then
  echo "note: the account $SVC exists already; it is left as it is, and undo.sh will not remove it"
  : > "$STATEDIR/account-existed"; MADE_FLAG=1
else
  useradd --system --create-home --home-dir /var/lib/probe-svc --shell /usr/sbin/nologin "$SVC"
  MADE_ACCOUNT=1
  echo "made the account $SVC"
fi

# 2. The program, owned by root and writable by nobody else: sudo runs it as root.
MADE_PROBE=1
install -o root -g root -m 0755 "$PROBE_SRC" "$INSTALLED"

# 3. The dispatcher's lock directory (root's) and the service's directory for used identifiers.
MADE_LIB=1
install -d -o root -g root -m 0755 /var/lib/probe /var/lib/probe/locks
install -d -o "$SVC" -g "$SVC" -m 0700 /var/lib/probe/used

# 4. The rule, in place; the whole configuration is checked once more, and the rule is taken out again if that fails.
MADE_RULE=1
install -o root -g root -m 0440 "$CHECK" "$RULE"
rm -f "$CHECK"; CHECK=
if visudo -c >/dev/null 2>&1; then
  echo "PASS: $RULE installed, and the whole sudoers configuration checks"
else
  echo "FAIL: the sudoers configuration does not check with the rule in place; everything this run did is taken back"
  exit 1
fi
DONE=1
echo "PASS: prepared: probe built from $COMMIT is installed. Next, ONE AT A TIME and reading the last line of each: sh a2-check-rule.sh"
