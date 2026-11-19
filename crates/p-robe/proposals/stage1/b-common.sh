#!/bin/sh
# Stage B, shared by b1, b2, b3 and undo-b: names, checks, the artifacts found from cargo's own output.
# Sourced (`. "$HERE/b-common.sh"`), never run. Everything it needs is in RUNBOOK-stage1-linux.md, part B.
# It needs POSIX sh, id, stat, getent, grep, sed, awk: nothing else (no jq, no interpreter).

SVC=probe-svc
GROUP=pledge-svc
PROBE=/usr/local/bin/probe
# Where b1 keeps what it made, so that undo-b removes only that. A directory ONLY ROOT CAN WRITE (root:root 0700, made by
# b1 with mkdir, which fails if the name exists), not /var/tmp: root obeys what is in this file (it removes the paths it
# names), so no other account may be able to put it there. Temporary files of the scripts live here too.
STATEDIR=/etc/probe-stage1
MARKER=$STATEDIR/b-state
KEYDIR=/etc/probe
SETTINGS=/etc/probe.json
LISTEN=127.0.0.1:8765

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
# stop: a precondition is missing or a step that the rest depends on failed; nothing after this is meaningful.
stop() { echo "STOP: $*"; exit 1; }
FAILED=0

need_root() { [ "$(id -u)" = 0 ] || stop "run as root"; }

# checkout_owner CHECKOUT -> the person: the user who owns the checkout, who builds it and runs pledge.
# Sets CHECKOUT, PERSON, PGROUP (the person's primary group), PHOME, PUID, HOST, RUNDIR, STATE.
identify() {
  CHECKOUT="${1:?usage: sh $0 CHECKOUT   (the checkout of the repository, owned by the person who will run pledge)}"
  [ -d "$CHECKOUT/.git" ] || stop "$CHECKOUT is not a checkout"
  PERSON=$(stat -c %U "$CHECKOUT" 2>/dev/null)
  { [ -n "$PERSON" ] && [ "$PERSON" != root ] && [ "$PERSON" != UNKNOWN ]; } || stop "the checkout must belong to the person (not root), owner: ${PERSON:-unknown}"
  PGROUP=$(id -gn "$PERSON") || stop "no such user $PERSON"
  PUID=$(id -u "$PERSON")
  PHOME=$(getent passwd "$PERSON" | awk -F: '{print $6}')
  [ -d "$PHOME" ] || stop "the home of $PERSON ($PHOME) does not exist"
  HOST=$(hostname)
  # pledge takes only these characters in a host or person name (A-Za-z0-9._-, at most 64).
  case "$HOST$PERSON" in *[!A-Za-z0-9._-]*) stop "the host name ($HOST) or the person ($PERSON) has characters pledge does not take: A-Za-z0-9._- only" ;; esac
  [ "${#HOST}" -le 64 ] || stop "the host name is longer than 64 characters"
  RUNDIR=/run/pledge-$PERSON
  STATE=$PHOME/.local/state/pledge
  HERE=$(cd "$(dirname "$0")" && pwd)
}

# as_owner COMMAND: runs it as the person, in a login shell (so that cargo is on the PATH as for him), in the checkout.
as_owner() { su - "$PERSON" -c "cd '$CHECKOUT' && $1"; }
# as_person COMMAND: as the person, in a login shell (fresh group membership), wherever he is.
as_person() { su - "$PERSON" -c "$1"; }

# The commit of the checkout, with -dirty if tracked files differ; the test and the binaries are told it.
commit_of_checkout() {
  COMMIT=$(as_owner "git rev-parse --short=12 HEAD") || stop "cannot read the checkout's commit"
  if [ -n "$(as_owner 'git status --porcelain --untracked-files=no')" ]; then COMMIT="$COMMIT-dirty"; fi
}

# artifact KIND NAME BUILD-COMMAND -> prints the path cargo names, builds as the owner. Never guesses a place.
artifact() {
  json=$(as_owner "$3 --message-format=json") || stop "the build failed: $3"
  path=$(printf '%s\n' "$json" | sh "$HERE/find-artifact.sh" "$1" "$2") || stop "cannot tell where cargo put the $1 $2"
  [ -x "$path" ] || stop "$path is not an executable"
  printf '%s\n' "$path"
}
find_pledge() { PLEDGE=$(artifact bin pledge "cargo build -p p-ledge --bin pledge") || exit 1; }
find_probe() { PROBE_SRC=$(artifact bin probe "cargo build -p p-robe --features test-verbs --bin probe") || exit 1; }
find_pact() { PACT=$(artifact bin pact "cargo build -p p-act --features pact --bin pact") || exit 1; }

# Pledge's own command line, as the person gives it: the directories are always named.
pledge_args() { echo "--state-dir '$STATE' --socket-dir '$RUNDIR'"; }
pledge_serve_command() { echo "su - $PERSON -c \"$PLEDGE serve $(pledge_args)\""; }

# in_group USER GROUP
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

# The marker: KEY=VALUE lines, root's, read back by undo-b.
# exists PATH: a name is there, a dangling symlink included (`-e` alone is false for one).
exists() { [ -e "$1" ] || [ -L "$1" ]; }
# The uid whose files may be obeyed: root's. (A plain assignment, never read from the environment; a test of the checks below
# sets it to its own.)
TRUSTED_UID=0
# root_only PATH KIND (d or f): not a symlink, of that kind, owned by root, and not writable by group or others.
root_only() {
  [ ! -L "$1" ] || return 1
  case "$2" in d) [ -d "$1" ] || return 1 ;; f) [ -f "$1" ] || return 1 ;; *) return 1 ;; esac
  # (GNU stat on Linux; the BSD form is only so that the tests of these checks run on a Mac.)
  set -- "$1" "$(stat -c '%u %a' "$1" 2>/dev/null || stat -f '%u %Lp' "$1" 2>/dev/null)"
  owner=${2%% *}; perm=${2#* }
  [ "$owner" = "$TRUSTED_UID" ] && [ -n "$perm" ] && [ $((0$perm & 022)) -eq 0 ]
}
# marker_safe: the directory and the marker are root's and nobody else can write them. Checked before the marker is
# read (undo-b obeys it) or appended to.
marker_safe() { root_only "$STATEDIR" d && { ! exists "$MARKER" || root_only "$MARKER" f; }; }
# a path read from the marker is absolute, has no `..`, and is not near the top of the file system (defence in depth:
# the marker is root's; a mistake in it must not remove /etc).
sane_path() {
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *..*|*'
'*) return 1 ;; esac
  [ "$(printf '%s' "$1" | tr -cd '/' | wc -c)" -ge 2 ]
}
mark() { marker_safe || stop "$STATEDIR or $MARKER is not root's alone: refusing to write to it"; printf '%s=%s\n' "$1" "$2" >> "$MARKER"; chmod 0600 "$MARKER"; }
marked() { root_only "$MARKER" f && grep -q "^$1=" "$MARKER"; }
marker_value() { root_only "$MARKER" f && sed -n "s/^$1=//p" "$MARKER" | tail -1; }
# ensure_statedir: the root-only directory exists, made here if it is not there (mkdir fails if the name appears meanwhile), and is
# checked if it is. Stage A (a1) makes it first; b1 finds it there. Whoever finds it must not use it unless it is root's alone.
ensure_statedir() {
  if exists "$STATEDIR"; then
    root_only "$STATEDIR" d || stop "$STATEDIR exists but is not a directory of root's that only root can write: look at it, remove it if it is not yours, and run this again"
  else
    mkdir -m 0700 "$STATEDIR" || stop "cannot make $STATEDIR (it appeared meanwhile?)"
    chown root:root "$STATEDIR" && chmod 0700 "$STATEDIR"
  fi
}
# tmpfile NAME: a fresh file in the root-only directory (mktemp: unpredictable name, created exclusively, 0600).
tmpfile() { mktemp "$STATEDIR/$1.XXXXXX"; }

# fresh_id N: the identifier of this script family's N-th call. The dispatcher does not refuse an identifier it has seen (the
# service's own store does, for calls that come through it; these go straight through the rule), so a rerun is not refused.
fresh_id() { printf '3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0b%02d' "$1"; }

# public_key_of LIST PURPOSE: the public key of that purpose from the text of `pledge keys list`
# (lines: purpose, fingerprint, public key with its comment).
public_key_of() { printf '%s\n' "$1" | awk -v p="$2" '$1==p { sub(/^[^ ]+ +[^ ]+ +/, ""); print; exit }'; }

# pledge_config_json PERSON HOST HOSTPUB GROUP URL: pledge's config.json for this host. Only characters that were checked
# (names: A-Za-z0-9._-; the key: two words of base64) go into it.
pledge_config_json() {
  cat <<JSON
{"person": "$1",
 "hosts": [{"host": "$2", "key": "$3"}],
 "services": [{"host": "$2", "name": "probe", "url": "$5"}],
 "service_group": "$4"}
JSON
}

# probe_settings_json PERSON HOST SOCKET UID: /etc/probe.json.
probe_settings_json() {
  cat <<JSON
{
  "host": "$2",
  "host_key": "/etc/ssh/ssh_host_ed25519_key",
  "person": "$1",
  "confirmed_key": "$KEYDIR/$1-confirmed.pub",
  "automatic_key": "$KEYDIR/$1-automatic.pub",
  "service_key": "$KEYDIR/service-key",
  "pledge_socket": "$3",
  "pledge_uid": $4,
  "used_dir": "/var/lib/probe/used",
  "listen": "$LISTEN",
  "probe": "$PROBE"
}
JSON
}

# -- calls through the rule: nothing is thrown away, and "the call failed" is told from "the record says no" --------------

# show_output RC OUTPUT: the whole of what a call printed and its exit code, indented, so that the cause is on the screen.
show_output() {
  echo "    exit code: $1"
  if [ -n "$2" ]; then printf '%s\n' "$2" | sed 's/^/    | /'; else echo "    | (it printed nothing)"; fi
}

# json_word LINE NAME: a member of one record line: its string, or true/false/null/a number; empty if it is not there.
json_word() {
  v=$(printf '%s\n' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" | head -1)
  [ -n "$v" ] || v=$(printf '%s\n' "$1" | sed -n "s/.*\"$2\":\([A-Za-z0-9.-]*\).*/\1/p" | head -1)
  printf '%s\n' "$v"
}

# classify_failure RC OUTPUT: why a call through the rule gave no answer, in words (never empty).
classify_failure() {
  case "$2" in
    *"sudo:"*) echo "sudo refused it (the rule does not match this form, or a password is wanted)"; return ;;
  esac
  case "$1" in
    64) echo "the dispatcher refused the call: $(printf '%s\n' "$2" | grep 'probe:' | tail -1)" ;;
    3) echo "the dispatcher answered 'unavailable' (it could not write its audit line, or the verb cannot run here)" ;;
    75) echo "the dispatcher was busy (another call holds the lock)" ;;
    76) echo "the dispatcher found the deadline already past" ;;
    0) echo "it exited 0 but printed no sys kit record (an older probe, or not JSON)" ;;
    *) if [ -z "$2" ]; then echo "exit code $1 and no output at all"; else echo "exit code $1 and no sys kit record in what it printed"; fi ;;
  esac
}

# kit_via_rule N: `sys kit` as probe-svc through the sudo rule, like the service will. Sets KIT_RC, KIT_OUT (stdout and
# stderr together) and KIT_REC (the installation record, if there is one).
kit_via_rule() {
  kit_id=$(fresh_id "$1")
  KIT_OUT=$(su -s /bin/sh -c "sudo -n $PROBE --within secret,lasting,outage,text --call $kit_id --until $(( $(date +%s) + 300 )) sys kit" "$SVC" 2>&1)
  KIT_RC=$?
  KIT_REC=$(printf '%s\n' "$KIT_OUT" | grep '"type":"installation"' | head -1)
}

# require_kit: stops, with the whole answer and the exit code, unless the call itself gave an installation record.
require_kit() {
  if [ "$KIT_RC" != 0 ] || [ -z "$KIT_REC" ]; then
    echo "STOP: the call itself failed (not ssh-keygen, which it never got to say): $(classify_failure "$KIT_RC" "$KIT_OUT")"
    show_output "$KIT_RC" "$KIT_OUT"
    case "$KIT_OUT" in *"bad --within"*) echo "      That is the message of a probe that does not take the fourth token of --within: /usr/local/bin/probe is older than this checkout. Rerun Stage A at this commit: (undo-b.sh if Stage B was prepared,) undo.sh, then  sh stage1/a1-prepare.sh CHECKOUT  (a1 builds the checkout itself), a2, a3." ;; esac
    exit 1
  fi
}

# require_installed_commit: the probe in /usr/local/bin is the build of the checkout's commit (COMMIT, from commit_of_checkout).
require_installed_commit() {
  built=$(json_word "$KIT_REC" built_from)
  if [ -z "$built" ]; then
    echo "STOP: /usr/local/bin/probe does not say which commit it was built from: it is older than this checkout ($COMMIT). Rerun Stage A at this commit: (undo-b.sh if Stage B was prepared,) undo.sh, then  sh stage1/a1-prepare.sh CHECKOUT  (a1 builds the checkout itself), a2, a3."
    show_output "$KIT_RC" "$KIT_OUT"; exit 1
  fi
  if [ "$built" != "$COMMIT" ]; then
    echo "STOP: /usr/local/bin/probe is the build of $built, and the checkout is at $COMMIT. Rerun Stage A at this commit: (undo-b.sh if Stage B was prepared,) undo.sh, then  sh stage1/a1-prepare.sh CHECKOUT  (a1 builds the checkout itself), a2, a3."
    exit 1
  fi
  pass "/usr/local/bin/probe is the build of this checkout's commit ($COMMIT)"
}

# require_keygen_usable: the record says ssh-keygen can be used under the rule; else the reason, or that there is none, and the record.
require_keygen_usable() {
  usable=$(json_word "$KIT_REC" ssh_keygen_usable)
  case "$usable" in
    true) pass "sys kit: ssh-keygen $(json_word "$KIT_REC" ssh_keygen_version) at $(json_word "$KIT_REC" ssh_keygen) is usable under the rule" ;;
    false)
      reason=$(json_word "$KIT_REC" ssh_keygen_problem)
      case "$reason" in ""|null) reason="the record gives no reason" ;; esac
      echo "STOP: sys kit says ssh-keygen cannot be used: $reason"
      show_output "$KIT_RC" "$KIT_OUT"; exit 1 ;;
    *)
      echo "STOP: the installation record has no ssh_keygen_usable member (an older probe than this checkout's?): the answer follows"
      show_output "$KIT_RC" "$KIT_OUT"; exit 1 ;;
  esac
}
