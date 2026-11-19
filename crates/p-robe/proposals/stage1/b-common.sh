#!/bin/sh
# Stage B, shared by b1, b2, b3 and undo-b: names, checks, the artifacts found from cargo's own output.
# Sourced (`. "$HERE/b-common.sh"`), never run. Everything it needs is in RUNBOOK-stage1-linux.md, part B.
# It needs POSIX sh, id, stat, getent, grep, sed, awk: nothing else (no jq, no interpreter).

SVC=probe-svc
GROUP=pledge-svc
PROBE=/usr/local/bin/probe
MARKER=/var/tmp/probe-stage1.b-state      # what b1 made, so that undo-b removes only that
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
find_pact() { PACT=$(artifact bin pact "cargo build -p p-act --features pact --bin pact") || exit 1; }

# Pledge's own command line, as the person gives it: the directories are always named.
pledge_args() { echo "--state-dir '$STATE' --socket-dir '$RUNDIR'"; }
pledge_serve_command() { echo "su - $PERSON -c \"$PLEDGE serve $(pledge_args)\""; }

# in_group USER GROUP
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

# The marker: KEY=VALUE lines, root's, read back by undo-b.
mark() { printf '%s=%s\n' "$1" "$2" >> "$MARKER"; chmod 0600 "$MARKER"; }
marked() { [ -r "$MARKER" ] && grep -q "^$1=" "$MARKER"; }
marker_value() { sed -n "s/^$1=//p" "$MARKER" | tail -1; }

# One call through the rule, as probe-svc, like a2's. ID is a fresh identifier. Prints the output.
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
