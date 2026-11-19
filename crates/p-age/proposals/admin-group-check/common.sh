#!/bin/sh
# The administrators' group check: names, checks and helpers shared by check-administrators.sh and undo-administrators.sh.
# Sourced (`. "$HERE/common.sh"`), never run. It only defines things; it changes nothing when sourced.
# Needs POSIX sh and: id stat getent awk sed grep su mktemp install pgrep pkill sleep date tr wc.

# -- names unlikely to exist (the script stops if any does) ------------------------------------------------------------
BROKER=pgchk-broker     # the broker's service account
MEMBER=pgchk-alice      # an administrator: in the group
OTHER=pgchk-bob         # not in the group
GROUP=pgchk-admins      # the administrators' group
# Where the check keeps what it made, so that undo removes only that: root:root 0700, made with mkdir (which fails if the
# name exists). Root obeys what is in it, so no other account may be able to write there. Temporary files live here too
# (mktemp), never in /tmp.
STATEDIR=/etc/page-admin-check-state
MARKER=$STATEDIR/marker
# The broker's world: ROOTDIR is root's (0755) so that the group can walk to the socket in ROOTDIR/state; state/ and private/
# are the broker's (0700).
ROOTDIR=/var/lib/page-admin-check
BINDIR=/usr/local/lib/page-admin-check
CONF=$ROOTDIR/page.json
STATE=$ROOTDIR/state
PRIVATE=$ROOTDIR/private
SERVEOUT=$PRIVATE/serve.out
PAGE=$BINDIR/page

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }
# stop: a precondition is missing or a step that the rest depends on failed; nothing after this is meaningful.
stop() { echo "STOP: $*"; exit 1; }
FAILED=0

need_root() { [ "$(id -u)" = 0 ] || stop "run as root"; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }

# identify CHECKOUT: the person is the user who owns the checkout; he builds it. Sets CHECKOUT, PERSON, HERE.
identify() {
  CHECKOUT="${1:?usage: sh $0 CHECKOUT   (the checkout of the repository, owned by the user who builds it)}"
  [ -d "$CHECKOUT/.git" ] || stop "$CHECKOUT is not a checkout"
  PERSON=$(stat -c %U "$CHECKOUT" 2>/dev/null)
  { [ -n "$PERSON" ] && [ "$PERSON" != root ] && [ "$PERSON" != UNKNOWN ]; } || stop "the checkout must belong to the user who builds it (not root); owner: ${PERSON:-unknown}"
  HERE=$(cd "$(dirname "$0")" && pwd)
}
# as_owner COMMAND: as the checkout's owner in a login shell (so that cargo is on the PATH as for him), in the checkout.
as_owner() { su - "$PERSON" -c "cd '$CHECKOUT' && $1"; }

# as_user USER COMMAND: sets RC and OUT (stdout and stderr together). `su -s /bin/sh -c`, not a login: su sets the groups
# of USER from the group database as it is NOW (initgroups), so an account that was just added to the group has it at once,
# and no fresh login is needed. (`sudo -u` would do the same; su is what the p-robe scripts use.) cd / first: root's
# directory may not be readable by the account.
as_user() { OUT=$(su -s /bin/sh -c "cd / && $2" "$1" 2>&1); RC=$?; }

# artifact KIND NAME BUILD-COMMAND -> prints the path cargo names; builds as the owner. Never guesses a place.
artifact() {
  json=$(as_owner "$3 --message-format=json") || stop "the build failed: $3"
  path=$(printf '%s\n' "$json" | sh "$HERE/find-artifact.sh" "$1" "$2") || stop "cannot tell where cargo put the $1 $2"
  [ -x "$path" ] || stop "$path is not an executable"
  printf '%s\n' "$path"
}

# show_output RC OUTPUT: the whole of what a call printed and its exit code, indented, so that the cause is on the screen.
show_output() {
  echo "    exit code: $1"
  if [ -n "$2" ]; then printf '%s\n' "$2" | sed 's/^/    | /'; else echo "    | (it printed nothing)"; fi
}
# must RC OUTPUT WHAT: a step the rest depends on: stops with the whole output and the exit code unless RC is 0.
must() { [ "$1" = 0 ] || { echo "STOP: $3 failed"; show_output "$1" "$2"; exit 1; }; }

# -- the marker: KEY=VALUE lines, root's, read back by undo --------------------------------------------------------------
TRUSTED_UID=0   # a plain assignment, never read from the environment; the tests of the checks below set it to their own
# root_only PATH KIND (d or f): not a symlink, of that kind, owned by TRUSTED_UID, not writable by group or others.
root_only() {
  [ ! -L "$1" ] || return 1
  case "$2" in d) [ -d "$1" ] || return 1 ;; f) [ -f "$1" ] || return 1 ;; *) return 1 ;; esac
  set -- "$1" "$(stat -c '%u %a' "$1" 2>/dev/null || stat -f '%u %Lp' "$1" 2>/dev/null)"
  owner=${2%% *}; perm=${2#* }
  [ "$owner" = "$TRUSTED_UID" ] && [ -n "$perm" ] && [ $((0$perm & 022)) -eq 0 ]
}
marker_safe() { root_only "$STATEDIR" d && { ! exists "$MARKER" || root_only "$MARKER" f; }; }
# a path read from the marker is absolute, has no `..`, no newline, and is not near the top of the file system.
sane_path() {
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *..*|*'
'*) return 1 ;; esac
  [ "$(printf '%s' "$1" | tr -cd '/' | wc -c)" -ge 2 ]
}
mark() { marker_safe || stop "$STATEDIR or $MARKER is not root's alone: refusing to write to it"; printf '%s=%s\n' "$1" "$2" >> "$MARKER"; chmod 0600 "$MARKER"; }
marked() { root_only "$MARKER" f && grep -q "^$1=" "$MARKER"; }
marker_values() { root_only "$MARKER" f && sed -n "s/^$1=//p" "$MARKER"; }
ensure_statedir() {
  if exists "$STATEDIR"; then
    stop "$STATEDIR exists: a check was run before; run undo-administrators.sh first, or look at it"
  fi
  mkdir -m 0700 "$STATEDIR" || stop "cannot make $STATEDIR (it appeared meanwhile?)"
  chown root:root "$STATEDIR" && chmod 0700 "$STATEDIR"
}
tmpfile() { mktemp "$STATEDIR/$1.XXXXXX"; }

# ssh_at_least_8_9 VERSIONTEXT: the text `ssh -V` prints ("OpenSSH_9.2p1 Debian-..."): is it OpenSSH 8.9 or later?
# (p-act's Keygen::system wants 8.9 or later; the broker will say so itself, but a precondition says it first.)
ssh_at_least_8_9() {
  v=$(printf '%s\n' "$1" | sed -n 's/^OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | head -1)
  [ -n "$v" ] || return 1
  major=${v% *}; minor=${v#* }
  [ "$major" -gt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -ge 9 ]; }
}

# path_trusted PATH: PATH and every directory above it are owned by root and not writable by group or others (what
# Keygen::system asks of /usr/bin/ssh-keygen). A symlink is not followed: it is refused.
path_trusted() {
  p=$1
  while :; do
    [ ! -L "$p" ] || return 1
    set -- "$p" "$(stat -c '%u %a' "$p" 2>/dev/null)"
    [ "${2%% *}" = 0 ] && [ $((0${2#* } & 022)) -eq 0 ] || return 1
    [ "$p" = / ] && return 0
    p=$(dirname "$p")
  done
}

# modes_of PATH: "owner group octal-mode" of a path, for what the check asserts.
modes_of() { stat -c '%U %G %a' "$1"; }
