#!/bin/sh
# Stage B, step 1: the person's side and the places the service and pledge share. Run as root, after Stage A passed.
#   sh b1-prepare-person.sh /path/to/CHECKOUT
# The person is the user who owns the checkout (he builds it and runs pledge). Everything this changes is in
# RUNBOOK-stage1-linux.md, section 3, and is undone by undo-b.sh; what it made is written to a marker so that undo-b
# removes only that. Everything that can fail is checked BEFORE the first change.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
need_root
identify "${1:-}"

# -- preconditions (nothing changed yet) ------------------------------------------------------------------------
[ -x "$PROBE" ] && [ -e /etc/sudoers.d/probe-svc ] || stop "Stage A is not in place ($PROBE or /etc/sudoers.d/probe-svc is missing): run a1 and a2 first"
id "$SVC" >/dev/null 2>&1 || stop "the account $SVC does not exist: run a1 first"
[ -e "$MARKER" ] && stop "$MARKER exists: Stage B was prepared before; run undo-b.sh first"
[ -e "$STATE/config.json" ] && stop "$STATE/config.json exists (pledge state of $PERSON from before): look at it, move it away if it is not wanted, or run undo-b.sh"
[ -e "$KEYDIR" ] && stop "$KEYDIR exists: look at it (it would hold a service key), move it away or run undo-b.sh"
[ -e "$SETTINGS" ] && stop "$SETTINGS exists: look at it, move it away or run undo-b.sh"
[ -e "$RUNDIR" ] && stop "$RUNDIR exists: a pledge of an earlier run? stop it (Ctrl-C in its terminal), then run undo-b.sh"
command -v ssh-keygen >/dev/null || stop "ssh-keygen is not installed"
command -v groupadd >/dev/null && command -v usermod >/dev/null || stop "groupadd/usermod (shadow-utils) are not installed"
as_owner "command -v cargo >/dev/null" || stop "cargo is not on the PATH of $PERSON (a login shell): the owner builds the checkout"
find_pledge
commit_of_checkout
echo "checkout $CHECKOUT at $COMMIT; person $PERSON (uid $PUID, group $PGROUP, home $PHOME); host $HOST"
echo "pledge: $PLEDGE"

mark PERSON "$PERSON"

# -- the host key: pledge's configuration names it, and the service's certificate is made with it ---------------------
HOSTKEY=/etc/ssh/ssh_host_ed25519_key
if [ ! -e "$HOSTKEY.pub" ]; then
  if [ -e "$HOSTKEY" ]; then stop "$HOSTKEY exists without $HOSTKEY.pub: restore it with  ssh-keygen -y -f $HOSTKEY > $HOSTKEY.pub  and run this again"; fi
  umask 077
  ssh-keygen -q -t ed25519 -N '' -C "root@$HOST" -f "$HOSTKEY" || stop "could not make the host key"
  chmod 0600 "$HOSTKEY"; chmod 0644 "$HOSTKEY.pub"
  mark HOSTKEY_MADE 1
  echo "note: this host had no Ed25519 host key; made $HOSTKEY (undo-b removes it, and only because it was made here)"
  umask 022
fi
HOSTPUB=$(awk '{print $1" "$2}' "$HOSTKEY.pub")
case "$HOSTPUB" in "ssh-ed25519 "*) ;; *) stop "$HOSTKEY.pub is not an Ed25519 public key" ;; esac

# -- the group that lets the service's account reach service.sock -------------------------------------------------
if getent group "$GROUP" >/dev/null; then
  echo "note: the group $GROUP exists already; it is left as it is"
else
  groupadd --system "$GROUP" || stop "groupadd $GROUP failed"
  mark GROUP_MADE 1
  echo "made the group $GROUP"
fi
for member in "$PERSON" "$SVC"; do
  if in_group "$member" "$GROUP"; then
    echo "note: $member is in $GROUP already"
  else
    usermod -aG "$GROUP" "$member" || stop "usermod -aG $GROUP $member failed"
    mark "ADDED_$member" 1
    echo "added $member to $GROUP"
  fi
done

# -- the places, with their modes written out (a group-writable umask must not decide) -------------------------------
# The socket directory: pledge accepts it only if it is owned by the person and mode 0700 (0710 once it has made it
# group-readable); /run/user/<uid> exists only for a login session, which `su` in a container does not make.
install -d -o "$PERSON" -g "$PGROUP" -m 0700 "$RUNDIR" || stop "cannot make $RUNDIR"
mark RUNDIR_MADE "$RUNDIR"
# The service's key and certificate, and the person's two public keys, go here (b2).
install -d -o root -g root -m 0755 "$KEYDIR" || stop "cannot make $KEYDIR"
mark KEYDIR_MADE 1
# pledge's state: the person's, private.
for dir in "$PHOME/.local" "$PHOME/.local/state"; do
  [ -d "$dir" ] || { install -d -o "$PERSON" -g "$PGROUP" -m 0755 "$dir" && mark "PARENT_MADE" "$dir"; }
done
install -d -o "$PERSON" -g "$PGROUP" -m 0700 "$STATE" || stop "cannot make $STATE"
mark STATE_MADE "$STATE"
# pledge's configuration: its person, this host and its key, the service the agents may reach, the group.
TMP=$(mktemp /var/tmp/probe-stage1.pledge-config.XXXXXX) || stop "mktemp failed"
pledge_config_json "$PERSON" "$HOST" "$HOSTPUB" "$GROUP" "http://$LISTEN/mcp" > "$TMP"
install -o "$PERSON" -g "$PGROUP" -m 0600 "$TMP" "$STATE/config.json"
rm -f "$TMP"
pass "prepared: $RUNDIR (owned by $PERSON, 0700), $KEYDIR, $STATE/config.json (0600), the group $GROUP with $PERSON and $SVC"

cat <<EOF2

NEXT, BY HAND, in a terminal of your own (the person's: pledge asks him, here, and you answer its questions):
  $(pledge_serve_command)
It prints a warning and then  pledge: serving. SSH agent socket: ...   (all three sockets are bound then).
  - If it says it cannot make the directory 0710 / give it to the group: $PERSON is not in $GROUP in that login.
    The line above uses  su - $PERSON  for that reason; do not start pledge from an older shell.
Leave it running. In a SECOND terminal, as $PERSON ( su - $PERSON ), make the three keys; each asks a question in the
FIRST terminal: answer  y  there each time:
  $PLEDGE keys create delegation $(pledge_args)
  $PLEDGE keys create confirmed  $(pledge_args)
  $PLEDGE keys create automatic  $(pledge_args)
Then, as root:  sh $HERE/b2-service.sh $CHECKOUT
EOF2
