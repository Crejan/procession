#!/bin/sh
# The owner's two-account check of `administrators_group`, steps 2 to 9 of "For the owner" in proposals/REPORT.md.
#   sh check-administrators.sh /path/to/CHECKOUT        (as root, on Debian; Linux only)
# Step 1 (cargo test -p p-ermit, cargo test -p p-age) stays a command for you. Undo: sh undo-administrators.sh.
#
# THIS HAS NEVER RUN. It was written where it cannot (a Mac); only `sh -n` and the shell helpers were tested. Read what it
# says: PASS lines, FAIL lines (the run goes on), a STOP line (it cannot go on; the whole output of the failed call and its
# exit code are printed), and ALL PASSED at the very end only if nothing failed.
#
# What it makes (all removed by undo-administrators.sh, which removes only what the marker in $STATEDIR says was made here):
#   accounts  pgchk-broker (the broker), pgchk-alice (in the group), pgchk-bob (not), and the group pgchk-admins with the
#             broker and alice in it. Names unlikely to exist: it stops if any does.
#   /usr/local/lib/page-admin-check/page   the broker binary: built as the checkout's owner, its path taken from cargo's own
#             JSON (never guessed), copied here (root's, 0755) so that the three accounts can run it.
#   /var/lib/page-admin-check/             root's 0755: the config page.json and the site file, the CA key's public half and
#             the TLS certificate (all 0644), and two directories of the broker's (0700): state/ (the register and
#             admin.sock) and private/ (its key, its certificate, its TLS key, its log and what it prints).
#   Made here with the tools the host has, the way the tests do:
#     site CA key        ssh-keygen -t ed25519: signs the broker's certificate; its public half is `site_ca` in the config
#     broker key + cert  ssh-keygen -t ed25519, certified by the CA with principal `broker`, no extension, valid from
#                        yesterday for 30 days: the broker's own certificate (`<broker_key>-cert.pub`), without which it
#                        is "not ready"
#     site file          one person, jan, with four plain ed25519 public keys, and one host; and directory.json beside it
#                        (source model, made now, jan active, no groups): what `page block jan` needs to know the person
#     TLS key + cert     openssl req -x509, P-256, self-signed, for two days: the broker will not start without them;
#                        nobody connects to its TCP port here
# Groups without a fresh login: every command of an account is run with `su -s /bin/sh -c`, which sets the account's groups
# from the group database at that moment (initgroups), so a user just added to the group has it. (`sudo -u` does the same.)
#
# Every precondition is checked before the first change. No time is compared by exact value.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/common.sh"
need_root
identify "${1:-}"

# -- preconditions (nothing changed yet) ----------------------------------------------------------------------------
echo "== preconditions"
[ "$(uname -s)" = Linux ] || stop "Linux only (the kernel's list of a peer's groups is read on Linux only)"
for tool in id stat getent awk sed grep su mktemp install pgrep pkill sleep date tr wc groupadd useradd userdel groupdel usermod ssh ssh-keygen openssl; do
  command -v "$tool" >/dev/null 2>&1 || stop "$tool is not installed (the check needs it)"
done
path_trusted /usr/bin/ssh-keygen || stop "/usr/bin/ssh-keygen is not root's alone (it, or a directory above it, is not owned by root or can be written by others): the broker would refuse to use it"
SSHV=$(ssh -V 2>&1)
ssh_at_least_8_9 "$SSHV" || stop "OpenSSH is older than 8.9 (ssh -V says: $SSHV): the broker would refuse ssh-keygen"
as_owner "command -v cargo >/dev/null" || stop "cargo is not on the PATH of $PERSON (a login shell): the owner builds the checkout"
for name in "$BROKER" "$MEMBER" "$OTHER"; do
  getent passwd "$name" >/dev/null && stop "the account $name exists already: look at it; this check does not use an existing one"
done
getent group "$GROUP" >/dev/null && stop "the group $GROUP exists already: look at it"
for path in "$STATEDIR" "$ROOTDIR" "$BINDIR"; do
  exists "$path" && stop "$path exists: a check was run before (sh undo-administrators.sh), or look at it"
done
as_owner "git rev-parse --short=12 HEAD" >/dev/null || stop "cannot read the checkout's commit"
COMMIT=$(as_owner "git rev-parse --short=12 HEAD")
echo "building the broker as $PERSON (cargo's own JSON names the binary)"
PAGE_SRC=$(artifact bin page "cargo build -p p-age --bin page") || exit 1
echo "checkout $CHECKOUT at $COMMIT; $SSHV; binary $PAGE_SRC"

# -- step 2: the accounts and the group -------------------------------------------------------------------------------
echo "== step 2: accounts and group"
ensure_statedir
mark CHECKOUT_COMMIT "$COMMIT"
groupadd --system "$GROUP" || stop "groupadd $GROUP failed"
mark GROUP_MADE "$GROUP"
for name in "$BROKER" "$MEMBER" "$OTHER"; do
  useradd --system --no-create-home --shell /usr/sbin/nologin "$name" || stop "useradd $name failed"
  mark ACCOUNT_MADE "$name"
done
usermod -aG "$GROUP" "$MEMBER" || stop "usermod -aG $GROUP $MEMBER failed"
usermod -aG "$GROUP" "$BROKER" || stop "usermod -aG $GROUP $BROKER failed"
in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }
in_group "$MEMBER" "$GROUP" && in_group "$BROKER" "$GROUP" && ! in_group "$OTHER" "$GROUP" \
  && pass "$MEMBER and $BROKER are in $GROUP, $OTHER is not" || stop "the group memberships are not what was made"
GID=$(getent group "$GROUP" | awk -F: '{print $3}')
BGROUP=$(id -gn "$BROKER")      # the broker's own group (useradd makes one by default; whatever it is, it is used)
MUID=$(id -u "$MEMBER")

# -- step 3: the files the broker needs ---------------------------------------------------------------------------------
echo "== step 3: keys, certificate, site file, TLS, configuration, the binary"
install -d -o root -g root -m 0755 "$BINDIR" || stop "cannot make $BINDIR"
mark BINDIR_MADE "$BINDIR"
install -o root -g root -m 0755 "$PAGE_SRC" "$PAGE" || stop "cannot install the binary"
install -d -o root -g root -m 0755 "$ROOTDIR" || stop "cannot make $ROOTDIR"
mark ROOTDIR_MADE "$ROOTDIR"
install -d -o "$BROKER" -g "$BGROUP" -m 0700 "$STATE" || stop "cannot make $STATE"
install -d -o "$BROKER" -g "$BGROUP" -m 0700 "$PRIVATE" || stop "cannot make $PRIVATE"
WORK=$STATEDIR/keys                        # root-only: the keys are made here, then copied with explicit modes
mkdir -m 0700 "$WORK" || stop "cannot make $WORK"
keygen() { OUT=$(umask 077; /usr/bin/ssh-keygen -q -t ed25519 -N '' -C "$2" -f "$1" 2>&1); must $? "$OUT" "ssh-keygen $2"; }
keygen "$WORK/site-ca" site-ca
keygen "$WORK/broker" broker
OUT=$(/usr/bin/ssh-keygen -q -s "$WORK/site-ca" -I broker -n broker -V -1d:+30d -O clear "$WORK/broker.pub" 2>&1); must $? "$OUT" "certifying the broker's key"
for name in confirmed automatic delegation connection host; do keygen "$WORK/jan-$name" "jan-$name"; done
publine() { awk '{print $1" "$2}' "$1"; }   # the key without its comment, as the site file holds it
install -o "$BROKER" -g "$BGROUP" -m 0600 "$WORK/broker" "$PRIVATE/broker"
install -o "$BROKER" -g "$BGROUP" -m 0644 "$WORK/broker.pub" "$PRIVATE/broker.pub"
install -o "$BROKER" -g "$BGROUP" -m 0644 "$WORK/broker-cert.pub" "$PRIVATE/broker-cert.pub"
install -o root -g root -m 0644 "$WORK/site-ca.pub" "$ROOTDIR/site-ca.pub"
cat > "$WORK/site.json" <<JSON
{"v":1,
 "persons":[{"name":"jan",
   "keys":{"confirmed":{"key":"$(publine "$WORK/jan-confirmed.pub")"},
           "automatic":{"key":"$(publine "$WORK/jan-automatic.pub")"},
           "delegation":{"key":"$(publine "$WORK/jan-delegation.pub")"},
           "connection":{"key":"$(publine "$WORK/jan-connection.pub")"}}}],
 "hosts":[{"name":"a.example","key":"$(publine "$WORK/jan-host.pub")"}],
 "groups":[]}
JSON
install -o root -g root -m 0644 "$WORK/site.json" "$ROOTDIR/site.json"
# directory.json beside it: source model, made now, jan active, no groups (the site file names none)
cat > "$WORK/directory.json" <<JSON
{"v":1,"source":"model","as_of":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","active":["jan"],"members":{}}
JSON
install -o root -g root -m 0644 "$WORK/directory.json" "$ROOTDIR/directory.json"
OUT=$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=page-admin-check \
  -keyout "$WORK/tls.key" -out "$WORK/tls.pem" 2>&1); must $? "$OUT" "making the TLS certificate"
install -o "$BROKER" -g "$BGROUP" -m 0600 "$WORK/tls.key" "$PRIVATE/tls.key"
install -o root -g root -m 0644 "$WORK/tls.pem" "$ROOTDIR/tls.pem"
cat > "$WORK/page.json" <<JSON
{"site":"$ROOTDIR/site.json","listen":["127.0.0.1:0"],
 "tls_cert":"$ROOTDIR/tls.pem","tls_key":"$PRIVATE/tls.key","broker_key":"$PRIVATE/broker",
 "state_dir":"$STATE","site_ca":"$ROOTDIR/site-ca.pub","log":"$PRIVATE/log.jsonl",
 "administrators_group":"$GROUP"}
JSON
install -o root -g root -m 0644 "$WORK/page.json" "$CONF"
rm -rf "$WORK"
as_user "$BROKER" "'$PAGE' init --config '$CONF'"; must "$RC" "$OUT" "page init as $BROKER"
pass "made: $ROOTDIR (config, site file, TLS, CA public key), $PRIVATE and $STATE (the broker's, 0700), $PAGE, the register"

# -- step 4: start the broker, with a bounded prober that has been running since before it started ---------------------
echo "== step 4: start; the member and the other account are tried continuously from before the start until after ready"
install -o "$BROKER" -g "$BGROUP" -m 0600 /dev/null "$SERVEOUT" || stop "cannot make $SERVEOUT"
PROBELOG=$(tmpfile probe) || stop "mktemp failed"
STOPFILE=$STATEDIR/stop-probe
rm -f "$STOPFILE"
# The prober: at most 400 rounds (about a minute at the slowest), each: is the ready line there; try status as the member and
# as the other; is the ready line there now. Written as "who ready-before ready-after". Root's file, root's process.
(
  i=0
  while [ ! -e "$STOPFILE" ] && [ "$i" -lt 400 ]; do
    b=no; grep -q 'page: ready:' "$SERVEOUT" 2>/dev/null && b=yes
    su -s /bin/sh -c "cd / && '$PAGE' status --config '$CONF'" "$MEMBER" >/dev/null 2>&1 && m=ok || m=no
    su -s /bin/sh -c "cd / && '$PAGE' status --config '$CONF'" "$OTHER" >/dev/null 2>&1 && o=ok || o=no
    a=no; grep -q 'page: ready:' "$SERVEOUT" 2>/dev/null && a=yes
    [ "$m" = ok ] && echo "member $b $a" >> "$PROBELOG"
    [ "$o" = ok ] && echo "other $b $a" >> "$PROBELOG"
    i=$((i + 1)); sleep 0.05
  done
) &
PROBEPID=$!
sleep 1
( su -s /bin/sh -c "cd / && exec '$PAGE' serve --config '$CONF' >> '$SERVEOUT' 2>&1" "$BROKER" ) &
SERVEPID=$!
mark BROKER_STARTED 1
n=0
until grep -q 'page: ready:' "$SERVEOUT" 2>/dev/null; do
  if ! kill -0 "$SERVEPID" 2>/dev/null; then
    echo "STOP: the broker ended before it was ready; what it printed:"; show_output "?" "$(cat "$SERVEOUT")"; touch "$STOPFILE"; exit 1
  fi
  [ "$n" -ge 300 ] && { echo "STOP: no 'page: ready:' within about 30 seconds; what it printed:"; show_output "?" "$(cat "$SERVEOUT")"; touch "$STOPFILE"; exit 1; }
  sleep 0.1; n=$((n + 1))
done
pass "the broker said ready"
sleep 1
touch "$STOPFILE"
n=0; while kill -0 "$PROBEPID" 2>/dev/null && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
kill -0 "$PROBEPID" 2>/dev/null && { kill "$PROBEPID" 2>/dev/null; echo "note: the prober had to be stopped"; }

# -- step 5: the order: nobody got in early, and the other account never got in at all -----------------------------------
echo "== step 5: not reachable before ready, reachable after"
EARLY=$(grep -c '^member no no$' "$PROBELOG")
OTHERS=$(grep -c '^other ' "$PROBELOG")
[ "$EARLY" = 0 ] && pass "the member never reached the broker in a round where the ready line was absent before and after the call (the member's rounds before the start all failed, as they must: no socket)" \
  || fail "the member reached the broker $EARLY time(s) while the ready line was still absent after the call"
[ "$OTHERS" = 0 ] && pass "the other account ($OTHER, not in $GROUP) never reached the broker, before or after ready" \
  || fail "the other account reached the broker $OTHERS time(s)"
AFTER=$(grep -c '^member ' "$PROBELOG")
echo "      (the member's successful rounds: $AFTER; the other's: $OTHERS)"

# -- step 6: the socket and the directory --------------------------------------------------------------------------------
echo "== step 6: modes on disk"
[ "$(modes_of "$STATE/admin.sock")" = "$BROKER $GROUP 660" ] && pass "admin.sock is $BROKER:$GROUP 0660" || fail "admin.sock is: $(modes_of "$STATE/admin.sock")"
[ "$(modes_of "$STATE")" = "$BROKER $GROUP 710" ] && pass "the state directory is $BROKER:$GROUP 0710" || fail "the state directory is: $(modes_of "$STATE")"
[ "$(modes_of "$STATE/register.json")" = "$BROKER $BGROUP 600" ] && pass "register.json stays 0600" || fail "register.json is: $(modes_of "$STATE/register.json")"

# -- step 7: who is let in -----------------------------------------------------------------------------------------------
echo "== step 7: admission"
as_user "$MEMBER" "'$PAGE' status --config '$CONF'"
[ "$RC" = 0 ] && printf '%s\n' "$OUT" | grep -q "administrators: group $GROUP (gid $GID)" \
  && pass "the member's page status works and says: administrators: group $GROUP (gid $GID)" \
  || { fail "the member's page status"; show_output "$RC" "$OUT"; }
as_user "$OTHER" "'$PAGE' status --config '$CONF'"
[ "$RC" = 3 ] && pass "the other account is not served (exit 3: no broker answers it)" || { fail "the other account: expected exit 3"; show_output "$RC" "$OUT"; }
as_user "$BROKER" "'$PAGE' status --config '$CONF'"
[ "$RC" = 3 ] && pass "the broker's own account is refused although it is in the group (exit 3)" || { fail "the broker's own account: expected exit 3"; show_output "$RC" "$OUT"; }
OUT=$("$PAGE" status --config "$CONF" 2>&1); RC=$?
if [ "$RC" = 0 ] && printf '%s\n' "$OUT" | grep -q 'recorded as root; run without sudo to be recorded by name'; then
  pass "root is served and told it is recorded as root"
else fail "root's page status"; show_output "$RC" "$OUT"; fi

# -- step 8: the record names the member ----------------------------------------------------------------------------------
echo "== step 8: a block as the member is recorded with the member's uid and name"
as_user "$MEMBER" "'$PAGE' block jan --config '$CONF'"
[ "$RC" = 0 ] && printf '%s\n' "$OUT" | grep -q 'blocked and stored: jan' && pass "page block jan as $MEMBER: blocked and stored" \
  || { fail "page block jan as $MEMBER"; show_output "$RC" "$OUT"; }
want="\"by\":{\"kind\":\"administrator\",\"uid\":$MUID,\"account\":\"$MEMBER\"}"
n=0; found=no
while [ "$n" -lt 20 ]; do   # the account's name is added after the answer, off its path: it may take a moment
  grep -qF "$want" "$STATE/register.json" 2>/dev/null && { found=yes; break; }
  sleep 0.5; n=$((n + 1))
done
if [ "$found" = yes ]; then pass "register.json says $want"; else
  fail "register.json does not say $want within about ten seconds; it says:"; show_output "-" "$(cat "$STATE/register.json" 2>&1)"
fi

# -- step 9: stop ---------------------------------------------------------------------------------------------------------
echo "== step 9: stop the broker"
pkill -u "$BROKER" -x page
n=0; while kill -0 "$SERVEPID" 2>/dev/null && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
if kill -0 "$SERVEPID" 2>/dev/null; then fail "the broker did not stop within about ten seconds"; else pass "the broker stopped"; fi
echo "its output:"; sed 's/^/    | /' "$SERVEOUT"

echo
if [ "$FAILED" = 0 ]; then echo "ALL PASSED (undo with: sh $HERE/undo-administrators.sh)"; else echo "SOME CHECKS FAILED (undo with: sh $HERE/undo-administrators.sh)"; exit 1; fi
