#!/bin/sh
# Stage B, step 2: the service. Run as root, after b1 and after the person started pledge and made the three keys.
#   sh b2-service.sh /path/to/CHECKOUT
# It checks that pledge is serving, reads the person's two public keys from `pledge keys list`, makes the service's key
# and certificate (`probe setup`), writes /etc/probe.json, installs and starts the units, and checks each step with a
# PASS or FAIL line. It STOPS where the rest would mean nothing. Undone by undo-b.sh.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
need_root
identify "${1:-}"

[ -e "$MARKER" ] || stop "b1 has not run ($MARKER is missing): run  sh $HERE/b1-prepare-person.sh $CHECKOUT"
marker_safe || stop "$STATEDIR or $MARKER is not root's alone (root:root, not writable by others): do not go on; look at it"
[ -x "$PROBE" ] || stop "$PROBE is missing: Stage A is not in place"
command -v systemctl >/dev/null || stop "systemctl is not on this host: the units of this step need systemd"
[ -d /run/systemd/system ] || stop "systemd is not running on this host (no /run/systemd/system): the units of this step need it"
find_pledge
commit_of_checkout
echo "checkout $CHECKOUT at $COMMIT; person $PERSON; host $HOST"

# -- 1. is pledge serving, with the group on service.sock? ---------------------------------------------------------
SOCK=$RUNDIR/service.sock
if [ ! -S "$SOCK" ] || [ ! -S "$RUNDIR/control.sock" ] || [ ! -S "$RUNDIR/agent.sock" ]; then
  stop "pledge is not serving: one of the three sockets is missing in $RUNDIR. The person starts it in a terminal of his own:
  $(pledge_serve_command)
and waits for the line  pledge: serving."
fi
mode=$(stat -c '%a %U %G' "$SOCK"); dmode=$(stat -c '%a %U %G' "$RUNDIR")
[ "$mode" = "660 $PERSON $GROUP" ] || stop "$SOCK is '$mode', expected '660 $PERSON $GROUP': pledge did not apply service_group (is $PERSON in $GROUP in the login that started pledge?)"
[ "$dmode" = "710 $PERSON $GROUP" ] || stop "$RUNDIR is '$dmode', expected '710 $PERSON $GROUP'"
pass "pledge is serving; service.sock is 660 and $RUNDIR is 710, both of $GROUP"
# probe-svc can reach it: it can search the directory and write the socket.
if su -s /bin/sh -c "test -x '$RUNDIR' && test -w '$SOCK'" "$SVC"; then pass "$SVC can reach service.sock"; else stop "$SVC cannot reach $SOCK: it is not in $GROUP in a fresh login (b1 added it; if the account was already running a process, restart that)"; fi

# -- 2. the person's keys ----------------------------------------------------------------------------------------
LIST=$(as_person "$PLEDGE keys list $(pledge_args)") || stop "pledge keys list failed: is pledge running for $PERSON?"
key_of() { public_key_of "$LIST" "$1"; }
CONFIRMED=$(key_of confirmed); AUTOMATIC=$(key_of automatic); DELEGATION=$(key_of delegation)
for pair in "confirmed:$CONFIRMED" "automatic:$AUTOMATIC" "delegation:$DELEGATION"; do
  case "${pair#*:}" in "ssh-"*|"ecdsa-"*) ;; *) stop "no $(echo "${pair%%:*}") key in pledge's list: as $PERSON run  $PLEDGE keys create ${pair%%:*} $(pledge_args)  and answer y in pledge's terminal, then run this again" ;; esac
done
umask 022
TMP=$(tmpfile key) || stop "mktemp failed"
printf '%s\n' "$CONFIRMED" > "$TMP"; install -o root -g root -m 0644 "$TMP" "$KEYDIR/$PERSON-confirmed.pub"
printf '%s\n' "$AUTOMATIC" > "$TMP"; install -o root -g root -m 0644 "$TMP" "$KEYDIR/$PERSON-automatic.pub"
rm -f "$TMP"
for f in confirmed automatic; do
  if ssh-keygen -l -f "$KEYDIR/$PERSON-$f.pub" >/dev/null 2>&1; then pass "$KEYDIR/$PERSON-$f.pub is a public key"; else stop "$KEYDIR/$PERSON-$f.pub is not a public key"; fi
done

# -- 3. the service's key and its certificate ---------------------------------------------------------------------
# sys kit first: it says whether ssh-keygen can be used under the rule (fixed path, ownership, version).
kit_via_rule 1
require_kit
require_installed_commit
require_keygen_usable
if "$PROBE" setup --host-key /etc/ssh/ssh_host_ed25519_key --host "$HOST" --out "$KEYDIR"; then pass "probe setup made the service's key and certificate"; else stop "probe setup failed (its words are above); nothing after this is meaningful"; fi
chown "$SVC:$SVC" "$KEYDIR/service-key" "$KEYDIR/service-key.pub" "$KEYDIR/service-key-cert.pub"
chmod 0600 "$KEYDIR/service-key"; chmod 0644 "$KEYDIR/service-key.pub" "$KEYDIR/service-key-cert.pub"
CERT=$(ssh-keygen -L -f "$KEYDIR/service-key-cert.pub" 2>&1)
if printf '%s\n' "$CERT" | grep -q "probe@$HOST"; then pass "the certificate is for probe@$HOST"; else fail "the certificate does not name probe@$HOST; what ssh-keygen -L says follows"; show_output "-" "$CERT"; fi

# -- 4. /etc/probe.json ---------------------------------------------------------------------------------------------
TMP=$(tmpfile settings) || stop "mktemp failed"
probe_settings_json "$PERSON" "$HOST" "$SOCK" "$PUID" > "$TMP"
install -o root -g root -m 0644 "$TMP" "$SETTINGS"; rm -f "$TMP"
mark SETTINGS_MADE 1
pass "$SETTINGS installed (root, 0644)"

# -- 5. the units -------------------------------------------------------------------------------------------------
UNITS=/etc/systemd/system
for unit in probe-serve.service probe-setup.service probe-setup.timer; do
  install -o root -g root -m 0644 "$HERE/$unit" "$UNITS/$unit" || stop "cannot install $unit"
done
mark UNITS_MADE 1
if systemd-analyze verify "$UNITS/probe-serve.service" "$UNITS/probe-setup.service" "$UNITS/probe-setup.timer" 2>"$STATEDIR/verify.out"; then
  if [ -s "$STATEDIR/verify.out" ]; then pass "systemd-analyze verify accepts the units (it also said, for you to read: $(tr '\n' ' ' < "$STATEDIR/verify.out"))"; else pass "systemd-analyze verify: nothing to say"; fi
else
  fail "systemd-analyze verify failed: $(cat "$STATEDIR/verify.out")"
fi
rm -f "$STATEDIR/verify.out"
systemctl daemon-reload
systemctl enable --now probe-setup.timer >/dev/null 2>&1 && pass "probe-setup.timer enabled" || fail "probe-setup.timer did not enable"
systemctl start probe-setup.service
if journalctl -u probe-setup.service --no-pager -n 20 2>/dev/null | grep -q 'Not due: 30 days'; then pass "the renewal unit ran and said: not due, 30 days left"; else fail "the renewal unit did not say 'Not due: 30 days'; what its journal says follows"; show_output "-" "$(journalctl -u probe-setup.service --no-pager -n 20 2>&1)"; fi
systemctl enable --now probe-serve.service >/dev/null 2>&1
# Wait up to 20 s for the service to listen.
n=0
while [ "$n" -lt 20 ]; do
  journalctl -u probe-serve.service --no-pager -n 30 2>/dev/null | grep -q "listening on $LISTEN" && break
  sleep 1; n=$((n + 1))
done
if systemctl is-active --quiet probe-serve.service && journalctl -u probe-serve.service --no-pager -n 30 | grep -q "listening on $LISTEN"; then
  pass "probe-serve is active and listening on $LISTEN"
  if journalctl -u probe-serve.service --no-pager -n 30 | grep -q "for $PERSON, pledge reachable"; then pass "the service reaches pledge"; else fail "the service does not say that pledge is reachable; its journal follows"; show_output "-" "$(journalctl -u probe-serve.service --no-pager -n 30 2>&1)"; fi
else
  fail "probe-serve is not active or does not listen: $(systemctl status probe-serve.service --no-pager 2>&1 | tail -15)"
fi

if [ "$FAILED" = 0 ]; then
  echo "ALL PASSED: the service runs as $SVC under systemd, certified by the host key, listening on $LISTEN, with $PERSON's keys."
  echo "Next, as root, with the person at pledge's terminal:  sh $HERE/b3-agent-calls.sh $CHECKOUT"
else
  echo "SOME FAILED: read the FAIL lines above (and journalctl -u probe-serve). b3 would not mean anything yet."
  exit 1
fi
