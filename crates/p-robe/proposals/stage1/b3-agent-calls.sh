#!/bin/sh
# Stage B, step 3: an agent and its calls, through the real pact, HTTP, the service under systemd, the sudo rule and
# the person's pledge. Run as root, after b2 passed, with the person at pledge's terminal (the terminal b1 told him to
# open). The calls that are ASKED wait for him: the script says, before each, what to answer there.
#   sh b3-agent-calls.sh /path/to/CHECKOUT
# `pact` runs as the person (the agent's user here: one user, a simplification of this trial). Undone by undo-b.sh.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/b-common.sh"
need_root
identify "${1:-}"

[ -e "$MARKER" ] || stop "b1 has not run: run  sh $HERE/b1-prepare-person.sh $CHECKOUT"
systemctl is-active --quiet probe-serve.service || stop "probe-serve is not active: b2 has not passed (systemctl status probe-serve)"
[ -S "$RUNDIR/service.sock" ] || stop "pledge is not serving in $RUNDIR: the person starts it ($(pledge_serve_command))"
find_pledge
find_pact
commit_of_checkout
SVCUID=$(id -u "$SVC")
echo "checkout $CHECKOUT at $COMMIT; person $PERSON; pact: $PACT; pledge: $PLEDGE"

BUNDLE=$PHOME/probe-stage1-bundle
CALLER=/var/tmp/probe-stage1.pact-call.sh
# The little script the person runs: pact reads the bundle from a regular file on standard input, which it must own
# with no group or other bits (pledge made it 0600 for him).
cat > "$CALLER" <<SH
#!/bin/sh
exec '$PACT' "\$@" < '$BUNDLE'
SH
chown "$PERSON:$PGROUP" "$CALLER"; chmod 0700 "$CALLER"
mark CALLER_MADE "$CALLER"

say() { echo; echo ">>> $*"; }
# pact_call TOOL JSON: prints pact's one line.
pact_call() { as_person "sh '$CALLER' call $1 '$2'"; }
id_of() { printf '%s\n' "$1" | sed -n 's/.*"id":"\([0-9a-f-]\{36\}\)".*/\1/p' | head -1; }
IDS=""
# expect LABEL OUTPUT WANT: the outcome word of pact's result.
expect() {
  id=$(id_of "$2")
  if printf '%s\n' "$2" | grep -q "\"outcome\":\"$3\""; then pass "$1: $3 (call $id)"; else fail "$1: expected $3; pact said: $(printf '%s\n' "$2" | cut -c1-300)"; fi
  IDS="$IDS $id:$3"
}

# -- the agent ----------------------------------------------------------------------------------------------
rm -f "$BUNDLE"
say "pledge will ask the person to allow a new agent. In pledge's terminal answer:  y"
if as_person "$PLEDGE agents start --groups admins --deadline 300 --label stage1 --output '$BUNDLE' $(pledge_args)"; then pass "an agent was started; its bundle is $BUNDLE"; else stop "pledge agents start failed (its words are above)"; fi
mark BUNDLE_MADE "$BUNDLE"
[ "$(stat -c '%a %U' "$BUNDLE")" = "600 $PERSON" ] && pass "the bundle is 0600 and the person's" || stop "the bundle is '$(stat -c '%a %U' "$BUNDLE")', expected '600 $PERSON'"

# -- the catalogue ------------------------------------------------------------------------------------------
TOOLS=$(as_person "sh '$CALLER' tools") || stop "pact tools failed (its words are above): the service is not reachable at http://$LISTEN/mcp, or the bundle is refused"
for t in sys_kit test_echo test_peak test_read; do
  printf '%s\n' "$TOOLS" | grep -q "\"$t\"" && pass "pact tools lists $t" || fail "pact tools does not list $t: $(printf '%s\n' "$TOOLS" | cut -c1-300)"
done
[ "$FAILED" = 0 ] || stop "the catalogue is not what the rest needs"

# -- the calls ----------------------------------------------------------------------------------------------
say "sys_kit: harmless, automatic: nothing to answer."
R=$(pact_call sys_kit '{"params":[]}'); expect "sys_kit (automatic; the verb runs as root through the sudo rule)" "$R" done
printf '%s\n' "$R" | grep -q '"euid":0' && pass "its answer says euid 0: the dispatcher ran as root" || fail "its answer does not say euid 0"
say "test_echo: harmless, automatic: nothing to answer."
R=$(pact_call test_echo '{"params":["hello"]}'); expect "test_echo (automatic)" "$R" done
printf '%s\n' "$R" | grep -q 'hello' && pass "its answer carries the argument" || fail "its answer does not carry the argument"

say "test_peak is rated at the top of a scale: pledge asks. In pledge's terminal answer  y  to the request and  y  to the presence check. This call waits for you."
R=$(pact_call test_peak '{"params":[]}'); expect "test_peak, asked and confirmed" "$R" done

say "test_peak again. This time answer  n  in pledge's terminal. This call waits for you."
R=$(pact_call test_peak '{"params":[]}'); expect "test_peak, declined" "$R" declined

say "test_read of /etc/hostname: a file outside the test's open place is rated secret: pledge asks. Answer  y  and  y. Its answer is a record with the file's bytes, which the service makes visible if they hold anything odd."
R=$(pact_call test_read '{"params":["/etc/hostname"]}'); expect "test_read, asked and confirmed" "$R" done
printf '%s\n' "$R" | grep -q '"type":"file"' && pass "its answer has a file record" || fail "its answer has no file record"

say "test_peak, the LONG one: pact gives up on a silent stream after 45 seconds; the service sends a comment every 15. WAIT at least 60 SECONDS in pledge's terminal before you answer  y  and  y. Start counting when the question appears."
T0=$(date +%s)
R=$(pact_call test_peak '{"params":[]}'); T1=$(date +%s)
expect "test_peak, answered late" "$R" done
WAITED=$((T1 - T0))
if [ "$WAITED" -ge 50 ]; then pass "the call lasted $WAITED s: past pact's 45 s idle timeout, so the service's keepalive comments arrived"; else fail "the call lasted only $WAITED s: it did not wait long enough to show a keepalive (answer after 60 s)"; fi

# -- pledge's record ------------------------------------------------------------------------------------------
HIST=$(as_person "$PLEDGE history $(pledge_args)")
if as_person "$PLEDGE history --verify $(pledge_args)" >/dev/null 2>&1; then pass "pledge history --verify: the chain is intact"; else fail "pledge history --verify failed"; fi
for pair in $IDS; do
  id=${pair%%:*}; want=${pair#*:}
  [ -n "$id" ] || continue
  line=$(printf '%s\n' "$HIST" | grep "call=$id" | grep -v 'received' | head -1)
  case "$want" in done) word=approved ;; declined) word=declined ;; *) word=$want ;; esac
  if printf '%s\n' "$line" | grep -q " $word"; then pass "pledge's record has $word for $id"; else fail "pledge's record has no '$word' entry for $id: $line"; fi
  printf '%s\n' "$line" | grep -q "peer-uid=$SVCUID" && pass "…received from uid $SVCUID ($SVC), read by pledge from the socket" || fail "…the entry of $id does not show peer-uid=$SVCUID"
done

# -- the service's log and the dispatcher's, by call identifier ---------------------------------------------------
sleep 1
JOURNAL=$(journalctl -t probe --no-pager -n 400 2>/dev/null)
for pair in $IDS; do
  id=${pair%%:*}; want=${pair#*:}
  [ -n "$id" ] || continue
  if [ "$want" = done ]; then
    printf '%s\n' "$JOURNAL" | grep "call=$id" | grep -q 'event=start' && printf '%s\n' "$JOURNAL" | grep "call=$id" | grep -q 'event=done' \
      && pass "the journal has start and done of the dispatcher for $id (identity=$SVC)" || fail "the journal lacks the dispatcher's start/done for $id"
  else
    printf '%s\n' "$JOURNAL" | grep "call=$id" | grep -q 'event=start' && fail "the journal has a start for $id, which was declined: the verb ran" || pass "no dispatcher line for $id: the declined call did not run"
  fi
  printf '%s\n' "$JOURNAL" | grep "id=$id" | grep -q "outcome=$want" && pass "the service's own line says outcome=$want for $id" || fail "the service's log has no 'outcome=$want' for $id"
done

echo
if [ "$FAILED" = 0 ]; then
  echo "ALL PASSED: a real agent (pact) called the service over HTTP; the verbs ran as root through sudo; the person's pledge asked, approved, declined; the record, the service's log and the dispatcher's lines agree by call identifier."
  echo "To take everything away:  sh $HERE/undo-b.sh   (and Ctrl-C pledge in its terminal first)"
else
  echo "SOME FAILED: read the FAIL lines above; journalctl -u probe-serve -n 100 and the pledge terminal say the rest."
  exit 1
fi
