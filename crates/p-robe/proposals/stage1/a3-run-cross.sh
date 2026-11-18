#!/bin/sh
# Stage A, step 3: the cross run (real pledge, pact's composer and signer, this crate's service core)
# with the verb run through the real sudo rule. Run as root, after a2-check-rule.sh has passed.
#   sh a3-run-cross.sh /path/to/CHECKOUT
# It builds, as the checkout's owner, the test and `pledge`, and takes their paths from cargo's own messages
# (`--message-format=json`, read by find-artifact.sh, which needs only grep and sed): nothing guesses where
# this cargo keeps a test executable, and no older file in a directory can be taken for it. It refuses to go on
# if it cannot name them. The test is built with the checkout's commit in it and told which commit to expect,
# and says so in its first line; a binary of another commit stops at once.
set -u
CHECKOUT="${1:?usage: sh a3-run-cross.sh CHECKOUT}"
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
[ -d "$CHECKOUT/.git" ] || { echo "FAIL: $CHECKOUT is not a checkout"; exit 1; }
OWNER=$(stat -c %U "$CHECKOUT" 2>/dev/null)
{ [ -n "$OWNER" ] && [ "$OWNER" != root ] && [ "$OWNER" != UNKNOWN ]; } || { echo "FAIL: the checkout must belong to the user who builds it, not root (owner: ${OWNER:-unknown})"; exit 1; }
# As the owner, in a login shell (so that cargo is on the PATH as it is for him).
as_owner() { su - "$OWNER" -c "cd '$CHECKOUT' && $1"; }
COMMIT=$(as_owner "git rev-parse --short=12 HEAD") || { echo "FAIL: cannot read the checkout's commit"; exit 1; }
if [ -n "$(as_owner 'git status --porcelain --untracked-files=no')" ]; then COMMIT="$COMMIT-dirty"; fi
echo "checkout $CHECKOUT at $COMMIT, built by $OWNER"
echo "building the test and pledge (this may take a while)..."
TEST_JSON=$(as_owner "PROBE_BUILT_FROM=$COMMIT cargo test -p p-robe --features test-verbs --test stage1_sudo --no-run --message-format=json") \
  || { echo "FAIL: the test did not build"; exit 1; }
TEST=$(printf '%s\n' "$TEST_JSON" | sh "$HERE/find-artifact.sh" test stage1_sudo) || { echo "FAIL: cannot tell where cargo put the test executable"; exit 1; }
PLEDGE_JSON=$(as_owner "cargo build -p p-ledge --bin pledge --message-format=json") || { echo "FAIL: pledge did not build"; exit 1; }
PLEDGE=$(printf '%s\n' "$PLEDGE_JSON" | sh "$HERE/find-artifact.sh" bin pledge) || { echo "FAIL: cannot tell where cargo put pledge"; exit 1; }
[ -x "$TEST" ] || { echo "FAIL: $TEST is not an executable"; exit 1; }
[ -x "$PLEDGE" ] || { echo "FAIL: $PLEDGE is not an executable"; exit 1; }
echo "test:   $TEST"
echo "pledge: $PLEDGE"
# Copy them where probe-svc can read them (the checkout is the owner's).
WORK=/var/tmp/probe-stage1-run
rm -rf "$WORK"
mkdir -p "$WORK"
cp "$TEST" "$WORK/stage1_sudo"
cp "$PLEDGE" "$WORK/pledge"
chown -R probe-svc:probe-svc "$WORK"
chmod -R u+rwX,go-rwx "$WORK"
su -s /bin/sh -c "cd /var/lib/probe-svc && env PROBE_STAGE1_SUDO=1 PROBE_BIN=/usr/local/bin/probe PROBE_PLEDGE_BIN=$WORK/pledge PROBE_EXPECT_BUILT_FROM=$COMMIT $WORK/stage1_sudo --ignored --nocapture" probe-svc
rc=$?
rm -rf "$WORK"
if [ "$rc" = 0 ]; then
  echo "PASSED (exit 0): see the 'PASSED' line above. Look at the verbs in syslog: journalctl -t probe | grep call="
else
  echo "FAILED (exit $rc): the first assertion that failed is printed above"
  exit "$rc"
fi
