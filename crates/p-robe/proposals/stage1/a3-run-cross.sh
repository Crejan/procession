#!/bin/sh
# Stage A, step 3: the cross run (real pledge, pact's composer and signer, this crate's service core)
# with the verb run through the real sudo rule. Run as root, after a2-check-rule.sh has passed.
#   sh a3-run-cross.sh /path/to/stage1_sudo-HASH /path/to/repo/target/debug
# The first argument is the test executable `cargo test -p p-robe --features test-verbs --test stage1_sudo --no-run`
# printed ("Executable tests/stage1_sudo.rs (target/debug/deps/stage1_sudo-HASH)"); the second is the target/debug
# directory that holds `pledge`. Both must be readable by probe-svc (see the runbook).
set -u
TEST="${1:?usage: sh a3-run-cross.sh TEST_EXECUTABLE TARGET_DEBUG_DIR}"
DEBUG="${2:?usage: sh a3-run-cross.sh TEST_EXECUTABLE TARGET_DEBUG_DIR}"
[ "$(id -u)" = 0 ] || { echo "FAIL: run as root"; exit 1; }
[ -x "$TEST" ] || { echo "FAIL: $TEST is not an executable"; exit 1; }
[ -x "$DEBUG/pledge" ] || { echo "FAIL: $DEBUG/pledge is not built"; exit 1; }
# The test finds `pledge` next to its own `deps` directory: copy the pair where probe-svc can read them.
WORK=/var/tmp/probe-stage1-run
rm -rf "$WORK"
mkdir -p "$WORK/debug/deps"
cp "$TEST" "$WORK/debug/deps/stage1_sudo"
cp "$DEBUG/pledge" "$WORK/debug/pledge"
chown -R probe-svc:probe-svc "$WORK"
chmod -R u+rwX,go-rwx "$WORK"
su -s /bin/sh -c "cd /var/lib/probe-svc && env PROBE_STAGE1_SUDO=1 PROBE_BIN=/usr/local/bin/probe $WORK/debug/deps/stage1_sudo --ignored --nocapture" probe-svc
rc=$?
rm -rf "$WORK"
if [ "$rc" = 0 ]; then
  echo "PASSED (exit 0): see the 'PASSED' line above. Look at the verbs in syslog: journalctl -t probe | grep call="
else
  echo "FAILED (exit $rc): the first assertion that failed is printed above"
  exit "$rc"
fi
