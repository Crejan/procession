#!/bin/sh
# Run OUTSIDE the agent sandbox, on macOS or Linux, as your own user.
#   sh run-trial.sh        everything: baseline, A1, A2, B, then C
#   sh run-trial.sh c      only C (the rustic_core program), against the sshd this script starts
#   sh run-trial.sh build  only build C (release), visibly
# Needs: restic >= 0.17, OpenSSH sshd, cargo (network to crates.io); `rustic` (cargo install
# rustic-rs --locked) for A1, A2, B. Touches only $W, plus ONE line in ~/.ssh/known_hosts
# (added for A2 and C, removed again on exit, also on Ctrl-C). Never points at a real repo.
set -eu
MODE="${1:-all}"
W="${W:-${TMPDIR:-/tmp}/p-reserve-trial}"; PORT="${PORT:-22222}"
HERE="$(cd "$(dirname "$0")" && pwd)"
KH="$HOME/.ssh/known_hosts"; ADDED="$W/known_hosts.added"; SSHD=""; AGENT=""

cleanup() {
  trap '' INT TERM HUP
  [ -n "$AGENT" ] && kill "$AGENT" 2>/dev/null || true
  # remove exactly the line this script appended, nothing else, keep the file's mode
  if [ -f "$ADDED" ] && [ -f "$KH" ]; then
    grep -vxF -f "$ADDED" "$KH" > "$W/known_hosts.rest" || true
    cat "$W/known_hosts.rest" > "$KH"; rm -f "$ADDED" "$W/known_hosts.rest"
  fi
  # master ssh processes the openssh crate leaves behind (ControlPersist) for this host:port
  pkill -f "ssh-connection.*127\.0\.0\.1" 2>/dev/null || true
  [ -n "$SSHD" ] && kill "$SSHD" 2>/dev/null || true
  echo "== cleanup done. Check:"
  echo "   grep -c '\\[127.0.0.1\\]:$PORT' $KH          # expect 0"
  echo "   pgrep -fl 'p-reserve-trial|ssh-connection'     # expect nothing"
  echo "   lsof -nP -iTCP:$PORT -sTCP:LISTEN              # expect nothing"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP     # EXIT trap then runs cleanup

mkdir -p "$W/src" "$W/restore" && chmod 700 "$W"
[ -f "$W/hostkey" ] || ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
[ -f "$W/id" ]      || ssh-keygen -q -t ed25519 -N '' -f "$W/id"
cp "$W/id.pub" "$W/authorized_keys"; chmod 600 "$W/authorized_keys"

echo "== versions (read these off your machine)"
restic version; ssh -V 2>&1; command -v rustic >/dev/null && rustic --version || echo "rustic: not installed"
cargo --version; rustc --version
cargo install --list 2>/dev/null | grep -A0 -E '^rustic' || true

if [ "$MODE" = build ]; then
  cd "$HERE"; cargo build --release --locked; grep -A1 -E 'name = "rustic_(core|backend)"' Cargo.lock; exit 0
fi

SFTP=/usr/libexec/sftp-server; [ -x "$SFTP" ] || SFTP=/usr/lib/openssh/sftp-server
cat > "$W/sshd_config" <<CFG
Port $PORT
ListenAddress 127.0.0.1
HostKey $W/hostkey
PidFile $W/sshd.pid
AuthorizedKeysFile $W/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
Subsystem sftp $SFTP
CFG
/usr/sbin/sshd -D -e -f "$W/sshd_config" 2> "$W/sshd.log" &
SSHD=$!; sleep 1
kill -0 "$SSHD" 2>/dev/null || { echo "sshd did not start:"; cat "$W/sshd.log"; exit 1; }
printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d' ' -f1-2 "$W/hostkey.pub")" > "$W/known_hosts"
SC="ssh -F /dev/null -i $W/id -o IdentitiesOnly=yes -o UserKnownHostsFile=$W/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes -p $PORT $USER@127.0.0.1 -s sftp"
[ -f "$W/pw" ] || echo secret > "$W/pw"; REPO="sftp:$USER@127.0.0.1:$W/repo"
echo hello > "$W/src/a.txt"; mkdir -p "$W/src/d"; echo b > "$W/src/d/b.txt"
if [ ! -d "$W/repo" ]; then
  restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" init
  restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" backup "$W/src"
fi
echo "== restic itself (baseline)"; restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" snapshots

pin_known_hosts() {   # the line goes into the REAL known_hosts: ssh ignores $HOME and has no per-process option
  mkdir -p "$HOME/.ssh"; touch "$KH"
  if ! grep -qxF -f "$W/known_hosts" "$KH"; then cp "$W/known_hosts" "$ADDED"; cat "$W/known_hosts" >> "$KH"; fi
}

if [ "$MODE" = all ]; then
cat > "$W/rustic.toml" <<CFG
[repository]
repository = "opendal:sftp"
password-file = "$W/pw"
[repository.options]
endpoint = "ssh://$USER@127.0.0.1:$PORT"
root = "$W/repo"
key = "$W/id"
known_hosts_strategy = "strict"
CFG
echo "== A1: strict, key file, pinned known_hosts NOT passable: expected to fail on the host key"
rustic -P "$W/rustic" snapshots || echo "A1 failed (see message)"
echo "== A2: pinned entry in the real ~/.ssh/known_hosts"
pin_known_hosts
rustic -P "$W/rustic" snapshots || echo "A2 failed"
echo "== B: agent, key = public half only"
eval "$(ssh-agent -s)" >/dev/null; AGENT="$SSH_AGENT_PID"; ssh-add "$W/id" 2>/dev/null
cp "$W/id.pub" "$W/idonly.pub"
sed "s#^key = .*#key = \"$W/idonly.pub\"#" "$W/rustic.toml" > "$W/rustic-agent.toml"
echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
rustic -P "$W/rustic-agent" snapshots || echo "B failed"
kill "$AGENT"; AGENT=""; unset SSH_AUTH_SOCK SSH_AGENT_PID
fi

echo "== C: build (visible; a first release build of rustic_core takes minutes)"
cd "$HERE"; cargo build --release --locked
pin_known_hosts
echo "== C: run (progress lines print before and after each step; Ctrl-C cleans up)"
TRIAL_ENDPOINT="ssh://$USER@127.0.0.1:$PORT" TRIAL_ROOT="$W/repo" TRIAL_KEY="$W/id" \
TRIAL_KNOWN_HOSTS_STRATEGY=strict TRIAL_PASSWORD=secret TRIAL_DIR="$W/src" TRIAL_FILE="$W/src/d/b.txt" \
TRIAL_DEST="$W/restore" /usr/bin/time -l "$HERE/target/release/p-reserve-trial"
echo "== restored file content:"; find "$W/restore" -type f -exec cat {} \;
