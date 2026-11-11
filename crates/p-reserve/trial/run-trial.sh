#!/bin/sh
# Run OUTSIDE the agent sandbox, on macOS or Linux, as your own user.
# Needs: restic >= 0.17, OpenSSH sshd, cargo (network to crates.io), optional `rustic`
# binary (cargo install rustic-rs --locked). Touches only $W. Never points at a real repo.
set -eu
W="${W:-${TMPDIR:-/tmp}/p-reserve-trial}"; PORT="${PORT:-22222}"
mkdir -p "$W/src" "$W/restore" && chmod 700 "$W"
[ -f "$W/hostkey" ] || ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
[ -f "$W/id" ]      || ssh-keygen -q -t ed25519 -N '' -f "$W/id"
cp "$W/id.pub" "$W/authorized_keys"; chmod 600 "$W/authorized_keys"
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
SSHD=$!; trap 'kill $SSHD' EXIT; sleep 1
# pinned known_hosts, as fundament records it
printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d' ' -f1-2 "$W/hostkey.pub")" > "$W/known_hosts"
# the sftp.command both predecessors use, here with key + pinned known_hosts + strict
SC="ssh -F /dev/null -i $W/id -o IdentitiesOnly=yes -o UserKnownHostsFile=$W/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes -p $PORT $USER@127.0.0.1 -s sftp"
echo secret > "$W/pw"; REPO="sftp:$USER@127.0.0.1:$W/repo"
echo hello > "$W/src/a.txt"; mkdir -p "$W/src/d"; echo b > "$W/src/d/b.txt"
restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" init
restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" backup "$W/src"
echo "== restic itself (baseline)"; restic -o "sftp.command=$SC" -r "$REPO" --password-file "$W/pw" snapshots
# --- A. rustic through OpenDAL: what CAN be passed (key, strict via default, known_hosts only via ~/.ssh)
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
echo "== A2: pinned entry in the real ~/.ssh/known_hosts (ssh ignores \$HOME, it uses the passwd home; there is no option to name another file)"
mkdir -p ~/.ssh; touch ~/.ssh/known_hosts
cat "$W/known_hosts" >> ~/.ssh/known_hosts      # removed again below, only this host:port
trap 'ssh-keygen -q -R "[127.0.0.1]:$PORT" >/dev/null 2>&1; kill $SSHD' EXIT
rustic -P "$W/rustic" snapshots || echo "A2 failed"
# --- B. agent socket: key file is the PUBLIC half (IdentitiesOnly + agent matches by public key)
eval "$(ssh-agent -s)" >/dev/null; ssh-add "$W/id" 2>/dev/null
cp "$W/id.pub" "$W/idonly.pub"
sed "s#^key = .*#key = \"$W/idonly.pub\"#" "$W/rustic.toml" > "$W/rustic-agent.toml"
echo "== B: SSH_AUTH_SOCK=$SSH_AUTH_SOCK, key=<pub only>"
rustic -P "$W/rustic-agent" snapshots || echo "B failed"
kill "$SSH_AGENT_PID"
# --- C. rustic_core program, memory and time
cd "$(dirname "$0")"
TRIAL_ENDPOINT="ssh://$USER@127.0.0.1:$PORT" TRIAL_ROOT="$W/repo" TRIAL_KEY="$W/id" \
TRIAL_KNOWN_HOSTS_STRATEGY=strict TRIAL_PASSWORD=secret TRIAL_DIR="$W/src" TRIAL_FILE="$W/src/d/b.txt" \
TRIAL_DEST="$W/restore" /usr/bin/time -l cargo run --release 2>&1 | tail -30
echo "== check restore"; find "$W/restore" -type f -exec cat {} \;
