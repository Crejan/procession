# p-reserve trial report: nothing could be run here; the SFTP questions are answered from sources

The sandbox blocked every run of the trial. rustic cannot be built or fetched, and no `sshd` can listen, so nothing was opened, listed or restored. What follows is read from source unless marked "run".

## Versions
- **Local toolchain (run):** macOS Darwin 25.5, OpenSSH_10.2p1 (LibreSSL 3.3.6), restic 0.19.0 (go1.26.4, darwin/arm64) at `/opt/homebrew/bin/restic`, cargo/rustc 1.97.0.
- **Not installed (run):** `rustic` and `docker`.
- **Read from the rustic_core git tags `rustic_core-v0.13.0` and `rustic_backend-v0.7.0`:** rustic_core 0.13.0 and rustic_backend 0.7.0, both edition 2024. Source clone: `rustic-rs/rustic_core`, main at d658ed9 (2026-11-09).
- **OpenDAL:** the 0.59.5 line, which `rustic_backend` pins. Clone: `apache/opendal`, 291c5c4 (2026-11-10), with the SFTP service in `core/services/sftp`. It depends on `openssh = "0.11.0"` and `openssh-sftp-client 0.15.3`.
- **`openssh` crate:** 0.11.6 (`openssh-rust/openssh`, 17afe72).
- **Sources were in `$TMPDIR/src/` (`/tmp/claude-501/src/`).** A fresh session will not have them; re-clone from the three repos above.

## Run, and what the sandbox blocked
| Attempt | Result |
|---|---|
| `cargo search rustic_core`, and curl of `index.crates.io`, `static.crates.io` and `docs.rs` | `CONNECT tunnel failed, response 403` (the sandbox proxy denies these hosts). |
| `~/.cargo` write (`touch ~/.cargo/probe`) | `Operation not permitted`. |
| Python `bind` to 127.0.0.1 | `PermissionError: [Errno 1] Operation not permitted`. |
| `sshd -D -e -p 22222 -h hostkey -o ListenAddress=127.0.0.1` | `Bind to port 22222 on 127.0.0.1 failed: Operation not permitted. Cannot bind any address.` |
| `ssh-keygen` (host key) | Works. |
| `github.com` and `raw.githubusercontent.com` | HTTP 200 (reachable). |

Because crates.io is blocked, the `rustic_core` program was never compiled. It is written against the 0.13.0 `examples/ls` and `examples/restore`, so expect small API fixes.

**What the owner can unblock:** allow `crates.io`, `index.crates.io` and `static.crates.io` for cargo, and make `CARGO_HOME` writable. Or skip all of that and run the script outside the sandbox. To keep running things inside it, set `sandbox.network.allowLocalBinding: true`.

**To run the trial outside the sandbox:**
```
sh crates/p-reserve/trial/run-trial.sh
```
It is committed on `agent/p-reserve` as e372d50, together with `trial/Cargo.toml` (not a workspace member), `trial/src/main.rs` and `trial/README.md`. The script:
- starts a user-level `sshd` on 127.0.0.1:22222 with its own host key and an authorized key;
- runs `restic init` and `restic backup` through `sftp.command` with a key file, a pinned `known_hosts` and strict checking (the baseline);
- runs `rustic` through `opendal:sftp` in three cases (A1, A2, B below), then the `rustic_core` program under `/usr/bin/time -l` for open time and memory.

Both the script and the program are unrun. It also needs `rustic` installed (`cargo install rustic-rs --locked`) and `restic` >= 0.17. The script appends one line to your real `~/.ssh/known_hosts` for `[127.0.0.1]:22222` and removes it again on exit; it touches no real repository.

## What can be passed to SFTP (read)
**Path:** `rustic_backend/src/opendal.rs:182` calls `Operator::via_iter(scheme, options)`. The scheme is the part of the repository string before `:`, so the repository is `opendal:sftp` and every option goes in the options map.

OpenDAL's sftp `config.rs` accepts exactly five keys: `endpoint`, `root`, `user`, `key`, `known_hosts_strategy`. `core.rs:100-120` turns them into a `SessionBuilder` call. The `openssh` master process (`builder.rs:395-485`) is spawned as `ssh -E log -S sock -M -f -N -o ControlPersist=yes -o BatchMode=yes -o StrictHostKeyChecking=<...>`.

| Requirement | Verdict | Mechanism |
|---|---|---|
| Specific key file | **Yes** | `key` becomes `-o IdentitiesOnly=yes -i <key>` (`builder.rs:446-447`). |
| Strict host key checking | **Yes, and it is the default** | `known_hosts_strategy` is `strict` (default), `add` (`accept-new`) or `accept` (`no`), at `backend.rs:142-158`. |
| Pinned `known_hosts` file | **No via rustic or OpenDAL** | `SessionBuilder::user_known_hosts_file` exists (`builder.rs:270`), but OpenDAL never calls it. |
| `SSH_AUTH_SOCK` | **Inherited only** | `SessionBuilder::ssh_auth_sock` exists (`builder.rs:282`), but OpenDAL never calls it. The ssh child inherits the process environment. |
| Extra `-o` options, `-F`, `-J` | **No** | `config_file` and `jump_hosts` exist in `openssh` but are not exposed. |
| Port | **Yes** | In the endpoint: `ssh://user@host:port`. |
| ssh binary | Always `ssh` from `PATH` | `builder.rs:408`. |
| Subsystem | Handled by `openssh-sftp-client` | It runs the sftp subsystem over the mux, not `ssh -s sftp` on the command line. |

- **Pinned `known_hosts` is the blocker.** OpenSSH uses the passwd home, not `$HOME`. I ran `HOME=/nonexistent/h ssh -G h`, which still shows `userknownhostsfile /Users/jancre/.ssh/known_hosts`. So the only routes are the real `~/.ssh/known_hosts`, `/etc/ssh/ssh_known_hosts`, or a `Host` alias in `~/.ssh/config`. The last one works because OpenDAL passes no `-F`, so the default config is read.
- **SSH agent socket, partly settled.** The process-wide `SSH_AUTH_SOCK` reaches `ssh` unchanged. Because `key` forces `IdentitiesOnly=yes`, the agent is used only for identities matching that key. I expect `key=<public-key file>` to select the one agent key, per `ssh_config(5)`, but this is not run. Case B in the script tests it.
- **Atticus differs from this.** It runs `ssh -F /dev/null -o BatchMode=yes -o PreferredAuthentications=publickey -o ConnectTimeout=10 'user@host' -s sftp` (`Resources/atticus-lib.sh:85`). `-F /dev/null` ignores the ssh config, so the `Host`-alias route does not reproduce Atticus exactly.
- **fundament's own ssh options** (`UserKnownHostsFile`, `StrictHostKeyChecking`, `IdentitiesOnly`) did not turn up in my greps of the fundament host kit. I could not confirm its exact command line; `specs/storage/backup.md` and `doc/storage.md` describe the pinned known_hosts and the key.

## Minimum Rust version
- **Both `rustic_core` 0.13.0 and `rustic_backend` 0.7.0 declare `rust-version = "1.91.0"`** (tags and workspace `Cargo.toml`). The workspace states 1.85, and the SPEC's "1.88 at 0.6.2" is out of date.
- The workspace MSRV is therefore a decision for the owner: raise it to 1.91, or give `p-reserve-core` and `p-reserve` their own `rust-version`.
- The trial crate (`crates/p-reserve/trial/`) inherits edition 2024 and nothing else from the workspace.

## Memory and time to open a repository
Not measured: the program could not be built and no server could run. Case C in the script prints open time and `time -l` memory.

## `device-id-for-hardlinks` equivalent
- **rustic has it, and it is the default.** `set_devid: Option<DevIdOption>` (`core/src/backend/ignore/mapper.rs:56` and `node/modification.rs:36-50,121`) takes `yes`, `hardlink` or `no`. The default is `hardlink`, which stores the device id only when `nlink > 1` and the node is not a directory. That matches restic's `device-id-for-hardlinks`.
- **Parent matching ignores `device_id` altogether.** It compares type, size, mtime, ctime and inode (`archiver/parent.rs:168-190`). A freshly mounted snapshot's new device number therefore does not force a rewrite of every tree, provided inode and ctime stay stable.
- **Unverified here:** this was read, not run.
- **Related flags** are `ignore_ctime` and `ignore_inode` in `commands/backup.rs:73,78`.

## Assessment of the three paths
**Recommendation: keep rustic as the engine, but treat the connection as a spawn-`ssh` backend of our own.** Treat plain rustic as conditionally viable, and expect the owner to need that own backend.

- **Rustic as it is** works for the key file, strict checking and the agent socket when `known_hosts` can live in the standard place. It fails when `known_hosts` must be pinned per repository or the ssh options must match Atticus's `-F /dev/null`.
  - **Certainty:** about 75% that the code paths work as described, but that is from reading only. The `key=<pub>` agent selection and OpenDAL's behaviour against a real `sshd` are untested.
- **An own backend** on `rustic_core`'s backend trait that spawns `ssh -s sftp` with the exact predecessor command line is the stronger fit. It reproduces `-F /dev/null`, `UserKnownHostsFile` and `IdentitiesOnly` exactly, and it keeps the open index that is the reason for the daemon.
  - **Cost:** we write the SFTP client code (OpenDAL's `openssh-sftp-client` over `ssh -s sftp`), but one transport serves both predecessors.
- **The restic command line behind `Engine`** is the safe fallback. It drops the open-index benefit, which is the project's reason to exist, so I would use it only if rustic itself fails to open the repositories.
- **What would change this:** a failing run of case C on a real repository (a format or compatibility problem in rustic) favours restic. A pinned-`known_hosts` setup that only needs the standard path favours plain rustic.

## Reconciled verb list (proposal only)
`main.rs` has `serve, run, status, health, snapshots, ls, restore, prune, check, verify`. SPEC "What the predecessors require" has `run, prune, check, verify, snapshots, restore, mount, unmount, unlock, reprovision`, and its order of work adds `ls`, `dump`, `forget` and `health`.

| Verb | Proposal |
|---|---|
| `serve`, `run`, `status`, `health` | Keep (in `main.rs`; SPEC defines them in its order of work). |
| `snapshots`, `ls`, `restore`, `check`, `verify` | Keep (in both). |
| `prune` | Keep, and let it include `forget` per retention. The SPEC lists both, so decide whether `forget` is a separate verb. |
| `dump` | Add as an engine function and a verb (`preserve dump <snapshot> <path>` to stdout). SPEC step 3 names it. |
| `reprovision` | Add as a later verb. SPEC lists it; fundament's `reprovision` creates a repository only when it is proven absent. |
| `mount`, `unmount` | **Drop.** The SPEC non-goals say no FUSE mount in v1. |
| `unlock` | **Drop for now.** rustic takes no restic locks, so there is nothing to unlock. Revisit only if a restic lock must be cleared. |
| `catalog` | Not a verb. It is handled outside `VERBS` in `main()`; either add it to the table or document it in the SPEC. |

Open questions for the owner and designer: whether `forget` is its own verb, whether `unlock` is wanted for repositories restic locked, and whether `reprovision` belongs in v1.

## Requests to the orchestrator
- The workspace `rust-version` decision above.
- Keep `rustic_core` and `rustic_backend` out of the default workspace build once they are used. The brief says to do this the way `p-lumber` is kept out; I made no workspace change.

Not verified: any actual SFTP connection, the agent selection by public key, the memory and time to open, and whether the `rustic_core` program compiles.

---

# Owner's run, 2026-11-18 (outside the sandbox, on his Mac)

Recorded as reported to me; I did not see the machine. This supersedes "not run" above for
the items below. The script at that time was e372d50's; it has since been changed (see
"Script changes").

| Step | Result |
|---|---|
| Baseline: restic over SFTP, `sftp.command` with key, pinned known_hosts, strict | **Worked.** Snapshot dbc721c9, 2 files. |
| A1: rustic through OpenDAL, strict, pinned known_hosts not passable | **Failed as predicted.** `failed to connect to the remote host: No ED25519 host key is known for [127.0.0.1]:22222 and you have requested strict checking. Host key verification failed.` Surfaced by rustic_core as an error "related to the backend ... Checking for the presence of `config` in the backend failed". |
| A2: pinned entry appended to the real `~/.ssh/known_hosts` | **Worked.** `repository opendal:sftp:: password is correct`, 1 snapshot (dbc721c9, 2 files, 8 B). |
| B: ssh-agent, `key` pointing at a public half only | **Worked**, same listing. That the signature came from the agent is the designer's reading (only the trial's key was authorised and the file had no private half); the output does not state it. |
| C: the rustic_core program under `/usr/bin/time -l cargo run --release 2>&1 \| tail -30` | **No output for about 15 minutes, interrupted.** With `tail`, a long first release build and a hang look the same. The ssh-agent had been killed just before C, as the script does. **Unknown which.** |

What this settles: key file and strict checking pass through OpenDAL; the agent route works
with `key` = public half; a pinned known_hosts cannot be passed, only placed in the real
`~/.ssh/known_hosts` (or `/etc/ssh/ssh_known_hosts`, or a `Host` stanza in `~/.ssh/config`).
Unsettled: open time and memory (C), whether the program compiles at all, whether C hangs.
A plausible but unproven reading of C: a first release build of rustic_core with OpenDAL's
dependency closure is several minutes of compile; a hang in `open` would need ssh waiting
(for example on a stale `SSH_AUTH_SOCK`; the new script unsets it before C).

## Which versions he ran
Not recorded. To know them, read off his machine:
- `rustic --version`, and `cargo install --list | grep rustic` (the `rustic-rs` binary, resolved
  on the day by `cargo install rustic-rs`);
- for the trial program: `grep -A1 -E 'name = "rustic_(core|backend)"' crates/p-reserve/trial/Cargo.lock`
  (the Cargo.toml pins `=0.13.0` and `=0.7.0`, so those, unless he edited it; the registry
  holds 0.14.0 and 0.8.0 too);
- `restic version`, `ssh -V`, `rustc --version`.
The new script prints all of these at its start.

## Script changes (after this run)
- C builds first as its own visible step (`cargo build --release`, no `tail`); `sh run-trial.sh build`
  builds only.
- C runs from the built binary, with progress lines before opening, listing and restoring.
- `sh run-trial.sh c` runs only C, against the sshd the script starts (and the repository it makes).
- `INT`, `TERM`, `HUP` and normal exit all run one cleanup: kills the agent and sshd, removes
  exactly the known_hosts line the script appended (only if it added it), kills leftover
  `ssh-connection` master processes for 127.0.0.1. It prints three checks:
  `grep -c '\[127.0.0.1\]:22222' ~/.ssh/known_hosts` (expect 0), `pgrep -fl 'p-reserve-trial|ssh-connection'`
  (expect nothing), `lsof -nP -iTCP:22222 -sTCP:LISTEN` (expect nothing).
- Not run by me: the script is still untested in the sandbox (it cannot bind a port). `/usr/bin/time -l` is the macOS form.
