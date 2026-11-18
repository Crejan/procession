# Which `ssh-keygen`, and how it is started (p-act, 2026-11-18)

Every signature in the system is verified by one program. This note answers the designer's four questions for every
place a program of ours starts it (tests aside), says what changed in p-act, and lists what p-robe and p-ledge must
change (not changed here).

## Where it is started

| Where | What it runs | Before | Now |
|---|---|---|---|
| `p-act` `sign::run` (all verifying, signing, `-L`; p-age and pledge's verification go through it) | `-Y sign`, `-Y verify`, `-L` | `Command::new("ssh-keygen")`: **PATH**, inherited environment (plus `SSH_ASKPASS`) | `keygen::Keygen::system()`: fixed path, ownership test, cleared environment, version, once |
| `p-robe` `setup.rs` `keygen_output` (`probe setup`, **runs as root**) | `-t ed25519` (key making), `-y` (public half), `-s` (the certificate) | **PATH**, inherited environment (plus `SSH_ASKPASS`) | unchanged: **to change** |
| `p-ledge` `issue.rs` `keygen` (pledge issuing an agent's key and certificate) | `-t ed25519` (the **agent's key pair**, in a private scratch directory) and `-s ... -U` through a private agent socket | **PATH**; `SSH_AUTH_SOCK` set to the private socket, or removed; inherited otherwise | unchanged: **to change** |
| `p-ledge` `certs.rs`, `p-age` | nothing in production (they call `p_act`) | | |

No other production code of the workspace starts it (I searched every crate's `src/` for `Command::new("ssh-keygen")`; the holder's own keys I did not trace and found no call). Test code in all crates runs it directly and may stay.

## The four questions

1. **Path.** Before: PATH, everywhere. Now `p_act::keygen::KEYGEN_PATH` = `/usr/bin/ssh-keygen`, one constant. The
   program and every directory above it (links resolved first) must be owned by root and not writable by group or
   others (a sticky directory such as `/tmp` passes for its mode, the owner of what is under it is still judged);
   otherwise `KeygenError::NotTrusted` names the path and why, and a missing file is `NotFound` ("install the OpenSSH
   client"). On a **Mac** `/usr/bin/ssh-keygen` is Apple's, `root:wheel` 0755 under System Integrity Protection, in
   `/usr/bin`, `/usr`, `/`, all `root:wheel` 0755: it passes. **A Homebrew OpenSSH earlier in PATH (`/opt/homebrew/bin`) is
   deliberately ignored**, since PATH is not looked at; a developer who wants another builds with `Keygen::at(path, owner)`.
   On Debian it is `/usr/bin/ssh-keygen` (merged-usr links are resolved before the check). NixOS and the like have no
   `/usr/bin/ssh-keygen` and are refused with that reason: a place for a second path is a decision, not made here.
2. **Environment.** Now cleared (`env_clear`) and given exactly `PATH=/usr/bin:/bin`, `LC_ALL=C`, `LANG=C`,
   `SSH_ASKPASS=false`, `SSH_ASKPASS_REQUIRE=force`. No `HOME`, no `SSH_AUTH_SOCK`, no locale, nothing of the parent's
   (a test starts a stand-in that prints its environment, in a parent that has `SSH_AUTH_SOCK`, `LC_MESSAGES` and a
   private variable set). `Keygen::command_with_agent(socket)` adds `SSH_AUTH_SOCK` and nothing else: what pledge's
   issuing needs.
3. **Is text parsed to decide?** Only the exit status decides, with these exceptions, each of which can only refuse:
   - `-L`: the line `Signing CA:` and the `SHA256:` fingerprint in it (`certificate_issuer`). The principals, validity,
     options and extensions are **not** read from `-L`, they are read from the certificate's own bytes (a parser of
     ours). A changed wording, a missing line, or another locale gives `NoIssuer` (a refusal); the fingerprint must also
     equal the issuer in the bytes, or `WrongIssuer`. Never an acceptance.
   - `-Y verify` and `-Y sign`: stderr and stdout are copied into the error text for a person; the verdict is the exit
     status. A wording change changes a message, not an outcome.
   - `ssh -V`: the version only (below); anything unreadable is a refusal.
   - `-y` in p-robe's setup: stdout *is* the public key, written to a file and then read by `certificate::ed25519_public`,
     which refuses what is not one Ed25519 key.
   With `LC_ALL=C` and OpenSSH having no message catalogues, wording does not vary by locale; it varies by version.
4. **Version.** Before: nowhere. Now `Keygen::system()` also runs `ssh -V` **in the same directory** (`/usr/bin/ssh`,
   which has to pass the same ownership test), parses `OpenSSH_<major>.<minor>`, and refuses below
   `keygen::MIN_VERSION` = 8.9 (the designer's floor), once, with `KeygenError::Version`; a program that starts with a
   refused `ssh-keygen` should say so at start, by calling `Keygen::system()` there. What p-act uses: `-Y sign`/`-Y verify`
   (OpenSSH 8.1), `cert-authority` and `namespaces=` in allowed-signers lines (8.1), certificates inside signatures,
   `-L`, `-O clear` (older). I tested only against OpenSSH 10.2p1 (LibreSSL), the Mac's; the 8.9 floor is a margin, not
   something I checked on a 8.1 to 8.8 install. `ssh-keygen` itself has no version option, which is why the sibling `ssh`
   is asked.

## The residue (as the designer asked it written)
With input that fits the pipe buffer the exit status alone decides; that needs an `ssh-keygen` that is wrong or replaced,
which can say yes whatever we do. What `run_command` adds for a program that is right but does not read its input: a
write that failed together with exit status 0 is `SignError::InputNotRead` (a refusal), a non-zero status is
`SignError::Tool` with its status and standard error, never an I/O error and never "accepted". The fixed path and the
ownership test narrow "replaced" to "somebody who is root"; they do not remove it.

## Changes behaviour for callers
- **Every `p_act::sign` call** (verify_*, sign_*, `certificate_issuer`, `Signer`): the program is now only
  `/usr/bin/ssh-keygen` (before: first in PATH). On a machine without it, or with a version below 8.9, or with a program
  or directory that others can write, every call fails with `SignError::Keygen` instead of working. The environment is
  cleared: a key that needs `HOME` or an agent no longer finds them (nothing in the workspace's tests does).
- New: `p_act::keygen` (`Keygen`, `Owner`, `KeygenError`, `KEYGEN_PATH`, `MIN_VERSION`, `problem`, `parse_version`).

## What p-robe and p-ledge must change (not done here)
- **p-robe `setup.rs` `keygen_output`**: `Keygen::system().map_err(...)?`, then `let mut c = keygen.command(); c.args(args).stdin(Stdio::null())`
  instead of `Command::new("ssh-keygen")` and its two `.env` calls. This is the one that runs as root: it matters most.
  The ownership test needs the key files' directories to be the caller's business, as today.
  Its `-y` and `-L` uses are unaffected. `probe setup` should call `Keygen::system()` first and refuse with its message.
- **p-ledge `issue.rs` `keygen`**: `let keygen = Keygen::system().map_err(...)?;` then
  `keygen.command_with_agent(socket)` when `env_agent` is `Some`, else `keygen.command()` (which has no `SSH_AUTH_SOCK`,
  so the `env_remove` goes); drop the two `.env` calls. pledge's start (`pledge serve`) should call `Keygen::system()`
  once and refuse with its message.
- **Tests** in both crates that run `Command::new("ssh-keygen")` to make keys may stay (they are not product code), or use
  `Keygen::system()` for the same program.
- p-age and p-reserve: nothing.
