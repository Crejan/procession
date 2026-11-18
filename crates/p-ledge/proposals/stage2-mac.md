# Proposal: pledge on a Mac (order of work, step 4; stage 2)

Status: a proposal by the p-ledge agent, for the designer. Nothing is built
on it, no source file was changed, and nothing was run: no key was made, no
Touch ID was asked for. Terms are those of `doc/approvals.md`, section 1.

**The reference.** I was told to compare with Atticus on its branch
`agent/key-roles`. That branch does not exist in
`/Users/jancre/dev/ws/atticus-develop`: `git branch -a` lists `develop`,
`main` and five remote branches, none of that name, and `git log --all`
has no commit that names it. Everything below that says "Atticus" is the
checked-out `develop` tree at `a1ada83`. What a branch about keys with
separate purposes would have added is therefore not in this comparison;
`develop` holds only the seam for it (section 5, row 9).

**How to read the claims.** Each technical claim carries one of three
marks:

- **[A]** read in Atticus's code, with the file named;
- **[D]** Apple's documentation as I remember it, not looked up now and not
  checked against the headers;
- **[U]** unverified: I believe it, and nothing I read shows it.

A claim about p-ledge's own code has no mark and names the file.

## 1. Keys in the Secure Enclave

### 1.1 What the Secure Enclave gives

- It makes and holds P-256 keys and nothing else usable here. No Ed25519.
  **[D]** Atticus's key is `SecureEnclave.P256.Signing.PrivateKey`
  (CryptoKit) **[A]** `Sources/Engine/SEPKey.swift`.
- A key's protection is fixed when the key is made, by a
  `SecAccessControl` object: an accessibility class and flags. **[A]**
  `SEPKey.generate` passes
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `.privateKeyUsage`,
  no other flag. The flags that demand the person are `.userPresence`
  (Touch ID, or the account password when Touch ID is not there or fails),
  `.biometryAny` (Touch ID only; survives a change of the enrolled fingers)
  and `.biometryCurrentSet` (Touch ID only; the key is dead once the
  enrolled fingers change). **[D]**
- What the program keeps is `dataRepresentation`: a blob the Secure Enclave
  wrapped. Atticus stores it in a file, mode 0600, and loads it again with
  `PrivateKey(dataRepresentation:)`. **[A]** The blob is useless on another
  Mac. **[D]** Whether another program of the same user on the same Mac can
  load the copied blob and sign with it is **[U]**; I believe it can,
  because the blob is not in a keychain and carries no access group. This
  matters (section 1.5, check 3, and question 2).
- A key with a presence flag takes an `LAContext` when it is loaded
  (`PrivateKey(dataRepresentation:authenticationContext:)`). The system
  shows its Touch ID prompt when the key signs, with the text in the
  context's `localizedReason`. **[D]** Atticus does not use this: its key
  has no presence flag by design, and a test greps `SEPKey.swift` to keep
  it so. **[A]** `SEPKey.swift`, lines 11 to 15 and 62 to 78;
  `tests/AtticImportTest.swift` around line 4804.
- An `LAContext` that passed once can be used again for further signatures
  within its reuse time (`touchIDAuthenticationAllowableReuseDuration`,
  zero by default). **[D]** "One presence check per signature" therefore
  needs a fresh context per signature, never kept. Whether one fresh
  context still lets two signatures through is **[U]** (check 5).

So the Secure Enclave can enforce *that the person was there for this
signature*. It shows nothing itself. *What* the person saw is said by the
process that set the prompt's text: software, not hardware (sections 2 and
4).

### 1.2 Each key

| Key (`doc/approvals.md` section 5; `SPEC.md` section 2) | In the Secure Enclave | Presence in the key | Accessible | Type |
|---|---|---|---|---|
| confirmed approval | yes | yes, each signature | when unlocked | P-256 |
| automatic approval | yes | **none** | question 4 | P-256 |
| delegation | yes | yes, each signature | when unlocked | P-256 |
| connection | yes | **none** | after first unlock | P-256 |
| shared (logins, `git`/`file` signatures) | yes | yes, each signature | when unlocked | P-256 |
| bound (one program's login) | yes | **none** | after first unlock | P-256 |

Which presence flag ("Touch ID only" or "Touch ID or password") is question
1; it differs per key.

All six can be Secure Enclave keys as far as the formats go:

- `doc/approval-formats.md`, section 3.1: "Every other key in this document
  is Ed25519 or ECDSA P-256", and the delegation key "is P-256 or Ed25519".
  A person's keys are P-256 "because the Secure Enclave makes nothing
  else". No purpose of a person's key demands Ed25519.
- The one key that must be Ed25519 is the agent's own (the certified key of
  the delegation). It is not the person's, it is made by `ssh-keygen -t
  ed25519` in a temporary directory (`src/issue.rs`), and it never touches
  the Secure Enclave. A P-256 key certifying an Ed25519 key is ordinary for
  OpenSSH; `src/issue.rs` has a test that issues with a P-256 delegation
  key from a file (`for key_type in [KeyType::Ed25519, KeyType::EcdsaP256]`).
  I did not run it.
- The connection key signs in `connection-v1@procession`
  (`doc/approval-connections.md`); a plain key on a plain allowed-signers
  line, no certificate.
- Login keys: a server must accept `ecdsa-sha2-nistp256`. Atticus logs in
  with exactly such a key. **[A]**

### 1.3 How the public key and a signature are obtained

- **Public key.** CryptoKit gives the point as 65 bytes (`0x04`, X, Y:
  `publicKey.x963Representation`); the SSH blob is `string
  "ecdsa-sha2-nistp256"`, `string "nistp256"`, `string point`. **[A]**
  `SEPKey.publicKeyBlob`. This is byte for byte what `blob_of` in
  `src/holder.rs` builds for a P-256 key in a file, so `pledge keys`
  (`KeyInfo::public_line`, `src/shared.rs`) needs no change.
- **Signature.** `key.signature(for: data)` hashes `data` with SHA-256 and
  returns r and s, 32 bytes each; the SSH signature blob is `string
  "ecdsa-sha2-nistp256"`, `string (mpint r, mpint s)`. **[A]**
  `SEPKey.sign`. Again the same bytes as `KeyStore::sign` in
  `src/holder.rs` for a P-256 file key.
- **SSHSIG.** The key holder never learns that a signature is an SSHSIG.
  The reader builds the bytes to sign (`sshsig::signed_data`:
  `SSHSIG`, namespace, empty, `sha512`, SHA-512 of the message), the holder
  signs those bytes, the reader wraps public blob and signature
  (`sshsig::armour`). With a P-256 key the holder's ECDSA hashes those
  bytes once more with SHA-256, which is what OpenSSH does for this key
  type. Nothing in `src/sshsig.rs` or `holder_sign` (`src/approvals.rs`)
  depends on where the key lives.
- **A certified key** (stage 3: the approval keys under the site CA). The
  SSHSIG then carries the certificate in the place of the public blob, and
  the key signs the same bytes. Only the blob handed to `sshsig::armour`
  changes; the Secure Enclave is not involved in that. Atticus serves a
  certificate for its Secure Enclave key in the same way, for logins.
  **[A]** `SEPKeyIdentityProvider.identities`.
- **Signatures differ each time.** ECDSA from the Secure Enclave is
  randomised. **[D]** The rule "the same request again gets the same
  answer again" is already met from the store on disk (`src/answers.rs`),
  not by signing again, so this costs nothing.

### 1.4 What `ssh-keygen` needs

- **`ssh-keygen -Y verify`** needs nothing special: it sees a public key or
  a certificate and a signature. It cannot tell a Secure Enclave key from a
  file. What must hold is that pledge's bytes are well formed for P-256
  (mpint encoding of r and s with a leading zero where the top bit is set).
  With file keys that code is `put_mpint` in `src/agent/wire.rs`, used by
  `KeyStore::sign`. Whether a P-256 approval made by pledge has ever been
  verified with `ssh-keygen -Y verify` I could not establish from what I
  read (the stage-1 run may have used Ed25519; `keys.create` defaults to
  it, `src/control.rs`). Check 7 covers it either way.
- **`ssh-keygen -s` with the CA key in hardware.** `ssh-keygen` cannot read
  a Secure Enclave key, so the private key must come through an SSH agent:
  `ssh-keygen -s <public key file> -U`. That is already how pledge issues
  (`src/issue.rs`, `serve_issuing_agent`: a private SSH agent socket with
  only the delegation key, which answers one signing request if the data
  is the certificate asked for). For the Mac nothing changes in that path
  except that `holder.sign` now waits for a touch. Two things are **[U]**:
  that `ssh-keygen` asks the SSH agent for exactly one signature per
  certificate (so: one touch), and how long it waits for the answer
  (check 9).
- **The site CA's key** is the issuer's, not a person's, and is not held by
  pledge. Whether the issuer keeps it in hardware is outside this proposal.
- Atticus never signs a certificate with its key. Its certificate code
  (`Sources/SSHCertificate.swift`, `Sources/Engine/SSHCertificateService.swift`,
  `Sources/CLI/SSHCertCLI.swift`) receives one for its key from elsewhere.
  **[A]** A Secure Enclave key as an issuing key is new here.

### 1.5 "Not checked: keys in a Secure Enclave", as checks to run by hand

Each is run by a person on a Mac with Touch ID, with a throwaway program of
some tens of lines (Swift, CryptoKit) and OpenSSH's tools. None was run.
The first five decide the design; do them before anything is built.

| # | Do | Observe |
|---|---|---|
| 1 | Make two keys in one program: one with `.privateKeyUsage` only, one with `.privateKeyUsage` and a presence flag. Sign 32 bytes with each. | The first signs with no prompt. The second shows a Touch ID prompt and signs only after the touch. (`SPEC.md` section 11: "side by side".) |
| 2 | With the presence key: cancel the prompt; then let it time out. | Each returns a distinct error, and no signature. Write down the two error codes: the holder must tell "declined" from "nobody answered". |
| 3 | Copy both blobs. From a second program (another binary, same user, not signed alike), load each and sign. | Whether the load succeeds. If the key without presence signs: any program of the person can make automatic approvals from the blob file. If the presence key shows a prompt: note which program's name the prompt carries. This answers question 2. |
| 4 | With the presence key and one `LAContext`: sign twice in a row. Then with a fresh context each. | With fresh contexts: two prompts. With one context: one prompt or two. If one, the holder must never keep a context. |
| 5 | Set `localizedReason` to a text of 60, 200 and 600 characters, with a host name and an action in it. | How much of it the prompt shows, and whether the rest is cut or the prompt grows. This bounds what the prompt can say (section 2.2). |
| 6 | Print the public key of the presence key as an OpenSSH line; `ssh-keygen -l -f` on it. | A fingerprint, type ECDSA 256. |
| 7 | Build an SSHSIG over a file with the presence key (namespace `approval-v1@procession`) as section 1.3 says; verify with `ssh-keygen -Y verify -f allowed -I jan:confirmed -n approval-v1@procession -s sig < file`, the allowed-signers line listing the key directly (stage 2 has no site CA). | `Good "approval-v1@procession" signature for jan:confirmed`. Then change one byte of the file: refused. Repeat 20 times, so that an r or s with the top bit set occurs. |
| 8 | Certify the same key with a file CA (`ssh-keygen -s ca -I t -n jan:confirmed key.pub`), put the certificate in the SSHSIG's key field, verify against a `cert-authority` line. | Accepted as `jan:confirmed`; refused as `jan:automatic`. (Stage 3; cheap to do now.) |
| 9 | Offer the presence key on a private SSH agent socket; run `ssh-keygen -s key.pub -U -I t -n jan -V +8h -O clear -O extension:groups@procession=a,b agent.pub` with an Ed25519 `agent.pub`. Touch after 5 seconds; then again and touch after 90 seconds. | One prompt per certificate, not two. `ssh-keygen -L` shows the certificate with the extension. Whether `ssh-keygen` still waits after 90 seconds. Then sign a call with the agent's key and verify it under `<person> cert-authority,namespaces="call-v1@procession" <the P-256 key>`. |
| 10 | Lock the screen. From an SSH session into the Mac, ask the running program to sign with (a) the key without presence made "after first unlock", (b) one made "when unlocked", (c) the presence key. | (a) signs. (b) signs or fails: this says whether macOS ties "when unlocked" to the screen lock at all. (c) fails without a prompt appearing behind the lock screen, and returns at once or hangs: write down which. |
| 11 | Run the program from an SSH session (no window server) and sign with the presence key. | An error and no prompt anywhere; write down the error code. |
| 12 | On a Mac with the lid closed and an external display (no Touch ID keyboard): sign with a `.biometryAny` key and with a `.userPresence` key. | The first fails at once; the second asks for the password. Then the same over screen sharing: whether the password can be typed from the remote side. |
| 13 | Log in to an sshd with the presence key through the SSH agent socket (`ssh -o IdentityAgent=...`), then make a `git` signature (`ssh-keygen -Y sign -n git` through the agent). | One prompt each; the login succeeds; `git verify-commit` or `ssh-keygen -Y verify` accepts. |
| 14 | Delete the blob file of a key; then try to load a copy made before. | Whether the copy still signs. If it does, "retiring deletes it from the hardware" (`SPEC.md` section 2) is not true for a blob in a file, and retiring means: delete every copy and tell the administrator. |
| 15 | Add a finger in System Settings; sign with a `.biometryAny` key and a `.biometryCurrentSet` key made before. | The first still signs, the second is dead. |
| 16 | Restart the Mac, log in, sign with each key before any Touch ID use. | Which keys sign, and whether the presence key asks for the password first. |

## 2. The presence check

### 2.1 What a confirmed approval needs

From `doc/approvals.md`: "presence check: the key hardware requiring the
person (Touch ID) for one signature"; R9, "pledge signs only what it
shows"; flow B, "if the person agrees, a presence check, and it signs with
the confirmed approval key". So:

1. one presence check per signature, never one per connection, per agent
   or per minute;
2. enforced by the key, not by pledge's own code: a pledge that is taken
   over still cannot make a confirmed approval without the person;
3. the person sees, at the moment of the touch, what the signature is for.

Atticus gives 1 and 3 and not 2. Its confirmation is
`LAContext.evaluatePolicy` in the app (`AgentPolicy.authorize`, policy
`.deviceOwnerAuthentication`, a fresh context each time), and after a "yes"
the app signs with a key that would also sign without it. **[A]**
`Sources/Engine/AgentPolicy.swift`, `Sources/Engine/SSHAgentServer.swift`
(`ClientConnection.drainMessages`). That is a deliberate choice there, so
that a backup needs no touch. Here the purposes have separate keys, so the
keys with a presence check can carry it in the hardware.

### 2.2 How Touch ID gives it

- The confirmed approval key is made with a presence flag (section 1.1).
- For each signature the key holder makes a fresh `LAContext`, sets its
  `localizedReason`, loads the key with it, signs, and drops the context.
  The system's prompt appears because the key is used; a touch releases
  that one signature. **[D]**
- The prompt's text is short and plain (check 5 says how short). It cannot
  show a request whole: parameters alone may be 2000 characters. So the
  request is shown in a dialog of pledge's own (section 4) and the prompt
  names it in few words. *Proposal:* the service's name and host and the
  action, which the formats bound and restrict to plain characters
  (`doc/approval-formats.md`, section 3): "approve: probe on a.example, rt
  procs". The person compares that line with the dialog behind it.
- The dialog closes at the deadline. An open prompt is ended by
  invalidating its context (`LAContext.invalidate()`). **[D]**
- A cancel at the prompt is a decline (`SPEC.md` section 4: "a 'no' at the
  presence check is a decline"). A prompt that ends because the deadline
  passed is `expired`. Anything else (no sensor, locked, no session) is
  `refused`, reason `unavailable`. Check 2 gives the error codes.

What this does **not** give: the Secure Enclave does not know what was on
the screen. A reader that is taken over can hand the key holder the bytes
of request Y and the words of request X. `SPEC.md` section 7 already says
so ("the key holder signs what it is given"). The hardware form narrows
this to: one touch, one signature. It does not remove it.

### 2.3 Without Touch ID, locked, over SSH, without a GUI

| Situation | A key with "Touch ID only" | A key with "Touch ID or password" | A key without presence |
|---|---|---|---|
| Mac without a sensor; lid closed, no Touch ID keyboard | cannot sign | asks for the account password **[D]** | signs |
| Touch ID fails several times | locked out until the password was typed at the system's own prompt **[D]** | falls back to the password | signs |
| Screen locked | no prompt can be answered; the signature fails **[U]** (check 10) | the same **[U]** | signs if made "after first unlock"; if made "when unlocked", **[U]** (check 10) |
| The person is logged in over SSH only; pledge runs in their GUI session | the prompt appears on the Mac's screen; the SSH session cannot answer it | the same; over screen sharing a password can be typed (check 12) | signs |
| pledge itself started without a GUI session | fails, no prompt **[U]** (check 11) | the same **[U]** | signs **[U]** |

What follows for pledge, whatever question 1 decides:

- A request in mode `ask` that arrives while no presence check is possible
  is not refused at once: the person may unlock the screen before the
  deadline. It waits like any request behind an open dialog and ends as
  `expired`. (*Proposal*; the other reading of R11 is to refuse at once
  with `unavailable`.)
- `pledge serve` started where no dialog can be shown says so when it
  starts, as the development form says that it protects nothing, and
  refuses every `ask` with `unavailable` (`Outcome::Unavailable` in
  `src/dialog.rs` already has this meaning).
- A `pledge agents start` typed in an SSH session reaches the running
  pledge over `control.sock`; the touch happens at the Mac. That is right:
  whoever only has the person's SSH login cannot start an agent.

**Password in place of Touch ID, per key** (question 1):

- *confirmed approval, delegation:* a password is weaker in exactly the two
  threats the presence check is there for. A stolen machine: the thief may
  have seen the password typed; a finger he has not. Malware in the
  session or someone at a shared screen: a password can be typed from
  afar, a touch cannot. Against that: without the fallback a person at a
  closed laptop with an ordinary keyboard can approve nothing.
- *shared key:* a login is the person's own act at their own keyboard.
  Atticus accepts the password here today. **[A]**

### 2.4 What the automatic key must not require

No presence flag, no `LAContext`, no window, no session with a window
server. It must sign with nobody there: that is U2. The same holds for the
connection key (pledge holds its connection "whenever the machine is
awake", so also with the screen locked: "after first unlock") and for a
bound key (a backup at night; Atticus's reason for the same choice,
**[A]** `SEPKey.swift`, lines 72 to 78).

What it may require is an unlocked screen. `doc/approvals.md`, section 4,
on a stolen machine: "if the thief has the unlocked session: automatic
approvals for agents already running". Read strictly, a locked Mac makes no
automatic approval. That is question 4.

A consequence to state plainly: a key without presence in a blob file is as
strong as the file. If check 3 shows that any program of the person can
load the blob, then on a Mac the automatic approval key is protected
against being carried off the machine and against nothing else. The threat
table already lists "Malware in the person's session: automatic approvals"
as what remains.

## 3. Who a program is, from its code signature

### 3.1 Today

`src/peer.rs`: `peer()` reads the user (`getpeereid`) and the process
(`LOCAL_PEERPID`); `program_path(pid)` asks `proc_pidpath`. `src/serve.rs`:
`accept_agent` and `accept_control` drop a peer that is another user
(`check_peer`, `is_own`); `accept_agent` then takes
`peer.pid.and_then(peer::program_path)` and that string is the program for
`src/agent_conn.rs` and `src/policy.rs`. The module says of itself that
this "protects nothing": a path says where a file is, not what it is; the
pid is looked up after the connection was made, so a process that execs, or
a pid that is used again, changes the answer.

Atticus does the same lookups (`AgentPolicy.peer(for:)`: `LOCAL_PEERPID`,
`getpeereid`, `proc_pidpath`, the parent through `sysctl`) and then checks
the code signature **by pid**: `SecCodeCopyGuestWithAttributes` with
`kSecGuestAttributePid`, a requirement text, `SecCodeCheckValidity`.
**[A]** `Sources/Engine/CodeValidator.swift`. It checks on every
connection and keeps no verdict. **[A]** `AgentPolicy.swift`, "hot-swap
invariant". It also has two shortcuts by path: a list of path prefixes that
decides which programs are checked at all, and "the peer's path is my own
executable's path: allow". **[A]** `AgentPolicy.evaluate`.

### 3.2 What the code signature adds

For a process, the system can say **[D]**:

- whether its code is validly signed *now* (the kernel's view of the
  running process, not the file on disk);
- the **team identifier** (who signed: a Developer ID team), empty for
  Apple's own programs and for ad-hoc signatures;
- the **signing identifier** (which program: `com.apple.ssh`,
  `de.c-it-work.atticus.restic`);
- the **code directory hash** (this exact build);
- its **designated requirement**: the rule by which a later build counts as
  "the same program". For Developer ID code it is in effect "this team and
  this identifier" under Apple's anchor.

Atticus writes its requirement texts by hand: `anchor apple and identifier
"com.apple.ssh"` for Apple's ssh, `anchor apple generic and certificate
leaf[subject.OU] = "<team>" and identifier "<identifier>"` for its own.
**[A]** `CodeValidator.swift`. The comment there says `/usr/bin/ssh` has
the identifier `com.apple.ssh` and no team, seen on macOS 26.0 on
2026-05-16. **[A]**

Atticus only ever asks "is this peer one of three programs I name?". pledge
must also *read* an unknown program's identity, to show it and to remember
it (`SPEC.md` section 3: admit, block). The call for that is
`SecCodeCopySigningInformation`, with the team and the identifier in the
result. **[D]** Atticus does not use it.

### 3.3 Without a race: the audit token

A pid names a process only while it lives, and says nothing about an
`exec`. An **audit token** names one process image: it carries the pid and
a version that changes at `exec`. **[D]** For a Unix socket the peer's
token is read with `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, and a code
object is made from it with `kSecGuestAttributeAudit` in the place of
`kSecGuestAttributePid`. **[D]** Both names are from memory; Atticus uses
neither.

*Proposal:*

1. `peer()` on macOS also reads the token. A connection whose token cannot
   be read is dropped, like one whose credentials cannot be read
   (`SPEC.md` section 7).
2. The identity is taken from the token, once, when the connection is
   accepted, before any message is read. It holds for that connection.
   Nothing is kept across connections (Atticus's rule, kept).
3. If the system no longer finds code for the token (the process ended, or
   it did `exec`), the program is "unknown, not identifiable" and gets what
   an incomplete chain gets: only the two "once" answers.

What I could not settle, **[U]**, checks for a person:

- which moment the token of `LOCAL_PEERTOKEN` describes: `connect`, or the
  time of the question. Check: a program connects, sleeps, then does
  `exec` of `/usr/bin/true`-like code that keeps the descriptor; ask before
  and after. If the token changes, a peer can still swap itself between
  the question and its first message, and pledge must ask again when it
  reads each signing request and compare.
- a descriptor handed to another process (inherited by a child, or sent
  over a socket): the token names whoever connected, not whoever writes.
  That cannot be closed from pledge's side; it is the "holes in the chain"
  of `SPEC.md` section 3.

### 3.4 The chain, and what stays weak

`SPEC.md` section 3 identifies "a link in the connecting process's chain
that the person picks", because the peer of the SSH agent socket is nearly
always `/usr/bin/ssh`, which says nothing about who started it. Atticus
walks up to four parents by pid and path. **[A]** `AgentPolicy.evaluate`.
A parent is found by pid, and I know no audit token for "the parent at the
time of the fork", so the chain above the peer is racy and stays so. The
rule in `SPEC.md` (an incomplete chain gets only "once" answers) is the
right size for that. A parent that has exited (the usual case for a
script) is a hole.

Weaker, and to be shown as weaker:

| Program | What identifies it | What that is worth |
|---|---|---|
| Developer ID signed, hardened runtime | team and identifier | the same program across updates; the person can admit it generally |
| Apple's own (`/usr/bin/ssh`, `/usr/bin/git`) | identifier under Apple's anchor | which tool, never who uses it. Admitting "ssh" generally admits everything that runs ssh. Only as a link below something else |
| signed, but without the hardened runtime | team and identifier | another program of the person can load code into it **[D]**; show it as signed, offer "once" only (question 6) |
| ad-hoc signed (every local build on Apple silicon, Homebrew) | the code directory hash, with the path for showing | this exact build. Every rebuild or upgrade is a new unknown program |
| unsigned, or the signature is not valid now | the path, for showing | nothing. "Once" answers only; never a bound key |
| an interpreter (python, node, a shell) | the interpreter's signature | nothing about the script. "Once" answers only |

A bound key "is fixed by its code signature at that moment" (`SPEC.md`
section 2). With this table: a bound key can be made only for a program in
the first row. p-reserve must therefore ship signed, with the hardened
runtime, before step 5.

### 3.5 What is shown

In an admission dialog, whole and apart from each other:

- for signed code: the signing identifier, the team identifier, and the
  path the process runs from;
- for ad-hoc code: "not signed by a developer", the path, and the hash
  whole (a hash shown in part can be matched by another build);
- for each further link of the chain the same, marked as "started by";
- where the chain has a hole: "what started this program could not be
  determined".

A team identifier is ten characters that mean nothing to a person. The
signer's name is in the certificate (its common name). It is the signer's
own claim under Apple's signature; showing it beside the team identifier is
reasonable. **[U]** how to read it.

The record keeps the same identity (`proposals/record.md`,
`signing-request`): today a path, then the string of section 6.3.

`control.sock`: `proposals/control-sock.md`, section 2, already says that
in the hardware form the peer's code signature must be pledge's own or the
desktop app's. With this section: a requirement of pledge's team and one of
a fixed list of identifiers, checked from the audit token in
`accept_control`. Atticus's "my own path is me" shortcut is not taken.

`service.sock` stays as it is: a service is another account's program and
is known by its key, not by its code.

## 4. A real dialog in place of standard input

### 4.1 What must be shown

For a request, from `SPEC.md` sections 4 and 5, `doc/approvals.md` R9 and
section 7, and as `description()` in `src/approvals.rs` builds it today:

- the person; the agent (its delegation's label and identifier);
- the service and its host, as verified from the request's signature;
- the action; each parameter on its own line, whole (up to 512 bytes each,
  2000 characters together);
- the rating, three words;
- the agent's claim, apart from the rest and marked as the agent's claim;
- the deadline, as time left.

Nothing shortened, nothing ellipsised, nothing hidden behind "more". A
field that is long wraps; a dialog that would not fit scrolls, and then the
answer is not offered until the end was reached (*proposal*). Text is
shown as plain text: no links, no styling from the content. The reader has
refused control characters and bidirectional marks before (`Call::showable`
in p-act); the dialog relies on that and does not clean anything itself.

Atticus differs here on purpose and its way does not carry over: it puts
the text into the Touch ID prompt, drops characters it does not like and
cuts a field at 64 characters with "…", and shows the first two host
names. **[A]** `SSHSignDescription.sanitize`, `.describe`. R9 forbids
both; pledge refuses what it cannot show.

For a signing request on the SSH agent socket: the program (section 3.5),
and the `Description` of `describe()` in `src/dialog.rs` (user and
verified host, or the namespace). For an admission: the four answers, and
typing the name for "admit generally".

One at a time, as now.

### 4.2 Which process shows it

Three places are possible.

| | The key holder shows it | A dialog process of pledge's own | The desktop app (step 7) |
|---|---|---|---|
| Parser near the keys | yes: it must turn a request into fields, or trust fields it is handed | no | no |
| Processes | reader, holder | reader, holder, dialog | reader, holder, app |
| Exists when step 4 is built | yes | yes | no |
| What decides "yes" | the touch | the touch | the touch |

*Proposal:* a dialog process of pledge's own, started by `pledge serve`
like the key holder and talking to it over a pipe, implementing the
`Dialogs` trait of `src/dialog.rs` in the place of `Terminal`. It holds no
key and decides nothing. When the desktop app exists it takes this part
over; `proposals/control-sock.md`, section 6 (`subscribe`), is the place
for that. Keeping it out of the key holder keeps `SPEC.md` section 7 true:
the process with the keys parses nothing and draws nothing.

The key holder still causes one piece of screen: the system's Touch ID
prompt, which belongs to the process that uses the key. Whether a program
without an app bundle, started by launchd in the person's session, can
cause that prompt, and under which name it appears, is **[U]** (the checks
of section 1.5 are to be run from such a program, not from an app, for
this reason).

### 4.3 How the answer is tied to the signature

The rule: **for anything that ends in a signature by a key with a presence
check, the click is not the answer. The touch is.**

- Request in mode `ask`: the dialog shows the request. *Proposal:* the
  Touch ID prompt is raised together with it, not after a click on
  "approve". Touch is yes; the dialog's "decline" (or the prompt's cancel)
  is no. One act, and nothing that a program could click for the person.
  Today's two steps in `src/approvals.rs` (`ask_request`, then `confirm`)
  become one (question 5).
- Signing request with the shared key: the same. `Dialogs::presence` is
  already described there as "in the hardware form it is a touch".
- Starting an agent: the delegation key's signature over the certificate is
  the presence check. The prompt names the person, the groups and the
  validity. `confirm` in `src/agents.rs` goes away on the Mac.

No other process can give that answer: it would need the finger. A program
that sends clicks or keys can at most decline. A decline by such a program
costs the agent a muted ten minutes after three; it releases nothing.

Answers that end in **no** signature are not covered by this and need
their own tie:

- "admit generally", "block" (they change `programs.json`);
- the two ceilings of a delegation (they stay in pledge and are not in the
  certificate);
- `keys.create`, `keys.retire`.

For these the presence check can only be `LAContext.evaluatePolicy`, as in
Atticus: enforced by pledge's code, not by a key. *Proposal:* the key
holder offers that as an operation of its own, with the text handed in, so
that it is at least not the dialog process that says "the person was
there"; and the document says that it is software. Retiring a key with a
presence check can do better: require a signature by that key over a fixed
text first. Question 7.

### 4.4 What a dialog process that is taken over could and could not do

Could:

- show a request other than the one that will be signed, to obtain a touch
  for it. The Touch ID prompt, whose text comes from the reader through
  the key holder and not from the dialog process, then names another
  service, host or action than the dialog; a person who compares notices.
  Parameters are not in the prompt, so a lie about parameters alone is not
  caught;
- show nothing, or decline everything, or say "unavailable": no action is
  carried out, agents get muted;
- answer admission questions falsely, as far as section 4.3's last list is
  not behind a presence check;
- learn every request and signing request it is shown.

Could not:

- make any signature, or cause one without a touch for a key with a
  presence check;
- change what is signed: the bytes go from the reader to the key holder
  and never pass it;
- make an automatic approval, or change the mode of a request;
- write the record.

A **reader** that is taken over can do more, as today: it chooses both the
bytes and every word shown. With hardware keys it still needs one touch
per confirmed approval and per delegation, and gets automatic approvals
for free. A **key holder** that is taken over can sign what it likes with
keys without presence, and can lie in the prompt's text for the others; it
cannot sign with those without a touch.

## 5. What carries over from Atticus

All paths are under `/Users/jancre/dev/ws/atticus-develop`, tree `develop`.

| # | Mechanism | Where in Atticus | Carries over | Why |
|---|---|---|---|---|
| 1 | Making, loading and using a Secure Enclave key; blob in a file | `Sources/Engine/SEPKey.swift` | with changes | Several keys, each with its own access control; in the key holder process, not in the app; no fixed file names |
| 2 | Public key blob and signature blob for `ecdsa-sha2-nistp256` | `SEPKey.publicKeyBlob`, `SEPKey.sign` | as is | The same bytes as `src/holder.rs` makes for file keys |
| 3 | The key has **no** presence flag; a test greps the source to keep it so | `SEPKey.swift` 11 to 15, 62 to 78; `tests/AtticImportTest.swift` near 4804 | not, for four keys; the test's idea, yes | Here presence belongs in the key for confirmed, delegation and shared. A test that pins each purpose to its flags is worth having |
| 4 | Confirmation by `LAContext.evaluatePolicy` in the app, fresh context, no cache | `AgentPolicy.authorize`; `Sources/Engine/LAContextProtocol.swift` | with changes | Only for what ends in no signature (section 4.3). The protocol seam for tests carries over as is |
| 5 | Password accepted in place of Touch ID (`.deviceOwnerAuthentication`) | `AgentPolicy.authorize` | open | Question 1, per key |
| 6 | One confirmation per signature, held back until the data is parsed; later messages wait | `SSHAgent.Outcome.confirm`; `SSHAgentServer.swift`, `ClientConnection.drainMessages` | as is, already there | `src/agent_conn.rs` `decide`: `CheckPresence` before `holder.sign` |
| 7 | The confirmation's words from the signed bytes and the verified host | `Sources/Engine/SSHSignDescription.swift`, `describe` | as is, already there | `describe()` in `src/dialog.rs` |
| 8 | Cleaning and cutting what is shown (drop characters, 64 and "…", two names) | `SSHSignDescription.sanitize`; `AgentPolicy.sanitizeDisplayName` | not | R9: show whole or refuse |
| 9 | A second key for Atticus's own processes, withheld from others | `SSHAgent.backupIdentityProvider`, `provider(for:)` in `Sources/Engine/SSHAgent.swift` | already there, differently | Declared and never assigned anywhere under `Sources/` in `develop`. p-ledge has it as purposes: bound and shared (`src/policy.rs`) |
| 10 | Refusing SSHSIG in a reserved namespace on the SSH agent socket | `SSHAgent.Refusal.reservedNamespace` (`atticus-`) | as is, already there | Here every namespace ending in `@procession` |
| 11 | Only user authentication and SSHSIG parse; session binding; forwarded connections refused; host named from `known_hosts` | `SSHSignContent.swift`, `SSHSessionBinding.swift`, `SSHHostKey.swift`, `SSHSignDescription.swift` | as is, already there | Step 1 ported them (`src/agent/`) |
| 12 | A setting that lets unbound logins through with a warning | `SSHAgent.requireHostBinding` | not | `SPEC.md` section 3: "there is no setting for it" |
| 13 | Peer from `LOCAL_PEERPID`, `getpeereid`, `proc_pidpath` | `AgentPolicy.peer(for:)` | with changes | Add the audit token; the pid is for showing only |
| 14 | Code signature checked against a requirement text, by pid, on every connection, no cache | `Sources/Engine/CodeValidator.swift`; "hot-swap invariant" in `AgentPolicy.swift` | with changes | By audit token; also read the identity of unknown programs, not only test for three known ones. "Every connection, no cache" as is |
| 15 | Path prefixes decide who is checked; "my own path is me" | `AgentPolicy.allowedPrefixes`, self-bypass in `evaluate` | not | A path is not an identity. The reason given for the bypass (a short-lived probe that exits before it can be checked) is what the audit token is for |
| 16 | Walking up to four parents to find who started ssh | `AgentPolicy.evaluate` | with changes | The person picks the link (`SPEC.md` section 3); a hole means "once" only |
| 17 | Silent signing for its own validated programs | `AgentPolicy.evaluate` returning `.allow`; `SSHAgent.Consent.silent` | not as such | Here only a bound key signs unseen, for one program and one login |
| 18 | One switch that turns all other programs off | `AgentPolicy.externalIntegrationEnabled` | not | Nothing in `SPEC.md` asks for it; blocking is per program |
| 19 | Passing what it cannot serve to the person's other SSH agent | `Sources/Engine/SSHAgentForwarder.swift` | not | Not in `SPEC.md`; it would put signatures past the record |
| 20 | A user certificate for the login key | `Sources/SSHCertificate.swift`, `Sources/Engine/SSHCertificateService.swift`, `Sources/CLI/SSHCertCLI.swift` | not now | `SPEC.md` section 2: not in the first version. How the certificate rides with the key (row 2, section 1.3) is the same as stage 3 needs |
| 21 | The access history and the decision trace in the system log | `SSHAgentServer.signEventSink`, `Sources/AgentDecisionLog.swift`, `Sources/AgentPolicyTrace.swift` | not | The record is the one place |
| 22 | SSH agent, parser, key and windows in one process | `Sources/Engine/SSHAgentServer.swift` and the app | not | `SPEC.md` section 7: reader and key holder are two processes |
| 23 | Signing with Developer ID, hardened runtime, pinned entitlements, no sandbox | `Makefile` (`CODESIGN_FLAGS`), `Resources/Atticus.entitlements`, `tools/check-entitlements.sh` | with changes | pledge's Mac parts must be signed the same way, or `control.sock` and a bound key have nothing to check. Which team: question 8 |
| 24 | A secret readable only by its own signed programs, through a keychain access group | `SECURITY.md`, "Defenses in place" (the restic password) | as an idea | Atticus does not do this for its key, only for a password. It is the known way to make a key "usable only by pledge's key holder" (question 2) |
| 25 | The setup turns shared connections off; the server limits sessions | `SECURITY.md`, "A confirmation covers one login" | as is | `SPEC.md` section 3 says the same |
| 26 | A manual checklist for what tests cannot reach (Touch ID, signed builds) | `tests/MANUAL_CHECKLIST.md`, items 26 to 29 | as is, as a form | Section 1.5 is the start of pledge's |

## 6. Where it attaches in p-ledge

### 6.1 The seam that exists

- **`KeyHolder`** (`src/holder.rs`): `list`, `sign(blob, data)`,
  `create(key_type, meta)`, `retire(blob)`. `Shared.holder` is a
  `Mutex<Box<dyn KeyHolder>>` (`src/shared.rs`). The one implementation
  for a process is `HolderClient`, over a child's standard input and
  output, in a fixed binary format (`OP_LIST`, `OP_SIGN`, `OP_CREATE`,
  `OP_RETIRE`; `serve_holder` on the other end with `KeyStore`).
  `ChildHolder::spawn(program, keys_dir)` starts `pledge key-holder`
  (`src/cli.rs`, `serve_verb` and `holder_verb`; `src/serve.rs`, `run`).
- **`Dialogs`** (`src/dialog.rs`): `ask_admission`, `presence`, `confirm`,
  `ask_request`, `tell`; `Terminal` is the implementation, chosen in
  `src/cli.rs` (`Terminal::stdio()`).
- **`peer`** (`src/peer.rs`): `peer()`, `program_path()`; used in
  `src/serve.rs` (`check_peer`, `accept_agent`, `accept_control`,
  `service_peer`).

A Secure Enclave holder is a second program that speaks `serve_holder`'s
format. That part of the seam is right as it is, and it is why the
separation was kept in the development form.

### 6.2 What would have to change in the holder's interface

1. **`sign` must be able to wait for a person and say how it ended.**
   Today it returns bytes or `Error::Holder(String)`. With a presence key
   it needs: the prompt's words; how long to wait and a way to stop
   (`Wait` in `src/dialog.rs` has both); and four endings: signed,
   declined, timed out, unavailable (`Outcome<T>` in `src/dialog.rs` has
   exactly these). The callers: `holder_sign` and the `Mode::Ask` arm in
   `src/approvals.rs`; `decide` in `src/agent_conn.rs`;
   `serve_issuing_agent` in `src/issue.rs`.
2. **`create` must say the protection.** Today the holder stores `meta`
   unread, and the purpose is inside it. A Secure Enclave key's access
   control is fixed at creation, so "presence or not" (and the
   accessibility) must be an argument of `create`, not something the
   holder would have to read out of `meta`. `keys_create` in
   `src/control.rs` derives it from the purpose.
3. **`list` must say the protection back**, from the key and not from
   `meta`, and the reader must refuse to use a key whose protection does
   not fit its purpose (a "confirmed" key without presence). `meta` is a
   file any program of the person can rewrite. Whether a CryptoKit key's
   access control can be read back from the key is **[U]**; if not, the
   holder stores it beside the blob and this check is worth less.
4. **One waiting signature must not hold up the others.** `Shared.holder`
   is one mutex over one pipe with one call at a time. A Touch ID prompt
   can stand for minutes; meanwhile an automatic approval and a bound
   key's backup login would wait behind it. Either the format gets a
   reference per call and answers in any order, or `pledge serve` starts
   two holders, one for keys with presence and one for keys without
   (question 3).
5. **The reader must know who does the presence check.** *Proposal:* the
   holder says per key whether the key enforces presence itself. If yes,
   the reader passes the words to `sign` and does not call
   `Dialogs::presence` or `Dialogs::confirm`. If no (keys in files), it
   calls them as today. That one question keeps the development form
   unchanged on Linux.
6. **An operation for a presence check without a signature**
   (section 4.3), if question 7 is answered that way. In the development
   form it is `Dialogs::confirm`.

Two orderings to keep, both already in `src/approvals.rs`: the entry
`received` is written before any dialog; the identifier is marked used
(`reserve()`) before the key signs. With the touch inside `sign`,
`reserve()` comes before the touch, so a cancelled touch is a decline with
the identifier used, as `SPEC.md` section 4 says. A touch that fails as
"unavailable" (sensor locked out) after `reserve()` leaves the identifier
used with a refusal; that is the "second decision, never a second
signature" side of the same rule, and the agent makes a new call.

### 6.3 What else changes

- **`src/peer.rs`**: `Peer` gains the audit token on macOS; beside
  `program_path` a function that returns the program's identity from the
  token (section 3). This is in the reader: it needs the socket, and the
  key holder must not see sockets. It is C API of Security.framework,
  reachable from Rust; no Swift needed for it. **[U]** which crate or
  binding; none is in `Cargo.toml` today.
- **The program's name for the rules.** `src/policy.rs`, `programs.json`
  and `Purpose::Bound { program }` know a program as a string, and
  `src/agent_conn.rs` passes `Option<&str>`. *Proposal:* keep the string
  and give it a form with a prefix: `team:<team>:<identifier>`,
  `apple:<identifier>`, `adhoc:<hash>`, and `path:<path>` for the
  development form. `src/policy.rs` then does not change. What may be
  admitted generally (section 3.4) is decided from the prefix, where
  `ask_admission` is called in `src/agent_conn.rs`.
- **`src/serve.rs`**, `accept_control`: after `is_own`, the requirement
  check of section 3.5.
- **`src/dialog.rs`**: a second implementation of `Dialogs` that talks to
  the dialog process; `Description` already is "title and labelled
  fields" and crosses a pipe as it is.
- **`src/cli.rs`**, `serve_verb`: which holder program and which `Dialogs`
  to start. By a setting in `config.json` with the development form as the
  default, or by what the build contains; never by what arrives.
- **`src/approvals.rs`**, `Mode::Ask`: `ask_request` and `confirm` become
  one step where the key enforces presence (question 5).
- **`src/agents.rs`** and **`src/control.rs`** (`presence`): `confirm`
  goes where a signature follows; stays, through the holder, where none
  does.
- **`SPEC.md`**, section 8, says the Mac part "is Swift or Objective-C,
  linked in or as the key holder". This proposal takes "as the key
  holder": a separate program, so that the Rust build on Linux needs no
  Apple toolchain and the process with the keys stays small.

### 6.4 An order in which it could be built

Each step leaves `cargo test` green on Linux and keys in files working.

1. **The hand checks 1 to 5 of section 1.5.** Throwaway programs, outside
   the tree. They can change everything below.
2. **The holder's interface, in Rust, with keys in files only**
   (section 6.2, points 1 to 5): `create` with protection, `list` with
   protection, `sign` with words, wait and four endings, calls that do not
   block each other. `KeyStore` answers "does not enforce presence" for
   every key, so every caller behaves as today. The existing tests are the
   specification; new tests use a holder double that "enforces presence"
   and answers from a script, like `Scripted` in `src/dialog.rs`.
3. **The Secure Enclave key holder**: a Swift program speaking the format
   of step 2. Tested against the same protocol tests with its keys
   replaced by a double; with real keys only by the manual checklist
   (checks 6 to 16).
4. **Who a program is**: the audit token and the identity in
   `src/peer.rs`, behind `cfg(target_os = "macos")`; the prefixed names;
   `accept_control`. Linux keeps `path:`.
5. **The dialog process**, as a second `Dialogs`. Until it exists, a Mac
   with Secure Enclave keys can already run with `Terminal`: the request
   is shown on the terminal and the touch is real. That is a usable stage
   2 for its one first user.
6. **Signed builds** of pledge's Mac parts (row 23), needed from step 4
   on for `control.sock` and before step 5 of `SPEC.md` (a bound key for
   p-reserve).
7. The connection to the broker (`SPEC.md` step 6) is independent of all
   of this except the connection key, which is a key without presence from
   step 3.

## 7. Open questions for the designer

1. **Password in place of Touch ID, per key.**
   *Recommendation:* confirmed approval and delegation: Touch ID only
   (`.biometryAny`), and a Mac where that is not possible makes no
   confirmed approval. Shared key: Touch ID or password (`.userPresence`).
   *Reason:* section 1 of `doc/approvals.md` defines the presence check by
   Touch ID, and the two threats it answers (stolen machine, malware in
   the session) are the two where a password is weaker (section 2.3). A
   login is the person's own act and Atticus accepts a password there
   today. The cost is the closed laptop; a Touch ID keyboard removes it.
   `.biometryAny` rather than `.biometryCurrentSet`, because a new finger
   would otherwise end keys an administrator entered.

2. **A blob in a file, or a key in the keychain bound to pledge's
   signature.** If check 3 shows that any program of the person can use a
   copied blob, the keys without presence are open to every such program,
   and the keys with presence can be prompted for by any of them under its
   own name.
   *Recommendation:* decide after check 3. If it comes out as I expect:
   blobs in files for stage 2, said plainly in `SPEC.md` section 2; the
   keychain with an access group as a step of its own before a site
   (stage 3).
   *Reason:* the keychain route needs an entitlement, so signed builds
   with a provisioned identifier, before the first key can be made; it
   would put step 6 of section 6.4 first. The threat table already counts
   automatic approvals as lost to malware in the session. `SPEC.md`
   section 11 assumes "each usable only by pledge's key holder"; that
   sentence is the one at stake.

3. **One key holder with calls that overlap, or two key holders.**
   *Recommendation:* two processes: one for keys with a presence check,
   one for keys without.
   *Reason:* the format stays one call at a time, as it is. The process
   that waits for touches is never the one a backup or an automatic
   approval waits for. And the one without presence needs no window
   server, which is what section 2.4 asks of it.

4. **Does a locked screen stop automatic approvals?**
   *Recommendation:* no for stage 2: the automatic key is "after first
   unlock" and signs while the screen is locked; and write that into the
   threat table's row on a stolen machine.
   *Reason:* U2 is an agent working while its person does something else,
   and a screen locks after minutes. The row's wording ("if the thief has
   the unlocked session") reads the other way, so this is the designer's
   call, not mine. Check 10 says whether the hardware could enforce the
   strict reading at all; if not, it would be pledge's own code watching
   the lock, which is worth less.

5. **Dialog and touch as one step, or approve first and touch second.**
   *Recommendation:* one step: the Touch ID prompt is raised with the
   dialog; touch is yes.
   *Reason:* a click before the touch protects nothing and can be made by
   a program. Two steps are two chances to stop being careful. Against
   it: a prompt that appears unasked trains a person to touch; the limits
   (one dialog, five waiting, muting after three declines) bound that.
   Where no presence check is possible in the key (keys in files), the
   two steps of today stay.

6. **Programs that are signed but not hardened, ad-hoc signed, or
   interpreters: "once" only?**
   *Recommendation:* yes; "admit generally" only for Developer ID code
   with the hardened runtime, and for Apple's tools only as a lower link
   of a chain whose upper link qualifies.
   *Reason:* section 3.4. It will annoy with Homebrew's git and with
   scripts. The alternative, admitting an ad-hoc build generally by its
   hash, is sound but lasts until the next upgrade; it could be allowed
   without loss.

7. **Presence for what ends in no signature** (admit generally, block,
   ceilings, making and retiring keys).
   *Recommendation:* `LAContext.evaluatePolicy` in the key holder, asked
   for by the reader, and say in `SPEC.md` that it is enforced by pledge's
   code and not by a key. For retiring a key with a presence check:
   require a signature by that key first.
   *Reason:* it is what exists (Atticus) and it is honest. A further key
   that signs rule changes would bind them to hardware, and is a fifth
   key with a purpose nobody outside pledge verifies; not now.

8. **Who signs pledge's Mac programs, and as what.**
   *Recommendation:* the owner's Developer ID team (the one Atticus is
   signed with), with identifiers of pledge's own; the reader, the key
   holder and the dialog process each get one.
   *Reason:* `control.sock`, a bound key and question 2 all need a
   signature to check, and three identifiers let each socket and each key
   name exactly the program it means. Until then the Mac form runs with
   ad-hoc builds and must say at its start what that leaves unprotected.

9. **What a request does while no presence check is possible** (screen
   locked, sensor locked out).
   *Recommendation:* it waits until its deadline and ends `expired`; it is
   not refused at once.
   *Reason:* deadlines are minutes, and a person who hears the request
   arrive unlocks the screen. R11 is kept either way: nothing is signed.

10. **What the Touch ID prompt says.**
    *Recommendation:* for a request: the service's name, its host and the
    action. For a login: user and host name or fingerprint. For a
    delegation: person, groups, validity. Never a parameter, never the
    agent's claim.
    *Reason:* these fields are bounded and plain by the formats; they are
    the cross-check against a dialog process that lies (section 4.4).
    Check 5 may force it shorter.

11. **The first Mac stage with `Terminal` and real keys** (section 6.4,
    step 5), before any window exists.
    *Recommendation:* yes, as an intermediate stage for the owner only.
    *Reason:* it proves the keys, the touch and the broker connection
    with the least new code, and the dialog process can then be built
    against something that works.

## 8. What was read, what was not; nothing was run

Read in full, in this worktree: `doc/approvals.md`,
`doc/approval-formats.md`, `crates/p-ledge/SPEC.md`,
`crates/p-ledge/src/holder.rs`, `src/peer.rs`, `src/dialog.rs`,
`src/sshsig.rs`, `src/lib.rs`, `Cargo.toml`.

Read in part (the places named above): `src/shared.rs`,
`src/approvals.rs`, `src/agent_conn.rs`, `src/issue.rs`, `src/serve.rs`,
`src/control.rs`, `src/agents.rs`, `src/cli.rs`, the head of
`src/policy.rs`; `proposals/control-sock.md` (sections 1 to 3, 5 to 7),
the head of `proposals/service-sock.md`.

Only searched, not read: `doc/approval-connections.md` (for the connection
key and the sign-in), `proposals/REPORT.md`, `proposals/record.md`,
`proposals/review-pact-bundle.md` (headings).

Not read: `src/record.rs`, `src/config.rs`, `src/delegations.rs`,
`src/answers.rs`, `src/mute.rs`, `src/paths.rs`, `src/service_conn.rs`,
`src/agent/*`, the tests, the crates p-act, p-age and p-robe. What this
proposal says about them is from the documents and from how the files I
read use them.

In Atticus (`develop`, `a1ada83`), read in full: `AGENTS.md` (it is about
issue tracking and has nothing on the design),
`Sources/Engine/SEPKey.swift`, `CodeValidator.swift`,
`LAContextProtocol.swift`, `AgentPolicy.swift`, `SSHAgentServer.swift`,
`SSHSignDescription.swift`, `Resources/Atticus.entitlements`. In part:
`Sources/Engine/SSHAgent.swift` (lines 1 to 140),
`SSHCertificateService.swift` and `Sources/CLI/SSHCertCLI.swift` (heads),
`SECURITY.md` (lines 28 to 120). Only searched: `Makefile` (for code
signing), `tests/MANUAL_CHECKLIST.md`, `tests/AtticImportTest.swift`.
Not read: `CLAUDE.md`, `README.md`, `SPEC.md`, `SSHSignContent.swift`,
`SSHSessionBinding.swift`, `SSHHostKey.swift`, `SSHAgentForwarder.swift`,
`SSHAgentIdentityProvider.swift`, `Sources/SSHCertificate.swift`,
`AgentPolicyTrace.swift`, `AgentDecisionLog.swift`, the views; rows 11,
19, 20 and 21 of section 5 rest on file names, on references from the
files I read and on `SECURITY.md`. No `secrets/` directory and no `.env`
file was opened. Nothing there was changed, built or checked out; the
commands were `git branch -a`, `git log --all --oneline`, `git status
--short`, and reading files.

No Apple documentation and no header was looked up. Every **[D]** is from
memory, every **[U]** is a belief. In particular not checked: the names
`LOCAL_PEERTOKEN`, `kSecGuestAttributeAudit`,
`SecCodeCopySigningInformation`, `LAContext.invalidate()`,
`touchIDAuthenticationAllowableReuseDuration`, and the CryptoKit
initialisers that take an `authenticationContext`.

Nothing was run: no build, no test, no `ssh-keygen`, no program that makes
or uses a Secure Enclave key, no Touch ID prompt.
