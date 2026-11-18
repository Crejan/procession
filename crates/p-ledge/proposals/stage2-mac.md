# Proposal: pledge on a Mac (order of work, step 4; stage 2)

Status: a proposal by the p-ledge agent, for the designer. Nothing is built
on it, no source file was changed, and nothing was run: no key was made, no
Touch ID was asked for. Terms are those of `doc/approvals.md`, section 1.

**The reference.** Everything below that says "Atticus" is the tree
`develop` of `/Users/jancre/dev/ws/atticus-develop` as it stands, at
`a1ada83`. Besides the files, five commits on it were read with `git show`:

| Commit | What it is | Bears on this proposal |
|---|---|---|
| `ee481a4` | the Touch ID prompt moves from accepting a connection to each signature; its words come from the parsed data and the verified host | section 2.1; section 5, rows 4, 6, 7, 8 |
| `d534f23` | review fixes for that work: a host counts as verified only for a hostbound login to the bound key; quotation marks stripped from shown fields; the buffer bounded while a prompt is open | section 5, rows 8, 11, 27 |
| `343f9c8` | a second key that only Atticus's own processes are offered | section 5, row 9 |
| `f18f7f6` | the snapshot browser runs one restic at a time | nothing: no key, SSH agent or confirmation code in it |
| `e869251` | the overview names an overdue backup | nothing, likewise |

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
  needs a fresh context per signature, never kept. Check 4 showed it
  (section 1.6): a context that is kept signs a second time with no touch,
  although its reuse time is zero. The rule is in section 2.2.

So the Secure Enclave can enforce *that the person was there for this
signature*. It shows nothing itself. *What* the person saw is said by the
process that set the prompt's text: software, not hardware (sections 2 and
4).

### 1.2 Each key

| Key (`doc/approvals.md` section 5; `SPEC.md` section 2) | In the Secure Enclave | Presence in the key | Accessible | Type |
|---|---|---|---|---|
| confirmed approval | yes | yes, each signature: Touch ID only (`.biometryAny`) | when unlocked | P-256 |
| automatic approval | yes | **none** | after first unlock | P-256 |
| delegation | yes | yes, each signature: Touch ID only (`.biometryAny`) | when unlocked | P-256 |
| connection | yes | **none** | after first unlock | P-256 |
| shared (logins, `git`/`file` signatures) | yes | yes, each signature: Touch ID or password (`.userPresence`) | when unlocked | P-256 |
| bound (one program's login) | yes | **none** | after first unlock | P-256 |

The presence flags and the automatic key's "after first unlock" are the
owner's decisions of 2026-11-18 (questions 1 and 4).

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

### 1.6 Results of the hand checks

Run by the owner on his Mac on 2026-11-18 with
`stage2-mac-checks/sechecks.swift`; relayed by the designer. These are his
observations. The table in `stage2-mac-checks/README.md` has them row by
row. Not yet run: 1c's question whether a password is offered, 2b, 2d,
3c, and checks 6 to 16.

| Check | Observed | What it settles |
|---|---|---|
| 0 (making the keys) | Five keys made (no presence, "after first unlock" and "when unlocked"; `.biometryAny`; `.userPresence`; `.biometryCurrentSet`), each with a public key line and a blob file. No prompt while making. No entitlement error | A program that is ad-hoc signed, with no bundle and no entitlement, can make and use Secure Enclave keys through CryptoKit. The **[U]** of section 4.2 about a program without an app bundle is answered for making keys and for raising the prompt (3b) |
| 3a (a copied blob, another program, no presence) | `sechecks-other: SIGNED plain after 0.0 s`, no prompt | The **[U]** of section 1.1 is answered as expected: another program of the same user loads a copied blob and signs. A key without a presence check is exactly as protected as its blob file |
| 3b (a copied blob, another program, Touch ID) | A Touch ID prompt that named the other program and carried its words; after the touch, `SIGNED touch after 2.6 s` | The presence check holds for a copied blob: no signature without the touch. But any program of the person can raise that prompt, under its own name and with its own text |

| 1a, 1b (keys side by side) | `sign plain`: signed, no prompt. `sign touch`: a prompt that began "sechecks trying to sign ..." (the full text was not copied), signed after the touch | `SPEC.md` section 11's assumption holds: keys with and without a presence check exist side by side in one program, and each behaves as made |
| 1c (`.userPresence`) | `sign touchpw`: signed. Whether "Use Password" was offered was not reported | That part of 1c is still open |
| 2a (cancel) | `NOT SIGNED touch after 12.0 s: error domain=com.apple.LocalAuthentication code=-2 ... Canceled by user.` | The person's cancel has a code of its own |
| 2c (the program ends the prompt; run with `--invalidate-after 2`) | `invalidating the context now`, then `NOT SIGNED touch after 2.1 s: error domain=com.apple.LocalAuthentication code=-9 ... Invalidated by client.` | A prompt can be closed by the program at a deadline, and that ending is told apart from the person's cancel. The **[D]** on `LAContext.invalidate()` in section 2.2 is now observed |
| 4a (two signatures, a fresh context each) | Two prompts: `SIGNED first after 3.0 s`, `second after 1.4 s` | One touch, one signature, with fresh contexts |
| 4b (two signatures, one context) | **One** prompt: `SIGNED first, shared context after 1.4 s`, `SIGNED second, shared context after 0.0 s` | **A kept context signs again with no touch.** The most important of these results: section 2.2, the rule |
| 5 (how much text the prompt shows) | 60 characters: shown whole. 200: shown through `END`. 600: cut inside `word67` | The prompt showed between 510 and 515 characters of the program's text. Section 2.2, the budget |

Checks 2b (left alone until the prompt ends by itself) and 2d (wrong
finger) were not run: the system's own timeout and the lockout have no
observed code yet.

**Decided on this (question 2):** blobs in files for stage 2, said plainly;
the keychain with an access group is a step of its own before a site.

Two consequences, both the designer's:

1. **The blob files' mode and their directory are the only protection of
   the keys without a presence check** (automatic approval, connection,
   bound). So they follow the strictest file rule the workspace has. In
   p-ledge that is `check_private` in `src/paths.rs`, which `KeyStore::open`
   in `src/holder.rs` already applies to key files: not a symlink, owned by
   this user, no permission for anyone else (0700 for the directory, 0600
   for the file), and a key holder that refuses to start otherwise. The
   Secure Enclave holder applies the same to its blobs, before every use
   and not only when it starts. What this does not stop is another program
   of the same user: check 3a is that case, and the rule cannot reach it.
   It is what the threat table's row "malware in the person's session"
   leaves, now observed and not only assumed.
2. **The Touch ID prompt's text is the person's only way to see who asks.**
   The system puts the asking program's name on the prompt (3b); the rest
   is that program's own words. So pledge's key holder always puts its own
   fixed words first, before anything that comes from a request, a login
   or a delegation, and never lets such a field come before them or stand
   alone. A prompt from any other program then differs in the name the
   system shows and cannot be given pledge's name; a person who knows the
   fixed words and the name can tell. Check 5 will say how much room the
   prompt has; the fixed words must fit in what is always shown. This
   narrows question 10's answer: the words there (service, host, action)
   come after the fixed ones. It also makes the key holder's program name
   matter: it is what the system shows (section 8.6, last paragraph).

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

**The rule from check 4b: the key holder never keeps and never reuses a
context.** One fresh context per signature, invalidated after it. Check 4b
showed why this is a rule and not a habit: with one context, the second
signature came after 0.0 s with no prompt. A holder that kept a context
"for the session" would turn a presence check per signature into one per
start, silently, and nothing on the screen or in the record would show it.
So:

- the holder's `sign` for a key with a presence check makes its context
  inside the call, uses it for that one signature, and invalidates it
  before it returns, on every path: signed, declined, closed, failed;
- nothing holds a context between calls: no field, no global, no cache,
  and no loaded key object either, because the key is loaded *with* the
  context and carries it;
- this has tests (section 6.5), and the hand check 4a through the real
  holder (two signatures, two prompts) is part of the manual checklist.

**The four endings of `sign`, from check 2.** For a key with a presence
check:

| Ending | When | Observed as | Becomes |
|---|---|---|---|
| signed | the touch | a signature | `approved` |
| declined by the person | Cancel at the prompt | `com.apple.LocalAuthentication`, code -2 (2a) | `declined`; counts toward muting and uses the call's identifier |
| closed by the holder | the holder invalidated the context: because the deadline passed, or because the one who asked went away | code -9 (2c) | `expired` or `cancelled`: the reader knows which, since it asked for the closing. A -9 that the holder did not cause itself is a failure |
| failed | everything else | any other code, or none | `refused`, reason `unavailable`; the record keeps domain and code |

So `expired` at the deadline is implemented by invalidating the context.
The rule for codes not in this table: **an unknown code is a failure,
never a decline.** A decline mutes an agent after three; a sensor fault
must not.

Still unknown, because not run: the code when the system ends the prompt
by itself (2b), and after wrong fingers and the lockout (2d). From memory,
**[D]**, not observed: -4 (the system cancelled), -8 (biometry locked
out), -6 and -7 (no biometry available, none enrolled), -1004 (no
interaction possible, which a locked screen or a session without a window
server may give; checks 10 and 11). The record's "why it could not be
asked" (question 9) needs 2b, 2d, 10 and 11 run before its values can be
named.

**The budget for the prompt's words, from check 5.** The 600-character
text was cut inside `word67`, which stands at characters 511 to 516 of it:
the prompt showed between 510 and 515 characters of the program's text,
after the system's own "<program> is trying to". One text, one Mac, one
system language; the cut may follow the width of the letters and not
their number. So the budget is set well below it:

- **300 characters for everything the holder puts into the prompt.**
- **First the holder's fixed words** (section 1.6, consequence 2), at most
  40 characters, the same for every prompt of one purpose, for example
  "pledge: approve a request." Nothing stands before them.
- **Then the names**: for a request the service, its host and the action.

**What does not fit is refused, never cut** (decided by the designer on
2026-11-18; I had proposed a marked cut). The prompt's words are the
person's check against a dialog that lies (section 4.4). A prompt that
ends in "… and more" checks nothing: what was left out is exactly where a
lie would be. So the rule for the dialog, a field whole and longer is
refused, holds for the prompt for the same reason.

How that is made true:

- **It is a property of the call, not a behaviour of the holder.** The
  three names the prompt carries (service, host, action) have a combined
  bound of 240 characters. With the fixed words (at most 40) and the
  separators that stays inside 300. The bound goes into `Call::showable`
  in p-act, which p-act builds, with the reason `not-showable`. A service
  refuses such a call before anybody is asked; pledge refuses it too, and
  pledge's refusal is the one that counts; the key holder never meets a
  request whose words do not fit.
- **The holder still checks the length of what it is handed**, and fails
  if the reader ever gives it more: the fourth ending of `sign`, never a
  shortened prompt. That is a guard, not the rule.
- **The same for the other two prompts.** A login: the user and the host
  (a name from `known_hosts`, or the fingerprint); a signing request whose
  words do not fit is refused as not showable. A delegation: the person,
  the **number** of groups and the validity. The prompt names the count
  and the dialog shows the list whole; a prompt that lists groups until it
  runs out of room is the same cut in another place.
- **The budget holds with keys in files too**, where there is no prompt,
  so that a call that is showable on Linux is showable on a Mac.

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

**Password in place of Touch ID, per key** (question 1, decided by the
owner on 2026-11-18: Touch ID only for confirmed approvals and delegations,
so a Mac that cannot offer Touch ID makes no confirmed approval and starts
no agent; Touch ID or password for the shared key). The reasons were:

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

It does not require an unlocked screen either (question 4, decided by the
owner on 2026-11-18): the automatic key is "after first unlock" and signs
while the screen is locked. `doc/approvals.md`, section 4, the row on a
stolen machine, says so now; what bounds it there is the delegation's end
and the administrator's block.

A consequence to state plainly: a key without presence in a blob file is as
strong as the file. Check 3a showed that any program of the person can
load the blob (section 1.6), so on a Mac the automatic approval key is
protected against being carried off the machine and against nothing else. The threat
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
| 9 | A second key for Atticus's own processes, withheld from others | `SSHAgent.backupIdentityProvider`, `provider(for:)` in `Sources/Engine/SSHAgent.swift` | already there, differently | Commit `343f9c8`. The mechanism is there and tested; no key is assigned to it anywhere under `Sources/` ("with no backup key set, behaviour is unchanged"). A request for the withheld key is refused without a prompt, as rule 2 of `SPEC.md` section 3 does. p-ledge has it as purposes: bound and shared (`src/policy.rs`) |
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
| 23 | Signing with Developer ID, hardened runtime, pinned entitlements, no sandbox | `Makefile` (`CODESIGN_FLAGS`), `Resources/Atticus.entitlements`, `tools/check-entitlements.sh` | with changes | pledge's Mac parts must be signed the same way, or `control.sock` and a bound key have nothing to check. The owner's Developer ID team, with identifiers of pledge's own (question 8, decided) |
| 24 | A secret readable only by its own signed programs, through a keychain access group | `SECURITY.md`, "Defenses in place" (the restic password) | as an idea | Atticus does not do this for its key, only for a password. It is the known way to make a key "usable only by pledge's key holder" (question 2) |
| 25 | The setup turns shared connections off; the server limits sessions | `SECURITY.md`, "A confirmation covers one login" | as is | `SPEC.md` section 3 says the same |
| 26 | A manual checklist for what tests cannot reach (Touch ID, signed builds) | `tests/MANUAL_CHECKLIST.md`, items 26 to 29 | as is, as a form | Section 1.5 is the start of pledge's |
| 27 | The rules for a login (session binding, verified host) apply to other programs only; Atticus's own backup signs without them | commit `d534f23`; `SSHAgent.swift`, the `.silent` arm of the sign handler | not | A bound key is for one login, fixed by the host key (`SPEC.md` section 2), so it needs the verified host more than any other key |

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

7. **No context outlives a call** (check 4b; section 2.2). The Secure
   Enclave holder's `sign` for a key with a presence check creates its
   `LAContext` inside the call, loads the key with it, signs once, and
   invalidates the context before returning. No field of the holder holds
   a context or a loaded key with a presence check; the holder keeps blobs
   and public keys, nothing else. Closing at the deadline is the same
   context invalidated from the thread that watches the wait
   (check 2c). Contexts come from a factory the tests can replace, as
   Atticus does (`AgentPolicy.lacontextFactory`,
   `Sources/Engine/LAContextProtocol.swift`).

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

### 6.5 What a later implementation must test

From the hand checks so far. "Test" is an automated test with the
framework replaced by a double, unless it says "by hand".

1. **One context per signature.** For a key with a presence check, each
   `sign` takes exactly one context from the factory and invalidates
   exactly that one before it returns: after a signature, after a
   decline, after a closing, after a failure. Two `sign` calls take two
   different contexts. (Atticus has the same shape of test for its
   prompt: "exactly one `evaluatePolicy` per `authorize`".)
2. **Nothing holds a context.** A test over the holder's source that
   fails if a stored property, a global or a static has the type of a
   context or of a Secure Enclave private key. (Atticus pins a property
   of `SEPKey.swift` by such a test.)
3. **By hand, through the real holder:** two signatures with a presence
   key give two prompts (check 4a's observation).
4. **The four endings.** Code -2 from the double gives "declined"; the
   holder's own invalidation gives "closed", and the reader makes
   `expired` or `cancelled` of it; a -9 the holder did not cause gives
   "failed"; any other code gives "failed" with domain and code kept; no
   code other than -2 ever gives "declined".
5. **The deadline closes the prompt.** With a double that never answers,
   `sign` returns "closed" at the deadline and the context was
   invalidated. By hand: an open prompt disappears at the deadline.
6. **The prompt's words.** The fixed words are first and whole for every
   input; the whole text is at most 300 characters; no parameter and no
   claim ever appears; a delegation's prompt carries the number of groups
   and no group's name. **Nothing is ever cut:** handed words that do not
   fit, the holder returns "failed" and shows no prompt. In p-act:
   `Call::showable` refuses a call whose service, host and action together
   exceed 240 characters, with `not-showable`, and accepts one at exactly
   240; the same on Linux with keys in files.
7. **Each purpose has its flags.** A key made for confirmed approval or
   delegation asks for `.biometryAny`; for shared, `.userPresence`; for
   automatic, connection and bound, no presence flag and "after first
   unlock" (questions 1 and 4).
8. **The blob files.** The holder refuses a blob that is a symlink, not
   the user's, or open to anyone else, before every use (section 1.6,
   consequence 1).

## 7. Open questions for the designer

**Where each stands, 2026-11-18.** The designer read this proposal and
accepted it as a proposal. Nothing is built from it until the owner has run
checks 1 to 5 (the program and the steps are in `stage2-mac-checks/`). The
questions below are left as they were asked; this table says what became of
them.

| # | Question | Stands | What was said |
|---|---|---|---|
| 1 | Password in place of Touch ID | decided, by the owner | Touch ID only (`.biometryAny`) for confirmed approvals and delegations. A Mac that cannot offer Touch ID makes no confirmed approval. The shared key keeps Touch ID or password |
| 2 | Blob in a file, or keychain with an access group | decided, after check 3 | Check 3 came out as expected (section 1.6). Blobs in files for stage 2, said plainly; the keychain with an access group is a step of its own before a site. `SPEC.md` section 11 and the threat table carry the designer's record of it |
| 3 | One key holder or two | decided | Two: one for keys with a presence check, one for keys without |
| 4 | Does a locked screen stop automatic approvals | decided, by the owner | It does not. The automatic key is "after first unlock". The threat table of `doc/approvals.md` (the row on a stolen machine) says so, bounded by the delegation's end and the administrator's block |
| 5 | Dialog and touch as one step | decided | One step: the Touch ID prompt is raised with the dialog and the touch is the yes. Keys in files keep today's two steps. The limits (one dialog at a time, the queue limit, muting after declines) apply unchanged |
| 6 | "Admit generally" for which programs | decided | Only for Developer ID code with the hardened runtime; and, also accepted, an ad-hoc build may be admitted generally by its hash, which lasts until the binary changes |
| 7 | Presence for what ends in no signature | decided | `LAContext.evaluatePolicy` in the key holder, said plainly to be software. Retiring a key with a presence check requires that key's signature first. No fifth key |
| 8 | Who signs pledge's Mac programs, and as what | decided, by the owner | His Developer ID team (the one Atticus is signed with), with identifiers of pledge's own for the reader, the key holder and the dialog process |
| 9 | A request while no presence check is possible | decided | It waits until its deadline and ends `expired`; the record says why it could not be asked (locked, sensor locked out) |
| 10 | What the Touch ID prompt says | decided; check 5 has run | As recommended: service, host and action; user and host for a login; person, groups and validity for a delegation; never a parameter or the agent's claim. Check 5 gives the room (section 2.2, the budget: 300 characters, the holder's fixed words first). Decided by the designer on 2026-11-18: what does not fit is refused, never cut; service, host and action together are at most 240 characters, a bound in `Call::showable`; a delegation's prompt names the number of groups |
| 11 | A first Mac stage with `Terminal` and real keys | decided | Accepted, for the owner only |
| 12 | One Mac app or two | decided, by the owner | Two Mac apps, from one Swift code base. preserve's app is admitted on pledge's `control.sock` for exactly `keys.create` of a bound key and `keys.list`, by a rule per command and peer |
| 13 | Take Atticus's SwiftUI front end at all | decided | Yes, with the condition as written: it becomes preserve's Mac front end only after the logic still in its views and view models has moved into the daemon and the socket protocol offers what section 8.5 lists. The three bypasses and the prune marker (section 8.2) are the list of what goes behind the protocol first. Nothing is copied yet |
| 14 | "Cancel by closing" in p-reserve's protocol | decided | Closing a connection cancels only what was asked as bound to it: browsing, a preview or dump for display, subscriptions. A backup run, a prune, a check and a restore are the daemon's jobs with an identifier: they go on when the connection that started them closes, are cancelled only by an explicit message naming the identifier, and a later connection can list running jobs and attach to their events |
| 15 | The licence of what is taken from Atticus | decided, by the owner | Atticus is his own, so its views may be taken into procession, and what results there is under `MIT OR Apache-2.0` like the rest; the shared Swift package states that licence. Atticus itself stays as it is and under its own licence: this covers taking code from it into procession, nothing else. **This is not a go for copying.** Copying views still waits on the condition of question 13 (the logic into the daemon first, the protocol meeting section 8.5) and, for anything that touches keys, on hand checks 1 to 5 |
| 16 | Where the dialog for a request lives | decided | As recommended: a small program in pledge's bundle that `pledge serve` starts itself, holding no key and deciding nothing. The app's window may show the same question as a second place; the answer never depends on the app |

Two of these decisions add to what the sections above say:

- Question 6 widens section 3.4: the row for ad-hoc signed code may be
  admitted generally, by its hash.
- Question 9 adds a fact to the record: for a request that expired
  unasked, why it could not be asked. Section 2.2's error codes (check 2)
  and check 10 are where the key holder learns "locked" and "sensor locked
  out" from.

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

12. **One Mac app or two** (section 8.4).
    *Recommendation:* two apps from one Swift code base; preserve's app
    is admitted on `control.sock` for `keys.create` with purpose `bound`
    and `keys.list` only, which needs a rule per command and peer there.
    *Reason:* the program that shows requests should hold no updater and
    no backup code, and one identity for everything is the wider key.

13. **Take Atticus's SwiftUI front end at all**, against the web views
    that `crates/p-reserve/SPEC.md` recommends.
    *Recommendation:* yes for preserve's Mac app, on one condition: the
    logic still in Atticus's views and view models moves into the daemon
    first, and the socket protocols meet section 8.5. For pledge, take the
    frame; its content is new either way.
    *Reason:* about 4800 lines of working views and view models, most of
    them already behind protocols; what is dropped is the layer under the
    protocols, which the Rust programs replace anyway. The price is a
    second front end for Linux later, which is why the condition is
    strict. This overturns a recommendation in p-reserve's specification,
    so it is its designer's call.

14. **"Cancel by closing" in p-reserve's protocol.**
    *Recommendation:* closing a connection cancels only requests that were
    made as bound to it (browsing, a preview); a run, a prune or a restore
    goes on and is cancelled by a message.
    *Reason:* a backup must not stop because a window closed. This belongs
    in p-reserve's proposal; it is raised here because the front end
    depends on it.

15. **The licence of what is taken from Atticus.** Its `LICENSE` is
    proprietary, all rights reserved; p-ledge is `MIT OR Apache-2.0`.
    *Recommendation:* the owner decides before any view is copied, and the
    shared Swift package states the result.
    *Reason:* it cannot be decided by whoever does the copying.

16. **Where the dialog for a request lives** (section 8.6).
    *Recommendation:* a separate small program in pledge's app bundle that
    `pledge serve` starts itself, with one pipe and no connection to
    `control.sock`; the front end shows only that a question is open.
    *Reason:* a request can arrive with no app open, and the answer never
    depends on the app: the touch is the yes.

## 8. Atticus's SwiftUI front end as the Mac front end

The owner's question: can Atticus's front end become the Mac front end of
procession, with the Rust programs behind it. This part answers from the
code, tree `develop` at `a1ada83`. What of it I read and what I only
searched is in section 9; several panes I only searched, and the lists
below can miss a call.

### 8.1 What the front end is

| Layer | Where | Size |
|---|---|---|
| Views | `Sources/Views/Redesign/`, 15 files | about 3450 lines |
| View models | `Sources/ViewModels/`, 9 files | about 1400 lines |
| Service protocols | `Sources/Core/Services/`, 13 files | about 390 lines |
| Their implementations | `Sources/Core/Services/Live/`, 14 files | about 2000 lines |
| Values the layers pass | `Sources/Core/Domain/`, 41 files, Foundation only | about 3300 lines |
| Wiring | `Sources/App/ServiceContainer.swift`, `AtticusApp.swift` (one `Window`, one `MenuBarExtra`) | |

A view builds its view model from the `ServiceContainer`; a view model
holds protocols (`BackupService`, `ConfigStore`, `SnapshotService`,
`SSHKeyService`, `HealthService`, `ScheduleStatusService`,
`ConnectionTestService`, `ImportService`, `UpdateService`, `DaemonService`,
`LoginItemService`, `SystemAccessService`, `ManagedConfigService`,
`SnapshotBrowserService`) and three small seams for the system
(`Pasteboard`, `AppActivator`, `SystemSettingsOpener`). A script,
`tools/check-layering.sh`, holds one boundary: `Core/Domain` imports
Foundation only and names nothing above it. It does **not** check that
views stay behind the protocols. Only one protocol has a second
implementation in the sources (`Mock/MockSnapshotBrowserService.swift`);
whether the tests bring others I did not look.

### 8.2 How clean the seam is

**Clean, as far as I read or searched:** the menu bar popover
(`MenuBarPopover.swift` with `MenuBarViewModel.swift`, both read: every
call goes to `BackupService`, `ConfigStore`, `ScheduleStatusService`,
`HealthService`, `UpdateService`, `AppActivator`), the overview, the
schedule pane, the snapshot list of the restore pane, and the key part of
the SSH pane (`SSHKeyViewModel.swift`: `SSHKeyService`, `ConfigStore`,
`Pasteboard`).

**Reaching past the protocols:**

| View or view model | Reaches | What that is |
|---|---|---|
| `SnapshotBrowserSheet.swift` (`@ObservedObject var browser: SnapshotBrowser`; calls `navigate`, `goUp`, `open(directory:)`, `open(file:)`, `refresh`, `restore(_:into:)`, `close`) and `RestoreViewModel.swift` (`activeBrowser: SnapshotBrowser?`) | `Sources/Engine/SnapshotBrowser.swift` | The engine class itself. It runs restic through `ProcessRunner`, reads `SSHAgentServer.socketPath` and the bundle's path, and imports AppKit. The protocol `SnapshotBrowserService` is only a factory: `makeBrowser()` returns this class. The seam here is the class's published surface, not a protocol |
| `SSHPane.swift` (`private let decisions: AgentDecisionLog`), `AccessHistorySheet.swift` (`AgentDecision`, `AgentPolicyTrace.Outcome`, `AgentDecisionLog.appName`) | `Sources/AgentDecisionLog.swift`, `Sources/AgentPolicyTrace.swift` | A concrete observable object, filled through two static hooks that `ServiceContainer.live()` sets (`AgentPolicy.traceSink`, `SSHAgentServer.signEventSink`). In memory only |
| `BackupPane.swift` (`private let excludeStore: ExcludeStore`, `excludeStore.reload()`), `OverviewViewModel.swift` (`let excludeStore: ExcludeStore`), `ExcludesEditorRedesign.swift` (`ExcludeRules`, eight uses; `FileManager.default.fileExists` to test a rule against the disk) | `Sources/ExcludeStore.swift`, `Sources/ExcludeRules.swift` | A concrete object that reads and writes the exclude file itself, and the rules for it |
| `RetentionRunner.swift` | `PruneRequest.write()`, `PruneRequest.clear()` (`Sources/Engine/PruneRequest.swift`) | A marker file for the daemon, written from the view-model layer |
| `BackupViewModel.swift` | `ExcludeRules.systemExcludes()`, `BackupConfig.defaultPruneIntervalHours` | Rules and a default, read directly |
| `GeneralViewModel.swift` | `catch let error as DaemonError` | An engine error type |
| `GeneralPane.swift` | the global `logPath`, `FileManager.default.fileExists`, `NSWorkspace.shared.open` | The log file's place, known to the view |
| `BackupPane.swift`, `GeneralPane.swift`, `MainWindow.swift`, `OverviewPane.swift` | `NotificationCenter.default.publisher(...)` | Which notifications, I did not read |

Using `NSOpenPanel` in a view (`SnapshotBrowserSheet.swift`,
`ExcludesEditorRedesign.swift`) is not counted: that is the view's own
business.

**The protocols themselves carry Atticus.** `ConfigStore` has the
repository password in the Keychain (`saveRepoPassword`,
`probeRepoPassword`, `rotateRepoPassword`), three switches of the SSH agent
that do not carry over (section 5, rows 12, 18, 19) and the locks of an
`.attic` profile. `SnapshotService.mount` is a FUSE mount, which
`crates/p-reserve/SPEC.md` leaves out of scope. `BackupService` hands out a
concrete observable object (`BackupMonitor`). Most getters are synchronous
and on the main actor (`info()`, `status()`, `current()`, `load()`): an
answer is expected at once, from memory or a file.

**The larger point.** What is behind the protocols is not a back end that
could be swapped. It is the program. The app's process *is* the SSH agent
(`LiveSSHKeyService.activate()` starts `SSHAgentServer` and sets the key);
it is the scheduler (`ScheduleRunner`, wired in `ServiceContainer.live()`);
it learns what a backup does by tailing a log file and polling every ten
seconds (`LiveBackupService`: `LogTailer`, a poll timer,
`BackupRunReducer`); it starts a run through `DaemonController`. So the
owner's memory is right for the direction that matters (most views know
only protocols) and the consequence is: the layer under the protocols is
not ported, it is dropped, about 2000 lines, and with it the parts of
`Core/Domain` that exist to read logs (`BackupRunReducer`,
`SchedulerLogScan`, `SchedulerTick`, `Gates`).

### 8.3 What it takes to put socket clients behind the protocols

Common to both programs:

- A Swift client for a Unix socket with one JSON object per line: requests
  with an identifier, answers and events matched by it, events as
  `AsyncStream`. One client type serves both sockets if both protocols
  keep the same envelope (`schema_version`, `type`, an identifier). Today
  `control.sock` calls it `ref` (`proposals/control-sock.md`, section 3);
  whatever p-reserve's proposal calls it, one word for both is worth
  agreeing now.
- The synchronous getters. Either the protocols become `async`, which
  touches every view model, or each client keeps the last state it was
  told and the getters read that. The second needs the daemon to push
  state: a `status` answer and events that keep it current. That is what
  section 8.5 asks of the protocols anyway.
- The three objects of section 8.2 that are not protocols
  (`SnapshotBrowser`, `ExcludeStore`, `AgentDecisionLog`) get one each,
  with the surface the views use today.

**`preserve`** (the daemon protocol is being proposed elsewhere; I have not
seen it, only its outline: requests with an identifier, answers and events
carrying it, progress as events, cancel by closing or by a message):

| Atticus protocol or object | Becomes |
|---|---|
| `BackupService.trigger`, `BackupMonitor` | a request to run; progress and the end as events into the monitor. `BackupRunReducer` and the log tailing go |
| `HealthService.current`, `.changes`; `ScheduleStatusService.status` | `status`, and events |
| `SnapshotService.list`, `.delete`, `.setPinned`, `.repositoryStatus`, `.initializeRepository` | requests. `.mount`, `.unmount` have no counterpart |
| `SnapshotBrowser` (list a level, preview a file, restore an item, cancel what the person left) | requests to list, dump and restore, each cancellable. The class's published surface (`currentPath`, `entries`, `listing`, `error`, `opening`, `restoring`, `restoreResult`) maps one to one. Read-ahead and "one restic at a time" (commit `f18f7f6`) are the daemon's concern then, or go: the daemon holds the repository open |
| `ConnectionTestService.test()` (a stream of stages) | one request whose events are the stages |
| `ConfigStore.load`, `.save…`; the repository password | reading and setting the daemon's configuration; the password through the daemon's own secret store (`crates/p-reserve/SPEC.md`, "Platforms") |
| `ExcludeStore`, `ExcludeRules`, `RetentionRunner` with `PruneRequest` | requests; the rules live in the daemon, once |
| `DaemonService`, `LoginItemService`, `SystemAccessService`, `UpdateService` | stay in the app: installing a job of launchd, the login item, Full Disk Access and the updater are the Mac app's own |
| `ImportService`, `ManagedConfigService` (`.attic` profiles) | a decision of p-reserve; not looked at |

**`pledge`** (`control.sock`, `proposals/control-sock.md`, section 4):

| Atticus protocol or object | Becomes |
|---|---|
| `SSHKeyService.info` | `keys.list` |
| `SSHKeyService.generate` (and "regenerate" behind a warning) | `keys.create`, `keys.retire`; the presence check is pledge's |
| `SSHKeyService.sshConfigSnippet` | the app's own text, with the socket path from `status` |
| `SSHKeyService.activate` | nothing: `pledge serve` is the SSH agent |
| `AgentDecisionLog`, the access history sheet | the record. `control.sock` has no command for it today (`pledge history` reads the file) and no events yet (`control-sock.md`, section 6, "later"). Both are needed (section 8.5) |
| the three SSH switches in `ConfigStore` | nothing |

For pledge that is one pane and one sheet. Everything else pledge needs to
show has no view in Atticus: programs (admit, block, forget), delegations
(start with groups and two ceilings, list, withdraw), the keys' block for
an administrator, requests that wait, and the dialog for a request. Atticus
gives pledge the frame (a window, a menu bar item, the router, the shared
components in `Components.swift`, the error alert) and little content.

Two more things that are not code:

- The licence (question 15, decided by the owner on 2026-11-18).
  Atticus's `LICENSE` begins "Copyright (c) 2026 C-IT-WORK GmbH. All rights
  reserved … proprietary"; `crates/p-ledge/Cargo.toml` says `MIT OR
  Apache-2.0`. Atticus is the owner's own, so its views may be taken into
  procession, and what results there is under `MIT OR Apache-2.0`; the
  shared Swift package states that licence. Atticus itself stays under its
  own. This settles the terms and is not a go: copying waits on the
  condition of question 13 and, for anything that touches keys, on hand
  checks 1 to 5.
- The views' texts are English keys with a German table
  (`Resources/de.lproj`), and some German is written into the views
  directly (`"Letztes Backup: …"` in `MenuBarPopover.swift`, `"Protokoll"`
  in `GeneralPane.swift`).

### 8.4 One Mac app or two

`crates/p-ledge/SPEC.md`, section 11, proposes one each;
`crates/p-reserve/SPEC.md` lists it as open and says that setup "stays one
flow in the desktop app although two programs are behind it".

**Decided by the owner on 2026-11-18: two apps from one code base.** A Swift package with
what both need (the socket client, the components, the window and menu bar
frame), and two targets:

- **pledge's app**: small. Keys, programs, delegations, the record, and the
  dialogs (section 8.6).
- **preserve's app**: Atticus's panes. For the one setup flow it is also a
  client of `control.sock`, for `keys.create` with purpose `bound`,
  `keys.list`, and nothing else.

Why not one:

- pledge's app is what shows a person what they are about to approve. It
  should hold as little else as possible. Atticus's app links an updater
  that fetches and installs code (`Sources/App/Updater.swift`, Sparkle);
  that belongs in a backup app and not in the process that shows requests.
- `control.sock` admits a peer by its code signature
  (`control-sock.md`, section 2). One identity that may do everything, from
  starting agents to pruning backups, is the wider key. With two apps the
  socket can admit preserve's app for two commands only. That needs a rule
  per command and peer in `control.sock`, which is not there today and
  is part of this decision.
- A person who approves requests and keeps no backup on that Mac needs
  pledge alone; p-reserve works with a key file where there is no pledge.

Why one would be tempting: one menu bar item, one thing to install. The
second target can still present itself inside the first later; the reverse
split is harder.

### 8.5 Linux: what the socket protocols must offer

SwiftUI ends at the Mac. Whatever is drawn on Linux later can only reuse
what crosses the sockets. So that a Linux desktop is not cornered:

1. **Everything a front end shows comes over the socket.** No front end
   reads a file of the daemon's: not the record, not a log, not the
   configuration, not an exclude file, not a marker file. Atticus's app
   does all of these. For pledge this means a command for the record
   beside `pledge history` reading the file.
2. **State, then events.** A `status` (and a list per noun) that gives the
   whole present state, and a subscription whose events are enough to keep
   it current. A client that connects late, or again, asks for the state
   and is right. No event is the only carrier of a fact.
3. **Codes and values, not sentences.** A front end words what it shows,
   in its language. The exceptions are the fields of a request and of a
   signing request, which are shown as they were signed.
4. **No nouns of one platform in the messages.** Not "Touch ID",
   "Keychain", "Full Disk Access", "launchd". Instead what they mean: "this
   key enforces presence itself", "a permission is missing: <code>", "the
   service is not installed". `status` already has `form` (`files` or
   `hardware`); it should say per key who performs the presence check.
5. **A dialog is a message, and the protocol says what an answer is
   worth.** An event "a question is open" with an identifier, a title as a
   code, the labelled fields whole, and the deadline; "closed" with the
   reason. Where the key enforces presence, whatever shows the dialog can
   say `decline` and never `approve` (section 8.6). Where it does not, the
   protocol says so, and an answer is then all there is. A FIDO2 token on Linux
   (`doc/approvals.md`, section 9) fits the first case unchanged: the touch
   is at the token.
6. **Long work has an identifier, progress as events, and a cancel; and
   closing a connection cancels only what was asked for that way.** A
   listing in the browser may end with its connection. A backup run or a
   prune must not stop because a window closed. "Cancel by closing", as
   the outline of p-reserve's protocol has it, needs this distinction
   (question 14).
7. **Several front ends at once.** The command line, a window and a tray
   item may be three processes on Linux. Events go to all; a question is
   answered once and the others are told it closed.
8. **Nothing rests on the peer's code signature alone.** Linux has none:
   there a peer is a user and a path. What the Mac guards by code
   signature, Linux must guard by a presence check or state as unguarded.
   The commands that widen something already have a check of their own
   (`control-sock.md`, section 4); keep that rule for every new command.
9. **A front end older or newer than its daemon.** `schema_version` and
   refusing unknown members are there. Add to `status` what this daemon
   can do, so that a front end hides what is missing instead of failing.
10. **Paths are the daemon's.** A restore target or an exclude rule is a
    path on the daemon's machine; a front end must not assume it can see
    it. This also keeps the view for a headless host, which
    `crates/p-reserve/SPEC.md` wants, possible.

Taking the SwiftUI front end is the third candidate of
`crates/p-reserve/SPEC.md` ("native per platform"), which that document
calls "tolerable only because the app holds no logic" and does not
recommend. The condition is therefore strict: the logic that Atticus's
views and view models still hold (section 8.2: exclude rules, the prune
marker, the reducer over the log) moves into the daemons before or with
the views, not after.

### 8.6 The dialog for a confirmed approval, in that app

Section 4.2 proposed a dialog process of pledge's own until the desktop app
exists. With an app, the question is whether the dialog can live there.

**It can live in that app's bundle, not in that app's process.** What ties
the answer to the signature does not move: it is the key. The confirmed
approval key enforces presence in the Secure Enclave; the Touch ID prompt
is raised by the key holder, with words that come from the reader (section
4.3). Whatever shows the request can say "decline" and has no way to say
"yes". A touch is the only yes.

**Which process: the dialog process of section 4.2 is a separate small
process, not the front end.** The front end (window, menu bar item, panes)
is one program; the dialog process is another, shipped in the same app
bundle and written with the same components. The reasons are those of
section 4.4, which wants the thing that shows requests to hold no key and
decide nothing:

- *It holds no key* either way: neither program has a key, and neither is
  the key holder.
- *It decides nothing* only if it also **does nothing else**. The front end
  is a client of `control.sock` that can start agents, set ceilings, admit
  programs and retire keys. A program that can ask for those things and
  also shows the request is two powers in one process: taken over, it
  could raise a ceiling and show the dialog that hides it. The dialog
  process has no connection to `control.sock` at all. It has one pipe, to
  `pledge serve`, over which it receives a `Description` and returns
  "declined" or "closed". There is nothing else it can say.
- *It is started by `pledge serve`*, not by the person and not by the
  front end, so a request is shown whether or not a window is open, and
  `pledge serve` knows which process it is talking to: its own child, not
  a peer of a socket to be identified.
- *It is small enough to read*: one window, no network, no updater, no
  settings, no state.

The front end may show the same question as a second place (decided,
question 16): read only. It takes no answer, and the answer never depends
on it. So section 4.2's proposal stands as it was, and this section adds
where the dialog process ships and what it is drawn with.

Conditions:

1. **The dialog must not depend on the person having opened an app.**
   `pledge serve` is a job of launchd; a request can arrive with no window
   open. The dialog process is started by `pledge serve` itself, speaking
   the `Dialogs` seam (section 6.3). If it cannot be shown, the request
   waits and expires (question 9, decided).
2. **It is pledge's app, not a shared one** (section 8.4), so that the
   program that shows requests has no updater and no backup code in it.
3. **`control.sock` sends a question's contents only to a peer it has
   identified** by audit token and code signature (section 3), since the
   app's window may show them. Until builds are signed (question 8) that
   check is the user and nothing more, and the document must say so. The
   narrower choice, events that say only that a question is open, would
   keep parameters from a front end altogether; it was my first answer
   and is not what was decided.
4. **`control.sock` gains what `control-sock.md`, section 6, left for
   later:** the subscription, with events that a question opened and
   closed. No answer travels over `control.sock`: declining is the dialog
   process's, over its pipe.

What Atticus offers for the dialog itself: nothing to take over. Its
confirmation of a signature is the system's Touch ID prompt with one
sentence (`AgentPolicy.authorize(reason:)`); there is no view for it. The
three SwiftUI confirmation dialogs in the app are the app asking about its
own acts: delete a snapshot (`RestorePane.swift`), clean up now
(`BackupPane.swift`), replace the key (`SSHPane.swift`). A dialog that
shows a request field by field, whole, with the agent's claim apart, is new
SwiftUI either way. The frame it sits in is Atticus's.

What an app that is taken over could and could not do is section 4.4,
unchanged: it can lie on the screen and decline; it cannot sign, cannot
cause a signature without a touch, and the Touch ID prompt's line (service,
host, action) does not pass through it.

One thing to see with eyes, **[U]**: the Touch ID prompt carries the name
of the program that uses the key, the key holder, and appears over the
app's dialog. The person then sees two program names for one act. The key
holder should be named so that it reads as pledge.

## 9. What was read, what was not; nothing was run

For section 8, in Atticus (`develop`, `a1ada83`). Read in full:
`Sources/Views/Redesign/MenuBarPopover.swift`,
`Sources/ViewModels/MenuBarViewModel.swift`,
`Sources/App/ServiceContainer.swift`,
`Sources/Core/Services/Live/LiveSSHKeyService.swift`, and the thirteen
protocol files in `Sources/Core/Services/` (comments left out). In part:
`SSHPane.swift` (lines 1 to 40, 160 to 183), `RestorePane.swift` (20 to
37), `BackupPane.swift` (115 to 125), `SSHKeyViewModel.swift` (the first 90
lines of code), `tools/check-layering.sh` (the first 80 lines), the first
lines of `LICENSE`. **Only searched**, for names of types declared outside
the views, for system calls and for how services are obtained: every other
view and view model, among them `OverviewPane.swift`, `SchedulePane.swift`,
`GeneralPane.swift`, `ImportSheet.swift`, `MainWindow.swift`,
`Components.swift`, `SnapshotBrowserSheet.swift` (its calls on the
browser), `ExcludesEditorRedesign.swift`; and of
`Sources/Engine/SnapshotBrowser.swift`, `Sources/ExcludeStore.swift`,
`Sources/AgentDecisionLog.swift` and `LiveBackupService.swift` the
declarations. The search took type names by a pattern and matched whole
words, comments included; a free function or a constant used by a view
(like `logPath`, found by a second search) can have escaped it. "Clean" in
section 8.2 means: that search found nothing. Not read: the other `Live`
implementations, `Sources/App/` beyond the container and the scenes of
`AtticusApp.swift`, the tests. The line counts are `wc -l`.

In this worktree, for section 8: `crates/p-reserve/SPEC.md`, the section
"The desktop app" and its neighbours read, the rest searched;
`proposals/control-sock.md`, section 4, read. The proposal for p-reserve's
daemon protocol I have not seen; what section 8 says of it is the outline
I was given.

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
`SECURITY.md` (lines 28 to 120). Commits, with `git show`: the messages
and file lists of `ee481a4`, `d534f23`, `343f9c8`, `f18f7f6` and
`e869251`; of the first three also the changes to `SSHAgent.swift`,
`SSHAgentServer.swift`, `AgentPolicy.swift`, `SSHSignDescription.swift`
and `ServiceContainer.swift`, not those to the tests, the host key and
session binding code or the views. Only searched: `Makefile` (for code
signing), `tests/MANUAL_CHECKLIST.md`, `tests/AtticImportTest.swift`.
Not read: `CLAUDE.md`, `README.md`, `SPEC.md`, `SSHSignContent.swift`,
`SSHSessionBinding.swift`, `SSHHostKey.swift`, `SSHAgentForwarder.swift`,
`SSHAgentIdentityProvider.swift`, `Sources/SSHCertificate.swift`,
`AgentPolicyTrace.swift`, `AgentDecisionLog.swift`, the views; rows 11,
19, 20 and 21 of section 5 rest on file names, on references from the
files I read and on `SECURITY.md`. No `secrets/` directory and no `.env`
file was opened. Nothing there was changed, built or checked out; the
commands were `git branch -a`, `git log --all --oneline`, `git status
--short`, `git show`, and reading files.

No Apple documentation and no header was looked up. Every **[D]** is from
memory, every **[U]** is a belief. Not checked at all: the names
`LOCAL_PEERTOKEN`, `kSecGuestAttributeAudit` and
`SecCodeCopySigningInformation`.

Added on 2026-11-18 with the checks program
(`stage2-mac-checks/sechecks.swift`): that file was type-checked against
the SDK (`swiftc -typecheck`, Swift 6.3.3, SDK 26.5; no binary written,
nothing run). So these names now exist as used, where before they were
from memory: `SecureEnclave.P256.Signing.PrivateKey(accessControl:)` and
`(dataRepresentation:authenticationContext:)`, the flags `.biometryAny`,
`.biometryCurrentSet`, `.userPresence`, `LAContext.localizedReason`,
`touchIDAuthenticationAllowableReuseDuration` and `invalidate()`. What they
do is still for the hand checks to show.

Nothing was run: no build of a binary, no test, no `ssh-keygen`, no
program that makes or uses a Secure Enclave key, no Touch ID prompt.
