# Hand checks for keys in the Secure Enclave

A throwaway program, `sechecks.swift`, and the steps for a person to run on
a Mac with Touch ID. It answers the checks of `../stage2-mac.md`, section
1.5: checks 1 to 5, which decide the design, and those others that cost
little once the program exists (6, 7, 10, 11, 12, 14, 15, 16). Checks 8, 9
and 13 need an SSH agent socket or a CA and are not here.

The program is not part of pledge. Nothing is built on it. Delete this
directory's products when done (section 5).

## 1. What was and was not done by its author

- **Never run.** No key was made, no Touch ID was asked for.
- **Type-checked: see section 6.** Type-checking reads the SDK's interface
  files and touches no key.
- So every *name* the program uses exists with the types it expects, if
  section 6 says the check passed. What each call *does* is not verified:
  that is what the checks are for. Each such call is marked `API:` in the
  source with what is expected of it.

## 2. Language, and why

Swift, one file, compiled with `swiftc`. CryptoKit's `SecureEnclave` and
LocalAuthentication are Swift and Objective-C interfaces; Atticus uses the
same calls (`Sources/Engine/SEPKey.swift` there); a later key holder for
pledge would be Swift as well. One file needs no Xcode project: the Command
Line Tools are enough.

The binary is ad-hoc signed by the linker, as every local build on Apple
silicon is. It has no entitlements and is not in a bundle. Making and using
a Secure Enclave key through CryptoKit, with the key kept as a blob in a
file, is expected to need neither. If `make` fails with an error about a
missing entitlement, that is itself a finding: write the error down, and
the checks then need a signed app (section 7).

## 3. Build

In this directory:

```
swiftc -Onone sechecks.swift -o sechecks
swiftc -Onone -D OTHER sechecks.swift -o sechecks-other
codesign -dv ./sechecks 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier'
codesign -dv ./sechecks-other 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier'
```

**The first compile takes minutes and prints nothing; later ones take
seconds. The source is not the cause, and it was not changed.** Reported
on 2026-11-18: on the owner's Mac the build finished after a long wait; in
the designer's session `swiftc -typecheck` did not finish within four
minutes. What I measured, on this Mac (Apple Swift 6.3.3, Command Line
Tools, SDK 26.5), without running the program:

| What | Module cache | Wall time |
|---|---|---|
| `swiftc -typecheck` of a **five-line file** with the same four imports and `print(1)` | empty | **330 s**; for the first 254 s the cache directory held only a lock for the standard library's module |
| `swiftc -typecheck sechecks.swift`, my first one (the one reported as "exit 0") | empty | more than 5 minutes: it outran a two-minute limit and went on in the background; I did not time it to the second |
| `swiftc -typecheck sechecks.swift` | built | 2.4 s |
| `swiftc -Onone sechecks.swift -o …` (full build with linking) | built | 3.0 s |
| `swiftc -O sechecks.swift -o …` (full build with linking) | built | 19 s |

The two full builds wrote binaries into a temporary directory. They were
not run.

- **The cause is the toolchain's module cache.** These Command Line Tools
  ship no prebuilt modules
  (`/Library/Developer/CommandLineTools/usr/lib/swift/macosx/prebuilt-modules/`
  is empty here), so the first Swift compile of any file builds the
  modules of the standard library, Foundation, CryptoKit and what they
  import from their interface files: about 20 modules, 120 MB, five to six
  minutes, silent. The five-line file shows that it is paid whatever the
  source is. It is paid once per cache directory.
- **No expression in the source is slow.** With `-Xfrontend
  -warn-long-expression-type-checking=50 -Xfrontend
  -warn-long-function-bodies=50` (both flags exist in this toolchain) the
  compiler names nothing: no expression and no function body takes 50 ms.
  There is no large literal, no nested ternary; the longest expression is
  a sum of five `Data` values.
- **So nothing was split, and `sechecks.swift` is byte for byte what the
  owner built.** His results for checks 0 and 3 stand for this source;
  nothing needs running again.
- **For the owner** the cache is built now: a rebuild takes seconds.
- **For a session that cannot write the default cache** (a sandbox: here
  the default one under `/var/folders/…/C/clang/ModuleCache` was refused
  with "Operation not permitted"), give the compiler a directory that
  lasts: `swiftc -module-cache-path <dir> …`. The first compile there
  takes the five to six minutes; a limit of four cuts it off each time and
  it starts again from nothing, which is what "did not finish" looks like.

Build with `-Onone`, as above: it is the faster of the two and loses
nothing (below). To see a first compile working, in a second terminal:

```
du -sh "$(getconf DARWIN_USER_CACHE_DIR)clang/ModuleCache"
```

The number stays small for about four minutes (the standard library's
module is built in memory first) and then grows to about 120 MB. Adding
`-v` to the `swiftc` line prints the compiler's steps.

**`-Onone` is a sound substitute for these checks.** They observe what the
frameworks and the Secure Enclave do: whether a prompt appears, which error
comes back, whether a signature verifies. The same framework calls are made
with the same arguments either way; optimisation changes only the speed of
this program's own few lines. The seconds the program prints are waits for
a person, not measurements.

`sechecks-other` is the same program built as "another program" for check
3: other name, other bytes. The two `codesign` lines should show
`Signature=adhoc`, no team, and two different identifiers. Write down what
they show.

**If it does not compile:** an error at a line marked `API:` means that
this name or signature is not what I remembered, and the matching sentence
in `../stage2-mac.md` (marked [D] there) is wrong as written. Do not work
around it silently: note the line and the compiler's message in the table.
The likely places, and what an error there would mean:

| Line marked | If it does not compile |
|---|---|
| `PrivateKey(accessControl:)`, `PrivateKey(dataRepresentation:authenticationContext:)` | CryptoKit's initialisers differ. Without a context at load there is no way to give the prompt its words or to end it: sections 2.2 and 4.3 of the proposal need another route (the Security framework's `SecKey` calls) |
| `.biometryAny`, `.biometryCurrentSet`, `.userPresence` | the flag names differ; question 1 is about the same choices under other names |
| `localizedReason`, `touchIDAuthenticationAllowableReuseDuration`, `invalidate()` | the prompt's text, the rule "no reuse" or closing a prompt at the deadline has no such call on macOS; section 2.2 changes |

## 4. The checks

Run from a normal Terminal window in your own session, except where a step
says otherwise. Every line the program prints starts with its name; the
ones to copy into the table are `MADE`, `SIGNED`, `NOT SIGNED` (with the
`error domain=… code=…` after it) and `LOAD FAILED`.

Make the keys first. Each `make` prints an OpenSSH public key line; keep
them.

```
./sechecks make plain    none     after-first-unlock
./sechecks make locked   none     unlocked
./sechecks make touch    biometry unlocked
./sechecks make touchpw  presence unlocked
./sechecks make touchset biometry-set unlocked
```

| # | Check of section 1.5 | Do | Observe | Result |
|---|---|---|---|---|
| 0 | | The five `make` lines above | Whether any `make` shows a prompt (expected: none), and whether all five print `MADE` | **Owner, 2026-11-18:** all five printed `MADE`, each with an `ecdsa-sha2-nistp256` public key line and a blob under `sechecks-keys/`. No prompt during `make`. No entitlement error |
| 1a | 1 | `./sechecks sign plain` | `SIGNED`, no prompt | **Owner, 2026-11-18:** signed, no prompt |
| 1b | 1 | `./sechecks sign touch` and touch | A Touch ID prompt; `SIGNED` only after the touch. Copy the prompt's whole text, with the program name it shows | **Owner, 2026-11-18:** a prompt "sechecks trying to sign ..."; signed after the touch. Later the same day: the prompt's text was as expected (not pasted) |
| 1c | 1 | `./sechecks sign touchpw` and touch | The same. Whether the prompt offers "Use Password" | **Owner, 2026-11-18:** signed; and, reported later the same day, the prompt did offer "Use Password" |
| 2a | 2 | `./sechecks sign touch`, press Cancel | `NOT SIGNED`; the `domain` and `code` | **Owner, 2026-11-18:** `NOT SIGNED touch after 12.0 s: error domain=com.apple.LocalAuthentication code=-2 ... Canceled by user.` |
| 2b | 2 | `./sechecks sign touch`, do nothing | How many seconds until it ends by itself, if it does (wait 5 minutes at most); `domain` and `code` | not run |
| 2c | 2 | `./sechecks sign touch --invalidate-after 10`, do nothing | The prompt closes after 10 s; `NOT SIGNED`; `domain` and `code`. If the prompt stays: a dialog cannot be closed at a deadline this way | **Owner, 2026-11-18,** run with `--invalidate-after 2`: `invalidating the context now`, then `NOT SIGNED touch after 2.1 s: error domain=com.apple.LocalAuthentication code=-9 ... Invalidated by client.` |
| 2d | 2 | `./sechecks sign touch`, use a wrong finger three times | What the prompt does; `domain` and `code` | not run |
| 3a | 3 | `cp -R sechecks-keys copy-keys` then `./sechecks-other --dir copy-keys sign plain` | `SIGNED` means: any program of yours can use a copied key that has no presence check. `LOAD FAILED` or `NOT SIGNED` means it cannot: copy the error | **Owner, 2026-11-18:** `sechecks-other: SIGNED plain after 0.0 s`. No prompt |
| 3b | 3 | `./sechecks-other --dir copy-keys sign touch` and touch | Whether a prompt appears, **which program name it shows**, and whether it signs | **Owner, 2026-11-18:** a Touch ID prompt appeared and named the other program (his words: "eine touch id anfrage von sechecks other (trying to sign 32 bytes)"); after the touch, `sechecks-other: SIGNED touch after 2.6 s` |
| 3c | 3 | `./sechecks-other --dir sechecks-keys sign plain` (the original files, the other program) | The same as 3a; tells a copied file from another program | |
| 4a | 4 | `./sechecks twice touch fresh`, touch each time asked | Two prompts, two `SIGNED` | **Owner, 2026-11-18:** two prompts; `SIGNED first after 3.0 s`, `second after 1.4 s` |
| 4b | 4 | `./sechecks twice touch shared`, touch each time asked | One prompt or two. One means: a context that is kept signs again without the person | **Owner, 2026-11-18:** **one** prompt; `SIGNED first, shared context after 1.4 s`, `SIGNED second, shared context after 0.0 s` |
| 5a | 5 | `./sechecks reason touch 60`, look, then touch or cancel | Whether the prompt shows the text up to `END` | **Owner, 2026-11-18:** shown whole |
| 5b | 5 | `./sechecks reason touch 200` | The same; if cut, the last word shown | **Owner, 2026-11-18:** shown through `END` |
| 5c | 5 | `./sechecks reason touch 600` | The same; whether the prompt grows, scrolls or cuts | **Owner, 2026-11-18:** cut inside `word67` (characters 511 to 516 of the text) |
| 6 | 6 | `./sechecks pub touch > touch.pub; ssh-keygen -l -f touch.pub` | No prompt for `pub`; a fingerprint, `(ECDSA)`, 256 | |
| 7a | 7 | `echo hello > msg; ./sechecks sshsig touch approval-v1@procession msg`, touch; then `echo "jan:confirmed namespaces=\"approval-v1@procession\" $(cat touch.pub)" > allowed; ssh-keygen -Y verify -f allowed -I jan:confirmed -n approval-v1@procession -s msg.sig < msg` | `Good "approval-v1@procession" signature for jan:confirmed` | |
| 7b | 7 | `echo hellp > msg2; ssh-keygen -Y verify -f allowed -I jan:confirmed -n approval-v1@procession -s msg.sig < msg2` | Refused | |
| 7c | 7 | Repeat 7a twenty times with the key `plain` (no touch needed): `./sechecks pub plain > plain.pub`, an `allowed` line for it, then a loop over `sshsig plain …` and `ssh-keygen -Y verify` | Twenty times `Good`. One failure means the number encoding is wrong for some signatures | |
| 10a | 10 | `./sechecks sign plain --delay 15`, lock the screen within the 15 s (Ctrl-Cmd-Q), unlock after 30 s and read | `SIGNED`: a key "after first unlock" works behind the lock | |
| 10b | 10 | The same with `locked` | `SIGNED` or `NOT SIGNED`: whether "when unlocked" means the screen lock on a Mac at all | |
| 10c | 10 | The same with `touch`; do not touch while locked | Whether it failed at once (seconds in the line), waited for the unlock and then prompted, or showed a prompt on the lock screen | |
| 11 | 11 | From another machine: `ssh <this Mac>`, `cd` here, `./sechecks sign plain`, then `./sechecks sign touch` | For `plain`: `SIGNED` or not. For `touch`: whether a prompt appears on the Mac's screen, or `NOT SIGNED` with which `code` | |
| 12 | 12 | Lid closed, external display and a keyboard without Touch ID: `./sechecks sign touch`, then `./sechecks sign touchpw` | `touch`: `NOT SIGNED`, which `code`, at once or after a wait. `touchpw`: a password prompt | |
| 14 | 14 | `rm sechecks-keys/plain.blob; ./sechecks --dir copy-keys sign plain` | `SIGNED` means: deleting a key file does not end the key while a copy exists | |
| 15 | 15 | Add a finger in System Settings, then `./sechecks sign touch` and `./sechecks sign touchset` | `touch` signs; `touchset` does not: its `code` | |
| 16 | 16 | Restart, log in with the password, then `./sechecks sign plain` and `./sechecks sign touch` | Whether each signs, and whether `touch` asks for the password before it accepts a finger | |

Check 15 changes your enrolled fingers; do it last or leave it out. Check
16 costs a restart.

### Results so far

Run by the owner on his Mac on 2026-11-18, from this source as it is on
`integration`; relayed by the designer. They are his observations, not the
author's. Not yet run: 2b, 2d, 3c, and 6 to 16.

- **Check 0.** An ad-hoc signed command line program without a bundle and
  without entitlements can make and use Secure Enclave keys through
  CryptoKit, in all five protections tried. Making a key raises no prompt.
- **Check 3a.** Another program of the same user, with another ad-hoc
  signature, loads a copied blob of a key without a presence check and
  signs with it, at once and unasked. The blob file is the key.
- **Check 3b.** The same other program can use a copied blob of a key with
  Touch ID. The system then asks for the touch **in that program's name
  and with that program's words**, and signs after it. The presence check
  holds (no signature without the touch); who is asking is told only by
  the prompt.

- **Checks 1a, 1b.** Keys with and without a presence check exist side by
  side and each behaves as made.
- **Check 1c.** A key made with `.userPresence` offers "Use Password": it
  falls back to the account password.
- **Check 2.** The person's cancel is code -2, the program's own closing
  of the prompt is code -9 (`com.apple.LocalAuthentication`). A prompt
  can be closed at a deadline.
- **Check 4.** With a fresh context each, two signatures need two touches.
  **With one kept context, the second signature needs none.**
- **Check 5.** The prompt showed between 510 and 515 characters of the
  program's text.

What follows from them is in `../stage2-mac.md`: section 1.6 (the results),
section 2.2 (the rule that no context is kept, the four endings, the
budget for the prompt's words) and section 6.5 (what must be tested).

## 5. What it leaves on the machine, and how to remove it

| Step | Creates |
|---|---|
| build | the files `sechecks` and `sechecks-other` in this directory |
| `make` | one Secure Enclave key per call, and one file `sechecks-keys/<name>.blob` (mode 0600, directory 0700) that holds it in wrapped form |
| check 3a | `copy-keys/`, a copy of those files |
| checks 6 and 7 | `touch.pub`, `plain.pub`, `msg`, `msg2`, `msg.sig`, `allowed` |
| check 15 | a finger in System Settings, which you remove there |

The program writes nothing else: no keychain item, no settings, no file
outside the directory it is run in (or the one given with `--dir`). That
the wrapped blob is all there is of a key, and that no keychain item
exists, is what I expect of CryptoKit and could not verify. To see for
yourself after `make`: open Keychain Access and search for "sechecks"; or
`security find-key -l sechecks 2>&1 | head` (expected: nothing found).

To remove everything:

```
rm -rf sechecks-keys copy-keys sechecks sechecks-other touch.pub plain.pub msg msg2 msg.sig allowed
```

With the blobs gone the keys cannot be used again by anyone; the Secure
Enclave keeps nothing that could be listed or would need deleting, as far
as I know. The public keys printed were entered nowhere.

Git: none of these products belongs in the repository. `git status` in
this directory should show nothing but what was there before.

## 6. Type-check

Done on 2026-11-18, on the owner's Mac, by the author's tooling:

```
swiftc -typecheck sechecks.swift
swiftc -typecheck -D OTHER sechecks.swift
```

Both ended with exit 0 and no message, with Apple Swift 6.3.3, target
`arm64-apple-macosx26.0`, SDK 26.5. (The compiler's module cache was put in
a temporary directory with `-module-cache-path`, because the default one
was not writable from where this ran; that changes nothing in the result.)

`-typecheck` parses the file and checks every name and type against the
SDK. It writes no binary, links nothing and runs nothing. So: every `API:`
name in the source exists with the argument labels and types used. 

Later the same day, to look into the slow build (section 3), two object
files were also written into a temporary directory (`swiftc -Onone
-emit-object` and `swiftc -O -emit-object`): both ended with exit 0.
Nothing was linked and nothing was run, so the linking step of section 3's
build lines is still untried; a failure there would be a linker matter, not
an API one.

## 7. Check 3 and the keychain with an access group

Check 3 as written needs no bundle and no signing: it asks whether a key
kept as a blob in a file can be used by another ad-hoc signed program of
the same user. That is the question that decides (question 2 of the
proposal).

The other side, a key that only pledge's own signed programs can use,
cannot be tried with this program. It means a key made through the
Security framework's `SecKey` calls and stored in the data protection
keychain under an access group, and that needs:

1. an app bundle (a command line tool alone cannot carry the entitlement in
   a way the system accepts);
2. the entitlements `keychain-access-groups` and an application identifier
   with the team's prefix;
3. a signature with a Developer ID (or development) certificate of that
   team, and a provisioning profile that grants those entitlements,
   embedded in the bundle.

Atticus's signing (`Makefile`, `CODESIGN_FLAGS`; `Resources/Atticus.entitlements`)
has the certificate and the hardened runtime but no `keychain-access-groups`
entry, and I did not find a provisioning profile there. So this is new
work with an Apple developer account, not a variation of Atticus's build.
It is worth doing only if check 3a comes out as expected (`SIGNED`), and
then as its own check with its own small app, after the designer has
decided question 2.
