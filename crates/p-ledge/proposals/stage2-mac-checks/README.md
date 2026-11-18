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
swiftc -O sechecks.swift -o sechecks
swiftc -O -D OTHER sechecks.swift -o sechecks-other
codesign -dv ./sechecks 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier'
codesign -dv ./sechecks-other 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier'
```

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
| 0 | | The five `make` lines above | Whether any `make` shows a prompt (expected: none), and whether all five print `MADE` | |
| 1a | 1 | `./sechecks sign plain` | `SIGNED`, no prompt | |
| 1b | 1 | `./sechecks sign touch` and touch | A Touch ID prompt; `SIGNED` only after the touch. Copy the prompt's whole text, with the program name it shows | |
| 1c | 1 | `./sechecks sign touchpw` and touch | The same. Whether the prompt offers "Use Password" | |
| 2a | 2 | `./sechecks sign touch`, press Cancel | `NOT SIGNED`; the `domain` and `code` | |
| 2b | 2 | `./sechecks sign touch`, do nothing | How many seconds until it ends by itself, if it does (wait 5 minutes at most); `domain` and `code` | |
| 2c | 2 | `./sechecks sign touch --invalidate-after 10`, do nothing | The prompt closes after 10 s; `NOT SIGNED`; `domain` and `code`. If the prompt stays: a dialog cannot be closed at a deadline this way | |
| 2d | 2 | `./sechecks sign touch`, use a wrong finger three times | What the prompt does; `domain` and `code` | |
| 3a | 3 | `cp -R sechecks-keys copy-keys` then `./sechecks-other --dir copy-keys sign plain` | `SIGNED` means: any program of yours can use a copied key that has no presence check. `LOAD FAILED` or `NOT SIGNED` means it cannot: copy the error | |
| 3b | 3 | `./sechecks-other --dir copy-keys sign touch` and touch | Whether a prompt appears, **which program name it shows**, and whether it signs | |
| 3c | 3 | `./sechecks-other --dir sechecks-keys sign plain` (the original files, the other program) | The same as 3a; tells a copied file from another program | |
| 4a | 4 | `./sechecks twice touch fresh`, touch each time asked | Two prompts, two `SIGNED` | |
| 4b | 4 | `./sechecks twice touch shared`, touch each time asked | One prompt or two. One means: a context that is kept signs again without the person | |
| 5a | 5 | `./sechecks reason touch 60`, look, then touch or cancel | Whether the prompt shows the text up to `END` | |
| 5b | 5 | `./sechecks reason touch 200` | The same; if cut, the last word shown | |
| 5c | 5 | `./sechecks reason touch 600` | The same; whether the prompt grows, scrolls or cuts | |
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
name in the source exists with the argument labels and types used. No
binary was built by the author, so the `swiftc -O … -o …` lines of section
3 are untried; a failure there would be a linker matter, not an API one.

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
