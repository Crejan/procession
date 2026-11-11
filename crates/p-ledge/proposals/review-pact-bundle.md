# Review of the `pact` bundle (option B), from pledge's side

Reviewer: the p-ledge agent. Reviewed: `crates/p-act/proposals/pact.md`
(section 2, and "Not decided" (d)), taking option B as decided: line 1 one
JSON object (`v`, services, settings, the TLS root); then the agent's key as an
unmodified OpenSSH private key block; then the certificate line; unknown
members refused; at most 64 KiB. Also taken as given: the agent's key is
Ed25519 always, the certificate has the person as its only principal, is
issued as `-O clear`, and carries the groups in `groups@procession`.
This concerns step 3 (`agents.start`); nothing is built.

**Verdict.** pledge can write exactly this, and option B suits it. What it
does not have today is the services list (host, name, url) and, in stage 2,
the way to get it. The shape leaks the key in two places that are about
delivery, not format (sections 3 and 4), and both are closed by a change to
`control-sock.md` that I propose in section 5.

## 1. Can `agents.start` produce exactly this?

At the moment `pledge agents start` has its answers pledge holds: the person's
groups and the two ceilings, the validity, the delegation key (after the
presence check), and in stage 2 the registration at the broker.

| Part of the bundle | Where it comes from | Remark |
|---|---|---|
| the Ed25519 key, as an OpenSSH private key block | pledge makes a seed from the system's random source and writes `openssh-key-v1` (cipher `none`, kdf `none`, one key, two equal check integers, `ssh-ed25519`, public key, 64 bytes seed and public key, an empty or fixed comment, padding to 8) | About forty lines in p-ledge, not `ssh-keygen`: the delegation key is in the key holder (in hardware, later), so `ssh-keygen -s` has no file to sign with. Tested by `ssh-keygen -y -f` (must print the public key) and by `p_act::sign` |
| the certificate line | pledge builds the OpenSSH user certificate (type 1, one principal, validity, `-O clear`: no permit extensions, critical options empty, extension `groups@procession`), and asks the key holder to sign the bytes with the delegation key | The holder signs bytes it is given and parses nothing, as for every other signature. Delegation key Ed25519 or P-256; the certificate's signature is of that type. Tested by `ssh-keygen -L` and `p_act::sign::signature_agent` |
| line 1: `v`, `deadline_seconds` | `v` is fixed; `deadline_seconds` from pledge's setting, at most 600 (R7's ten minutes) | pledge also refuses a call with a deadline beyond that, so the two bounds cannot drift: one constant in `p-act` would do |
| line 1: `min_wait_seconds` | not written | pact.md already says the floor is for tests; I agree it must not be a bundle member (below) |
| line 1: `services`, `tls_root` | not known today | section 2 |

So: yes, from what it has, plus the services. The key never exists as a file
in pledge: it is made in memory of the reader, written, and the reader keeps
the public part and the certificate, not the key (`SPEC.md`, section 4).

The one thing I ask of the format: **spell out the exact bytes.** Line 1, then
`\n`; the key block exactly as `ssh-keygen` writes it, ending
`-----END OPENSSH PRIVATE KEY-----\n`; the certificate line, then `\n`;
nothing after. Then pact can refuse anything that does not parse as exactly
this, and pledge's output is testable by comparing `pact`'s parse with the
parts.

## 2. What pledge must know about services

The bundle's `services` are the only services the agent will talk to: host,
name, `url`; and `tls_root` for `https`. pledge does not know any of this
today. It knows the person's *groups*, not services.

- **Stage 1** (one machine, no broker, no site): nothing to ask. The person
  tells pledge, in a file in the state directory the person owns
  (`agent-services.json`, the same members as `services` and `tls_root`) or by
  options of `pledge agents start` (`--service host/name=url`). `http` on
  loopback and no root is what stage 1 uses. This is configuration, and it is
  the person's: nothing in it comes from the model.
- **Stage 2** (a broker, a Mac): three different facts.
  - *Which services exist for these groups*: the broker knows (the site
    project's service types name the groups that may use them, `approvals.md`
    section 10, "Open"). pledge could receive the list, with the groups, in its
    standing (the names of the person's groups already arrive that way).
  - *Where the sandbox reaches a service* (`url`): this depends on how the
    sandbox is networked, not on the site project. It must not come from the
    broker, because a url the broker names is where the agent sends its call
    (action, parameters, claim). A taken-over broker already sees who asks
    for what, so this is not a new exposure, but it is a new way to redirect
    the agent. *Proposal:* the url comes from the person's own configuration in
    pledge (a template or a per-host entry), checked against the host and name
    the broker lists; a service the broker lists and the person has no url for
    is left out of the bundle, with a line telling the person.
  - *The TLS root*: pledge already has it, to verify the broker's own
    certificate (`SPEC.md`, section 4, "The broker"). The same root goes into
    the bundle. If services use another root than the broker, that is a second
    setting; I would not allow it in the first version.
- In both stages pledge **checks** what it writes: each `host` and `name`
  must match the grammar of the formats (the call's `service.host` and
  `service.name`), and `url` must be `http` or `https` with no credentials,
  so a bundle pledge writes is one pact accepts. A request for a bundle with
  no services is refused (`bad-arguments`).

*Open for the designer:* whether the services list in stage 2 is the broker's
alone, the person's configuration alone, or the broker's list narrowed by
the person's configuration as proposed above.

## 3. Does the shape make it easy to leak the key?

Format: no worse than any private key file. Option B is better than option A
on one point I care about: line 1 can be logged and checked without the key.
Where it can go wrong is delivery.

1. **A partial write.** The bundle goes to standard output, into an SSH
   connection or a pipe. If the connection breaks after the key block and
   before the certificate, the key has left and the delegation exists. The
   certificate is not a secret (pledge records it, and in stage 2 the broker
   holds it), so *key alone* is as good as *key and certificate* to whoever
   has the key. A truncated bundle is harmless to pact (it refuses it) and
   harmful if what was cut is only the end.
   - pledge writes the bundle **once, from one buffer**, only when it has all
     of it, and treats a short write or an error as a failure.
   - A failed write **withdraws the delegation at once** (stage 2: and tells
     the broker) and records it. That is what section 5's `delivered` step
     does.
   - Key first or certificate first does not change this; it must not be
     reordered for it.
2. **Where it is written.** A terminal puts the key in scrollback; a file is
   readable by whoever can read it. `pledge agents start` refuses to write
   the bundle to a terminal (a `--to-terminal` option would be for a person
   who knows), and when told `--output FILE` creates the file exclusively,
   mode 0600, and deletes nothing it did not create.
3. **A log line.** The key crosses `control.sock` and the command line's
   memory. In pledge: a type for the key bytes whose `Debug` and `Display`
   print nothing, that is zeroed on drop, and that is never `Serialize`d
   except by the one function that writes the reply; `pledge serve` logs and
   records no reply (the record holds the delegation's identifier, the
   fingerprint of the agent's key, the groups, the ceilings; never the key).
   The same rule in `p-act`'s `Bundle` (see 5): the key is a field whose
   `Debug` redacts.
4. **A command line or the environment.** Nothing in this shape puts the key
   there; `pledge agents start` takes no key option. Keep it so.
5. **`min_wait_seconds` in a production bundle.** A person should not be able to
   set the wait to one second by accident. pledge never writes it; pact should
   refuse it unless started in its test mode. (This is pact's side; I agree
   with pact.md's own suggestion.)
6. **A bundle that is kept.** Output to a file leaves the key on disk until
   the person deletes it, and the delegation ends in at most 24 hours
   (`approvals.md`, section 7) whatever happens to the file. The 24-hour limit
   is the real bound; the person withdraws with `pledge agents withdraw`.
7. **Two keys' worth of risk in one process.** The reader makes the agent's
   key in its memory. That weakens "the process that holds the keys parses
   nothing" slightly: the agent's key is not one of pledge's keys, it is
   short-lived and narrow, and it is meant to leave. The delegation key stays
   in the holder.

## 4. The size and the line

64 KiB is far more than needed (key block about 400 bytes, certificate about
700, the TLS root 1 to 3 KiB, a service about 100). It is there to stop a
reader being fed without end. pact reads line 1 with a limit of its own
(`control.rs`'s rule of 96 KiB per line applies here too in spirit: a first
line that does not end in 64 KiB is refused). Line 1 holds the root as a JSON
string with `\n` escaped; no raw line break.

## 5. How this fits `control-sock.md`

`control-sock.md`, section 4, has `agents.start` return `key` and
`certificate` in its reply, and the command line writes them to standard
output or a file. With option B, three changes, and one open point:

1. **The reply carries the key and the certificate as bytes, base64** (the
   workspace rule: a document or signature carried inside another is the
   base64 of its exact bytes): `key_block` (exactly the OpenSSH block) and
   `certificate` (exactly the line). Not as JSON strings with escaped line
   breaks.
2. **Who composes the bundle.** *Proposal:* the command line. It knows the
   person's services configuration (section 2) and the TLS root file; `pledge
   serve` knows the delegation. The command line calls `p_act::pact::Bundle`
   (the function pact.md proposes) with the services, the settings and the two
   byte strings, and writes the result. The key therefore crosses the socket
   once and is not interpreted on the way. The alternative, `serve` composing
   the whole bundle, puts services configuration in the daemon and makes the
   reply bigger, with no gain.
3. **A second step, `agents.delivered`.** `agents.start` replies with the
   key; the command line writes the bundle; then it sends `agents.delivered
   {delegation}`. If the connection closes, or the command line says
   `agents.failed`, before that, `pledge serve` withdraws the delegation, tells
   the broker (stage 2), and records `delegation-withdrawn` with `by`
   `delivery-failed`. Until then the delegation is `pending` and signs
   nothing: **R8 requires "not withdrawn", and a pending delegation counts as
   not yet issued** for request checks. This closes the partial-write leak of
   section 3: a bundle that did not arrive is a delegation that ends at once.
   It costs one more command and one more state.
4. **Open (designer):** whether the delegation exists for calls only after
   `delivered`. *Proposal:* yes. A delay of one round trip is nothing against
   a leak.

Also: `agents.start` already needs a presence check (a delegation, R3); that
stays before the key is made. The key's lifetime in pledge's memory is from
creation to the end of writing the reply; it is zeroed after.

## 6. What I need from pact and p-act

- The exact bytes of the bundle (section 1) in `pact.md`, and `Bundle` as
  `Bundle::write(&Settings, &[Service], tls_root: Option<&str>, key_block:
  &[u8], certificate: &str) -> Result<Vec<u8>>`, the key as opaque bytes whose
  type redacts `Debug`.
- A decision on `min_wait_seconds` (not a member; a test option).
- A shared constant for the call deadline's maximum, so `deadline_seconds`
  and pledge's refusal use one.
- For step 3, from `p_act::sign`: the checks `pledge` runs on the certificate
  it just made (the `signature_agent` rules, applied to its own output before
  it is handed over), so that a malformed certificate is never given out.

## 7. Questions for the designer

1. Services in stage 2: the broker's list, the person's configuration, or the
   broker's list narrowed by the person's configuration (section 2).
2. A pending delegation until `delivered` (section 5, points 3 and 4).
3. Writing the bundle to a terminal: refuse by default (section 3, point 2).
