# p-ledge - specification (draft)

Holds a person's keys on their own machine and decides what they are used
for. Two jobs: an SSH agent with a rule per program, and the person's end of
the approval system, in which services ask before they act. Binary `pledge`.

It starts from the SSH half of Atticus (the Secure Enclave key, the
in-process SSH agent, its signing rules), taken out of the backup program.
The backup half is p-reserve, which becomes one of this program's clients.
Atticus stays as it is.

License: MIT OR Apache-2.0.

Status: a skeleton. Two decisions are implemented with tests: `src/policy.rs`
(section 3, the order of the four rules; not who a program is, and not what
a login must carry) and `src/rating.rs` (section 4, the mode of a request).
Nothing else exists: no socket, no key, no dialog. The name is a working
name.

The approval system as a whole is [`doc/approvals.md`](../../doc/approvals.md).
This document uses its terms (its section 1) and specifies only what pledge
does. In particular: "agent" alone is an AI agent; the SSH agent is always
written out. A "request" is a service's; what arrives on the SSH agent
socket is a "signing request".

## 1. Functions

| # | Function |
|---|---|
| F1 | Manage keys: create, print the public parts, retire |
| F2 | Offer keys to local programs over the SSH agent socket |
| F3 | Admit or block local programs |
| F4 | Answer requests for approval: refuse, sign at once, or ask the person |
| F5 | Issue a delegation for an agent; withdraw one |
| F6 | Keep the record |

## 2. Keys

One key per purpose. A key is used for its purpose and nothing else.

| Key | Purpose | On the SSH agent socket | Presence check |
|---|---|---|---|
| bound | one program's login to one server (p-reserve's to its repository) | for that program and that login only | none |
| shared | logins and signatures of every other local program | yes | each signature |
| confirmed approval | approvals the person was asked for | never | each signature |
| automatic approval | approvals in mode `automatic` | never | none |
| delegation | an agent's certificate | never on `agent.sock`; for issuing, pledge hands it to its own `ssh-keygen` child over a private socket | each signature |
| connection | pledge's sign-in to the broker | never | none |

Every SSHSIG namespace ending in `@procession` is reserved for the approval
system (`doc/approval-formats.md`, section 1). The SSH agent socket refuses
a signature in any of them, whichever key is named. The connection key signs
in the namespace `connection-v1@procession`.

- Keys are made in the machine's key hardware and never leave it.
- **How a key becomes known elsewhere.** `pledge keys` prints public parts.
  The four lower keys go, as one block, to an administrator, who enters them
  in the site project; nothing else makes them valid. A bound or shared
  key's public part goes wherever the person wants to log in with it, as
  with any SSH key.
- **A bound key** is created for one program and one login (user and host
  key). The host is fixed by its host key's fingerprint, always; a name is
  for showing only, taken from `known_hosts` where pledge finds one. The
  program is fixed by its code signature at that moment.
- **Retiring** a key: pledge deletes it from the hardware and records that.
  For the four lower keys the person also tells an administrator, because
  the site project still lists it.
- **A lost or replaced machine**: its keys are gone with it. An administrator
  blocks them and enters the new machine's (`doc/approvals.md`, flow D). A
  new bound key is switched to only once it is installed on the server it
  logs in to; otherwise the program locks itself out.
- One machine per person.

SSH certificates for logins (a bound or shared key certified by a site's
user CA, as Atticus supports) are not in the first version.

## 3. Local programs

For a signing request on the SSH agent socket. The order is fixed and the
first match wins:

1. Data the SSH agent cannot interpret is **refused**, whichever program
   sent it. Only an SSH user authentication and an SSHSIG signature are
   interpreted.
2. A key is offered only for its purpose: a bound key to its program for
   its login, a shared key to every program that has no bound key. A signing
   request for any other key is refused without a dialog.
3. A bound key signs without a dialog.
4. For a shared key:
   - a **blocked** program is refused without a dialog;
   - an **unknown** program is put to the person;
   - an **admitted** program gets a presence check for each signature.

An answer "block" is recorded as a decline of that signing request, because
the person said no to it, and the block itself as an event; later signing
requests of that program are refused, reason blocked.

What the person can answer about an unknown program:

| Answer | Effect |
|---|---|
| block | refused from now on, without a dialog |
| decline once (the default) | this signing request is refused; the next one asks again |
| admit once | this signing request goes on to its presence check; the next one asks again |
| admit generally | the program may ask from now on; each signature still gets a presence check |

No answer makes a shared key sign without the person. Admitting generally
asks for the program's name to be typed, not for a click.

**Who a program is.** On macOS the code signing identity (team and
identifier; for ad-hoc signed code its hash and path) of a link in the
connecting process's chain that the person picks. Never the command line,
never the path alone. The chain has holes: `exec` and re-parenting drop
links, and a program with its own SSH implementation ends the chain at
itself. With an incomplete chain only the two "once" answers are offered.

**What a login must carry.**

- A user authentication is bound to the session (`session-bind@openssh.com`)
  and to a host key the SSH agent verified against `known_hosts` or a
  `@cert-authority` line. A revoked entry counts as unknown. A client that
  does not bind (older than OpenSSH 8.9) cannot use pledge's keys; there is
  no setting for it, and the dialog and the record say why. Unbound is
  refused.
- A forwarded SSH agent connection is refused.
- A presence check covers one login. A shared connection (`ControlMaster`)
  carries later sessions that never reach the SSH agent; the setup
  instructions turn it off and the server limits sessions per connection.
  The SSH agent cannot read a client's effective options reliably, so this
  stays a rule for the setup, not a check.

**Which signatures a shared key gives.** SSHSIG in the namespaces `git` and
`file`; any other namespace is refused. The dialog names the namespace.

## 4. Approvals

What pledge does with a request, which arrives from the broker or, in stage
1, from a service on the same machine (section 7):

1. It checks the call inside the request: signed under a delegation pledge
   issued itself, not ended, not withdrawn; the call's deadline has not
   passed and is not further away than the longest allowed; pledge has not
   decided on this call's identifier before (`doc/approvals.md`, R5: the
   same request again gets the same answer again, from a store on disk; a
   different request under a used identifier is refused).
2. It checks the request: signed by a service key that a host it knows
   certified; that host and the service's name are the ones the call names.
   The request holds the call as the bytes the agent signed, so action,
   parameters and deadline cannot differ (`doc/approval-formats.md`).
3. It checks that it can show every field as it is: none too long, none with
   control characters or bidirectional marks.
4. If any of these fails, the request is refused and recorded. No dialog.
5. It applies the limits on how much an agent may ask
   (`doc/approvals.md`, section 7). How many requests of one agent may wait
   is a setting of pledge, five by default.
6. It derives the mode from the request's rating and the delegation's two
   ceilings (`src/rating.rs`):
   - `refuse`: it answers no;
   - `automatic`: it signs with the automatic approval key;
   - `ask`: it asks. If the person agrees: a presence check, and it signs
     with the confirmed approval key. If the person declines, it answers no.
7. It keeps the call's identifier as used until the call's end, from the
   moment it approved or the person declined, and records the request, the
   answer (approved, declined, refused, expired; or cancelled, when the
   service gave up first), the key and the agent. Without a record entry
   there is no approval.

A request rated at the top of any scale (`secret`, `lasting`, `outage`) is
never signed with the automatic approval key: pledge does not let an automatic ceiling be set that high and
does not honour one it finds.

A "no" at the presence check is a decline: it counts toward muting and uses
the call's identifier. When the same request is submitted on several
connections, there is one dialog, and it closes when the last submitter of
those bytes has gone. A dialog shows every field whole, up to the formats'
limit for it; the parameters of a call together are at most 2000 characters,
beyond that the request is refused as not showable. The identifier is marked
used before the approval is signed: a crash in between costs a second
decision on the same bytes, never a second signature in circulation. A
delegation that was started and whose bundle was not handed over was never a
delegation: the record has an event of its own for it
(`delegation-not-delivered`), and "withdrawn" there always means that
something which could sign was stopped.

**Deadlines.** pledge refuses to sign after a request's deadline, closes a
dialog that is still open when it passes, and records the request as
expired. It watches the deadline itself.

**Delegations.** pledge writes neither a certificate nor a private key
itself: OpenSSH does. The agent's key pair is made by `ssh-keygen -t
ed25519` in a private temporary directory, read and removed. The
certificate is made by `ssh-keygen -s <delegation public key> -U`, which
gets its signature through a private SSH agent socket that pledge offers for
that one issuing (in a directory only the person can enter, holding only the
delegation key, closed when `ssh-keygen` exits). The reader sees the
certificate to be signed in that signing request, reads it with p-act, and
lets the key holder sign only if it is an agent's certificate by
`doc/approval-formats.md`, section 3.1, for this person, with the groups and
the validity the person just chose. The key holder still parses nothing.

A delegation exists only once the bundle with key and certificate has been
handed over (`agents.delivered` on `control.sock`): until then pledge signs
for no call under it and has not registered it, and a control connection
that closes first ends it, leaving a record entry. A bundle is never
written to a terminal. The key's bytes are held in a type that cannot be
printed or logged. Which services the bundle names is the person's own file
or options; never the broker's word.

Issuing: the person picks groups and the two ceilings; a
presence check; pledge creates the agent's key pair, issues its certificate
with the delegation key (the person as its only principal, the groups in
the extension `groups@procession`; `doc/approval-formats.md`, section 3.1),
registers it with the broker, and writes key and
certificate to where the person's start of the sandbox reads them (standard
output of `pledge agents start`, for a pipe into an SSH connection, or a
file only the person can read). pledge keeps the ceilings and the
certificate, not the agent's private key. `pledge agents list` shows the
delegations pledge issued and when each last asked; pledge cannot know
whether an agent still runs.

Withdrawing: pledge stops signing for that delegation at once and tells the
broker. The broker's answer says whether it stored the withdrawal. pledge
writes that into the record with the withdrawal; while it is in force but
not stored, pledge sends it again at every sign-in and at most once a minute
on a standing connection, until the broker says stored. The person is asked
nothing; `pledge agents list` and `pledge history` show it as a state of the
withdrawal, not as an alarm. A registration the broker answers with
`not-registered`, `unavailable` means the agent is not started: the
delegation is not delivered, the person is told that the broker could not
take it and that they can try again, and pledge does not try again by
itself. A withdrawal or block an administrator made at the broker reaches
pledge over its connection and has the same effect.

**The broker.** pledge connects to the broker over TLS, checks the broker's
TLS certificate against the site's certificate authority, and signs in with
its connection key. Whatever arrives as the broker's own word (a block, a
withdrawal, a renewed certificate, the names of the person's groups) pledge
accepts only with a signature by the key the site CA certified as `broker`.
A request passed on needs no such signature: it carries the service's.

**Stage 2 as built (step 6).** `config.json` has a `broker` member (`address`
host:port, `server_name`, `tls_root` a PEM, `site_ca` a public key line that is not
the key material of the TLS root). With it `pledge serve` needs a `person` and a
`connection` key and keeps one TLS 1.3 connection to the broker on a thread of its
own, signing in with that key over what both ends export from the connection; it
reconnects after 1 s, doubling to 60 s with jitter. What it does with the broker's
word:

- A `standing` counts only if it verifies as `broker` against `site_ca`, is for
  this person and this connection, and is newer than the last one. `blocked`,
  `blocked_keys` and `withdrawn` only restrict, at once, and are kept in
  `broker-state.json` so that a restart does not forget them; a request that waits
  is refused `blocked` or `delegation-withdrawn`. Certificates of the person's
  approval keys are each checked by pledge against `site_ca` and are re-checked
  when the file is loaded; an approval then carries the certificate instead of the
  bare key. Groups are shown, decide nothing and are not trusted from disk.
- `carried` is ignored in this step (stage 2 reads hosts from `config.json`).
- A request from the broker is answered on the connection and recorded with
  `via: broker`. A lost connection cancels nothing: the broker sends it again and
  it is answered from what pledge kept.
- `agents start` registers the delegation with the broker before the bundle is
  handed over. No connection, no answer or `unavailable`: refused,
  `broker-unavailable` ("the broker could not take it, try again"); any other
  reason: `broker-refused`. A delegation is never issued for pledge alone.
- A withdrawal is local at once, then told to the broker and followed:
  `not told`, `not stored yet`, `stored` in `pledge agents list`; sent again at every
  sign-in and at most once a minute until the broker says it stored it.

## 5. Dialogs

- One at a time.
- Text comes only from what was checked: for a login, the parsed bytes and
  the verified host; for a request, its fields and the host that signed it.
  Nothing is shortened or altered; what cannot be shown as it is, is refused
  (section 4, step 3).
- What a requester says about its reasons is shown as its claim, apart from
  the rest.
- A dialog for a request closes at the request's deadline, and the request
  is recorded as expired. A dialog for a login closes after 60 seconds, and
  the signing request is refused.
- A local program that the person declines three times within ten minutes is
  refused without a dialog for ten minutes, and the person is told.

## 6. The record

Every signing request and every request, with the time, who asked (the
program's identity; or the agent, its delegation and the service), what was
asked in the dialog's words, the answer, and the key that signed. Refused
and expired ones included.

`approved` means that this machine signed, not that the action was done;
the record and `pledge history` say so in those words. What ran is in the
service's own log (for p-robe its syslog lines, which carry the call's
identifier, so the two can be joined).

A request that waits (queued, or shown in a dialog) gets an entry `received`
when it arrives, with the call's fields and the request's hash: no record,
no dialog. Its answer is a second entry that names the hash. A request
answered at once (automatic, refused) has one entry. When `pledge serve`
starts, every `received` without an answer gets an entry `lost`, with the
time pledge was down if it can tell. So a request ends as one of six:
approved, declined, refused, expired, cancelled, lost. A request whose
submitter goes away at or after its deadline, or within 2 seconds before it,
is `expired`; earlier it is `cancelled`.

Kept for a year, readable with `pledge history`. Each entry carries the hash
of the one before it, so that removing or changing one in the middle shows;
entries older than a year are removed from the start, and the first one kept
says so. The record protects against forgetting, not against someone who
controls the person's account.

## 7. Structure

```
ssh, git, ... ────┐  SSH agent protocol
preserve ─────────┼──> agent.sock ──> reader ──> key holder (signs)
                  │     (parses, identifies the program)    ▲
pledge CLI ───────┤                                         │ decided
desktop app ──────┼──> control.sock ──> pledge serve ───────┘
                  │                       ├─ rules, delegations, used calls
local service ────┴──> service.sock ──────┤─ dialogs
   (stage 1)                              ├─ record
                                          └─ connection to the broker
```

`pledge serve` binds the three sockets one after another and prints
"serving" only when all three are bound. That line, or all three sockets
taking a connection, is what anything that waits for pledge may rely on; one
socket taking a connection says nothing about the others.

- **The process that holds the keys parses nothing.** Signing requests and
  requests are read and checked in a separate process without access to
  keys; the key holder receives what to sign and with which key. This keeps
  a parser bug away from the keys. It does not protect against a reader that
  is taken over: the key holder signs what it is given.
- Three sockets. `agent.sock` speaks the standard SSH agent protocol, so
  every SSH client works unchanged. `control.sock` is for pledge's own
  command line and desktop app, checked by code signature. `service.sock`
  takes requests from services on the same machine, in the broker's place;
  it exists for stage 1 and for a machine without a site. **All three drop a
  connection whose peer credentials cannot be read**: no request is handled
  for it, the peer is told nothing (the connection ends; a service gives its
  agent `unavailable` and nothing more specific), and pledge writes one line
  on its standard error, at most one per ten seconds per socket with a count
  of those held back, never a record entry. `agent.sock` and `control.sock`
  also drop a peer that is another user; `service.sock` takes any user the
  file mode lets in (a service runs under an account of its own).
- pledge is started as a job of launchd in the person's session.

## 8. Platforms

The first version of pledge with hardware keys is macOS: Secure Enclave
(P-256), Touch ID as the presence check, programs identified by code
signature, native dialogs. That part is Swift or Objective-C, linked in or
as the key holder.

For development and for stage 1 of the approval system, pledge runs on Linux
and macOS with keys in files, dialogs on a terminal, and programs identified
by path. That form protects nothing and says so when it starts.

On a Linux server p-reserve logs in with a key file and pledge is not
involved.

## 9. Relation to p-reserve

- p-reserve reaches its repository through the SSH agent socket. pledge
  recognises it by its code signature and offers it its bound key, for the
  login to the repository server only.
- Setup stays one flow in p-reserve's desktop app: create the bound key
  (pledge), show its public part for the server, run the first backup.
- Open on p-reserve's side: its part that takes snapshots runs as root, and
  how that part reaches a socket in the person's session.

## 10. Order of work

1. The SSH agent protocol and the parsers (user authentication, SSHSIG,
   session binding, host keys), ported with Atticus's tests as the
   specification.
2. `pledge serve` with keys in files: the SSH agent socket, section 3, the
   record, dialogs on a terminal.
3. Approvals with keys in files: `service.sock`, section 4. This is stage 1
   of `doc/approvals.md`, with p-robe as the service.
4. Secure Enclave keys and Touch ID; who a program is, from its code
   signature.
5. p-reserve as a client with a bound key.
6. The connection to the broker: stage 2.
7. The desktop app.

## 11. Open, each with a proposal

- **The name.** `pledge` unless a better one turns up.
- **Whether the Secure Enclave can hold keys with and without a presence
  check side by side.** They can (the owner's check of 2026-11-18,
  `proposals/stage2-mac.md`, check 0). But a key kept as a blob in a file is
  **not** usable only by pledge's key holder (check 3): another program of
  the same person, with another signature, loaded a copied blob of a key
  without a presence check and signed with it, with no prompt; with a key
  that has a presence check it raised the Touch ID prompt under its own
  name and signed after the touch. Decided: blobs in files for stage 2, and
  said plainly. The automatic key and the connection key are then protected
  only against leaving the machine: any program that runs as the person and
  can read the blob can use them. So the blob files and their directory
  follow the strictest file rule the workspace has (the directory 0700, the
  files 0600, owned by the person, refused otherwise), since that is their
  only protection. For a key with a presence check the touch is the only
  barrier and the prompt's text the person's only way to see who asks, so
  the key holder always puts its own fixed words first. The keychain with
  an access group is a step of its own before a site uses this. Nothing of
  step 4 is built before the owner has run the proposal's checks 1 to 5.
- **One desktop app for p-reserve and p-ledge, or one each.** *Proposal:*
  one each; they are two programs with two purposes, and p-ledge's is small.
- **The interfaces**: the three sockets, the record's format. After the
  call, request and approval of `doc/approvals.md`.
