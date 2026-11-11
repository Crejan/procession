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
| delegation | an agent's certificate | never | each signature |
| connection | pledge's sign-in to the broker | never | none |

The SSH agent socket refuses a signature in any namespace the four lower
keys use, whichever key is named.

- Keys are made in the machine's key hardware and never leave it.
- **How a key becomes known elsewhere.** `pledge keys` prints public parts.
  The four lower keys go, as one block, to an administrator, who enters them
  in the site project; nothing else makes them valid. A bound or shared
  key's public part goes wherever the person wants to log in with it, as
  with any SSH key.
- **A bound key** is created for one program and one login (user and host).
  The program is fixed by its code signature at that moment.
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
  `@cert-authority` line. A revoked entry counts as unknown. Unbound is
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
   signed for this call's identifier before.
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
7. It keeps the call's identifier as used until the call's end, and records
   the request, the answer (approved, declined, refused, expired), the key
   and the agent.

A request rated at the top of any scale (`secret`, `lasting`, `outage`) is
never signed with the automatic approval key: pledge does not let an automatic ceiling be set that high and
does not honour one it finds.

**Deadlines.** pledge refuses to sign after a request's deadline, closes a
dialog that is still open when it passes, and records the request as
expired. It watches the deadline itself.

**Delegations.** Issuing: the person picks groups and the two ceilings; a
presence check; pledge creates the agent's key pair, issues its certificate
with the delegation key, registers it with the broker, and writes key and
certificate to where the person's start of the sandbox reads them (standard
output of `pledge agents start`, for a pipe into an SSH connection, or a
file only the person can read). pledge keeps the ceilings and the
certificate, not the agent's private key. `pledge agents list` shows the
delegations pledge issued and when each last asked; pledge cannot know
whether an agent still runs.

Withdrawing: pledge stops signing for that delegation at once and tells the
broker. A withdrawal or block an administrator made at the broker reaches
pledge over its connection and has the same effect.

**The broker.** pledge connects to the broker over TLS, checks the broker's
TLS certificate against the site's certificate authority, and signs in with
its connection key. Whatever arrives as the broker's own word (a block, a
withdrawal, a renewed certificate, the names of the person's groups) pledge
accepts only with a signature by the key the site CA certified as `broker`.
A request passed on needs no such signature: it carries the service's.

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

- **The process that holds the keys parses nothing.** Signing requests and
  requests are read and checked in a separate process without access to
  keys; the key holder receives what to sign and with which key. This keeps
  a parser bug away from the keys. It does not protect against a reader that
  is taken over: the key holder signs what it is given.
- Three sockets. `agent.sock` speaks the standard SSH agent protocol, so
  every SSH client works unchanged. `control.sock` is for pledge's own
  command line and desktop app, checked by code signature. `service.sock`
  takes requests from services on the same machine, in the broker's place;
  it exists for stage 1 and for a machine without a site.
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
  check side by side**, each usable only by pledge's key holder. Assumed;
  *proposal:* check it before step 4, with a ten-line program.
- **One desktop app for p-reserve and p-ledge, or one each.** *Proposal:*
  one each; they are two programs with two purposes, and p-ledge's is small.
- **The interfaces**: the three sockets, the record's format. After the
  call, request and approval of `doc/approvals.md`.
