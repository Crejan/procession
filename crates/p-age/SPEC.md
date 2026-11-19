# p-age - specification (draft)

The broker of the approval system: the one central program of a site. It
checks that a request may be put to a person, carries it to that person's
machine and the answer back, and registers delegations. Binary `page`: it
pages a person, and carries messages like a page.

The system as a whole is [`doc/approvals.md`](../../doc/approvals.md); this
document uses its terms (its section 1) and specifies only what the broker
does.

License: MIT OR Apache-2.0.

Status: step 1 of the order of work is built: the register, the two
connections over TLS (`doc/approval-connections.md`), passing a request
through with persons and hosts from a file, the queue, the clearance and the
log. Checks 0 to 3 are made; check 4 (R10), `page load`, blocking by key,
the administrator's verbs and renewals are not built. The name is a working
name.

## What it is for

- A person's machine is behind NAT and often asleep; a service is somewhere
  else. Both connect out to the broker, and it joins them.
- Whether a person may have an action carried out on a host is a site's
  rule. The broker is the one place that evaluates it, so that no service
  has to hold the rules.
- An administrator needs one place to stop a person or a delegation at
  once.

## What it must not be able to do

- **Release an action.** A service acts only on an approval signed by the
  person's machine. The broker has no key a service would accept in its
  place.
- **Say who a person is.** Persons' keys are certified by the site CA, whose
  key is not here.
- **Put a foreign request in front of a person.** pledge checks itself that
  a request is from one of its own agents.

Anything that would give the broker one of these is a defect, not a feature:
a broker that renews certificates, a service that accepts a clearance alone,
a pledge that trusts the broker's word about a delegation.

## What it is trusted for

Keeping away from a person what the site would not let them have carried
out; honouring withdrawals and blocks; being there. Taken over, it can let a
person exceed their rights (with that person's own approval), ignore an
administrator's blocks, refuse everything, and see who asks for what.

## What it does

**It proves who it is.** Its key is certified by the site CA under the name
`broker`, which no person can have. It signs every clearance with it, and
everything it tells a pledge in its own name. Its TLS certificate comes from
the site's certificate authority. A pledge or a service that cannot verify
both treats it as absent.

**Two kinds of connection**, both inbound, both TLS:

- from a person's pledge, signed in with that person's connection key. It
  stays open while the machine is awake.
- from a service, which signs each request with its own key, certified by
  its host's key; the connection itself needs no sign-in.

**For a request from a service**, in this order; the first failure is the
answer, a refusal with its reason:

0. The call's deadline has not passed and is not more than 10 minutes
   ahead. This bounds what the broker holds; it is a limit, not a trust.
1. The request is signed by a service key that a host of the site project
   certified, and host and service are the ones the call names.
2. The call is signed under a delegation that is registered, not ended, not
   withdrawn (`src/register.rs`).
3. The delegation's person is enabled for the broker (in the site file and
   active in `directory.json`) and not blocked.
4. That person may have this action carried out on this host
   (`doc/approvals.md`, R10): one of the delegation's groups (read from the
   extension `groups@procession` of the agent's certificate,
   `doc/approval-formats.md`, section 3.1, and from nowhere else) is a
   group the person is in, and is among the groups that the service's
   binding names for this host. Where a group may log in (`access`) plays
   no part.
Then it passes the request to that person's pledge. If that pledge is not
connected, the broker keeps the request and passes it on when the pledge
connects; per agent it keeps as many as the site's setting allows (five by
default) and refuses further ones. Either way it
waits until the request's deadline, and no longer. An approval that comes back gets the broker's clearance (a
signature over the same request, with the time) and both go to the service.
A refusal or a decline goes back as it is. At the deadline the broker
forgets the request.

It does not check the approval. That is the service's.

**For a pledge:**

- it registers a delegation the pledge sends: the certificate, verified
  against that person's delegation key from the site project;
- it takes withdrawals from the delegation's own person;
- it sends what the pledge needs: an administrator's withdrawals and blocks
  concerning this person, renewed certificates, the names of the person's
  groups.

**For an administrator**, on the broker's host: `page block` blocks a person or
one key, `page unblock` lifts a block, `page withdraw` withdraws a delegation
and `page status` says whether the broker is degraded and what it holds. They
speak to the running broker over a socket in its state directory
(`proposals/admin-socket.md`), never to `register.json`, so that the rule for
a register that cannot be written holds for them: a restricting verb prints
"blocked and stored" or "blocked, NOT stored: <why>" and exits non-zero in the
second case; unblocking is refused while the register cannot be written.
`page delegations` (a list) is not built.

The verbs' exit codes have one meaning each; each verb's `--help` and usage
print this table:

| Code | Meaning |
|---|---|
| 0 | done (and stored, where something is stored) |
| 1 | refused (an unknown person, key or delegation; unblocking while the register cannot be written) |
| 2 | usage |
| 3 | no broker answers |
| 4 | in force but NOT stored (block, withdraw) |
| 5 | the broker is degraded (`status` only; nothing else returns it) |
| 6 | an enabled person has no valid certificate for a purpose (`status` only) |
| 7 | the broker has no valid certificate of its own and issues no clearances (`status` only) |

When more than one of 5, 6 and 7 holds, `status` returns the gravest, 7, then 5, then 6 (nothing is vouched for at all; the register cannot be stored; some person cannot be approved), and prints a line for each; the exit code is the gravest condition and the lines are the complete list. Each code has one meaning.

**The broker's own certificate** is not in that directory and has no member in
the configuration: its path is derived, `<broker_key>-cert.pub` beside the key
(`ssh-keygen` finds the key by the certificate's name), and `page status` names
it. `site_ca` (the path to the site CA's public key) is required: there is no
mode, test support included, in which the broker does not check its own
certificate. It is checked at start and once a minute: its one principal is
`broker`, issued by the site CA, valid now, no critical option, no extension, and
it certifies the key the broker holds (the broker reads `<broker_key>-cert.pub`,
checks it with `p_act::sign::check_broker_certificate` and compares its key with
`<broker_key>.pub`; the time it judges itself, so that "not yet valid" and
"ended" are told apart). A broker without a
valid one is **not ready** and vouches for nothing:
- an approval that comes back is answered to the service `refused` with the
  reason `not-ready`, with no clearance; the broker logs `approval-lost:not-ready`
  and says on standard error whose approval was lost;
- a pledge that signs in is let in, gets `ready` and then `{"type":"not-ready"}`
  in place of a standing, and the connection stays open; on it only what
  restricts is served (`withdraw` is taken and answered as always; a registration
  is answered `not-registered` with `unavailable`); requests wait; when the
  certificate is valid again the broker sends the standing and what waited,
  without a new sign-in;
- a pledge already connected when the certificate ends is told `not-ready` once,
  at the end (the sweep sees it, every second), and the same holds from then.
`not-ready` is a code of its own; `busy` keeps its one meaning (too many open).

**`ssh-keygen`.** Every signature is made and verified by the system's
`ssh-keygen`, started only through `p_act::keygen::Keygen::system` (the broker
starts it nowhere else): `/usr/bin/ssh-keygen`, owned by root with the
directories above it, a cleared environment, version 8.9 or later. When it
cannot be used the broker can verify and sign nothing; `page status` then has
a line of its own, `ssh-keygen-unusable`, with the reason. It has the same
meaning as code 7 (the broker vouches for nothing), so it has the same exit
code and no code of its own.

**`page status`** prints every condition that holds, one line each, and exits with
the gravest, in the order 7, 5, 6; the exit code is the gravest condition and the
lines are the complete list. `page status --format json` gives the same list as
an array of `{"code","condition","detail"}`, `[]` when none holds. With the
broker's certificate valid it shows the days left.

**Certificates.** The certificates of persons' approval keys that the broker
carries to pledge are a separate input, not part of the site file (which has no
`certificates` member). The configuration has two members, given together or
not at all: `site_ca`, the path to the site CA's public key (one line, read
with the settings rule), and `certificates`, a directory. The broker reads the
files named `*-cert.pub` in it (OpenSSH's own convention; the writer's is
`<login>-<purpose>-cert.pub`) and nothing else there: a plain `*.pub` beside
them is not opened. The person, the purpose and the key are read from the
certificate, never from the file's name. The directory and each file follow
`p-ermit`'s settings rule (owned by root or the broker's user, no write bit for
group or others; a file that is a link is not a regular file); a directory that
fails it is refused whole and nothing is carried. Each certificate is checked
when it is loaded with `p_act::sign::check_approval_certificate` against the
site CA (one line, a user certificate with the one principal
`<person>:confirmed` or `:automatic`, no critical option, signature and issuer),
for validity now, and against the site file: the person must be in it with keys,
and the certified key must be the one the site file lists for that person and
purpose. One that fails is **not carried** and is reported on standard error
with its file and the reason, and counted in `page status`. They are read at
start, and again by the sweep, at most once a minute, when the directory's
listing changed or a carried certificate has ended or one not yet valid has
begun; a connected pledge whose person's set changed is sent a new standing.
The broker never makes or changes a certificate. `page status` shows how many
are carried, how many were not, and each enabled person who has no valid
certificate for a purpose (exit code 6).

The socket is `admin.sock` in the state directory (0600 set after `bind`); a
peer is served only if `p_act::peer` read its credentials and its user is the
broker's own or root (`Policy::OwnUserOrRoot`: the broker runs as the owner of
its state directory, so no list of users is needed). A peer whose credentials
cannot be read is dropped, told nothing.

**Who may use the socket: `administrators_group`.** Through `sudo` a caller
arrives as uid 0, and a name the client passes (`SUDO_USER`) is the client's
word and is never recorded. So that the register says *who*, the person must
be the peer: the members of one group connect to `admin.sock` as themselves.

- **The member.** One optional config member, `administrators_group` (a group
  name; in stage 3 it comes from the site file, in stage 2 this member is the
  source). Absent: root and the broker's own uid are admitted (without a group
  the broker commonly runs in a person's own account, in tests or a single-user
  setup, and that person administers it). Present: root and the group's
  members are admitted, and **the broker's own uid is refused** (with a group
  the broker is a service account that is in the group only so that it may set
  the socket's group). Either way the record for the own uid is the ordinary
  `by {kind: administrator, uid, account}`. It is
  resolved to a gid **once, at start**. An unknown name, group 0, and the
  broker's own primary group (which would admit every process of its user) are
  refused, naming the member, and so is any system that cannot tell the groups
  of a peer ("not supported here": Linux only, `SO_PEERGROUPS`); there is no
  fallback to a lookup.
- **The socket, and the directory as the guard.** There is no `umask` call (it
  would need libc); the state directory keeps everyone else out while the socket
  is made, in this order, and the broker does nothing that accepts before the
  last step has passed:
  1. the state directory is **checked, not only set**: the broker's own, a real
     directory and not a link, mode exactly 0700 (a 0710 left by a former run is
     made 0700 first; anything else refuses the start);
  2. `bind`; then `chmod 0600`. Between the two the socket carries the process
     umask's mode, inside a directory no one else can enter;
  3. the socket is given to the group, group = the gid, mode 0660;
  4. **only after that** the directory is given to it, group 0710 (the group may
     traverse it, nobody else may do anything; `register.json` stays 0600);
  5. both are looked at again (`lstat`); any difference refuses the start;
  6. only then is anything accepted, and the broker says `page: ready` on
     standard error.
  The broker's account is in the group as a supplementary group (the unit's
  matter) so that it may set it. Without a group, steps 1, 2 and 5's look at the
  mode are the same, and the socket stays 0600.
- **Admission, per connection, from the kernel only.** Peer uid 0; or the
  peer's groups contain the gid: its primary gid (`SO_PEERCRED`) or one of its
  supplementary groups (`SO_PEERGROUPS`). No name service decides admission.
  **The broker's own user is refused although it is in the group.** A peer whose
  groups cannot be read is dropped, never admitted. Everyone else is dropped
  without reading, as on every socket. Membership counts when the connection is
  made; one command per connection; nothing is cached.
- **Rights.** Members have the same rights as root on this socket: `block`,
  `unblock`, `withdraw`, `status`. There is no split in stage 2.
- **The record** is as decided: `by {kind: administrator, uid, account}`; the
  uid is the record, the account is `account_of` as of then and never stands
  between a verb and its answer. Nothing new is stored.
- **Root** may do everything. `page` run as uid 0 while a group is configured
  does the work and says on standard error: `page: recorded as root; run without
  sudo to be recorded by name`. Exit codes are unchanged.
- **`page status`** says `administrators: group NAME (gid N)`, or, without a
  group, `administrators: root and the broker's account (uid N)`.
- **Who is in the group is the operating system's matter**, not the broker's.
- **Not yet run on Linux.** The Linux branch of `p_ermit::peer::peer_groups`
  (`SO_PEERGROUPS`) and p-age's two Linux tests are **uncompiled and unrun**
  until the owner's Debian run (`proposals/REPORT.md`, "For the owner"). Until
  then what is shown of group admission is the pure rule, with the groups
  injected.
Blocking a key means: no request is passed to a pledge that signed in with
it, and no approval by it is given a clearance.

**From the site**, in two files (`page load`, "What `page load` reads"): the site
file (hosts with their keys, service bindings, the groups they name, persons =
name and approval keys) and `directory.json` beside it (who is active, who is
in which group). The first comes from the site project when the broker's host
is converged; the second from the same converge on a local site, from the job
`page-sync` on a directory site (stage 3). The broker does not know what a
directory is. It holds a copy and nothing else: no rule is made here.

## What it keeps

- The register of delegations, until each one's end. On disk it is
  `register.json` in the state directory: the file readable and writable by
  its owner only (0600, the directory 0700), with a member `v`, replaced by
  writing a new file and renaming it. The broker refuses to start on a
  register it cannot read whole, and on a missing one: a deleted file and a
  damaged file are the same doubt, and an empty register in their place
  would drop blocks without a word. The first start is explicit: `page init`
  creates the empty register and refuses if one exists.
  The clearance names the approval it cleared (`approval`, the hash of the
  armoured signature as pledge made it) and the standing says when the broker
  made it (`at`, the broker's clock, UTC to the second, shown and never decided
  on). At `v` 1 (the draft; it freezes with stage 2) each delegation also records
  its groups (from the certificate's extension), the key's label and when it was
  registered; each block and each withdrawal records when it was made and by
  whom: `"by":{"kind":"pledge","person":...}` for the person's own pledge, or
  `"by":{"kind":"administrator","uid":N,"account":"name"}` for the administrator whose
  user `p_act::peer` read on `admin.sock`. The **uid** is what the kernel said
  and is the record; the **account** name is the name the system gave that uid
  at that moment, for a reader (it can change later, so it is never used to
  decide anything) and is left out if it cannot be looked up. Every name, label,
  group and account in the register is validated when it is read back
  (`p_ermit::text`, and the name patterns): a register with one that fails is
  one the broker cannot read whole, and it does not start.
  - **The lookup never stands between an administrator and a block.** The
    account database may be slow or hang (a directory site reaches it through
    the name service). The restriction takes effect and is stored with the uid
    first; the name is looked up afterwards, off the path that answers the verb,
    and added to the entry if it arrives. An entry without a name is complete.
  - **An administrator who acts through sudo arrives as uid 0.** The record says
    uid 0 and nothing more: `SUDO_USER` and anything else the caller could set
    is not read. The trail is as honest as the peer lookup and no more: on most
    hosts it will say uid 0. A site that wants names in it has its
    administrators run `page` as themselves, which needs
    `administrators_group` (above).
  - **Nothing is ever decided by the account database**: not who may connect,
    not what a verb does; the name is shown beside the uid, uid first.
- When the register cannot be written, what happens goes by direction. A
  change that restricts (a block, a withdrawal, forgetting a registration)
  takes effect in memory at once, always, and its caller is told that it is
  in force but not stored, with a non-zero result: the administrator's verbs
  say "blocked and stored" or "blocked, NOT stored: <why>". A change that
  permits (registering, lifting a block) is refused: nothing is permitted
  that would not survive a restart as recorded. From the first failed write
  the broker is degraded: its status output and stderr say so, it tries the
  whole write again on every later change and at least once a minute, and
  it leaves that state when a write succeeds. Degraded, it goes on serving
  with what it holds in memory. To a pledge the two cases look like this
  (`doc/approval-connections.md`, section 5): its withdrawal is answered
  `withdrawn` with `stored` false; its registration is answered
  `not-registered` with the reason `unavailable`, and the connection stays
  open.
- Blocks, until lifted.
- A log of every request: when, from which host, for which person, what
  became of it. Not the parameters of the action; those are in the person's
  record and the service's.

- Requests waiting for a pledge to connect, each until its deadline.

It keeps no request beyond its deadline. An answer, an approval included,
it holds in memory until the service has acknowledged it or the deadline has
passed, whichever is first, so that a connection lost at the last moment
does not cost the person a second dialog. Never on disk, never past the
deadline. An approval is not a secret and is of use only to the service
whose request it signs.

The register's `v`: `blocked_keys` was added with `v` still 1 and "a missing
member is empty", **this one time**, because no register exists outside tests
yet. From now on a member that is added is a new `v`, and a reader refuses a
`v` it does not know (it does).

A delegation is known in the register by the SHA-256 fingerprint of the
agent's public key (`doc/approval-formats.md`, section 3.1).

## Order of work

1. The register (done), the two connections, and passing a request through,
   with persons and hosts from a file. Stage 2 of `doc/approvals.md`.
2. `page load` from the site project, checks 3 and 4, blocking. Stage 3.
3. Renewed certificates and group names to the pledges.

## What `page load` reads

The broker has **two inputs, the same on every kind of site**: the site file,
and `directory.json` beside it (`doc/fundament-approvals-note.md`, point 4,
"The two inputs"). A person is **enabled for the broker exactly if the site
file has the row and `active` of `directory.json` has the name**. A person who
is not in the site file is unknown: no sign-in, no clearance, no key held for
them. A person who is in it and not active is as `enabled: false` once was: no
sign-in and no clearance (their row stays; blocks and withdrawals still
work).

**The site file** (from the model, by the converge of the broker's host) holds
hosts with their keys, service bindings, the groups they name, and persons =
name and approval keys. **It carries neither `enabled` nor `members`**, on any
kind of site; either is refused as an unknown member. `v` is `1`.

**`directory.json`** (beside the site file; written 0644 by write-then-rename
by its writer, read with the usual file checks of `p_act::settings`):

```json
{"v":1,"source":"model","as_of":"2026-11-19T10:15:00Z",
 "active":["alice","bob"],
 "members":{"rt-operators":["alice"],"admins":[]}}
```

`source` is `model`, `freeipa` or `hosted-ldap`; it is shown by `page status`
and decides nothing. `as_of` is the writer's time, UTC to the second; it is
shown. A writer gives **every group the site file names as a key of `members`**,
possibly with an empty list, and `members` holds only persons that are in
`active`; the broker does not need the first to hold (below). R10's membership
comes from `members`.

**Each file is read and checked on its own, and replaces its predecessor when it
is valid in itself.** Nothing waits for the other: a converge that removes a
person or a group from the site file must not be held back until a fitting
`directory.json` arrives (a restricting change waiting on an outside system).

- **Refused whole, the file the broker holds standing** (the file contradicts
  itself or its form): the site file: a missing or unknown `v`, an unknown
  member of the object (`enabled` and `members` among them), a name outside the
  character rules, a person's keys that are not four different Ed25519 or
  ECDSA P-256 keys, a name or a group twice. `directory.json`: a missing or
  unknown `v`; an unknown member of the object; a `source` outside the three;
  an `as_of` that is not a UTC time to the second, or is more than 60 seconds
  ahead of the clock; a name outside the character rules; a name repeated
  within one list (`active`, or one group's); a key of `members` repeated; a
  name under `members` that is not in `active`.
- **What the broker decides from is the intersection, computed at load.** A
  person is enabled if the site file has the row **and** `active` has the
  name. A group's members are the names under its key that are enabled
  persons. A name in `active` or `members` that is no person of the site file
  is **ignored**; a key of `members` that is no group of the site file is
  **ignored**; a group of the site file that has no key in `members` is
  **empty**. Each of these only restricts, so no order of arrival admits what
  neither file admits, and nothing waits.
- **So that the tolerance does not hide a writer's fault**, `page status`
  prints, beside `directory: source S, as of T`, the counts and (escaped, the
  first ten) the names of the three kinds: `names not in the site file`,
  `groups not in the site file`, `groups of the site file without members key`;
  the audit log gets one line, `directory-sets:names=N,groups=N,empty=N`, when
  the view is made and these sets are not all empty (a reload that changes the
  sets writes one again: `page load` is not built), and so does standard
  error. **The exit code is unchanged by them.**
- **At start:** the site file is required (missing or refused, there is no
  broker). `directory.json` is not: without a valid one (missing, or refused
  on its own faults) **nobody is active**; the broker starts, issues no
  sign-in and no clearance to anyone, and clears nothing (blocks and
  withdrawals are the register's and stand); `page status` says
  `directory: none (why)` and standard error says it. Why start rather than
  refuse: that only restricts, and a broker that cannot start because an
  outside system's file is late is a worse failure for the persons waiting
  than a broker that refuses everyone and says why. If the designer would
  rather the broker refuse to start, that is one line in `Site::load`.

**Stage 2** reads both files by hand: `directory.json` with `source: model`,
beside the site file (no member in the configuration names it). **Without the
setting `directory_max_age_seconds` the file does not age**: that is the whole
freshness rule of stage 2, and the setting is not built. Stage 3 only, not
built: `page-sync`, the age setting and the reason `directory-stale`,
`page directory extend` and `resume`, and the register's `directory_hold`.

`page status` shows `directory: source S, as of T` (or `directory: none`).

**The file forms freeze with stage 3.** Until then the site file read today is
the stage-2 stand-in, and differs from the note's form (`proposals/REPORT.md`):

1. `persons` is a list of `{name, keys}`, not a mapping by login; `hosts` a list
   of `{name, key}`, not a mapping by name.
2. `groups` is a list of names (the groups the site names), not a mapping with
   descriptions.
3. No `services` (check 4 is stage 3), no `ca`, no `settings`: the one setting,
   `waiting_per_agent`, is in the configuration file, and the CA is `site_ca`.
4. A person's `keys` are required: the four, each `{key, verified_on?}`, four
   different keys, none another person's or a host's, each Ed25519 or ECDSA
   P-256.

**Certificates are not part of this view.** The certificates the broker carries
to a pledge are products of the converge's signing step: a separate input
beside the view, with its own check (signed by the site CA; the name; the
validity), as above under "What it does".

## Open, each with a proposal

- **The name.** `page` unless a better one turns up.
- **Where it runs.** *Proposal:* one per site, on a host that can be reached
  from outside, as a service type in fundament's catalogue.
- **Whether `atticus-server`'s relay skeleton is a starting point.**
  *Proposal:* no. It was written for another protocol; the TLS and storage
  setup may be worth reading.
- **The interfaces**: the two connections. After the call, request and
  approval of `doc/approvals.md`.
