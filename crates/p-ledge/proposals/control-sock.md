# Proposal: `control.sock`

Status: a proposal by the p-ledge agent, for the designer. Fills in
`SPEC.md`, section 7 ("`control.sock` is for pledge's own command line and
desktop app"). Nothing is built on it. Framing, `schema_version`, `ref`,
limits and the `error` message are those of `service-sock.md`, section 3.

## 1. What it is for

`pledge keys`, `pledge programs`, `pledge agents` and, later, the desktop
app talk to the running `pledge serve` here. It carries what a person tells
their pledge. It carries no request, no approval and no signing request.

`pledge history` is not here: the record is a file the person's own account
reads (`record.md`, section 7). `pledge serve` itself is started by launchd
or in a terminal and is stopped by a signal; there is no `shutdown`.

## 2. Who may connect

- The socket is in the directory of `service-sock.md`, section 6 (0700, the
  person's), mode 0600, no group.
- **Development form (keys in files):** the peer must be the person's own
  user (`SO_PEERCRED`, `getpeereid`). That protects nothing against another
  program of the same user, and `pledge serve` says so when it starts.
- **Hardware form:** the peer's code signature must be `pledge`'s own, or
  the desktop app's (`SPEC.md`, sections 7 and 8). What changes the person's
  rules needs more than the socket in any case: a presence check for a
  delegation, a key, or retiring one; typing the program's name to admit it
  generally (`SPEC.md`, section 3), which the command line asks for on a
  terminal and does not do without one.

## 3. Messages

Two types besides `error`:

```json
{"schema_version":1,"type":"command","ref":"1","name":"agents.list","args":{}}
{"schema_version":1,"type":"reply","ref":"1","result":"ok","data":{...}}
{"schema_version":1,"type":"reply","ref":"1","result":"error","error":"not-found"}
```

(`request` and `response` are not used: a request is a service's.)

- `ref` as in `service-sock.md`. A client may have several commands open;
  replies come in any order. Most come at once; the ones that wait for the
  person (`agents.start`, `keys.create`, `keys.retire`) come when they are
  done or fail, and a client that closes the connection cancels its
  command, which pledge records as not done.
- `args` and `data` are objects; unknown members in `args` are an error
  (`bad-arguments`).
- `error` codes: `unknown-command`, `bad-arguments`, `not-found`,
  `already-exists`, `refused` (a rule says no: the program is blocked, the
  ceiling set above what a person may set), `presence-denied` (the presence
  check failed or the person said no), `unavailable` (no terminal, no key
  hardware, record not writable), `broker-unavailable` (stage 2: no connection
  to the broker, no answer in 10 s, or it said `unavailable`: nothing was issued, try
  again), `broker-refused` (the broker refused the delegation). Nothing else is put into a reply: no
  paths, no text from outside.

## 4. Commands

| `name` | `args` | `data` | Presence check |
|---|---|---|---|
| `status` | none | `version`, `form` (`files` or `hardware`), the socket paths, counts of programs, delegations and open asks | no |
| `keys.list` | none | each key: `purpose`, `fingerprint`, `public` (the line `ssh-keygen` would print), `created`; and `block` for the four lower keys, the one block of public parts for an administrator (`SPEC.md`, section 2) | no |
| `keys.create` | `purpose` (`bound`, `shared`, or one of the four lower ones); for `bound`, `program`, `user` and `host_key` (the host key's fingerprint; a name is for showing only) | the key as in `keys.list` | yes |
| `keys.retire` | `fingerprint` | none | yes |
| `programs.list` | none | programs known to pledge: identity, state (`admitted`, `blocked`), last asked | no |
| `programs.admit` | `program`, `scope` (`generally`) | none | the name typed, by the command line |
| `programs.block` | `program` | none | no |
| `programs.forget` | `program` | none | no |
| `agents.start` | `groups`, `automatic_ceiling`, `ask_ceiling` (ratings), `valid_seconds` (60 to 86400, default 28800), `label`, and for the bundle `services` (the person's own: host, name, url), `tls_root`, `deadline_seconds` | `delegation`, `bundle` (the base64 of the bundle's exact bytes, composed by `p_act::pact::bundle::Bundle::write`), `valid_until`. The delegation is held on this connection and does not exist for pledge yet | yes |
| `agents.delivered` | `delegation` | none: the bundle is written; the delegation exists (is stored, signs) from now on. If the connection ends first, or `agents.failed` is sent, it never existed; the record gets `delegation-withdrawn`, `by` `delivery-failed` | no |
| `agents.failed` | `delegation` | none | no |
| `agents.list` | none | each delegation pledge issued: `delegation`, `groups`, both ceilings, `valid_until`, `withdrawn`, `last_asked`, `muted_until` | no |
| `agents.withdraw` | `delegation` | none | no: it only narrows |

`programs.block` and `agents.withdraw` only take something away, so they
need no more than the socket. What widens what a program or an agent may do
has a check of its own (R3).

- **Ceilings** are the ratings of `doc/approval-formats.md`
  (`{"exposure":..,"damage":..,"disruption":..}`). `agents.start` refuses
  an automatic ceiling above `internal`, `recoverable`, `brief`, or one above
  the ask ceiling (`refused`): pledge does not let one be set that high
  (`SPEC.md`, section 4; `p-act` rating).
- **As built** (`review-pact-bundle.md`, section 5, and the designer's decisions): the certificate and the key pair are made by OpenSSH (`ssh-keygen -s -U` against a private SSH agent socket, `issue.rs`); serve composes the bundle with p-act and replies with its bytes; the command line only writes them (to a file, created exclusively with mode 0600, or a pipe; never a terminal, and no option changes that), then sends `agents.delivered`.
- **`agents.start` returns a private key** over the socket to the command
  line, which writes it to standard output or to a file only the person can
  read (`SPEC.md`, section 4). pledge keeps the ceilings and the
  certificate, not the key. It is the only command whose reply holds a
  secret; a client must not log it.
- **`groups`** are names; in stage 1 pledge does not check them (one person,
  no site). With the broker it takes them from the names it received
  (`doc/approvals.md`, section 6).
- **`delegation`** is the delegation's identifier (`record.md`, section 8).

## 5. The presence check in the development form

Without key hardware there is nothing to touch. *Proposal:* where the table
says "yes", `pledge serve` asks on **its own terminal**, with the command's
meaning in words, and the command waits (its `reply` comes when answered).
The command line prints "waiting for the presence check on the terminal of
`pledge serve`". That is the stand-in for Touch ID and it protects nothing
against a program that can type into that terminal; the form says so
already. In the hardware form the same commands are unchanged and the check
is Touch ID.

## 6. Events, later

The desktop app needs to hear that a dialog opened or closed, that an agent
was muted, that a delegation ended. *Proposal:* a command `subscribe`, after
which `pledge serve` sends `event` lines on that connection (same envelope).
Not specified now; nothing in sections 1 to 5 stands in its way.

## 7. Decided (all three as proposed)

1. **Does the command line prompt, or does `pledge serve`?** Section 5 puts
   the presence check on `serve`'s terminal so that the command line holds
   no decision. The other way (the command line prompts on its own terminal
   and tells `serve`) is easier to use and gives a program that can write to
   `control.sock` the same power as one that can type. *Proposal:* section 5.
2. **`agents.start` over a socket.** A private key crosses it. The
   alternative, `pledge agents start` making the key itself and sending
   only the public part, would let the command line hold a private key
   without the key holder's rules. *Proposal:* as written; the socket is the
   person's, and the key is minted where the delegation key is.
3. **`programs.admit` needs a terminal.** Typing the name stops a program
   that can only write to the socket. In the hardware form the code
   signature check covers it too. *Proposal:* as written.

## 8. What a desktop front end needs: `stage2-mac.md` section 8.5, point by point

A note for the designer. Nothing in the protocol is changed. "Today" is what is built.

1. **Everything a front end shows comes over the socket.** *Not met.* The record is read as a file by
   `pledge history`; there is no command for it. *Change:* a `history` command (a page of entries by
   `seq`, the same JSON as the file) and the same for `agents.list`'s withdrawn state, which is already a command.
2. **State, then events.** *Half met.* `status`, `keys.list`, `programs.list`, `agents.list` give state;
   there are no events (section 6 is still "later"). *Change:* `subscribe`, and a rule that an event is
   never the only carrier of a fact (the dialog that is open, the broker's state, a withdrawal not yet stored
   at the broker would be in `status`).
3. **Codes and values, not sentences.** *Met*, for replies and errors (closed codes). The record's `why` of a
   refusal (`approvals.rs`) is a short English sentence of pledge's own, for the person on the command line;
   a front end would want a code beside it. *Change:* add `why_code`; keep the sentence.
4. **No nouns of one platform.** *Met today* (`form` is `files`; nothing names Touch ID). *Change:* `status`
   says per key who does the presence check.
5. **A dialog is a message, and the protocol says what an answer is worth.** *Not met.* Dialogs are
   `dialog::Dialogs`, a trait with a terminal implementation; nothing crosses a socket. *Change:* the
   events of 2, plus a command to answer; the decided dialog program (a small program of pledge's bundle,
   started by `pledge serve`, holding no key and deciding nothing) is a second implementation of
   `Dialogs` behind the seam that exists, so it needs no change to the socket.
6. **Long work has an identifier, progress and a cancel; closing cancels only what was asked that way.**
   *Partly.* `agents.start`, `keys.create`, `keys.retire` wait for the person and a closed connection cancels
   them (section 3); that is the right rule for these. There is no other long work in pledge. *Change:*
   an explicit `cancel` by `ref` for a command that waits.
7. **Several front ends at once.** *Not met.* Each connection serves its own commands; there is no broadcast.
   A question open in the terminal of `serve` is not shown elsewhere. *Change:* events to every subscriber,
   a question answered once and the others told.
8. **Nothing rests on the peer's code signature alone.** *Met in the form built.* The peer is the person's
   user (`p_act::peer::Policy::OwnUser`) and says so; what widens something has its own check (section 4).
9. **A front end older or newer than its daemon.** *Partly.* `schema_version` and unknown members refused are
   there. *Change:* `status` lists the command names this daemon has.
10. **Paths are the daemon's.** *Met.* No command takes a path from the front end; the bundle comes back as bytes
    and only the command line writes it.

**A rule per command and peer.** *Cannot be said today.* The one rule is the socket's: the peer is the
person's own user, for every command (and for `agent.sock`; `service.sock` takes any readable user). With
`p_act::peer` (`Peer` with uid, gid, pid, program) the information for a rule is there, but pledge has no
table of "command, peer". If preserve's app is to get exactly `keys.create` for a bound key and `keys.list`,
the change is small: a second socket (or a check after `accept`) with a list of allowed command names and, for
`keys.create`, a required `purpose` of `bound`, per peer program or, on the Mac, per code signature. In the
development form the program is a path and protects nothing; the rule means something only where the peer is
identified by code signature (hardware form), as with the rest of that form.
