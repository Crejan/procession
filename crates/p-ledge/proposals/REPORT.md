# p-ledge report: step 1 and three proposals

Branch `agent/p-ledge`. Commits: `b9edf9e` (SSH agent protocol and parsers),
`557dae9` (proposals, rename to follow the terms), the merge of `integration`
(4c8c58b..., clean) and the commit adding this report and the update of
`service-sock.md` to the designer's decisions (base64 signatures, separable
from its transport). Step 2 and 3 not started; `rating.rs` untouched.

## What changed

`src/agent/`: `message` (framing, 256 KiB limit, strict parse of the three
messages understood, replies), `sign_content` (strict login and SSHSIG
parser, reserved namespaces), `binding` (`session-bind@openssh.com`,
per-connection state), `host_key`, `known_hosts`, `wire`, `text`.
Dependencies: `ring`, `base64` (both already in Cargo.lock). Fixtures in
`testdata/` made with ssh-keygen 10.2 (throwaway keys).

Choices of mine: R9 refusal instead of Atticus's cleaning (login user and
SSHSIG namespace with control/bidi characters or over 200 characters are
not understood; empty namespace and non-empty SSHSIG `reserved` too);
any namespace ending in `@procession` (ASCII case-insensitive) is
reserved for every key; messages with trailing bytes are malformed.

## Verified

- `cargo test -p p-ledge --offline`: 73 pass (45 new). `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo doc` clean; pedantic
  clean for `agent/` (existing policy/rating/main still warn).
- Four mutations (invalid bind not failing, CA signature unchecked,
  reserved namespace unchecked, SHA-1 RSA accepted) each made tests fail.
- Real ssh-keygen certificates parse and match `ssh-keygen -l`
  fingerprints: ed25519 under an ed25519 CA, P-256 under an RSA CA
  (rsa-sha2-512), a user certificate, a P-521 key.
- Ported from Atticus: 15 malformed-login cases, login parsing, SSHSIG
  refusals (`atticus-` becomes `@procession`), unknown data, every
  supported host key type, wrong signatures, SHA-1 RSA, 1024-bit RSA,
  unknown key types, forged and tampered certificates, bind framing,
  direct/unbound/failed/forwarded/unverifiable routes, bind rules (second
  bind, session id moving, 16-bind limit), known_hosts naming, CA,
  revoked, hashed, patterns, unknown opcode.
- Not ported: Atticus "own peers sign silently", key roles, upstream
  forwarding, user-certificate login (not in the first version),
  `describe`/`sanitize` (step 2; sanitising is deliberately not done).

## Not verified

- No real `ssh`/`ssh-add` (no socket yet); session binding is tested
  against my own signed fixtures.
- `ring` has no P-521 and RSA only 2048..8192 bits: such host keys give an
  unverifiable binding, so logins to them are refused while a binding is
  required (Atticus supports P-521 and RSA to 16384).
- The designer now limits key types to Ed25519 and ECDSA P-256. My host key
  code also accepts P-384 and RSA, since servers' host keys are not ours to
  restrict; say if you want that narrowed.
- Sandbox: crates.io blocked (used `--offline`); Unix sockets cannot be
  bound under `$TMPDIR` (/tmp/claude-501) but can under `/tmp/claude/`;
  local ports not tested.

## The three proposals

- `proposals/service-sock.md`: `ask`/`answer`/`cancel`/`error`, `ref`,
  closed reason list, same messages for service-pledge, service-broker,
  broker-pledge; sign, record, send; separable from transport (section 10).
- `proposals/record.md`: JSONL, hash over the raw bytes of the previous
  line, entry types `request`, `signing-request`, `event`; no record, no
  approval; unshowable text never stored as text.
- `proposals/control-sock.md`: `command`/`reply` in the same envelope,
  command table, presence check on `serve`'s terminal in the development
  form.

## Needs

- p-act: `Ask`/`Answer` types and line codec (or I write them in p-ledge
  and move them); parse/verify for call, request, approval; whether its
  strict-text check is exposed (I have `agent/text.rs`).
- p-robe: review of `service-sock.md` from the client side.
- Orchestrator: socket directory/group decision (service-sock section 6);
  `/tmp/claude/` for socket tests; reconciling the envelope with p-age's
  connection messages; `@procession` reserved-namespace rule in
  `approval-formats.md`.

## Open questions for the designer

1. Fifth record outcome for a cancelled ask (proposal: `cancelled`).
2. A declined call asked again (proposal: allowed until deadline, counts
   toward muting).
3. Fineness of the reasons given to the agent (oracle?).
4. First entry kept after a year's trim (proposal: `trimmed` event plus
   reader derives it from `seq`).
5. Delegation identifier (proposal: fingerprint of the agent's key). Note
   the designer's change: the certificate has the person as only
   principal and `groups@procession`; check this still fits the record's
   `person`/`delegation`/`agent` members.
6. Presence check in the development form on `serve`'s terminal.
7. Private key crossing `control.sock` in `agents.start`.
8. Which way the 60 s clock tolerance tilts for a deadline.
9. Name of the connection key's namespace (reserved as part of the
   `@procession` family meanwhile).

## Update: rating moved to p-act (done)

Merged `agent/p-act` (Cargo.lock conflict resolved by taking theirs and
letting cargo add p-ledge's deps). `p-ledge` depends on `p-act` by path;
nothing in p-ledge used `rating` besides its own module, so
`src/rating.rs` and its export are deleted (no re-export). Tests: 65 pass
(73 minus the 8 rating tests, which live in p-act), clippy `-D warnings`
and fmt clean. Not started: step 2, the `ask`/`answer` codec.

## Update: `service-sock.md` revised after the review and reconciliation

Rewritten as the Unix-socket transport only: it refers to p-age's shared
exchange for `submit`/`answer` instead of defining them. Changes: `ask`
became `submit`; correlation by the request's hash, no `ref`, no
`duplicate-ref`; `by` on `refused`/`expired`; line limit 96 KiB; 16 open
requests as a transport parameter; door fixed (0710/0660 with a group, else
0700/0600; the service checks the other end); stage 1 refuses clearance
members, stage 2 requires them by configuration; unknown hash in `cancel` or
`answer` is ignored and logged. Section 7 lists each p-robe point and
whether I adopt it (not adopted: `shown`, `ping`). Section 6 states what
pledge keeps under either reading of R5 (A idempotent by hash, B refuse any
second submit); I recommend A.
Notes for the reconciliation: p-age uses `v`, the orchestrator keeps
`schema_version`; p-age's pledge reasons (`not-mine`, `replayed`,
`bad-call`, `above-ceiling`) differ from mine and p-robe adopted mine;
`detail` is dropped (no free text). `record.md` is unchanged: its
`cancelled` result and `request_hash` already fit; the "ask" wording
there is not used for messages. Seven questions remain in section 8.

## Step 2: `pledge serve` with keys in files

Merged `integration` (f4a97a7) first; the proposals now follow the designer
(service-sock section 6 and 8, record section 8, control-sock section 7), and
the reserved-namespace rule is "ending in `@procession`" (ASCII
case-insensitive).

### What exists

- **Reader and key holder as two processes.** `pledge serve` (reader) starts
  `pledge key-holder` as a child. The holder (`holder.rs`) opens the key
  files, and speaks a fixed binary format on its pipes: list, sign (blob,
  data), create, retire. It reads nothing inside the data. The reader never
  opens a key file. Same user, so it protects nothing here; the separation is
  in place for hardware. Keys: Ed25519 and ECDSA P-256, PKCS#8 files, mode
  0600, with a description file the holder returns unread.
- **SSH agent socket** (`agent_conn.rs`): list identities per program
  (`Policy::offered`), signing requests through `SignContent::parse`, the
  session rules of `binding.rs`, then `policy.rs` decides; dialogs for the
  verdicts `AskAdmission` and `CheckPresence`; sign through the holder; the
  record entry is written and flushed before the signature is handed over,
  and a record that cannot be written means no signature (tested with a
  failing sink). Muting after three declines in ten minutes with a notice
  (`mute.rs`). Programs are identified by the path of the connecting process
  (`peer.rs`: `SO_PEERCRED` / `LOCAL_PEERPID` and `proc_pidpath`). A program
  that cannot be named or shown gets nothing.
- **Rules of SPEC section 3 as built:** data not understood refused first for
  every program; a key pledge does not hold refused (`key-not-offered`) before
  any dialog; every login needs a verified host binding (a bound key too: its
  login is matched as `login <user>@<host>` against the names `known_hosts`
  gives the verified host); forwarded and failed-bind connections refused; a
  shared key signs SSHSIG in `git` and `file` only (added to `policy.rs`,
  with tests, as `KeyNotOffered`).
- **Record** (`record.rs`) as `record.md`: chain over raw line bytes, `flock`,
  fsync per entry, torn-tail repair, trim at start without re-hashing,
  `read_and_verify` (breaks reported, reading goes on). Entries: `signing-request`
  and events (`started`, `repaired`, `trimmed`, `key-created`, `key-retired`,
  `program-admitted/blocked/forgotten`, `program-muted`). Unreadable data is
  stored as hash and length, never as text; a program path that cannot be shown
  is stored as a hash.
- **Dialogs** (`dialog.rs`): on the terminal of `pledge serve`; fields one per
  line, each as signed (no quotes, no cleaning); one at a time; answers from
  standard input (a pipe works, which is how the tests answer); lines typed
  ahead are discarded only when standard input is a terminal; a login dialog
  closes after 60 s (`expired`). Admitting generally needs the program's name
  typed. No input at all is `refused/unavailable`.
- **`control.sock`** as `control-sock.md` for what step 2 needs: `status`,
  `keys.list/create/retire`, `programs.list/admit/block/forget`; presence
  check on `serve`'s terminal; peer must be the same user; `deny_unknown_fields`
  on commands and arguments; line reader with 96 KiB and 10 s from the first byte.
  Not built: `agents.*` (step 3), `subscribe`.
- **CLI:** `pledge serve | keys | programs | history` (`history` reads the file
  directly, verifies the chain, `--verify` exits 3 on a break; control
  characters are escaped on output). `programs admit` refuses without a terminal.
  `agents` still says not implemented. Exit codes 0, 2 usage, 3 failed, 4 refused.
- The warning at start is printed on standard error and tested.
- No `service.sock`.

### Verified

- `cargo test -p p-ledge --offline`: 117 unit tests and 6 integration tests
  pass, three runs in a row; `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, `cargo doc` clean. Four mutations of the new code
  (signature handed over without a record, unknown key reaching the dialog,
  blocked program not refused, binding rule skipped) each failed tests;
  restored. Pedantic is not clean for the new files (about a dozen minor
  warnings: format-append, by-value arguments, casts); not fixed.
- **Real programs** (`tests/real_programs.rs`, against the built `pledge`):
  - `ssh-add -l` on an empty pledge (exit 1, "no identities"), then after
    `pledge keys create shared`: the fingerprint `ssh-add` prints is the one
    `pledge keys list` prints and `ssh-keygen -lf` computes; `ssh-add -L`
    equals the public line.
  - `ssh-keygen -Y sign -U` signs through pledge: the unknown program is asked
    about, admitted by typing its path, presence check, and the signature
    verifies with `ssh-keygen -Y check-novalidate`. Then the admitted program
    gets only the presence check (namespace `file`), and a declined one gets no
    signature. The history has `approved git`, `approved file`, `declined git`
    with the program's path.
  - `-n approval-v1@procession`, `call-v1@procession`, `anything@procession`
    refused with no dialog (`reserved-namespace`), `-n other` refused
    (`key-not-offered`).
  - A blocked program stays blocked without a dialog; a second `pledge serve`
    on the same directories exits 3 ("in use").
- **Did not run:** a login with real `ssh` against a local `sshd`
  (`ssh_logs_in_through_pledge_to_a_local_sshd_or_is_skipped`). Binding a TCP
  port is refused in this sandbox, so it prints
  `SKIPPED ... binding a local TCP port is not allowed here` and returns. It is
  written but has never run, so it may need fixing the first time it does.
  Session binding and the login rules are therefore tested only against my own
  signed fixtures (unit tests of `binding.rs` and `agent_conn.rs`), not a real
  `ssh` client.

### Not verified, limits, deviations

- Graceful shutdown: none. A killed `pledge serve` leaves its sockets; the next
  start replaces a stale one and refuses a live one. Trimming of the record is
  at start only (not daily).
- Program identity by process path: a pid that is reused, or a program that
  execs another, changes the answer. Said at start.
- Every login, a bound key's too, needs a verified host binding (SPEC
  section 3 says so; Atticus exempted its own silent peers). A client
  without `session-bind@openssh.com` or hostbound authentication (OpenSSH
  before 8.9) cannot use pledge for logins; there is no setting for it
  (`require_binding` exists in `Shared`, always true).
- A bound key names its host as `known_hosts` does; a host not in
  `known_hosts` (or only hashed) cannot match a bound key.
- The holder lists keys at start and after each create/retire; a key file
  placed by hand needs a restart.
- Admission "block" of a program is recorded `refused / blocked`; "decline once"
  and a "no" at the presence check are `declined` and count toward muting.
- macOS quirk, handled: `setsockopt(SO_RCVTIMEO)` fails with EINVAL on a socket
  whose peer has closed, so the line reader ignores that error (the read ends
  at once anyway).
- The sandbox allows Unix sockets under `/tmp/claude/` but not under `$TMPDIR`;
  `testing::TestDir` and the integration tests choose a directory where a bind
  works (never hard-coded outside tests).

### Questions for the designer (new)

1. Logins by a client without session binding (older than OpenSSH 8.9): refuse
   always (as built), or allow with the dialog saying "NOT verified" behind a
   setting, as Atticus does?
2. A bound key and a host that `known_hosts` knows only by hash or not at all:
   as built it cannot match. Should a bound key be able to name a host key
   fingerprint instead of a name?
3. Is "refused / blocked" (the person blocked it in the dialog) right for the
   record, or should it be `declined` with the block as an event?

## Review of the pact bundle (option B)

`proposals/review-pact-bundle.md`. Short: pledge can write exactly the bundle
(Ed25519 OpenSSH key block built by hand, certificate built by pledge and
signed by the key holder, `-O clear` plus `groups@procession`); it lacks the
services list (stage 1: the person's file or options; stage 2: the broker's
list narrowed by the person's own url configuration, TLS root from its own
broker setting). The leak risks are in delivery: I propose `agents.delivered`
(a delegation is pending and signs nothing until the command line reports
the bundle written; a closed connection withdraws it), no bundle to a terminal
by default, a redacting key type. Changes to `control-sock.md` are listed in
section 5 of the review; not yet applied to that file.

## Step 3: approvals with keys in files

Merged `agent/p-act` (`p_act::exchange`, `verify_call_agent`,
`verify_request`, `signature_agent`) and `integration`. Commit
`a837d5c`. Nothing of step 4 or later.

### What exists

- **`service.sock`** (`service_conn.rs`, `serve.rs`): the shared exchange
  with `p_act::exchange` under `ClearancePolicy::Refused`. 16 requests open
  per connection (`too-many-open` then close), one thread per submit, the
  end of a connection cancels what it had open, a request that does not parse
  is answered `refused/malformed` for its hash and the connection stays, a
  line not finished in 10 s ends the connection (`TimedRead`). Door: 0600 in
  0700, or with `service_group` in `config.json` 0660 in 0710 (group set by
  `chown`); the peer is recorded, not decided on.
- **The checks of SPEC section 4 in their order** (`approvals.rs`): the
  delegation (own, active, not withdrawn, not ended, and the call verified
  with `verify_call_agent` under the delegation key that issued it), the
  deadline by pledge's own clock, the identifier, the service's signature
  under the configured host's key, every field showable, the limits, the mode
  from the ceilings. Then sign, record, store, send. No record entry, no
  approval (tested with a failing record). The key holder is unchanged: it
  signs the bytes it is given.
- **Modes**: `Ceilings::mode` from p-act. An automatic ceiling above the
  highest a person can set (and above the ask ceiling) is cut down on
  every load (`delegations.rs`), and refused when issuing; a request at the
  top of any scale is asked about and signed with the confirmed key. Tested
  with the file tampered and pledge restarted.
- **Store of answers** (`answers.rs`, `answers.jsonl`): `used` identifiers and
  `answer`s until the call's deadline, fsync per line, compacted at start.
  Verdicts, approvals and declines are kept; `limit`, `muted`, `unavailable`,
  `deadline-past`, `call-used`, expiry and cancellation are not. The same bytes
  get the same answer (same approval bytes) with no dialog and no new record
  entry, also after a restart; a different request under a used identifier is
  `call-used`. The identifier is used when the approval is about to be signed
  and when the person declines. Two connections with the same open request
  share one dialog and both get the answer.
- **Limits and muting**: 5 open requests per agent by default
  (`max_waiting`), refused `limit`; 3 declines within 10 minutes mute the
  agent for 10 minutes (`muted`, even harmless requests), the person is told;
  one dialog at a time; a dialog waits its turn within the deadline and
  closes at it (`expired`), or when cancelled.
- **Delegations** (`agents.rs`, `openssh.rs`, `delegations.rs`): `pledge
  agents start` makes an Ed25519 key in memory, builds the OpenSSH key block and
  the certificate (person as only principal, no critical option, extension
  `groups@procession`, `-O clear`), has the key holder sign it with the
  delegation key, checks it with `verify_call_agent` on a probe call, and
  replies with both. The delegation's identifier is the key's fingerprint.
  `list`, `withdraw`. Validity 60 s to 24 h, default 8 h. The delegation is
  pending until `agents.delivered`; a closed connection or `agents.failed`
  withdraws it. The bundle (`bundle.rs`) is as reviewed: line 1, the key block,
  the certificate line; the CLI writes it once from one buffer, refuses a
  terminal unless `--to-terminal`, creates `--output` exclusively with mode
  0600, and checks the configuration (services, https/http rule) before it
  starts a delegation.
- **Record**: `request` entries with the five outcomes (`approved`,
  `declined`, `refused`, `expired`, `cancelled`), delegation, person, service,
  call, deadline, shown fields, rating, mode, key role and fingerprint,
  `request_hash`, peer; events `delegation-issued`, `delegation-withdrawn`
  (`by` `person` or `delivery-failed`), `agent-muted`. `pledge history` prints them.
- **Keys**: `pledge keys create confirmed|automatic|delegation` (never offered
  on the SSH agent socket, tested; one of each).
- **Stage 1 configuration**: `config.json` in the state directory: `person`,
  `hosts` (name and public key line of the host that certifies services),
  `services` and `tls_root` (for the bundle), `deadline_seconds`, `max_waiting`,
  `service_group`.

### Verified

- `cargo test -p p-ledge --offline`: 165 unit, 3 + 6 integration tests; four runs
  in a row clean; `clippy --all-targets -D warnings`, `fmt --check`, `doc`
  clean. Mutations of the new code (deadline tolerance extended, verdicts not
  kept, used identifier not checked, pending delegation signing, limit off,
  request signature unchecked, call signature unchecked, ceiling not clamped)
  each failed a test (one, the call signature, needed a new test first).
- **With a service faked in the tests** (a throwaway host key certifying a
  throwaway service key, as p-act's tests do; calls signed with the key and
  certificate from our own `agents start`, by the real `ssh-keygen`; approvals
  verified by `ssh-keygen -Y verify` through `verify_approval`): approved
  automatic and confirmed, declined, refused (ceiling, service-mismatch,
  not-showable, malformed, call-used, deadline past/too far, limit, muted,
  unavailable, unknown and withdrawn and ended delegation, a foreign
  delegation, a loose key, a call signature carried to other bytes), expired
  with the dialog open, cancelled, a connection that ends, the same bytes
  again (stored), a different request under a used identifier, a restart
  between submit and repeat, the 17th open request, no record no approval, the
  certificate against `ssh-keygen -L` (and a reference made with `-O
  extension:groups@procession=`), the key block against `ssh-keygen -y`.
- **Against the real binary** (`tests/real_approvals.rs`): `pledge keys create`,
  `agents start --output`, the bundle read back (line 1, key block, cert line,
  mode 0600), a call signed with it by `ssh-keygen`, requests on `service.sock`
  from a faked service, answers verified, withdraw, `history --verify`, a
  restart of `pledge serve` and the same approval again, `agents start`
  refused without services and the withdrawal after a bundle that could not be
  written.

### Not verified

- The real `pact` and the real `probe serve`: neither exists in this
  worktree. Whether `pact` reads this bundle (key block without a `.pub`
  file, certificate line without comment) is only shown by `ssh-keygen`
  signing with it.
- Keys of type ECDSA P-256 for the delegation or approval keys: the holder
  signs P-256 and `agents start` would take it, but no test makes one.
- `service_group` with a group other than the user's own, and a peer that is
  not this user.
- The login test with real `ssh` and `sshd` is still skipped here (no port).
- Load: every request costs two to three `ssh-keygen` runs.
- The certificate-validity tolerance of the clock decision: `ssh-keygen`
  decides on the agent's certificate; pledge backdates the ones it makes by
  60 s. The 60 s is otherwise only in "more than 10 minutes ahead".

### Where I had to choose (all of them)

1. `config.json` and its members (above). The person's name is the
   configuration's; a call whose certificate names another person is
   `unknown-delegation`.
2. The presence check in the development form is a second prompt after the
   request's dialog.
3. A shown field is at most 200 characters, `action`, `parameters` and
   `claim` alike; a `parameter` of 201 to 512 (which the formats allow) is
   `not-showable`. The 2000 of a command is not applied (U6 is stage 4).
4. A control character or bidirectional mark never reaches that check:
   `p_act` refuses it at parsing, so it is `malformed`.
5. How long verdicts are kept: to the call's deadline, but at most 11
   minutes from now (a deadline far ahead would keep an entry for years); for
   `malformed` there is no deadline, so 11 minutes.
6. `deadline-past` and `call-used` are not in the document's lists of kept or
   not kept answers; I do not keep them. `expired` and `cancelled` are not kept.
7. `unknown-delegation` covers: a certificate that does not keep to 3.1, a
   fingerprint pledge did not issue, a pending delegation, a person that is
   not this pledge's, an issuing key pledge no longer has, a signature that
   does not verify, ceilings in words that are not the scale.
8. The identifier is marked used before the approval is signed; if pledge
   dies before it records and stores, the same bytes are decided again (a
   signature nobody got), a different request is `call-used`.
9. A repeated answer from the store is not recorded again (as `record.md`
   section 8 decided).
10. A `cancel` on one connection while another has submitted the same bytes
    removes only the first; the dialog closes when the last has gone.
11. A "no" at the presence check counts as a decline for muting and uses the
    identifier.
12. Waiting requests count while their dialog is queued or open, automatic
    ones only for the instant they take.
13. The record's `request` entry carries `peer` (uid, pid) of the connection.
14. The shared exchange's 10 s line timeout is applied by `TimedRead`
    (the clock starts when a read leaves an unfinished line).
15. The bundle's line-1 members: `v`, `services` (`host`, `name`, `url`),
    `deadline_seconds`, `tls_root` (named as `pact.md` section 2 names them;
    its option B text was not final in my copy); `min_wait_seconds` is never
    written.
16. An agent's label (the certificate's key id) is `pledge agent` unless given
    (`--label`), shown by nobody yet.
17. Verification uses `p_act`'s `ssh-keygen` runs in the reader process.
18. A delegation can be activated only once, from pending.

### Questions for the designer

1. Should `deadline-past` and `call-used` be answered again from the store?
   (They are verdicts on this request by the clock and by another request.)
2. Is a call with another person's certificate `unknown-delegation`, or does
   it deserve its own reason?
3. Fields of 201 to 512 characters that the formats allow in `params` are
   refused here as `not-showable`; should the formats' limit follow the dialog's
   200, or the dialog's follow the formats?
4. Is a delegation that was started but whose bundle was not delivered
   rightly `withdrawn` in the record (`by` `delivery-failed`), or should it
   have its own event?

## Step 3, second pass: the designer's decisions A to D

Merged `integration` (SPEC sections 2, 3, 4) and `agent/p-act` 64077e0.
This replaces the parts of the step 3 report that say pledge writes a
certificate, a key block or a bundle.

**A. No writers in pledge.** `ssh-keygen -s <delegation .pub> -U` works against
my SSH agent code on the first try, for an Ed25519 and for a P-256 delegation
key, with `-O clear` and `-O extension:groups@procession=...`; nothing failed,
so nothing of my own was written. The one seam is `src/issue.rs`:
`issue(shared, work_dir, &Issuing{person, groups, label, valid_seconds, now})
-> Issued{key: KeyBlock, agent_public, certificate, agent}`; nothing else knows
how. Inside: `ssh-keygen -t ed25519 -N ''` into a private directory (0700), key
read and removed at once; a private SSH agent socket in that directory,
offering only the delegation key; `ssh-keygen -s ... -U` with `SSH_AUTH_SOCK`
set to it; the socket and directory are gone when it exits. The reader reads
the certificate out of the signing request (with p-act's `agent_certificate`,
the signature field padded empty) and lets the key holder sign only if it is
the certificate this issuing asked for: this person, exactly these groups,
this label, validity within a few seconds of what was chosen (and at most 24 h
plus the backdating), no critical option, no other extension, Ed25519 certified
key (all p-act's rules, plus the comparison). The result is read again with
`agent_certificate` and compared before it is used. The key holder still parses
nothing. `openssh.rs`, my bundle writer and the probe call are deleted; the key
is p-act's `KeyBlock` (prints nothing, zeroed on drop); the bundle is
`Bundle::write`, which reads it back with `pact`'s own parser. `p_act::limits`
replaces my copies of 600/60/8 h/24 h.
Tests: `ssh-keygen` issues for both delegation key types; six attempts at
other certificates (another person, other groups, no groups, a week, another
label, no `-O clear`) each get no signature from the private agent and
`ssh-keygen` fails; nothing is left behind in the work directory; the
certificate against `ssh-keygen -L` and a reference made with `-O
extension:`; the key block against `ssh-keygen -y`; calls signed by
`ssh-keygen -Y sign` with that key and certificate verify through
`verify_call_agent`; an agent under a P-256 delegation key is approved.

**B. Delivery.** A delegation exists for pledge only from `agents.delivered`:
until then it is held on the control connection that started it, is not in
`delegations.json`, signs for no call (`unknown-delegation`), and a connection
that ends first (or `agents.failed`) leaves one record entry,
`delegation-withdrawn` by `delivery-failed`. `State::Pending` is gone. A bundle
is never written to a terminal and there is no option (`--to-terminal` is
removed). `agents.start` now composes the bundle in `pledge serve` and replies
with its bytes (base64); the command line writes them once (`--output` created
exclusively, mode 0600, or a pipe). `control-sock.md` is updated as the review
said.

**C. Services in the bundle**: `--service host/name=url` (repeatable),
`--tls-root FILE`, `--deadline S`, overriding `config.json`'s `services`,
`tls_root`, `deadline_seconds`; never the broker's word.

**D. The SSH agent half.** (1) A login without a verified `session-bind`
is always refused (`require_binding` is gone); the record says
`host-not-verified` and the terminal tells the person why. (2) A bound key is
bound to a user and a host key's fingerprint (`policy::login_use`, `keys create
bound --program P --user U --host-key SHA256:...`); `known_hosts` names are
shown only. (3) "Block" is recorded as `declined` for that signing request, the
block as the event `program-blocked`, later requests are refused `blocked`; it
does not count toward muting.

`ApprovalTrust::PersonKeys` now takes the person: my tests pass `jan`.

### Verified (all of step 2 and 3)

`cargo test -p p-ledge --offline`: 163 unit + 3 + 6 integration tests, three
runs in a row clean; `clippy --all-targets -D warnings`, `fmt --check` and `doc`
clean. Earlier mutation checks stand; the new code's behaviours each have a
failing-then-passing test (six refused certificates, the pending/delivered
cases, bound by fingerprint, block as decline, unbound refused).

### The login test against a local sshd: written, never run

`tests/real_programs.rs`, test `ssh_logs_in_through_pledge_to_a_local_sshd_or_is_skipped`.
Here binding a TCP port is refused, so it prints
`SKIPPED ssh login test: binding a local TCP port is not allowed here` and
returns, which cargo counts as a pass. To run it by hand on the owner's
machine (a Mac or Linux box where `127.0.0.1` can be bound, with
`/usr/sbin/sshd` and OpenSSH 8.9 or later):

```
cargo test -p p-ledge --test real_programs ssh_logs_in -- --nocapture
```

It counts only if no `SKIPPED` line is printed. It makes a host key and a
`known_hosts`, starts `pledge serve` with that `known_hosts`, makes a shared
key, starts an unprivileged `sshd -D -f <config>` (`UsePAM no`,
`StrictModes no`, `AuthorizedKeysFile` = pledge's key) on a free port, runs
`ssh -p PORT user@127.0.0.1 true` with `IdentityAgent` set to pledge's
socket, admits `ssh` in the dialog (answers `g`, its path, `y` on pledge's
standard input) and checks that the login succeeded and the record has an
approved login with `host_verified: true` and the host's name. It has never
executed: if it fails on first run, look at `sshd`'s own refusal first (a
non-root `sshd` can be picky), then at the test.

### Not verified (changed from the step 3 report)

- The real `pact`: its parser reads what `Bundle::write` makes (that is how
  `Bundle::write` checks), and `ssh-keygen` signs with the key and certificate
  in it; `pact serve` itself was not run.
- `service_group` with a group other than the user's own.
- Everything that needs a Secure Enclave, a broker or a real `probe`.

## Step 3, third pass: the designer's reading of the 18 choices

Merged `integration`. Changes:
1. `deadline-past`, `call-used`, `expired`, `cancelled`: not stored (as built).
2. `unknown-delegation` split: a call that is not a valid call (a certificate
   breaking formats 3.1, a signature that does not verify, none) is `malformed`; a
   well-formed call not under a delegation pledge answers for (unknown fingerprint,
   another person's certificate, issuing key gone) is `unknown-delegation`;
   ceilings in words that are not the scales give `unavailable`, not kept, and the
   event `delegation-unusable` in the record. (A pending delegation no longer
   exists: it is not stored before delivery.)
3. A dialog shows a field whole: `action` and `claim` as p-act limits them, each
   parameter up to 512 bytes; all parameters together over 2000 characters, or any
   control or bidirectional mark, is `not-showable`. A 300-character parameter is
   shown whole (tested); five of 450 are refused.
4. A delegation started and not delivered: the event `delegation-not-delivered`,
   never `delegation-withdrawn`.
The 11-minute cap on kept verdicts is written next to `expiry()` as the 10 minutes
of `MAX_DEADLINE_AHEAD_SECONDS` plus the 1 minute of `CLOCK_TOLERANCE_SECONDS`.
Tests: 164 unit + 9 integration pass twice; clippy and fmt clean.

## The intermittent `Locked` in the unit tests

Not the helper alone and not a leaked `Arc`: `Rig::restart` replaces the old
record before reopening, so no owner of the old `Shared` can keep it. The cause
is `flock`: the lock belongs to the open file, and a child made by `fork` holds
it until it execs. Tests run in parallel and every `ssh-keygen` one of them
starts forks the whole process, so another test's record file (and its lock) is
briefly held by that child. In a real `pledge serve` the same can happen to a
quick restart if an `ssh-keygen` of the old one (issuing) is still alive.
Fix in pledge, not the helper: `Record::open` waits up to `LOCK_WAIT` (2 s) for
the lock before it says another `pledge serve` holds it (`open_waiting` for a
different wait); a real second instance is still refused, after the wait.
Result: 0 failures in 40 runs of the unit tests (before: 4 of 32 in the lead's
runs). I did not reproduce the failure before the fix myself.

## Stage-1 run: decisions 1 to 4

1. `pledge history` prints a legend on standard error (and `--help` says the
   same): `approved` means this machine signed, not that the action was done; what
   ran is in the service's own log, joined by the call's identifier. `record.md`
   section 9 likewise.
2. A submitter gone at or after the deadline, or within 2 s before it
   (`approvals::CANCEL_AS_EXPIRED_SECONDS`, local until `p_act::limits` holds it), is
   recorded `expired`; earlier `cancelled`. Tested at 3 s before, 1 s before and after.
3. `received` entry before a request that waits is queued or shown (no record, no
   dialog, tested); the answer is a second entry with the same hash; one answered at
   once keeps one entry. At start (`Shared::settle_lost`, before `started`) every
   `received` without an answer gets `lost` (when received, last entry before the
   start). Test with the real binary: killed with a dialog open, restarted,
   `history --verify` exits 0 and shows `received` then `lost`.
4. `Call::showable()` from p-act replaces my 2000-character sum; the person's name
   stays checked by pledge.
Unit tests 20 runs in a loop: 0 failures.
