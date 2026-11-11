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
