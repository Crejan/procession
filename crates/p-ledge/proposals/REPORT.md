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
any namespace containing `@procession` (ASCII case-insensitive) is
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
