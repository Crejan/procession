# Proposal: the record

Status: a proposal by the p-ledge agent, for the designer. Fills in
`SPEC.md`, section 6 (R12 of `doc/approvals.md`). Nothing is built on it.

## 1. What it is

A file of JSON lines, appended to by `pledge serve` and nothing else; each
line is an entry; each entry carries the hash of the line before it. One
file, so that `pledge history` and a person's own tools read it without
pledge running. The workspace's machine-output convention (one JSON object
per line, `schema_version`).

| | |
|---|---|
| Linux | `$XDG_STATE_HOME/pledge/record.jsonl`, default `~/.local/state/pledge/record.jsonl` |
| macOS | `~/Library/Application Support/pledge/record.jsonl` |
| Mode | 0600; directory 0700. It holds parameters and commands |
| Writer | `pledge serve`, with an exclusive `flock` for as long as it runs |

## 2. The chain

An entry is one line. Its hash is `sha256:` and 64 hex digits over **the
bytes of that line, without the `\n`**, as they are in the file. The next
entry's `prev` is that hash. Nothing is re-serialised or canonicalised, on
writing or on verifying: the same principle as the signed formats
(`approval-formats.md`, section 1).

```json
{"schema_version":1,"seq":42,"time":"2026-11-11T15:04:05Z","prev":"sha256:9c2f...","type":"request",...}
```

- `seq` starts at 1 and rises by 1. `prev` of entry 1 is `null`.
- `time` is UTC to the second, as in the formats. It is pledge's clock and is
  not checked to rise; `pledge history --verify` reports a decrease.
- A reader verifies by hashing each line as read. A line that is not valid
  JSON, a `seq` that does not follow, or a `prev` that does not match is a
  break, reported with its line number; reading goes on after it so that
  one break does not hide the rest.
- A trailing line without `\n` is a write that did not finish. A reader
  ignores it; `pledge serve` cuts it off at start and appends a
  `repaired` event.

## 3. When an entry is written: no record, no approval

The entry is written and flushed (`fdatasync`) **before** the approval or
signature it describes is handed over. The order for everything that
signs is: reserve the call's identifier (a separate store, on disk), sign,
append, flush, send. If the entry cannot be written, nothing is sent and
the answer is a refusal with reason `unavailable`. A crash between signing
and appending loses a signature nobody received. A crash cannot produce an
approval that is not recorded.

Refused and expired ones are recorded the same way, but they release
nothing, so a failure to write them does not change their answer.

## 4. Entries

Every entry has `schema_version`, `seq`, `time`, `prev`, `type`. The types:

### `request`: a service's request that reached pledge (`SPEC.md`, section 4)

```json
{"schema_version":1,"seq":42,"time":"2026-11-11T15:04:05Z","prev":"sha256:9c2f...","type":"request",
 "result":"approved","key":"confirmed","key_fingerprint":"SHA256:...",
 "person":"jan","delegation":"SHA256:...","agent":"SHA256:...",
 "service":{"host":"a.example","name":"probe"},
 "call":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z",
 "action":"rt procs","params":["pid=4711"],"claim":"checking why the control loop misses cycles",
 "rating":{"exposure":"internal","damage":"none","disruption":"none"},"mode":"ask",
 "request_hash":"sha256:..."}
```

| Member | Meaning |
|---|---|
| `result` | `approved`, `declined`, `refused`, `expired` or `cancelled` (`service-sock.md`, open question 1) |
| `reason` | only with `refused`: the code of `service-sock.md`, section 4 |
| `key` | only with `approved`: `confirmed` or `automatic`, the key that signed; `key_fingerprint` its fingerprint |
| `mode` | `refuse`, `ask` or `automatic`; absent if the request was refused before a mode could be derived |
| `person`, `delegation`, `agent` | from the call's certificate; `delegation` is the delegation's identifier (open question 2), `agent` the fingerprint of the agent's key |
| `service` | host and name as the call names them |
| `call`, `deadline`, `action`, `params`, `claim` | the call's own members, exactly what the dialog showed. `claim` is the agent's claim, as in the dialog |
| `rating` | as in the request |
| `request_hash` | the hash of the request's bytes, so that what the service holds can be matched with this entry |
| `peer` | the connecting process of `service.sock` (user, process, as information) |

"In the dialog's words": the entry holds the same fields the dialog is
built from, as the call has them. It does not hold a rendered text, so that
a later change of wording does not make the record say something else.

**What cannot be shown as it is is not stored as text.** A request refused
with `not-showable` (R9) has fields with control characters or bidirectional
marks. The entry then holds `request_hash`, `service` if it parsed, and the
`reason`, and no `action`, `params` or `claim`: `pledge history` prints a
terminal, and the record must not become a way to reach it. When the request
did not parse at all, `person`, `delegation` and `agent` are absent too. A
request that was refused before its call could be read has only the reason,
the hash and `peer`.

### `signing-request`: a signing request on the SSH agent socket

```json
{"schema_version":1,"seq":43,"time":"...","prev":"sha256:...","type":"signing-request",
 "result":"approved","key_fingerprint":"SHA256:...","key_purpose":"shared",
 "program":"/usr/bin/ssh","use":"login","user":"jan","host":"backup.example.org",
 "host_fingerprint":"SHA256:..."}
```

- `use` is `login` (with `user`, and `host`, `host_fingerprint` if the SSH
  agent verified them; `host_verified` is `false` otherwise and the dialog
  said so) or `sshsig` (with `namespace`).
- `program` is who the SSH agent says the program is, in the form of
  `SPEC.md`, section 3 (a path in the development form, a code signing
  identity later), with `chain_complete` `false` where the chain had holes.
- `result` is as above; for a refusal `reason` is a [`Refusal`](../src/agent/mod.rs)
  label (`reserved-namespace`, `unrecognised`, `host-not-verified`,
  `forwarded`, `bind-failed`, `session-mismatch`) or a policy reason
  (`key-not-offered`, `blocked`). A dialog for a login that nobody answers in
  60 seconds is `expired`.
- What the SSH agent refused as data it could not show is not stored as
  text: `use` is `unreadable`, and the entry has `data_hash` and the
  length.

### `event`: what else the person would want to find

`SPEC.md` lists signing requests and requests. These also happen in pledge
and are needed to read the rest, so they are in the same chain:

| `event` | Members |
|---|---|
| `started` | `form` (`files` or `hardware`; `files` says it protects nothing), `version` |
| `repaired` | `dropped_bytes` |
| `key-created`, `key-retired` | `purpose`, `key_fingerprint` |
| `program-admitted`, `program-blocked`, `program-forgotten` | `program`, `scope` |
| `delegation-issued` | `delegation`, `person`, `groups`, both ceilings, `valid_until` |
| `delegation-withdrawn` | `delegation`, `by` (`person` or `administrator`) |
| `agent-muted`, `agent-unmuted` | `delegation`, `until` |
| `trimmed` | `count`, `through_seq`, `through_time`: entries older than a year were removed |

## 5. A year, and the first entry kept

Entries older than a year are removed from the start, at start and once a
day: the file is rewritten without them (to a temporary file in the same
directory, `fsync`, `rename`). **Nothing is re-hashed**: the entries kept
are the lines they were, so the first one kept has a `prev` that points to
an entry no longer there, and a `seq` above 1. A reader takes that `prev`
as its starting point and says so: "earlier entries removed; the record
starts at seq N". A `trimmed` event, appended when the removal is done,
says how much went and up to where.

This departs from `SPEC.md`, section 6, in one way: the first entry kept
does not say so itself, because changing it would change its hash and break
the next. The reader says it from `seq`, and the chain does from the
`trimmed` event. (Open question 1.)

## 6. What it protects against, and what it does not

- A line removed or changed in the middle: the chain breaks there.
- A person's memory: it is complete for what reached pledge, including
  refusals and expiry.
- **Not** against someone who controls the account: they can rewrite the
  file from any point on and hash it again, or cut it off at the end.
  `SPEC.md`, section 6, says the same. A hardware form may later anchor the
  newest hash in a signature by a key that needs no presence check; not now.

## 7. `pledge history`

Reads the file directly, with no help from `pledge serve` (0600, same
user), verifies the chain as it goes, and prints. Filters: `--since`,
`--type`, `--result`, `--agent`, `--person`, `--service`; `--format json`
prints the entries as they are. In text, a string that has anything but
printable characters is shown with those escaped: the writer keeps control
characters out, the reader does not rely on it.

## 8. Open questions for the designer

1. **The first entry kept.** `SPEC.md` says it "says so". *Proposal:* as in
   section 5: the reader says so from `seq`, and a `trimmed` event follows.
   The alternative, re-hashing the whole file at each trim, rewrites every
   entry daily for no gain.
2. **A delegation's identifier.** A human-readable one is needed in the
   record, in `pledge agents list` and in `withdraw`. *Proposal:* the SHA-256
   fingerprint of the agent's public key, `SHA256:...` as `ssh-keygen -l`
   prints it. It needs nothing stored; the certificate's key id can carry the
   person's name and a short label the person gave. Needs the formats
   document's blessing, because the certificate is checked by others.
3. **The whole request in the record.** The entry has the call's fields and
   the request's hash. Keeping the request's bytes and the approval would
   make a dispute answerable from the record alone (up to 32 KiB an entry).
   *Proposal:* hash only; a service keeps its own copy.
4. **Events in the record.** `SPEC.md` names two types of entry; this adds
   `event`. *Proposal:* keep: delegations and muting are exactly what a
   person asks about afterwards.
5. **Anchoring the head of the chain** to catch a cut-off tail. Not now (see
   section 6).
