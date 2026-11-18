# Proposal: pledge's connection to the broker (step 6, stage 2)

Status: a proposal by the p-ledge agent, for the designer. Contract:
`doc/approval-connections.md` sections 3 and 5, `SPEC.md` sections 2 and 4,
`doc/approvals.md`. Types: `p_act::broker`, `p_act::exchange`; none is written
again. Built in step 6 as decided; this text says what was built, where it differs
from the first proposal.

## 1. How the connection lives in `pledge serve`

**Proposal: a thread, blocking rustls, no runtime.**

- Dependencies added to pledge (the binary): `rustls` 0.23 (`ring`, `std`, TLS
  1.3 only, as p-age) and `rustls-pki-types`. No tokio.
- One **link thread** owns the TLS stream (`rustls::StreamOwned` over a
  `TcpStream`, or any `Read + Write` with a read timeout) and the line buffer
  (`p_act::exchange::LineBuffer`). It runs a tick of 50 ms: write what the
  outgoing channel holds, read with the 50 ms timeout, handle every complete
  line, send a `ping` after 30 s of nothing else, enforce the broker's 10 s
  line timeout. Other threads (the per-request threads of `approvals`, the
  control commands) never touch the stream: they put a message on a channel.
  `StreamOwned` with a read timeout loses no TLS state on a timeout, which is
  what makes one thread for both directions safe. Cost: an answer waits at most
  one tick (50 ms) to be written; nothing a person can notice, since it follows
  a touch.
- A **supervisor loop** around it reconnects: 1 s, doubled to 60 s, with jitter;
  the delay resets after a completed sign-in. Every connection signs in anew.
- The **session logic** (hello, challenge, sign-in, standing, registration,
  withdrawal, ping, what arrives and what it does) is a state machine over
  messages (`ToPledge` in, `FromPledge` out), independent of the transport, so
  it is tested without sockets and again over real TLS.

What follows for pledge's process split: the reader (`pledge serve`) gets a TLS
library and a socket to a remote host. It still holds no key of the person: the
connection key is in the key holder (section 2); the TLS exchange has no
client key (the sign-in is the SSHSIG, not a client certificate). It does hold,
briefly, an agent's private key while issuing (`issue.rs`, unchanged); a runtime
and its dependencies in that process would be more code near that key than one
thread and rustls. That is the reason for no tokio, the same reason the designer
gave for `pact`. If the designer prefers a runtime, only the link thread is
replaced: the session logic and everything after it do not change.

Transport seam: `trait Link { set_read_timeout; set_write_timeout }` on top of
`Read + Write`, implemented for `TcpStream` and `UnixStream`. The Unix
implementation exists only so that tests can run real TLS where TCP cannot be
bound.

## 2. The connection key

One of the person's four keys (`SPEC.md` section 2): purpose `connection`,
made by `pledge keys create connection` (Ed25519 or P-256, in a file for now,
in the key holder, never offered on `agent.sock`, no presence check). The
reader builds the connection document with `ConnectionDocument::compose`
(person, the broker's nonce, the 32 bytes of `export_keying_material` with
`TLS_EXPORTER_LABEL`), has the holder sign
`sshsig::signed_data("connection-v1@procession", doc)` (the holder signs bytes
it is given and parses nothing), and armours the signature itself
(`sshsig::armour`). `ConnectionDocument::sign` of p-act runs `ssh-keygen` on a
key file; pledge's key is not a file the reader can name, so it is not used.
The public key is printed with the other three for the administrator.

## 3. Configuration (`config.json`)

A new optional member, one object, unknown members refused, like the rest of
the file (and read by `p_act::settings`):

```json
"broker": {"address":"broker.example:8443","server_name":"broker.example",
           "tls_root":"-----BEGIN CERTIFICATE-----\n...","site_ca":"ssh-ed25519 AAAA..."}
```

- `address`: `host:port`. `server_name` (default: the host part): checked
  against the broker's certificate. `tls_root`: the site's TLS root (PEM), the
  only trust anchor for the connection. `site_ca`: the site CA's public key: the
  anchor for the broker's signature on the standing (principal `broker`) and for
  the certificates in it (`<person>:confirmed`, `<person>:automatic`).
- All four are required together. The person (`person`) must be the one the
  broker knows.
- Services' `tls_root` (for bundles) stays a separate member.

**Without `broker`, stage 1 is unchanged**: no thread, no connection, no new
refusal; `service.sock` as before; `agents start` registers nothing and a
delegation exists locally from `agents.delivered`. **With `broker`**, `service.sock`
stays bound too (SPEC: a machine without a site), but `agents start` needs the
connection (section 5).

## 4. What arrives, what leaves

- `submit` from the broker: handed to `approvals::submit` with a responder whose
  `send` puts the `answer` on the link channel (`by` `pledge`; no clearance:
  `ClearancePolicy::Refused`). pledge's checks are all its own, unchanged. A
  record entry carries `"via":"broker"` instead of `peer`.
- A lost connection does **not** cancel what is open (the broker keeps it and
  sends it again): the request stays in `approvals`; the new connection's
  `submit` of the same bytes attaches its responder (already how
  `approvals::submit` treats a second submitter). If an answer was made while
  disconnected, the stored answer is sent again on the new connection.
- `cancel` from the broker: `approvals::cancel` for that responder.
- `standing` (`notice`): verified as `broker` with `site_ca`
  (`Standing::parse_verified`: `to` is the person, `nonce` this connection's,
  `n` higher than the last). `blocked`, `blocked_keys`, `withdrawn` only
  restrict, at once: no asking or signing, waiting requests refused (`blocked`,
  `delegation-withdrawn`); absent from a newer standing they are lifted.
  `certificates`: each verified against `site_ca` by pledge itself for its own
  approval key and the right name before it is kept; they replace the public key
  in the SSHSIG of an approval (`sshsig::armour(cert_blob, ...)`), so that a
  service needs only the CA's line. `groups`: shown when the person starts an
  agent (`agents start` lists them; nothing decides on them).
- `carried`: ignored in this step, logged once per connection (stage 2 reads
  hosts from its own configuration, 5, "carried").
- `ping` every 30 s.
- Delegations and withdrawals: section 5.

**Decided and built (a):** what the standing restricts is kept in `broker-state.json`
(0600): `blocked`, `blocked_keys`, `withdrawn`, the certificates, and the withdrawals
with their state. It only restricts, so a restart that has not connected yet does not
forget a block. Certificates are checked again when the file is loaded
(`reverify_certificates`) and dropped if they no longer verify. Groups are shown,
decide nothing and are not trusted from disk. `n` and the nonce belong to the
connection and are not kept. A standing missing a restriction lifts it, but only
a verified, newer one.

## 5. Delegations and withdrawals

- **Registration** (`agents start`, SPEC section 4): after issuing and before the
  bundle is handed over, pledge sends `delegation` with the certificate and
  waits up to 10 s for `registered` or `not-registered`. `registered`: go on as
  now (bundle, then `agents.delivered`). `not-registered` (any reason) or no
  answer or no connection: the agent is not started; the person is told that the
  broker could not take it and can try again; nothing is stored; pledge does not
  retry by itself. For this, the control commands get one new error code,
  `broker-unavailable` (no connection, no answer, `unavailable`), and
  `broker-refused` (`not-registered` with another reason); the reason code is
  not passed on as text.
- **Withdrawal** (`agents.withdraw`): local at once, as now. Then, if connected,
  `withdraw`; the answer `withdrawn` with `stored`. The state of each withdrawal
  is kept in `delegations.json`: `told` (never sent), `in force` (`stored`
  false), `stored`. A withdrawal not `stored` is sent again at every sign-in and
  at most once a minute on a standing connection. It shows in
  `pledge agents list` (`withdrawn, broker: stored | not stored yet | not told`)
  and in `pledge history` (event `delegation-withdrawn` with `stored`, and an
  event `withdrawal-stored` when the answer says so). Not an alarm.
- A withdrawal that came in a standing is the same effect, recorded with `by`
  `administrator`.

## 6. Tests

Against the real `page` code in-process, over real TLS: p-age as a
**dev-dependency** of pledge (so tokio is compiled for pledge's tests, not its
binary); the broker side is `p_age::net::serve_tls` over a tokio `UnixStream`
under `/tmp/claude/` (the sandbox cannot bind TCP), the pledge side the real
link thread over a std `UnixStream` with rustls on top, so TLS 1.3, the
exporter and the sign-in binding are real. Covered: hello within 10 s, sign-in
(and refusals: wrong person, a binding from another connection), the standing
(blocks, withdrawals, a stale `n`, a wrong nonce, a bad signature), a request
through `submit` to an answer with the approval verified, a repeat after a
reconnect getting the stored answer, a request that waited and is sent again,
registration with `registered`, `not-registered`, `unavailable`, withdrawal
with `stored: false` and again until true, ping, reconnect with backoff (with a
fake clock). **Never run over TCP:** `TcpStream::connect`, name resolution, and
a real network's behaviour on timeouts (the link is generic over the stream and
the timeout calls are the same on both types, but the TCP path itself is not
exercised here).

## 7. What `p-act` lacks (reported, not written)

- A TLS **client** configuration and the exporter helper
  (`p_age::tls::client_config`, `exporter`) live in p-age, which depends on
  tokio; pledge cannot depend on p-age for them. I will write the ~15 lines of
  rustls client config in pledge (TLS 1.3, `ring`, the roots from `tls_root`),
  as the one place pledge needs it. If the designer wants one copy, it belongs
  in a small crate both use.
- Signing a `ConnectionDocument` or verifying a `Standing` **with a raw
  signature** is possible (`Signed`, `parse_verified` take bytes and armour); only
  `ConnectionDocument::sign` needs a key file, so pledge builds the armoured
  signature itself, as it does for approvals.

## 8. Decided

1. Blocking rustls on a thread: built. 2. Restrictions and certificates kept on
disk, certificates re-checked: built. 3. Registration before the bundle, two new
control codes: built. 4. A broker configured but not connected refuses `agents start`;
no local-only delegation: built. 5. `carried` is ignored in this step (SPEC says so).
