# p-act: report on the first usable version

## What changed
Branch `agent/p-act`; nothing pushed, `main` untouched.
- `0cc7819`: `rating.rs` copied from p-ledge (byte-identical, checked with `diff`; p-ledge untouched). `Call`, `Request`, `Clearance` parsing, the hash, and `"crates/p-act"` added to `members` in the root `Cargo.toml` (`Cargo.lock` changed with it).
- `63c84b1`: sign and verify for the four document types, plus `tests/ssh.rs`.
- A third commit adds this file.

## What was verified and how
- `cargo test -p p-act --offline`: 37 unit tests and 15 integration tests passed, 0 failed.
- `cargo clippy --all-targets -p p-act --offline`: no warnings.
- `cargo fmt -p p-act`, then `cargo fmt --check -p p-act`: clean.
- Parser refusals, each with its own `ParseError` variant: size, BOM, line break, invalid UTF-8, not one JSON object; duplicate, unknown, missing members and wrong types; wrong `v` or `type`; control characters and bidirectional marks; malformed UUID, time, host, service name, action, hash; base64, rating values, parameter and claim limits; the call inside a request.
- Signatures against a real `ssh-keygen` (OpenSSH 10.2) with keys made in a temporary directory: a call under a delegation, a request under a host key's certificate, an approval and a clearance under a site CA. Every refusal the formats document lists (wrong name, wrong namespace, changed bytes, expired certificate), plus: wrong CA or host key, a certificate with two principals, an uncertified key, an automatic approval at the top of a scale, stage 1 with the person's two keys listed directly, and one full exchange from call to clearance.
- No prompts: `ssh-keygen` runs with `SSH_ASKPASS=false` and `SSH_ASKPASS_REQUIRE=force`; a passphrase-protected key fails instead of asking (tested).
- Dependency restriction hit: `sha2` 0.11 needs crates that are cached but not unpacked, and `~/.cargo/registry/src` is not writable (`failed to create directory .../block-buffer-0.12.1: Operation not permitted`). I used `ring` for SHA-256 (already in the workspace lockfile). Other runtime dependencies: `serde`, `serde_json`, `base64`, `tempfile`, `thiserror`, all already unpacked.

## What is not verified
- Keys in a Secure Enclave or held by an SSH agent: only key files without passphrase are tested.
- The 60-second clock tolerance, clearance freshness and deadline checks (policy, left to callers).
- Linux, and other `ssh-keygen` versions than 10.2.
- `ssh-keygen` is found through `PATH`.

## Public API
- `p_act::rating`: p-ledge's `Exposure`, `Damage`, `Disruption`, `Rating`, `Mode`, `Ceilings`, unchanged.
- `Call::parse(impl Into<Vec<u8>>) -> Result<Call, ParseError>`; `Call::compose(&CallContent) -> Result<Call, ParseError>`; accessors `content`, `id`, `deadline`, `service`, `action`, `params`, `claim`. `CallContent { id: CallId, deadline: Timestamp, service: ServiceId, action, params, claim }`; `CallId::parse(&str)`; `ServiceId { host, name }` with `.principal()` = `name@host`.
- `Request::parse(bytes)`; `Request::compose(&Call, call_sig: &str, Rating)`; `call()` (parsed from the carried bytes), `call_sig()`, `rating()`.
- `Clearance::parse(bytes)`; `Clearance::compose(DocumentHash, Timestamp)`; `request()`, `at()`, `covers(&Request) -> bool`.
- `Document` trait (`as_bytes()`, `hash() -> DocumentHash`) for all three; `DocumentHash` displays/parses as `sha256:<hex>`.
- `Timestamp`: `FromStr`, `Display`, `now`, `from_unix`, `unix`, `checked_add`.
- `p_act::sign`:
  - `sign_call(&Signer, &Call) -> Result<String, SignError>`; `verify_call(&Call, sig, &PublicKey) -> Result<String /*person*/, SignError>`
  - `sign_request`; `verify_request(&Request, sig, &PublicKey /*host key*/)` (principal `<service>@<host>` from the call inside)
  - `sign_approval(&Signer, &Request)`; `verify_approval(&Request, sig, ApprovalTrust) -> Result<ApprovalKind, SignError>`; `ApprovalTrust::{SiteCa(&PublicKey), PersonKeys { confirmed, automatic }}`; an automatic approval is refused at the top of any scale
  - `sign_clearance`; `verify_clearance(&Clearance, sig, &PublicKey /*site CA*/)`
  - helpers: `Signer::plain(path)`, `Signer::certified(path)` (needs `<path>-cert.pub`), `PublicKey::parse/read`, `signature_person`, `signature_certificate`, `request_person`, `looks_armoured`; `Namespace`, `SignError`.
- Person from the signature: I parse the SSHSIG blob myself rather than `ssh-keygen -Y find-principals`. `find-principals` answers from lines of an allowed-signers file, and the person's name is what a service does not yet have. Only Ed25519 certificates are read; other types are refused.

## What I need from another part or from you
- p-ledge and p-robe switch their `rating` imports to `p_act::rating` (I did not edit them).
- Add p-act to `README.md` (and `doc/` if wanted).
- Decide `ring` versus `sha2`.

## Open questions for the designer
1. `approvals.md` section 5 says the delegation certificate has "the chosen groups as principals"; `approval-formats.md` sections 3 and 7 say the principal is the person. I implemented the latter: exactly one principal, which must be the person; two principals is an error.
2. `call_sig` in the request (section 4 example) contains `\n`, which section 2 forbids in strings. I allow `\n` only in `call_sig`, which must look like an armoured signature.
3. Names the formats leave open, which I restricted: `service.host` and the person's name match `[A-Za-z0-9._-]+` (safe in allowed-signers lines); an `action` is words matching `[a-z][a-z0-9-]*` separated by single spaces.
4. Section 2 gives no clearance size limit; I chose 1 KiB.
5. My allowed-signers lines list only the one namespace being verified; section 7 lists both on the CA line (wider than needed).
6. The signature over a request is not part of `Request`; it travels beside it (section 1). No wrapper is defined.

## 2026-11-11: ECDSA P-256 added (follow-up)
- `signature_certificate`/`signature_person`/`request_person` now read certificates whose subject key is Ed25519 or `ecdsa-sha2-nistp256`. The key that signed a certificate is never parsed, so a CA of either type works.
- `PublicKey::parse` accepts exactly `ssh-ed25519` and `ecdsa-sha2-nistp256`; any other type (RSA, P-384, ...) gives `SignError::UnsupportedKeyType(<type>)`, as does a certificate with another subject type. This replaces the Ed25519-only statement under "Person from the signature" above.
- New tests (5, in `tests/ssh.rs`, real `ssh-keygen -t ecdsa -b 256` file keys): Ed25519 agent under a P-256 delegation key; P-256 agent certificate; approvals by P-256 keys under an Ed25519 and a P-256 site CA (confirmed, automatic, top-of-scale refusal, wrong CA, other request); P-256 broker clearance and stage-1 plain P-256 approval keys; RSA and P-384 refused with their own error.
- Verified: `cargo test -p p-act --offline` 37 unit + 20 integration passed; `cargo clippy --all-targets -p p-act --offline` clean; `cargo fmt -p p-act` applied. `ring` kept.
- Not verified: Secure Enclave keys themselves (file keys only). The six design questions above are unchanged and behaviour is as before.

## 2026-11-11: designer decisions implemented (merged `integration` 4c8c58b)
Verified: `cargo test -p p-act --offline` 38 unit + 27 integration passed; `cargo clippy --all-targets -p p-act --offline` clean; `cargo fmt --check` clean.

**Incompatible changes**
- A request's wire form: `call_sig` is now the base64 of the armoured signature. `Request::compose(&Call, &str /*armoured*/, Rating)` and `Request::call_sig() -> &str` (armoured text) keep their signatures; the bytes differ from before. `compose` returns `ParseError::MalformedSignature` for text that does not look armoured (it was control/bidi errors before). Parsing gives `MalformedBase64("call_sig")` or `MalformedSignature`.
- `signature_person`/`verify_call`/`request_person` now apply the section 3.1 rules (no critical option, no extension but a valid `groups@procession`), so they refuse a certificate issued without `-O clear`. `signature_certificate` (raw) does not judge, but refuses an unsupported subject or issuer key type.
- `Certificate` gained `critical_options` and `extensions` fields.
- Host and person names are at most 64 characters (host was 253).
- The `\n` exception for `call_sig` is gone.

**New API**
- `signature_agent(sig) -> Result<Agent { person, groups, key_id }, SignError>`; `verify_call_agent(&Call, sig, &PublicKey) -> Result<Agent, SignError>` (for the broker). `verify_call` and `signature_person` still give only the person (for a service).
- `GROUPS_EXTENSION`; `SignError::{CriticalOption, UnknownExtension, BadGroups}`.
- `signature_to_base64(&str) -> String` and `signature_from_base64(&str) -> Result<String, SignError>` (padded standard base64; checks that the text looks armoured).
- The issuer key of every certificate read is checked: Ed25519 and P-256 only, else `UnsupportedKeyType(<type>)` (tested with an RSA CA, an RSA host key and an RSA certified key).

**Decisions of mine inside the rules**
- Group names: refused if empty, containing whitespace, a control or a bidirectional character; sorted means strictly increasing bytewise (so `B,a` is valid, `a,B` is not). A present but empty `groups@procession` value is refused (empty name). The extension twice is refused.
- Test certificates for agents, services, approvals and the broker are now issued with `-O clear` (as pledge does); the refusal tests use a default-extension certificate and `-O force-command` / `source-address`.

## 2026-11-11: site CA lines and PersonKeys (integration 47bb806 merged)
Verified: `cargo test -p p-act --offline` 38 unit + 30 integration passed; clippy and `cargo fmt --check` clean.
- `ApprovalTrust::SiteCa` now uses the line `*:confirmed,*:automatic cert-authority,namespaces="approval-v1@procession" <CA>`; `verify_clearance` uses `broker cert-authority,namespaces="clearance-v1@procession" <CA>`. The pattern list behaves as hoped with OpenSSH 10.2 (tested directly with `ssh-keygen -Y verify` on both lines verbatim, and through the API, for an Ed25519 and a P-256 CA): `<person>:confirmed`, `<person>:automatic` and `broker` verify, each only for its own document type; `<person>`, `<person>:other`, `<person>:`, `:confirmed`, `<person>:confirmed:automatic`, `broker:confirmed`, a non-ASCII name, `broker` for an approval and a person's name for a clearance verify nowhere. Nothing was widened.
- `ApprovalTrust::PersonKeys` with the same key as confirmed and automatic gives the new `SignError::SameApprovalKey` (tested with Ed25519 and P-256).
- Not implemented, as instructed: the hosts list (formats 6.1, `hosts-v1@procession`). `service.name` grammar unchanged.

## 2026-11-11: fingerprints, reserved namespaces, `pact` proposal (integration f4a97a7 merged)
Verified: `cargo test -p p-act --offline` 38 unit + 35 integration passed; clippy and `cargo fmt --check` clean (see the commit).
- `Fingerprint` (`SHA256:...`, `FromStr`/`Display`, `as_str`); `PublicKey::fingerprint()`; `Certificate.fingerprint` (the certified key, not the certificate); `signature_fingerprint(sig)` (the key behind a signature: the certified key if the signature carries a certificate, else the plain key); `Agent.delegation` is that fingerprint for the agent's key. Tested against `ssh-keygen -l -f` for Ed25519 and P-256 keys, and for Ed25519/P-256 agent keys under Ed25519/P-256 CAs. Other key types: `UnsupportedKeyType`. New error `SignError::MalformedFingerprint`.
- `Namespace` gained `Connection`, `Broker`, `Hosts` and `Namespace::ALL`; `is_reserved_namespace(&str)` (ends in `@procession`, ASCII case ignored, which only widens it) and `RESERVED_SUFFIX`. No parsers for those documents.
- Proposal: `crates/p-act/proposals/pact.md` (no code). Main points: two processes (`pact serve` holds the key from stdin and listens on a Unix socket; `pact stdio` is the model's MCP stdio shim); SSHSIG signed in-process with `ring` (no `ssh-keygen` or key file in the sandbox); services only from the bundle; the tool schema is pact's own; outcomes normalised to the closed list, plus a proposed new reason `no-answer`; no HTTP client crate exists in the local registry, so a minimal hand-written client over `httparse` (+ `rustls` for TLS) is proposed. Open: key secrecy needs a separate user in the sandbox; `_meta` member names; the bundle's shape.

## 2026-11-11: the shared exchange, `p_act::exchange` (integration 1cc4161 merged)
Verified: `cargo test -p p-act --offline` 51 unit + 35 integration passed; clippy and `cargo fmt --check` clean. Section 3 of `doc/approval-connections.md` only; the broker's own messages (sections 4, 5) are not in it.
- Types: `Message::{Submit, Answer, Cancel, Error}`; `Submit` (`request() -> &Request` parsed from the decoded bytes, `request_sig()` armoured, `hash()`), `Answer { request: DocumentHash, outcome: Outcome }`, `Outcome::{Approved(Approved), Declined, Refused(Refused), Expired(By), Unknown}`, `Approved` (`approval()` armoured, `clearance: Option<ClearanceAnswer>` with a parsed `Clearance` and `clearance_sig()`), `Refused::{Pledge(PledgeReason), Broker(BrokerReason), Unknown}`, `Cancel`, `ErrorMessage`.
- Closed enums with `Unknown`, `ALL`, `from_wire(&str)`, `wire()`: `By`, `PledgeReason` (service-sock.md section 5 and `blocked`: 14), `BrokerReason` (3.7: 7), `ErrorCode` (3.5, all ten). `Unknown` is written as the word `unknown` and keeps nothing of what was received; tested that no received code comes back out.
- `ClearancePolicy::{Required, Refused}` is an argument of `Message::parse`, `Message::encode`, `LineReader::read_message` and `write_message`, in both directions; there is no "if present".
- `LineReader<R: Read>` (`read_line`, `read_message(policy)`; holds at most a line and a chunk; `MAX_LINE` = 96 KiB without the `\n`), `write_message`, `Message::encode` (one line with its `\n`). No timeout (the transport's).
- Errors: `ExchangeError` (`LineTooLong`, `Truncated`, `UnsupportedVersion`, `UnknownType`, `Malformed(ParseError)`, `BadBase64`, `BadSignature`, `BadRequest { hash, source }`, `BadClearance`, `ClearanceMissing`, `ClearanceNotAllowed`, `Io`), each with `code() -> Option<ErrorCode>` (`line-too-long`, `unsupported-version`, `unknown-type`, everything else `malformed-line`; `Truncated` and `Io` have none). `EncodeError` for writing. An unknown `schema_version` is judged first, before type and members.
- Points where section 3 is silent and I chose, for the designer to confirm or change:
  1. An `answer` whose `result` is not in the list parses to `Outcome::Unknown` and **no other member belongs to it** (3.3 says an unknown code maps to `unknown` but not which members an unknown result may have).
  2. A `submit` whose decoded request does not parse is `BadRequest { hash, .. }` with code `malformed-line`; whether a receiver closes the connection or answers `refused` (`malformed`/`bad-request`) for that hash is its decision, which is why the hash is carried. 3.5 and pledge's `malformed` / the broker's `bad-request` both seem to apply.
  3. A code that is clean text but not `[a-z][a-z-]*`, or a known reason of the other list (`not-entitled` by `pledge`), maps to `Unknown`; it is not an error. Control or bidirectional characters are an error (the formats' string rule).
  4. The 96 KiB limit counts the line without its `\n`.
  5. p-age's first reason set for pledge (service-sock.md section 5, last paragraph) is not reconciled; I used the table, plus `blocked`.

## 2026-11-11: `pact.md` revised after the p-robe review
Document only; no code changed. `crates/p-act/proposals/pact.md` second version. Section 0 is a table of every review point with adopted / changed / presented; adopted: flat `_meta` keys `procession/call` and `procession/call_sig`, `params` always present, `progressToken` plus a 45 s idle timeout (no deadline-based read timeout), a 10 s wait floor, a 4 MiB response limit (1 MiB passed to the model), prefix-less names for one service, the service's outcome words (`unknown` becomes `refused`/`not-allowed`, no `invalid-call`/`no-route`, `503`+`Retry-After` is `try-later`), HTTP header details, `http`/`https` URLs only. As decided: the service's tool schema passes through (checked, never widened, `wait_seconds` rewritten to the floor and the setting; `pattern` not evaluated); `pact` adds only that. Stage-1 end-to-end test: section 10 (bundle recipe and `p_act::pact::Bundle`, `pact call` / `pact tools`, id and hash on stderr, short deadline and settable floor, a fake pledge from the existing codec and signing API, optional `p_act::testing::FakePledge`).
Dependency on the service (asked of the p-robe agent): the SSE response head must be sent when the call is accepted, not at the first notification.
Presented, not decided: (a) in-process `ring` signing against `ssh-keygen -Y sign` (and a third way via a private SSH agent socket, untested), with how an in-process writer would be tested (Ed25519 byte-for-byte against `ssh-keygen`, ECDSA by `-Y verify`); (b) the exact requirement on the sandbox for key secrecy (a separate user, no ptrace or DAC capabilities, `/proc` hidden, binary and socket directory not writable by the model's user); (c) `no-answer`, three options; (d) the bundle's shape, two options; (e) the HTTP client for the owner (`ureq` 3 with `rustls`/`ring` against a hand-written one); (f) progress relay.
