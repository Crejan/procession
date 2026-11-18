# Approvals - formats (draft)

The four things that are signed in the approval system
([`approvals.md`](approvals.md), whose terms this document uses): the call,
the request, the approval, the clearance. Who sends what to whom over which
connection is not here; that is the next document.

Status: a draft. Every signature and verification below was run with
OpenSSH 10.2 and keys in files (section 7). Nothing implements these formats
yet.

## 1. Principles

- **What is signed is bytes, and nobody re-creates them.** A signer writes a
  document, signs exactly those bytes, and sends bytes and signature. A
  verifier checks the signature over the bytes it received and only then
  reads them. A document that contains another carries the other's bytes,
  not a re-serialisation. There is no canonical form to get wrong.
- **A document or signature carried inside another is always the base64 of
  its exact bytes** (standard alphabet, padded).
- **One line of JSON.** A document is one JSON object, UTF-8, without a byte
  order mark and without a line break. That is this workspace's convention
  for machine output, and it is what a person's dialog is built from.
- **A signature is an armoured SSHSIG**, in the form `ssh-keygen -Y sign`
  writes. The form is that one; the writer need not be (`approvals.md`,
  section 5). A
  signature made with a certified key contains the certificate, so
  certificates are never sent separately.
- **One namespace per document type.** A signature for one type can never
  verify as another.
- **Every SSHSIG namespace ending in `@procession` is reserved for this
  system.** pledge's SSH agent socket refuses a signature in any of them,
  for every key.

| Document | Signed by | Namespace |
|---|---|---|
| call | the agent's key, certified by its person's delegation key | `call-v1@procession` |
| request | the service's key, certified by its host's key | `request-v1@procession` |
| approval | the person's confirmed or automatic approval key, certified by the site CA | `approval-v1@procession` |
| clearance | the broker's key, certified by the site CA | `clearance-v1@procession` |

Two more namespaces belong to the connections
(`approval-connections.md`): `connection-v1@procession`, pledge's sign-in to
the broker with the person's connection key, and `broker-v1@procession`,
what the broker says to a pledge in its own name. A service's
allowed-signers lines never list either. `hosts-v1@procession` is section
6.1.

A change that an old reader would misread gets a new number in `v` and in
the namespace. A reader refuses a `v` it does not know.

## 2. Common rules

- **Strings** contain no control characters (U+0000 to U+001F, U+007F to
  U+009F) and no bidirectional marks (U+061C, U+200E, U+200F, U+202A to
  U+202E, U+2066 to U+2069). A document with one is refused, not cleaned.
- **Times** are UTC, to the second: `2026-11-11T15:04:05Z`.
- **Identifiers** of calls are UUIDs, version 4, lower case with hyphens.
- **A hash** of a document is SHA-256 over its bytes, written
  `sha256:<64 hex digits>`.
- **Unknown members** make a document invalid. Nothing is ignored: what a
  dialog does not show must not be in what is signed.
- **Size**: a call is at most 16 KiB; a request at most 32 KiB; a clearance
  at most 1 KiB; a connection document at most 1 KiB; a standing at most
  64 KiB (both in `approval-connections.md`, section 5).

## 3. The call

What an agent asks for. Signed by the agent.

```json
{"v":1,"type":"call","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"host":"a.example","name":"probe"},"action":"rt procs","params":["pid=4711"],"claim":"checking why the control loop misses cycles"}
```

| Member | Type | Meaning |
|---|---|---|
| `v` | number | `1` |
| `type` | string | `"call"` |
| `id` | string | a UUID the agent made for this call and never uses again |
| `deadline` | string | the time after which the call, and the request made from it, is void |
| `service.host` | string | the host's name as the site project has it: `[A-Za-z0-9._-]+`, at most 64 characters |
| `service.name` | string | the service's name: `[a-z][a-z0-9-]*`. It is the name of the service's type in the catalogue (`probe`), not a name a site gave; a host has at most one service of a type |
| `action` | string | the action, in the service's own words: words `[a-z][a-z0-9-]*` separated by single spaces |
| `params` | array of strings | the action's parameters, in the order the service defines; at most 64, each at most 512 bytes |
| `claim` | string, optional | what the agent says about its reasons; at most 200 characters. Shown as the agent's claim and never acted on |

- The deadline is the agent's choice: how long it is prepared to wait. It is
  the only time in the whole exchange. pledge and the service refuse a call
  whose deadline is more than 10 minutes after they first see it, or already
  past.
- The identifier is what makes a call single-use. pledge signs for an
  identifier once, and the service acts on one once; both keep it until the
  deadline, after which the call is void anyway.

The person the agent acts for is not a member: it is the name in the agent's
certificate, which is inside the signature.

### 3.1 The agent's certificate

The certificate pledge issues for an agent's key with the person's
delegation key (approvals.md, section 5), and which every call's signature
contains.

- **The person is its only principal.** A person's name is
  `[A-Za-z0-9._-]+`, at most 64 characters. A certificate with no principal
  or more than one is refused.
- **The delegation's groups are in the extension `groups@procession`**: the
  group names joined by commas, sorted, without spaces. A delegation without
  groups has no such extension. A value that is not sorted, has a duplicate
  or has an empty name is refused. The extension is inside the certificate,
  so it is signed by the person's delegation key; the broker reads the
  groups from there and from nowhere else.
- **Nothing else.** A certificate with any other extension, or with any
  critical option, is refused. It is issued with `-O clear`, so that it
  carries none of the login extensions.
- **The key ID** is a free label for the person's dialogs and the record. No
  decision is ever made on it.
- **A delegation's identifier** is the SHA-256 fingerprint of the agent's
  public key, as `ssh-keygen -l` prints it (`SHA256:...`). The record and
  the broker's register know a delegation by it.
- **Key types**: the certified key of an agent's certificate is Ed25519,
  always (pledge creates it; the signer in the sandbox refuses any other);
  the issuing key, a person's delegation key, is P-256 or Ed25519. Every
  other key in this document is Ed25519 or ECDSA P-256. Any other type is
  refused, with an error that names it; a person's keys are P-256
  because the Secure Enclave makes nothing else, and a host needs an Ed25519
  or P-256 host key to run a service.

```
ssh-keygen -s <delegation key> -I '<label>' -n <person> -V +8h -O clear \
    -O extension:groups@procession=admins,diag-readers agent.pub
```

Checked with OpenSSH 10.2: `-Y verify -I <person>` accepts a signature by
such a key (an unknown extension is ignored, unlike a critical option), and
`ssh-keygen -L` shows the extension.

Who needs what from it: a service the person; the broker the person and the
groups; pledge neither, but it checks that the certificate is one it issued.

## 4. The request

What a service states it will do. Signed by the service.

```json
{"v":1,"type":"request","call":"eyJ2IjoxLCJ0eXBlIjoiY2FsbCIs...","call_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K...","rating":{"exposure":"internal","damage":"none","disruption":"none"}}
```

| Member | Type | Meaning |
|---|---|---|
| `v` | number | `1` |
| `type` | string | `"request"` |
| `call` | string | the call's bytes, base64 (standard alphabet, padded) |
| `call_sig` | string | the call's armoured signature as the agent made it, its bytes base64 (standard alphabet, padded) |
| `rating.exposure` | string | `open`, `internal` or `secret` |
| `rating.damage` | string | `none`, `recoverable` or `lasting` |
| `rating.disruption` | string | `none`, `brief` or `outage` |

A request says nothing of its own about what will be done: the action, its
parameters, the service and the deadline are the call's, and they are in the
request as the bytes the agent signed. So a request cannot say something
else than the call (approvals.md, R6); what pledge compares is that the
service that signed the request is the service the call names. The service
adds one thing, the rating.

There is no second identifier and no second time. The call's `id` and
`deadline` are the request's.

## 5. The approval

A person's machine saying yes to one request. It is not a document: it is
the SSHSIG signature over the request's bytes, in the namespace
`approval-v1@procession`, by the person's confirmed or automatic approval
key. Which of the two it was is in the certificate inside the signature:
`<person>:confirmed` or `<person>:automatic`.

There is nothing else to sign. "No" has no signature: a decline, a refusal
and an expiry are reported (in the answer, whose format belongs to the
connections) and recorded, and a service acts on none of them.

## 6. The clearance

The broker saying a request passed its checks. Signed by the broker.

```json
{"v":1,"type":"clearance","request":"sha256:9c2f...e1","at":"2026-11-11T15:04:41Z"}
```

| Member | Type | Meaning |
|---|---|---|
| `v` | number | `1` |
| `type` | string | `"clearance"` |
| `request` | string | the hash of the request's bytes |
| `at` | string | when the broker issued it: when the approval came back |

A service accepts a clearance for 60 seconds after `at`.

### 6.1 The list of hosts' keys

Not part of an exchange, but signed the same way: what tells a pledge which
key is a host's, from stage 3. Made by the issuer and signed with the site
CA's key itself, not with a certified key, in the namespace
`hosts-v1@procession`; carried to a pledge by the broker, which cannot alter
it; verified by pledge with a plain line, not a `cert-authority` one:

```
hosts namespaces="hosts-v1@procession" <the site CA's public key>
```

A pledge accepts a list only if its `at` is later than that of the list it
holds, and keeps the newest. A list does not expire. A host that left the
site stays in a pledge's list until the next one, which is harmless: the
broker passes on nothing from a host it does not know. A draft: the member
names are not settled, and the whole list stands under an open decision
(approvals.md, section 10: certifying a service's key by the site CA would
remove it).

```json
{"v":1,"type":"hosts","at":"2026-11-11T15:00:00Z","hosts":[{"name":"a.example","key":"ssh-ed25519 AAAAC3..."}]}
```

Before there is a site CA (stages 1 and 2) pledge reads hosts and their keys
from its own configuration.

## 7. Verifying

Each party needs an allowed-signers file with a few lines, and one
`ssh-keygen` call per signature. `<person>`, `<host>` and `<service>` are
filled in from what is being verified.

**The call**, by pledge (against its own delegation key) and by the broker
(against the person's delegation key from the site project):

```
<person> cert-authority,namespaces="call-v1@procession" <the person's delegation public key>
```
```
ssh-keygen -Y verify -f allowed -I <person> -n call-v1@procession -s call.sig < call
```

`<person>` is the principal in the agent's certificate. `ssh-keygen` also
checks the certificate's validity, which is the delegation's.

**The request**, by pledge and by the broker:

```
<service>@<host> cert-authority,namespaces="request-v1@procession" <the host's public host key>
```
```
ssh-keygen -Y verify -f allowed -I <service>@<host> -n request-v1@procession -s request.sig < request
```

with `<service>` and `<host>` taken from the call inside the request;
`<service>` is the type's name (section 3). That
is the comparison of R6: a request signed by any other service or host does
not verify under this name.

**The approval and the clearance**, by a service:

```
*:confirmed,*:automatic cert-authority,namespaces="approval-v1@procession" <the site CA's public key>
broker cert-authority,namespaces="clearance-v1@procession" <the site CA's public key>
```

Two lines, so that a certificate under any other name verifies nowhere.
Run with OpenSSH 10.2 and keys in files, on 2026-11-11. Accepted: a
confirmed key as `<person>:confirmed` and an automatic key as
`<person>:automatic` for an approval; the broker's key as `broker` for a
clearance. Refused: an automatic key as `<person>:confirmed`; the broker's
key for an approval under either name; a person's key for a clearance under
either name; a certificate named `<person>` without an ending, under
`<person>` and under `<person>:confirmed`.
```
ssh-keygen -Y verify -f allowed -I <person>:confirmed -n approval-v1@procession -s approval.sig < request
ssh-keygen -Y verify -f allowed -I broker -n clearance-v1@procession -s clearance.sig < clearance
```

For a request rated below the top of every scale the service also accepts
`-I <person>:automatic`. `<person>` is the principal of the agent's
certificate inside `call_sig`; the service reads it from there and does not
verify that certificate, which it cannot (approvals.md, section 5): what
proves the person is the approval.

Run with OpenSSH 10.2 and keys in files, on 2026-11-11: all four verify as
written; an approval does not verify under the name `broker`, nor a
clearance key under a person's name, nor any signature under another
namespace.

A verifier may write a line with only the namespace it is verifying; it
must never write one with more.

**Names that the site CA must never certify for a person:** `broker`,
`hosts`, and anything without the `:confirmed` or `:automatic` ending. A person's name
never contains `:` (section 3.1), which these endings rely on.

## 8. In the first stage

Stage 1 of approvals.md has no broker and no site CA. The formats are the
same; only the allowed-signers lines differ:

- the service lists the one person's two approval keys directly, as
  `<person>:confirmed <key>` and `<person>:automatic <key>` with the same
  namespaces, and checks no clearance. The two must be different keys: one
  key under both names would make every automatic approval verify as a
  confirmed one, so that is refused;
- pledge lists the one host's key as above.

## 9. Open

- How the call rides on an MCP tool call: decided, in the tool call's
  `_meta` (approvals.md, section 10); the member names are with the
  connections.
- Whether `params` should be named values rather than a list. A list is what
  the dispatcher of p-robe takes today (`key=value` tokens), and what a
  dialog can show without knowing the action.
Done since the first draft: the crate for these formats, `p-act`, used by
p-ledge, p-age and p-robe; it holds `rating` as well.
