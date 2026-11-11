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
- **One line of JSON.** A document is one JSON object, UTF-8, without a byte
  order mark and without a line break. That is this workspace's convention
  for machine output, and it is what a person's dialog is built from.
- **A signature is an armoured SSHSIG**, as `ssh-keygen -Y sign` writes it. A
  signature made with a certified key contains the certificate, so
  certificates are never sent separately.
- **One namespace per document type.** A signature for one type can never
  verify as another.

| Document | Signed by | Namespace |
|---|---|---|
| call | the agent's key, certified by its person's delegation key | `call-v1@procession` |
| request | the service's key, certified by its host's key | `request-v1@procession` |
| approval | the person's confirmed or automatic approval key, certified by the site CA | `approval-v1@procession` |
| clearance | the broker's key, certified by the site CA | `clearance-v1@procession` |

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
- **Size**: a call is at most 16 KiB; a request at most 32 KiB.

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
| `service.host` | string | the host's name as the site project has it |
| `service.name` | string | the service's name on that host: `[a-z][a-z0-9-]*` |
| `action` | string | the action, in the service's own words: lower-case words separated by single spaces |
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

## 4. The request

What a service states it will do. Signed by the service.

```json
{"v":1,"type":"request","call":"eyJ2IjoxLCJ0eXBlIjoiY2FsbCIs...","call_sig":"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH...\n-----END SSH SIGNATURE-----\n","rating":{"exposure":"internal","damage":"none","disruption":"none"}}
```

| Member | Type | Meaning |
|---|---|---|
| `v` | number | `1` |
| `type` | string | `"request"` |
| `call` | string | the call's bytes, base64 (standard alphabet, padded) |
| `call_sig` | string | the call's signature, as the agent sent it |
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

with `<service>` and `<host>` taken from the call inside the request. That
is the comparison of R6: a request signed by any other service or host does
not verify under this name.

**The approval and the clearance**, by a service:

```
* cert-authority,namespaces="approval-v1@procession,clearance-v1@procession" <the site CA's public key>
```
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

**Names that the site CA must never certify for a person:** `broker`, and
anything without the `:confirmed` or `:automatic` ending.

## 8. In the first stage

Stage 1 of approvals.md has no broker and no site CA. The formats are the
same; only the allowed-signers lines differ:

- the service lists the one person's two approval keys directly, as
  `<person>:confirmed <key>` and `<person>:automatic <key>` with the same
  namespaces, and checks no clearance;
- pledge lists the one host's key as above.

## 9. Open

- How the call rides on an MCP tool call: which header carries the call's
  bytes and which its signature. With the connections.
- Whether `params` should be named values rather than a list. A list is what
  the dispatcher of p-robe takes today (`key=value` tokens), and what a
  dialog can show without knowing the action.
- A crate for these formats, used by p-ledge, p-age and p-robe, so that
  three programs do not each write a parser: `p-act`, binary none. It would
  also take `rating` out of p-ledge.
