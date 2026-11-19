# procession

Tools for diagnosing, operating and administering hosts and workstations.
It began with the processes of a realtime Linux host, and most of it is
still about those. Each tool is its own crate and binary; they share one set
of conventions, and the realtime tools one library.

| Crate | Binary | Role | Spec |
|---|---|---|---|
| `p-roc` | - | Library: reads and writes what the kernel knows about CPUs, threads, IRQs, sockets and devices (`/proc`, `/sys`) | [`crates/p-roc/SPEC.md`](crates/p-roc/SPEC.md) |
| `p-usher` | `pusher` | Daemon: keeps unprivileged RT threads off the housekeeping CPUs; watchdog for starved housekeeping CPUs | [`crates/p-usher/SPEC.md`](crates/p-usher/SPEC.md) |
| `p-rover` | `prover` | Diagnosis: one command per question, and `analyze`, which explores one process per cycle | [`crates/p-rover/SPEC.md`](crates/p-rover/SPEC.md) |
| `p-layer` | `player` | Starts, places and tunes the processes of a host and shows them running; web UI | [`crates/p-layer/SPEC.md`](crates/p-layer/SPEC.md) |
| `p-lumber` | `plumber` | Lists and subscribes to iceoryx2 services, decodes samples, measures rate, jitter and loss, benchmarks pub/sub | [`crates/p-lumber/SPEC.md`](crates/p-lumber/SPEC.md) |
| `p-reserve` | `preserve` | Backups into a restic-format repository: runs them, keeps them fresh, browses and restores them; with `p-reserve-core` (library) and `p-reserve-gui` (desktop app); also on macOS | [`crates/p-reserve/SPEC.md`](crates/p-reserve/SPEC.md) |
| `p-ledge` | `pledge` | Holds a person's keys on their own machine: an SSH agent with a rule per program, and the person's end of the approval system; macOS first | [`crates/p-ledge/SPEC.md`](crates/p-ledge/SPEC.md) |
| `p-age` | `page` | The broker of the approval system: checks that a request may be put to a person, carries it there and back, registers delegations | [`crates/p-age/SPEC.md`](crates/p-age/SPEC.md) |
| `p-robe` | `probe` | A host's diagnostics as a fixed table of rated verbs built on the tools above, offered to agents as a service that asks before it acts | [`crates/p-robe/SPEC.md`](crates/p-robe/SPEC.md) |
| `p-act` | - | The formats the approval system's programs share: call, request, approval, clearance, rating, and their signatures through `ssh-keygen` | [`doc/approval-formats.md`](doc/approval-formats.md) |
| `p-lace` | `place` | Resources and who holds them: reserve, release, share; hosts pull their reservation and warn at login; remote desktops through adapters (executables, JSON in and out); web UI, CLI, MCP. Spec only, no crate yet | [`crates/p-lace/SPEC.md`](crates/p-lace/SPEC.md) |

Each name reads twice: an usher who seats threads (pusher), a rover who
explores (prover), a player on stage (player), a plumber for the pipes
between processes (plumber), a reserve that keeps (preserve), a ledge to hold
on to and a signature given (pledge), a page who carries messages and pages
people (page), a robe and a probe, a place one holds (place), and `/proc` (p-roc).

What spans several tools has a document of its own:
[`doc/approvals.md`](doc/approvals.md), how a service learns that a person
agrees to an action their agent asked for. `p-ledge`, `p-age` and `p-robe`
are its three parts, and `p-act` is what they share.

The crates from `p-reserve` to `p-act` are skeletons or first versions with
specifications and are not published (`publish = false`); `p-lace` is a
specification only.

## Conventions

- License MIT OR Apache-2.0; edition 2024; MSRV 1.91; published on
  crates.io, so `cargo install p-usher` etc. needs nothing but cargo.
- Linux at runtime; p-lumber also on macOS. Readers take a root (`/proc`,
  `/sys`) so tests run against fixture trees on any OS.
- Configuration: two classes of settings file, by who writes them. A file
  that a roll-out renders and that carries trust decisions (keys, anchors,
  who may connect) is JSON: `pledge`, `probe`, `page`. A file a person
  writes by hand for a tool, with lists that want comments, is TOML in
  `/etc/<crate>.toml`: `pusher`, `preserve`, `prover`. Every key optional;
  defaults work. The strictness does not differ: a regular file, owned by
  root or the running user, no group or other write bit, an unknown key
  refused, a key given twice refused, a size limit, and error texts that
  carry no value from the file. Secrets are never in a settings file: a path
  to a file of mode 0600, or the key store.
- Strings from outside. No program writes a string that came from outside
  (a file another writer could have touched counts as outside) into JSON or
  text without the rule of `p-ermit` (`p_ermit::text`): by validation where
  it enters, or by the escape form where it is put out. A JSON writer's own
  escaping is not that rule: it covers U+0000 to U+001F and lets other
  control characters and bidirectional marks through. Each program has one
  test that feeds a C1 control character and a bidirectional mark through
  every output it has. A state file of a program's own that fails
  validation when read back is refused whole.
- Repeated keys. A reader of JSON that is signed, checked or decided on
  refuses an object with a repeated key; it never takes the first or the
  last. A derived struct does that by itself; whatever is read through a
  map or a generic value (the arguments of a call, `_meta`, a `settings`
  object, a `members` object, a register) needs the one reader that does.
- Errors. An error names the file, the member and what was wrong with it,
  and never repeats the offending value, except through the escape form
  with a length bound where an operator needs to see it. The stderr of a
  program that was run is never forwarded to anyone but a log, escaped and
  bounded.
- Tests. A test never asserts on the result of an operation on a socket or
  pipe whose other end the test's subject may already have closed (a write,
  a flush, a shutdown, setting a timeout), unless that result is the thing
  under test. A test that cannot run where it is run says SKIPPED and has a
  strict mode in which that is a failure. A test's files and directories
  get their modes explicitly, never from the umask. No test waits a fixed
  time for another process to be ready; it waits for the thing itself.
- A `health` or `status` verb meant for a monitor documents its exit codes
  in a table in the program's SPEC and never uses one code for two meanings.
- Machine output: `--format json` with `schema_version`, one record type per
  observed object.
- Every change a tool makes to a thread, an IRQ or a NIC is a `Change` from
  `p-roc`: it carries the value it replaces, so it can be checked before it
  is applied and reverted afterwards.
- Each crate is versioned and released on its own; tags `<crate>-v<version>`.

## Layout

```
Cargo.toml          workspace
crates/p-roc/
crates/p-usher/     contrib/ (unit file, example config)
crates/p-rover/     bpf/ (BPF sources and the shipped objects)
crates/p-layer/     templates/, assets/ (embedded into the binary)
crates/p-lumber/
xtask/              maintainer tasks: build and check the BPF objects
```

p-lumber depends on iceoryx2, which needs clang to build. It is left out of
the workspace's `default-members`, so `cargo build` and `cargo test` in the
root need no clang; `cargo build -p p-lumber` builds it, in its own CI job.

`xtask` is a small, unpublished binary crate run as `cargo xtask <task>`
(alias in `.cargo/config.toml`); it replaces shell scripts and a Makefile.

## Order of work

1. Extract `p-roc` from `p-usher`; `p-usher` depends on it, behaviour unchanged.
2. `p-usher` watchdog.
3. `p-rover` phases (static observe subcommands first).
4. `p-layer` phases (read-only views first).
5. `p-lumber` phases (independent of 2-4; can start any time after 1).

## Build

```sh
cargo build              # default members: everything but p-lumber
cargo test
cargo build -p p-lumber  # needs clang
```
