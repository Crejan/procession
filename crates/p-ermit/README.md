# p-ermit

What may be trusted on a Unix system, checked the same way by every program that asks:

- **a settings file**, by its owner and mode (`p_ermit::settings`): a regular file, owned by root or by the user that
  runs the program, not writable by its group or by others, within a size limit. The checks are made **on the open
  file** (no gap between check and read). The errors say what to do (`run chmod 600 <path>`), never hold a value from
  the file, and tell a missing file (`SettingsError::NotFound`) from every other problem.
- **a secret file**, such as a password file (`read_secret_checked`, `read_secret_optional`, `check_open_secret`): the same, but
  with no permission bit at all for group or others (reading is as bad as writing). The refusal gives the exact
  `chmod 600 <path>` or `chown` for the caller's path; the content is never in an error.
- **text from elsewhere** (`p_ermit::text`): `check` is the rule for what is refused (no control characters, no
  bidirectional marks); `escape`, `escape_bytes`, `escape_clipped`, `unescape` are the one escape form for diagnostic data
  that is shown or passed on instead: `\u{202e}`, `\x{ff}` for bytes that are not UTF-8, `\\` for a backslash,
  reversible, and the result passes `check`.
- **a TOML settings file** (feature `toml`, off by default; brings `toml` 0.9 and `serde`): `read_toml`,
  `read_toml_optional`, `parse_toml`, with the same checks, and errors that name the offending *key* and its line and
  column but never print a *value*. Unknown keys are refused by the caller's own `#[serde(deny_unknown_fields)]`;
  `toml` itself refuses a key given twice and text after the document.
- **a Unix socket's peer** (`p_ermit::peer`): user, group, process and program of the connecting process (Linux:
  `SO_PEERCRED` and `/proc/<pid>/exe`; macOS: `getpeereid`, `LOCAL_PEERPID` and `proc_pidpath`). *Read or drop*: a `Peer`
  exists only if its credentials were read, and `admit`/`accept` never treat "could not read" as anyone. A throttled log
  line, at most one per interval per socket, goes to a sink the caller gives.

libc only by default. Unix only (except `text`, which is portable). Minimum Rust 1.91.

## Use

```rust,ignore
let bytes = p_ermit::settings::read_checked(Path::new("/etc/prog.conf"), 1 << 20)?;   // the checks, then the bytes
let cfg: Config = p_ermit::settings::read_toml(Path::new("/etc/prog.toml"))?;          // feature `toml`
let peer = p_ermit::peer::admit(&stream, &p_ermit::peer::Policy::OwnUserOrRoot)?;      // read or drop
```

## Status

Written for the `procession` workspace, where `p-act` re-exports it for the programs that already depend on `p-act`.
**Nobody has checked the name `p-ermit` against crates.io**, and publishing is not decided (`publish = false`). The Linux
branches of `peer` (and `program_path`) are copied from code that ran on Debian 13 and were not compiled where the crate
was written (macOS).

Licence: MIT OR Apache-2.0.
