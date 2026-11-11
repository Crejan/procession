//! Rating a call by its parameters: the one generic function that reads the
//! data beside a verb (`proposals/rating-rule.md`).
//!
//! A row without parameter rules (`Args::None`, `Args::Some`) is rated at the
//! row's worst case. A row with `Args::Params` is rated at the worst of its
//! `floor` and what each parameter contributes. For a path the contribution
//! is that of the longest matching prefix of the *resolved* path, and nothing
//! under a directory that anyone but its owner or root can write is rated
//! lower: such a call keeps the row's worst rating (`doc/approvals.md`, R4).
//! What cannot be rated is rated at the row's worst.

use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use p_act::rating::Rating;

use crate::table::{Args, Verb};

/// Where a parameter is in the call's `params`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The n-th token that is not a `key=value` of this row (from 0).
    Position(usize),
    /// `key=value`, split at the first `=`.
    Key(&'static str),
}

/// The prefixes of a path rule: `("/etc/ssh/", rating)` is a directory (every
/// path below it, whole components), `("/etc/shadow", rating)` is that path
/// only.
#[derive(Debug, Clone, Copy)]
pub enum Entries {
    Static(&'static [(&'static str, Rating)]),
    /// A test build: `<PROBE_TEST_SANDBOX>/open/` is rated harmless.
    #[cfg(feature = "test-verbs")]
    Sandbox,
}

impl Entries {
    fn list(&self) -> Vec<(String, Rating)> {
        match self {
            Entries::Static(entries) => entries.iter().map(|(path, rating)| ((*path).to_string(), *rating)).collect(),
            #[cfg(feature = "test-verbs")]
            Entries::Sandbox => std::env::var_os("PROBE_TEST_SANDBOX")
                .and_then(|dir| std::fs::canonicalize(dir).ok())
                .map(|dir| vec![(format!("{}/open/", dir.display()), Rating::HARMLESS)])
                .unwrap_or_default(),
        }
    }

    fn worst(&self) -> Rating {
        self.list().into_iter().fold(Rating::HARMLESS, |worst, (_, rating)| worst.worst_of(rating))
    }
}

/// How a path is rated.
#[derive(Debug, Clone, Copy)]
pub struct PathRule {
    pub entries: Entries,
    /// What a path no entry matches contributes.
    pub otherwise: Rating,
}

/// What a parameter's value is, and what it contributes.
#[derive(Debug, Clone, Copy)]
pub enum ParamType {
    /// An absolute path, resolved and matched against a rule.
    Path(PathRule),
    /// One of a fixed list of words, each with its rating. Others: not accepted.
    Choice(&'static [(&'static str, Rating)]),
    /// An integer in `min..=max`. With `steps` (`up to N: rating`, ascending)
    /// the rating of the first step that holds it; above the last: not accepted.
    Number { min: u64, max: u64, steps: &'static [(u64, Rating)] },
    /// Anything the argument class lets through; contributes nothing.
    Plain,
}

/// One parameter of a verb.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub form: Form,
    pub required: bool,
    pub ty: ParamType,
}

impl Param {
    /// The worst this parameter can contribute.
    #[must_use]
    pub fn worst(&self) -> Rating {
        match &self.ty {
            ParamType::Path(rule) => rule.otherwise.worst_of(rule.entries.worst()),
            ParamType::Choice(words) => words.iter().fold(Rating::HARMLESS, |w, (_, r)| w.worst_of(*r)),
            ParamType::Number { steps, .. } => steps.iter().fold(Rating::HARMLESS, |w, (_, r)| w.worst_of(*r)),
            ParamType::Plain => Rating::HARMLESS,
        }
    }

    /// The rule as lines for the catalogue.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let words = |r: Rating| crate::table::format_rating(r);
        match &self.ty {
            ParamType::Path(rule) => rule
                .entries
                .list()
                .into_iter()
                .map(|(path, rating)| format!("{path} {}", words(rating)))
                .chain([format!("otherwise {}", words(rule.otherwise))])
                .collect(),
            ParamType::Choice(list) => list.iter().map(|(word, r)| format!("{word} {}", words(*r))).collect(),
            ParamType::Number { min, max, steps } => std::iter::once(format!("{min}..{max}"))
                .chain(steps.iter().map(|(up_to, r)| format!("up to {up_to} {}", words(*r))))
                .collect(),
            ParamType::Plain => Vec::new(),
        }
    }
}

/// The worst case of a row with parameters: what the table must declare.
#[must_use]
pub fn derived_worst(floor: Rating, params: &[Param]) -> Rating {
    params.iter().fold(floor, |worst, param| worst.worst_of(param.worst()))
}

/// How a path is looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Open it, and keep the open file: where the action is carried out.
    Open,
    /// Resolve and look at the name only (`realpath`, `stat`): the service,
    /// an unprivileged account, which can search directories it cannot read
    /// files in. Nothing is kept.
    Name,
}

/// A call that cannot be rated because it is not one the row accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAccepted(pub String);

fn not_accepted<T>(why: impl Into<String>) -> Result<T, NotAccepted> {
    Err(NotAccepted(why.into()))
}

/// What became of one path parameter.
#[derive(Debug)]
pub struct PathUse {
    pub param: &'static str,
    /// Where the file is, as the kernel resolves it; `None` if it could not be.
    pub resolved: Option<PathBuf>,
    /// The open file (`Mode::Open`), the one the verb reads. `None` if it
    /// could not be opened.
    pub file: Option<File>,
    pub is_dir: bool,
}

/// The rating of a call, and the files it opened.
#[derive(Debug)]
pub struct Rated {
    pub rating: Rating,
    pub paths: Vec<PathUse>,
}

/// Rates `args` for `verb`.
///
/// # Errors
/// [`NotAccepted`] when the row does not accept the call: an unknown, repeated
/// or missing parameter, a value of the wrong shape, a path that is neither a
/// regular file nor a directory.
pub fn rate(verb: &Verb, args: &[String], mode: Mode) -> Result<Rated, NotAccepted> {
    let Args::Params { floor, params } = verb.args else {
        return Ok(Rated { rating: verb.rating, paths: Vec::new() });
    };
    let mut slots: Vec<Option<&str>> = vec![None; params.len()];
    let mut position = 0;
    for token in args {
        let keyed = params.iter().enumerate().find_map(|(index, param)| match param.form {
            Form::Key(key) => {
                token.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')).map(|value| (index, value))
            }
            Form::Position(_) => None,
        });
        let (index, value) = match keyed {
            Some(found) => found,
            None => {
                let Some(index) = params.iter().position(|param| param.form == Form::Position(position)) else {
                    return not_accepted(format!(
                        "unexpected argument {}",
                        crate::audit::quote(&crate::audit::clip(token, 60))
                    ));
                };
                position += 1;
                (index, token.as_str())
            }
        };
        if slots[index].replace(value).is_some() {
            return not_accepted(format!("{} given twice", params[index].name));
        }
    }
    let mut rating = floor;
    let mut paths = Vec::new();
    for (param, slot) in params.iter().zip(slots) {
        let Some(value) = slot else {
            if param.required {
                return not_accepted(format!("missing {}", param.name));
            }
            continue;
        };
        match &param.ty {
            ParamType::Plain => {}
            ParamType::Choice(words) => match words.iter().find(|(word, _)| *word == value) {
                Some((_, contribution)) => rating = rating.worst_of(*contribution),
                None => return not_accepted(format!("{}: not one of the accepted words", param.name)),
            },
            ParamType::Number { min, max, steps } => {
                let number: u64 = value.parse().or_else(|_| not_accepted(format!("{}: not a number", param.name)))?;
                if number < *min || number > *max {
                    return not_accepted(format!("{}: outside {min}..{max}", param.name));
                }
                if !steps.is_empty() {
                    match steps.iter().find(|(up_to, _)| number <= *up_to) {
                        Some((_, contribution)) => rating = rating.worst_of(*contribution),
                        None => return not_accepted(format!("{}: above the last step", param.name)),
                    }
                }
            }
            ParamType::Path(rule) => {
                let (contribution, used) = rate_path(rule, verb.rating, param.name, value, mode)?;
                rating = rating.worst_of(contribution);
                paths.push(used);
            }
        }
    }
    Ok(Rated { rating, paths })
}

/// Why a path could not be looked at.
enum Fault {
    /// Not a call this row accepts.
    Refuse(String),
    /// Opening, resolving or the cross-check failed: rate at the row's worst.
    CannotTell,
}

fn rate_path(
    rule: &PathRule,
    worst: Rating,
    name: &'static str,
    value: &str,
    mode: Mode,
) -> Result<(Rating, PathUse), NotAccepted> {
    if !value.starts_with('/') {
        return not_accepted(format!("{name}: not an absolute path"));
    }
    let seen = match mode {
        Mode::Open => open_resolved(value),
        Mode::Name => name_resolved(value),
    };
    let (file, resolved, is_dir) = match seen {
        Ok(found) => found,
        Err(Fault::Refuse(why)) => return not_accepted(format!("{name}: {why}")),
        Err(Fault::CannotTell) => {
            return Ok((worst, PathUse { param: name, resolved: None, file: None, is_dir: false }));
        }
    };
    let rating = rating_of(rule, worst, &resolved, is_dir);
    Ok((rating, PathUse { param: name, resolved: Some(resolved), file, is_dir }))
}

/// Open once, `fstat`, the name of what is open, and the check that the name
/// is that file (device and inode). Nothing looks at the path before the open.
fn open_resolved(value: &str) -> Result<(Option<File>, PathBuf, bool), Fault> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(value)
        .map_err(|_| Fault::CannotTell)?;
    let meta = file.metadata().map_err(|_| Fault::CannotTell)?;
    check_type(&meta)?;
    let resolved = path_of(&file).ok_or(Fault::CannotTell)?;
    let named = std::fs::metadata(&resolved).map_err(|_| Fault::CannotTell)?;
    if (named.dev(), named.ino()) != (meta.dev(), meta.ino()) {
        return Err(Fault::CannotTell);
    }
    Ok((Some(file), resolved, meta.is_dir()))
}

fn name_resolved(value: &str) -> Result<(Option<File>, PathBuf, bool), Fault> {
    let resolved = std::fs::canonicalize(value).map_err(|_| Fault::CannotTell)?;
    let meta = std::fs::metadata(&resolved).map_err(|_| Fault::CannotTell)?;
    check_type(&meta)?;
    Ok((None, resolved, meta.is_dir()))
}

/// Only regular files and directories: reading a FIFO, a socket or a device can
/// block or act.
fn check_type(meta: &std::fs::Metadata) -> Result<(), Fault> {
    if meta.is_file() || meta.is_dir() {
        Ok(())
    } else {
        Err(Fault::Refuse("not a regular file or a directory".into()))
    }
}

/// Where an open file is, as the kernel says. Linux: `/proc/self/fd/<n>`;
/// macOS (build and test only): `F_GETPATH`.
#[cfg(target_os = "linux")]
fn path_of(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(target_os = "macos")]
fn path_of(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes into the buffer.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0)?;
    buffer.truncate(end);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buffer)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn path_of(_: &File) -> Option<PathBuf> {
    None
}

fn components(path: &Path) -> Vec<&std::ffi::OsStr> {
    path.components()
        .filter_map(|c| if let std::path::Component::Normal(part) = c { Some(part) } else { None })
        .collect()
}

/// The longest matching entry decides, by whole components; none: `otherwise`.
/// A rating below the row's worst needs every directory the entry vouches for
/// to be closed (`closed_directories`).
fn rating_of(rule: &PathRule, worst: Rating, resolved: &Path, is_dir: bool) -> Rating {
    let have = components(resolved);
    let entries = rule.entries.list();
    let mut best: Option<(usize, bool, Rating)> = None;
    for (entry, rating) in &entries {
        let is_prefix = entry.ends_with('/');
        let want = components(Path::new(entry));
        let hit = if is_prefix { have.starts_with(&want) } else { have == want };
        if hit && best.is_none_or(|(len, _, _)| want.len() > len) {
            best = Some((want.len(), is_prefix, *rating));
        }
    }
    let Some((entry_len, is_prefix, rating)) = best else { return rule.otherwise };
    // The directories from the one the entry names (or the file's parent, for an
    // exact entry) down to the file's parent, and the file itself if it is one.
    // Above the entry nothing needs a check: a link planted there changes where
    // the path resolves, and the resolved path is what was matched.
    let start = if is_prefix { entry_len } else { have.len().saturating_sub(1) };
    let mut dirs: Vec<PathBuf> = (start..have.len()).map(|n| prefix(&have[..n])).collect();
    if is_dir {
        dirs.push(resolved.to_path_buf());
    }
    if dirs.iter().all(|dir| closed_directory(dir)) { rating } else { worst }
}

fn prefix(parts: &[&std::ffi::OsStr]) -> PathBuf {
    let mut path = PathBuf::from("/");
    path.extend(parts);
    path
}

/// Whether nobody but the directory's owner (or root) can write in it: no
/// group or other write bit. (Access lists are not looked at.) A directory
/// that cannot be looked at is not closed.
fn closed_directory(dir: &Path) -> bool {
    std::fs::metadata(dir).is_ok_and(|meta| meta.is_dir() && meta.mode() & 0o022 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::Availability;
    use p_act::rating::{Damage, Disruption, Exposure};
    use std::os::unix::fs::{PermissionsExt, symlink};

    const OPEN: Rating = Rating::HARMLESS;
    const INTERNAL: Rating = Rating::new(Exposure::Internal, Damage::None, Disruption::None);
    const SECRET: Rating = Rating::new(Exposure::Secret, Damage::None, Disruption::None);

    fn leak<T>(value: T) -> &'static T {
        Box::leak(Box::new(value))
    }

    /// A verb `t read <path>` whose path rule is `entries`, otherwise secret.
    fn path_verb(entries: Vec<(String, Rating)>) -> &'static Verb {
        let entries: &'static [(&'static str, Rating)] =
            leak(entries.into_iter().map(|(p, r)| (&*Box::leak(p.into_boxed_str()), r)).collect::<Vec<_>>());
        let params: &'static [Param] = leak(vec![Param {
            name: "path",
            form: Form::Position(0),
            required: true,
            ty: ParamType::Path(PathRule { entries: Entries::Static(entries), otherwise: SECRET }),
        }]);
        leak(Verb {
            noun: "t",
            verb: "read",
            runs: "probe",
            rating: SECRET,
            args: Args::Params { floor: OPEN, params },
            summary: "test",
            availability: Availability::NotBuilt("test"),
        })
    }

    fn dir(mode: u32) -> PathBuf {
        let path = std::fs::canonicalize(crate::testdir::new("rate")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn sub(parent: &Path, name: &str, mode: u32) -> PathBuf {
        let path = parent.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn file(parent: &Path, name: &str) -> PathBuf {
        let path = parent.join(name);
        std::fs::write(&path, "x").unwrap();
        path
    }

    fn rated(verb: &Verb, path: &Path, mode: Mode) -> Rating {
        rate(verb, &[path.display().to_string()], mode).unwrap().rating
    }

    /// `<root>/open/` rated open, `<root>/etc/` internal; `root` is closed (0755).
    fn site() -> (PathBuf, &'static Verb) {
        let root = dir(0o755);
        let verb = path_verb(vec![
            (format!("{}/open/", root.display()), OPEN),
            (format!("{}/etc/", root.display()), INTERNAL),
        ]);
        sub(&root, "open", 0o755);
        sub(&root, "etc", 0o755);
        sub(&root, "private", 0o755);
        (root, verb)
    }

    #[test]
    fn a_path_is_rated_by_its_prefix_by_the_open_file_and_by_the_name() {
        let (root, verb) = site();
        let (a, b, c) = (file(&root.join("open"), "a"), file(&root.join("etc"), "b"), file(&root.join("private"), "c"));
        for mode in [Mode::Open, Mode::Name] {
            assert_eq!(rated(verb, &a, mode), OPEN, "{mode:?}");
            assert_eq!(rated(verb, &b, mode), INTERNAL);
            assert_eq!(rated(verb, &c, mode), SECRET);
        }
    }

    #[test]
    fn the_open_file_is_kept_and_named_as_the_kernel_resolves_it() {
        let (root, verb) = site();
        let a = file(&root.join("open"), "a");
        let link = root.join("open/link");
        symlink(&a, &link).unwrap();
        let rated = rate(verb, &[link.display().to_string()], Mode::Open).unwrap();
        assert_eq!(rated.paths[0].resolved.as_deref(), Some(a.as_path()));
        assert!(rated.paths[0].file.is_some());
        assert!(rate(verb, &[link.display().to_string()], Mode::Name).unwrap().paths[0].file.is_none());
    }

    #[test]
    fn prefixes_match_whole_components() {
        let root = dir(0o755);
        let verb = path_verb(vec![(format!("{}/ssh/", root.display()), OPEN)]);
        sub(&root, "ssh", 0o755);
        sub(&root, "sshd_evil", 0o755);
        assert_eq!(rated(verb, &file(&root.join("ssh"), "f"), Mode::Open), OPEN);
        assert_eq!(rated(verb, &file(&root.join("sshd_evil"), "f"), Mode::Open), SECRET);
        assert_eq!(rated(verb, &root.join("ssh"), Mode::Open), OPEN, "the directory itself is under its entry");
    }

    #[test]
    fn the_longest_entry_wins_and_may_raise_or_lower() {
        let root = dir(0o755);
        let verb = path_verb(vec![
            (format!("{}/etc/", root.display()), INTERNAL),
            (format!("{}/etc/certs/", root.display()), OPEN),
            (format!("{}/etc/shadow", root.display()), SECRET),
        ]);
        let etc = sub(&root, "etc", 0o755);
        let certs = sub(&etc, "certs", 0o755);
        assert_eq!(rated(verb, &file(&etc, "hosts"), Mode::Open), INTERNAL);
        assert_eq!(rated(verb, &file(&certs, "ca"), Mode::Open), OPEN);
        assert_eq!(rated(verb, &file(&etc, "shadow"), Mode::Open), SECRET);
    }

    #[test]
    fn a_link_is_rated_by_where_it_leads() {
        let (root, verb) = site();
        let open_file = file(&root.join("open"), "a");
        let secret = file(&root.join("private"), "s");
        symlink(&secret, root.join("open/to-secret")).unwrap();
        symlink(&open_file, root.join("private/to-open")).unwrap();
        assert_eq!(rated(verb, &root.join("open/to-secret"), Mode::Open), SECRET);
        assert_eq!(rated(verb, &root.join("private/to-open"), Mode::Open), OPEN);
        assert_eq!(rated(verb, &root.join("open/to-secret"), Mode::Name), SECRET);
    }

    #[test]
    fn dot_dot_cannot_leave_a_prefix_unnoticed() {
        let (root, verb) = site();
        file(&root.join("private"), "s");
        assert_eq!(rated(verb, &root.join("open/../private/s"), Mode::Open), SECRET);
        assert_eq!(rated(verb, &root.join("open/../private/s"), Mode::Name), SECRET);
    }

    #[test]
    fn nothing_is_rated_lower_under_a_directory_others_can_write() {
        for mode_bits in [0o777, 0o775, 0o757, 0o1777] {
            let (root, verb) = site();
            let loose = sub(&root.join("open"), "loose", mode_bits);
            let f = file(&loose, "f");
            for mode in [Mode::Open, Mode::Name] {
                assert_eq!(rated(verb, &f, mode), SECRET, "{mode_bits:o} {mode:?}: the row's worst");
            }
            // The directory itself, listed, and a file one level further down.
            assert_eq!(rated(verb, &loose, Mode::Open), SECRET);
            let inner = sub(&loose, "inner", 0o755);
            assert_eq!(rated(verb, &file(&inner, "g"), Mode::Open), SECRET, "a loose directory above in the entry");
        }
    }

    #[test]
    fn the_entry_directory_itself_must_be_closed() {
        let root = dir(0o755);
        let verb = path_verb(vec![(format!("{}/open/", root.display()), OPEN)]);
        let open = sub(&root, "open", 0o777);
        assert_eq!(rated(verb, &file(&open, "f"), Mode::Open), SECRET);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(rated(verb, &open.join("f"), Mode::Open), OPEN);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(rated(verb, &open.join("f"), Mode::Open), OPEN, "owner only is closed");
    }

    #[test]
    fn an_exact_entry_needs_its_parent_closed() {
        let root = dir(0o755);
        let verb = path_verb(vec![(format!("{}/d/f", root.display()), OPEN)]);
        let d = sub(&root, "d", 0o755);
        file(&d, "f");
        assert_eq!(rated(verb, &d.join("f"), Mode::Open), OPEN);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(rated(verb, &d.join("f"), Mode::Open), SECRET);
    }

    #[test]
    fn what_cannot_be_looked_at_is_rated_at_the_rows_worst() {
        let (root, verb) = site();
        assert_eq!(rated(verb, &root.join("open/absent"), Mode::Open), SECRET);
        assert_eq!(rated(verb, &root.join("open/absent"), Mode::Name), SECRET);
        let unreadable = file(&root.join("open"), "locked");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let as_root = unsafe { libc::geteuid() } == 0;
        assert_eq!(rated(verb, &unreadable, Mode::Open), if as_root { OPEN } else { SECRET });
        assert_eq!(rated(verb, &unreadable, Mode::Name), OPEN, "the name can be looked at without reading");
    }

    #[test]
    fn only_regular_files_and_directories_are_accepted() {
        let (root, verb) = site();
        let fifo = root.join("open/fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        for mode in [Mode::Open, Mode::Name] {
            let refused = rate(verb, &[fifo.display().to_string()], mode).unwrap_err();
            assert!(refused.0.contains("not a regular file"), "{refused:?}");
        }
        assert!(rate(verb, &["/dev/null".to_string()], Mode::Open).is_err());
    }

    #[test]
    fn a_path_must_be_absolute() {
        let (_, verb) = site();
        assert!(rate(verb, &["relative/p".into()], Mode::Open).is_err());
        assert!(rate(verb, &["~/x".into()], Mode::Open).is_err());
    }

    #[test]
    fn a_link_planted_between_rating_and_opening_is_seen_by_the_second_rating() {
        let (root, verb) = site();
        let harmless = file(&root.join("open"), "a");
        let secret = file(&root.join("private"), "s");
        let path = root.join("open/link");
        symlink(&harmless, &path).unwrap();
        let approved = rated(verb, &path, Mode::Name); // the service rates
        assert_eq!(approved, OPEN);
        std::fs::remove_file(&path).unwrap(); // someone plants a link
        symlink(&secret, &path).unwrap();
        let at_opening = rated(verb, &path, Mode::Open); // the dispatcher rates again
        assert_eq!(at_opening, SECRET);
        assert!(!at_opening.within(approved), "the dispatcher refuses");
    }

    // -- parameters --------------------------------------------------------

    const CHOICES: &[(&str, Rating)] = &[("quick", OPEN), ("deep", INTERNAL)];
    const STEPS: &[(u64, Rating)] = &[(10, OPEN), (60, Rating::new(Exposure::Open, Damage::None, Disruption::Brief))];

    fn many() -> &'static Verb {
        let params: &'static [Param] = leak(vec![
            Param { name: "mode", form: Form::Key("mode"), required: true, ty: ParamType::Choice(CHOICES) },
            Param {
                name: "s",
                form: Form::Key("s"),
                required: false,
                ty: ParamType::Number { min: 1, max: 60, steps: STEPS },
            },
            Param { name: "what", form: Form::Position(0), required: false, ty: ParamType::Plain },
        ]);
        leak(Verb {
            noun: "t",
            verb: "many",
            runs: "probe",
            rating: derived_worst(OPEN, params),
            args: Args::Params { floor: OPEN, params },
            summary: "test",
            availability: Availability::NotBuilt("test"),
        })
    }

    fn call(args: &[&str]) -> Result<Rating, NotAccepted> {
        rate(many(), &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), Mode::Open).map(|r| r.rating)
    }

    #[test]
    fn the_worst_of_the_floor_and_every_contribution() {
        assert_eq!(call(&["mode=quick"]).unwrap(), OPEN);
        assert_eq!(call(&["mode=deep"]).unwrap(), INTERNAL);
        assert_eq!(call(&["mode=quick", "s=5"]).unwrap(), OPEN);
        assert_eq!(
            call(&["s=30", "mode=quick", "anything"]).unwrap(),
            Rating::new(Exposure::Open, Damage::None, Disruption::Brief)
        );
        assert_eq!(
            call(&["mode=deep", "s=60"]).unwrap(),
            Rating::new(Exposure::Internal, Damage::None, Disruption::Brief)
        );
        assert_eq!(many().rating, Rating::new(Exposure::Internal, Damage::None, Disruption::Brief));
    }

    #[test]
    fn what_the_row_does_not_accept_is_not_rated() {
        for bad in [
            &[][..],
            &["mode=none"],
            &["mode=quick", "mode=deep"],
            &["mode=quick", "s=0"],
            &["mode=quick", "s=61"],
            &["mode=quick", "s=x"],
            &["mode=quick", "one", "two"],
            &["s=5"],
        ] {
            assert!(call(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_row_without_rules_is_rated_at_its_worst() {
        let kit = crate::table::find("rt", "jitter").unwrap();
        assert_eq!(rate(kit, &["x".into()], Mode::Open).unwrap().rating, kit.rating);
    }

    // -- the table's own rows --------------------------------------------------

    #[test]
    fn every_row_declares_what_its_parameters_can_reach() {
        for row in crate::table::verbs() {
            if let Args::Params { floor, params } = row.args {
                assert_eq!(row.rating, derived_worst(floor, params), "{}", row.label());
                assert!(floor.within(row.rating), "{}", row.label());
                for param in params {
                    assert!(param.worst().within(row.rating), "{} {}", row.label(), param.name);
                    if let ParamType::Path(rule) = param.ty {
                        check_entries(&row.label(), rule);
                    }
                }
            }
        }
    }

    fn check_entries(label: &str, rule: PathRule) {
        let entries = rule.entries.list();
        for (index, (path, rating)) in entries.iter().enumerate() {
            assert!(
                path.starts_with('/')
                    && !path.contains("//")
                    && !path.split('/').any(|part| part == ".." || part == "."),
                "{label}: {path}"
            );
            assert!(
                !entries[..index].iter().any(|(other, _)| components(Path::new(other)) == components(Path::new(path))),
                "{label}: {path} twice"
            );
            let _ = rating;
        }
        assert!(
            rule.entries.worst().within(rule.otherwise),
            "{label}: `otherwise` must be at least as bad as every entry"
        );
    }
}
