//! The certificates of persons' approval keys that the broker carries to pledge: **a separate input** beside the
//! site file, a directory of `*-cert.pub` files (OpenSSH's own naming) written by the site's signing step.
//!
//! The broker never makes or changes one. Each is checked when it is loaded, with `p-act`'s verifier against the site
//! CA's key (shape, name `<person>:confirmed` or `<person>:automatic`, no critical option, signature and issuer), for
//! validity now, and against the site file: the person must be there and the certified key must be the one the site
//! file lists for that person and purpose. A certificate that fails any of it is **not carried** and is reported
//! with its file and the reason. The person, the purpose and the key come from the certificate and never from the
//! file's name.
//!
//! The directory and the files follow `p-ermit`'s settings rule: owned by root or the broker's user and not writable
//! by group or others; a directory that fails it is refused whole.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use p_act::peer::own_uid;
use p_act::settings::{check_owner_and_mode, read_checked};
use p_act::sign::{ApprovalKind, PublicKey};

use crate::crypto::Crypto;
use crate::site::Site;
use crate::util::{shown, shown_error};

/// Only files named like this are read; a plain `*.pub` beside them is not a certificate and is not opened.
pub const SUFFIX: &str = "-cert.pub";
/// A certificate file is one line.
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// Where the certificates are, and what they are checked against.
#[derive(Debug, Clone)]
pub struct CertificateInput {
    pub site_ca: PublicKey,
    pub directory: PathBuf,
}

/// A certificate that is carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    /// The `-cert.pub` line, as the file had it.
    pub line: String,
    pub kind: ApprovalKind,
    pub valid_after: u64,
    pub valid_before: u64,
}

/// A certificate that was not carried, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCarried {
    pub file: String,
    pub reason: String,
}

/// What was in the directory when it was read.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    /// By person.
    pub carried: BTreeMap<String, Vec<Carried>>,
    pub not_carried: Vec<NotCarried>,
    /// Why the directory was refused whole, if it was (nothing is carried then).
    pub directory_refused: Option<String>,
    /// The listing the next read compares with: file name, modification time, length.
    pub listing: Vec<(String, i64, u64)>,
    /// The next time something changes without the directory changing: a carried certificate ends, or one that is not
    /// yet valid begins (seconds since the epoch).
    pub next_event: Option<u64>,
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The directory's listing of `*-cert.pub` files, sorted: what changes when a file is added, replaced or removed.
fn list(directory: &Path) -> std::io::Result<Vec<(String, i64, u64)>> {
    let mut listing = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.len() > SUFFIX.len() && name.ends_with(SUFFIX) {
            let meta = entry.metadata()?;
            listing.push((name, meta.mtime() * 1_000_000_000 + meta.mtime_nsec(), meta.len()));
        }
    }
    listing.sort();
    Ok(listing)
}

/// Whether the directory is different from what `loaded` saw.
#[must_use]
pub fn changed(input: &CertificateInput, loaded: &Loaded) -> bool {
    list(&input.directory).map_or(true, |now| now != loaded.listing)
}

fn kind_name(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::Confirmed => "confirmed",
        ApprovalKind::Automatic => "automatic",
    }
}

/// Read and check every `*-cert.pub` in the directory, at `now`.
pub fn load(input: &CertificateInput, site: &Site, crypto: &dyn Crypto, now: SystemTime) -> Loaded {
    let mut loaded = Loaded::default();
    let dir_text = input.directory.display().to_string();
    // The directory first: a directory that fails the rule is refused whole.
    let directory_ok = fs::symlink_metadata(&input.directory).map_err(|e| e.to_string()).and_then(|m| {
        if m.is_dir() {
            check_owner_and_mode(&dir_text, m.uid(), m.mode(), own_uid()).map_err(|e| e.to_string())
        } else {
            Err(format!("{dir_text} is not a directory"))
        }
    });
    if let Err(why) = directory_ok {
        loaded.directory_refused = Some(shown(&why));
        return loaded;
    }
    let listing = match list(&input.directory) {
        Ok(l) => l,
        Err(e) => {
            loaded.directory_refused = Some(shown(&format!("cannot read {dir_text}: {e}")));
            return loaded;
        }
    };
    let now_secs = u64::try_from(unix(now)).unwrap_or(0);
    for (name, ..) in &listing {
        let refuse = |loaded: &mut Loaded, reason: String| {
            // Both are outside data: the file's name (any bytes the file system allows) and the reason (which may quote the
            // certificate). Stored escaped and bounded, so that nothing downstream can print them raw.
            loaded.not_carried.push(NotCarried { file: shown(name), reason: shown(&reason) });
        };
        let path = input.directory.join(name);
        // A link is not a file of ours: the rule is about the file, not about what a link points at.
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                refuse(&mut loaded, "not a regular file".to_owned());
                continue;
            }
            Err(e) => {
                refuse(&mut loaded, shown_error(&e));
                continue;
            }
        }
        let bytes = match read_checked(&path, MAX_FILE_BYTES) {
            Ok(b) => b,
            Err(e) => {
                refuse(&mut loaded, shown_error(&e));
                continue;
            }
        };
        let Ok(text) = String::from_utf8(bytes) else {
            refuse(&mut loaded, "not UTF-8".to_owned());
            continue;
        };
        let line = text.strip_suffix('\n').unwrap_or(&text);
        if line.contains(['\n', '\r']) || line.is_empty() {
            refuse(&mut loaded, "not one line".to_owned());
            continue;
        }
        let cert = match crypto.check_approval_certificate(line, &input.site_ca) {
            Ok(c) => c,
            Err(e) => {
                refuse(&mut loaded, shown_error(&e));
                continue;
            }
        };
        // Validity, judged here so that a certificate that has not begun can be read again when it does.
        if now_secs < cert.valid_after {
            loaded.next_event = Some(loaded.next_event.map_or(cert.valid_after, |n| n.min(cert.valid_after)));
            refuse(&mut loaded, "not yet valid".to_owned());
            continue;
        }
        if now_secs >= cert.valid_before {
            refuse(&mut loaded, "expired".to_owned());
            continue;
        }
        // Against the site file: the person is there, and the key is the one listed for that person and purpose.
        let Some(keys) = site.person(&cert.person).and_then(|p| p.keys.as_ref()) else {
            refuse(&mut loaded, "the person is not in the site file, or has no keys there".to_owned());
            continue;
        };
        let listed = match cert.kind {
            ApprovalKind::Confirmed => &keys.confirmed,
            ApprovalKind::Automatic => &keys.automatic,
        };
        if !cert.certifies(listed) {
            refuse(&mut loaded, format!("not the {} key the site file lists for that person", kind_name(cert.kind)));
            continue;
        }
        loaded.next_event = Some(loaded.next_event.map_or(cert.valid_before, |n| n.min(cert.valid_before)));
        loaded.carried.entry(cert.person).or_default().push(Carried {
            line: line.to_owned(),
            kind: cert.kind,
            valid_after: cert.valid_after,
            valid_before: cert.valid_before,
        });
    }
    loaded.listing = listing;
    loaded
}

impl Loaded {
    /// The lines carried for `person` that are valid at `now`, sorted (what the standing carries).
    #[must_use]
    pub fn lines_for(&self, person: &str, now: SystemTime) -> Vec<String> {
        let now = u64::try_from(unix(now)).unwrap_or(0);
        let mut lines: Vec<String> = self
            .carried
            .get(person)
            .into_iter()
            .flatten()
            .filter(|c| c.valid_after <= now && now < c.valid_before)
            .map(|c| c.line.clone())
            .collect();
        lines.sort_unstable();
        lines.dedup();
        lines
    }

    /// How many certificates are carried and valid at `now`.
    #[must_use]
    pub fn carried_count(&self, now: SystemTime) -> usize {
        self.carried.keys().map(|p| self.lines_for(p, now).len()).sum()
    }

    /// `<person>:<purpose>` for each enabled person who has keys and no valid certificate for a purpose.
    #[must_use]
    pub fn uncovered(&self, site: &Site, now: SystemTime) -> Vec<String> {
        let now = u64::try_from(unix(now)).unwrap_or(0);
        let mut missing = Vec::new();
        for name in site.person_names() {
            if !site.person(name).is_some_and(|p| p.enabled && p.keys.is_some()) {
                continue;
            }
            for kind in [ApprovalKind::Confirmed, ApprovalKind::Automatic] {
                let covered = self
                    .carried
                    .get(name)
                    .into_iter()
                    .flatten()
                    .any(|c| c.kind == kind && c.valid_after <= now && now < c.valid_before);
                if !covered {
                    missing.push(format!("{name}:{}", kind_name(kind)));
                }
            }
        }
        missing
    }

    /// Whether the directory needs to be read again at `now` although it did not change: something ended or began.
    #[must_use]
    pub fn due(&self, now: SystemTime) -> bool {
        self.next_event.is_some_and(|at| u64::try_from(unix(now)).unwrap_or(0) >= at)
    }
}

/// What the broker's own certificate says, once it has passed the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerCertificate {
    /// Seconds since the Unix epoch.
    pub valid_after: u64,
    pub valid_before: u64,
}

/// Why the broker's own certificate is not good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerCertificateFailure {
    /// There is no certificate file beside the key.
    Missing,
    NotYetValid,
    Expired,
    /// Anything else: not the name `broker`, not issued by the site CA, a critical option, an extension, not for the
    /// key the broker holds, not readable. The text is for standard error.
    Refused(String),
}

impl BrokerCertificateFailure {
    /// A code from a closed list, for the administrator's answer: `missing`, `not-yet-valid`, `expired`, `refused`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            BrokerCertificateFailure::Missing => "missing",
            BrokerCertificateFailure::NotYetValid => "not-yet-valid",
            BrokerCertificateFailure::Expired => "expired",
            BrokerCertificateFailure::Refused(_) => "refused",
        }
    }
}

impl std::fmt::Display for BrokerCertificateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerCertificateFailure::Refused(why) => write!(f, "refused: {why}"),
            other => f.write_str(other.code()),
        }
    }
}
