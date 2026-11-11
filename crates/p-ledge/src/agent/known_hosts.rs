//! Read-only view of OpenSSH `known_hosts` files, for naming a host key the
//! SSH agent verified through `session-bind@openssh.com`. A name shown in a
//! dialog is only as trustworthy as these files: the trust `ssh` itself
//! places in them.
//!
//! A name that cannot be shown as it is (a control character, a
//! bidirectional mark, too long) is left out, never cleaned; the dialog then
//! falls back to the fingerprint.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::host_key::HostKey;
use super::text::is_showable;

/// Largest file read; anything bigger is not read at all.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// What a verified host key is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostName {
    /// Host names (or addresses) listed for this key, in file order.
    Named(Vec<String>),
    /// The key is listed, but only under hashed names (`HashKnownHosts`).
    HashedOnly,
    /// Not listed, or listed as revoked.
    Unknown,
}

/// A line's marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// An ordinary entry.
    None,
    /// `@cert-authority`
    CertAuthority,
    /// `@revoked`
    Revoked,
}

/// One line of a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `@cert-authority`, `@revoked` or none.
    pub marker: Marker,
    /// The comma-separated host patterns.
    pub patterns: Vec<String>,
    /// The key's wire blob.
    pub key_blob: Vec<u8>,
}

/// All entries of the files read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

impl KnownHosts {
    /// The files OpenSSH reads, for the person whose home is `home`.
    #[must_use]
    pub fn default_paths(home: &Path) -> Vec<PathBuf> {
        vec![
            home.join(".ssh/known_hosts"),
            home.join(".ssh/known_hosts2"),
            PathBuf::from("/etc/ssh/ssh_known_hosts"),
            PathBuf::from("/etc/ssh/ssh_known_hosts2"),
        ]
    }

    /// Reads and parses the files that exist and are at most
    /// [`MAX_FILE_BYTES`]; any other is skipped.
    #[must_use]
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut text = String::new();
        for path in paths {
            let Ok(file) = fs::File::open(path) else { continue };
            let mut bytes = Vec::new();
            // One byte more than the limit tells "too big" from "just fits".
            if file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_FILE_BYTES {
                continue;
            }
            text.push_str(&String::from_utf8_lossy(&bytes));
            text.push('\n');
        }
        Self::parse(&text)
    }

    /// Parses the text of `known_hosts` files. Lines that are not entries
    /// are skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let entries = text.lines().filter_map(parse_line).collect();
        Self { entries }
    }

    /// What `key` is called, at `now` (Unix time, seconds).
    #[must_use]
    pub fn name(&self, key: &HostKey, now: u64) -> HostName {
        let plain = key.plain_blob();
        let ca_key = key.certificate.as_ref().map(|certificate| certificate.ca_key.as_slice());
        let revoked = self
            .entries
            .iter()
            .any(|e| e.marker == Marker::Revoked && (e.key_blob == plain || Some(e.key_blob.as_slice()) == ca_key));
        if revoked {
            return HostName::Unknown;
        }
        let mut names: Vec<String> = Vec::new();
        let mut add = |name: String| {
            if is_showable(&name) && !names.contains(&name) {
                names.push(name);
            }
        };
        if let Some(certificate) = key.certificate.as_ref().filter(|c| c.is_valid_host_certificate(now)) {
            for entry in
                self.entries.iter().filter(|e| e.marker == Marker::CertAuthority && e.key_blob == certificate.ca_key)
            {
                for principal in certificate.principals.iter().filter(|p| host_matches(p, &entry.patterns)) {
                    add(principal.clone());
                }
            }
        }
        let mut hashed = false;
        for entry in self.entries.iter().filter(|e| e.marker == Marker::None && e.key_blob == plain) {
            for pattern in &entry.patterns {
                if pattern.starts_with("|1|") {
                    hashed = true;
                } else if !pattern.starts_with('!') && !pattern.contains(['*', '?']) {
                    add(display_pattern(pattern));
                }
            }
        }
        if !names.is_empty() {
            HostName::Named(names)
        } else if hashed {
            HostName::HashedOnly
        } else {
            HostName::Unknown
        }
    }
}

fn parse_line(line: &str) -> Option<Entry> {
    let mut fields = line.split([' ', '\t']).filter(|field| !field.is_empty());
    let first = fields.next().filter(|first| !first.starts_with('#'))?;
    let (marker, patterns) = match first {
        "@cert-authority" => (Marker::CertAuthority, fields.next()?),
        "@revoked" => (Marker::Revoked, fields.next()?),
        marker if marker.starts_with('@') => return None,
        patterns => (Marker::None, patterns),
    };
    fields.next()?; // key type
    let key_blob = STANDARD.decode(fields.next()?).ok()?;
    Some(Entry { marker, patterns: patterns.split(',').map(str::to_owned).collect(), key_blob })
}

/// `[host]:port` becomes `host:port`; everything else is unchanged.
fn display_pattern(pattern: &str) -> String {
    match pattern.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((host, port)) => format!("{host}{port}"),
        None => pattern.to_owned(),
    }
}

/// `ssh`'s host-pattern rule: some positive pattern matches and no negated
/// one does. Comparison ignores ASCII case, as `ssh` lowercases host names.
#[must_use]
pub fn host_matches(host: &str, patterns: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let mut positive = false;
    for raw in patterns {
        let (negated, pattern) = raw.strip_prefix('!').map_or((false, raw.as_str()), |rest| (true, rest));
        if !wildcard_match(pattern.to_ascii_lowercase().as_bytes(), host.as_bytes()) {
            continue;
        }
        if negated {
            return false;
        }
        positive = true;
    }
    positive
}

/// `*` matches any run of bytes, `?` any one byte.
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                backtrack = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match backtrack {
                Some((star, matched)) => {
                    backtrack = Some((star, matched + 1));
                    p = star + 1;
                    t = matched + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::testing::{certificate, ed25519_key, fresh_ed25519_key, known_hosts_line};

    const NOW: u64 = 1_800_000_000;

    fn parsed(key: &crate::agent::testing::TestKey) -> HostKey {
        HostKey::parse(&key.blob).expect("parses")
    }

    // ported: testKnownHosts_namesHostKeys
    #[test]
    fn a_key_is_named_by_the_lines_that_list_it() {
        let (a, b, c, d) = (fresh_ed25519_key(), fresh_ed25519_key(), fresh_ed25519_key(), fresh_ed25519_key());
        let hosts = KnownHosts::parse(
            &[
                "# comment".to_owned(),
                known_hosts_line("backup.example.org,192.0.2.7", &a.blob, ""),
                known_hosts_line("[git.example.org]:2222,*.example.org,!evil.example.org", &b.blob, ""),
                known_hosts_line("|1|c2FsdA==|aGFzaA==", &c.blob, ""),
                known_hosts_line("revoked.example.org", &d.blob, ""),
                known_hosts_line("*", &d.blob, "@revoked"),
                "garbage line".to_owned(),
                "@unknown-marker host ssh-ed25519 AAAA".to_owned(),
            ]
            .join("\n"),
        );
        assert_eq!(
            hosts.name(&parsed(&a), NOW),
            HostName::Named(vec!["backup.example.org".into(), "192.0.2.7".into()])
        );
        assert_eq!(hosts.name(&parsed(&b), NOW), HostName::Named(vec!["git.example.org:2222".into()]));
        assert_eq!(hosts.name(&parsed(&c), NOW), HostName::HashedOnly);
        assert_eq!(hosts.name(&parsed(&d), NOW), HostName::Unknown, "revoked");
        assert_eq!(hosts.name(&parsed(&fresh_ed25519_key()), NOW), HostName::Unknown, "unlisted");
    }

    #[test]
    fn a_certificate_without_a_trusted_ca_is_named_by_its_plain_key() {
        let (ca, host) = (ed25519_key(20), ed25519_key(21));
        let hosts = KnownHosts::parse(&known_hosts_line("backup.example.org", &host.blob, ""));
        let cert = certificate(&host, &ca, &["other.example.org"], 2, u64::MAX, None);
        assert_eq!(hosts.name(&parsed(&cert), NOW), HostName::Named(vec!["backup.example.org".into()]));
    }

    // ported: testKnownHosts_certificateAuthority
    #[test]
    fn a_ca_line_names_the_principals_it_covers_for_valid_host_certificates_only() {
        let (ca, other_ca, host) = (ed25519_key(22), ed25519_key(23), ed25519_key(24));
        let hosts =
            KnownHosts::parse(&known_hosts_line("*.example.org,!evil.example.org", &ca.blob, "@cert-authority"));
        let name = |cert: &crate::agent::testing::TestKey| hosts.name(&parsed(cert), NOW);
        let principals = ["backup.example.org", "evil.example.org", "other.net"];
        assert_eq!(
            name(&certificate(&host, &ca, &principals, 2, u64::MAX, None)),
            HostName::Named(vec!["backup.example.org".into()])
        );
        assert_eq!(name(&certificate(&host, &other_ca, &["backup.example.org"], 2, u64::MAX, None)), HostName::Unknown);
        assert_eq!(
            name(&certificate(&host, &ca, &["backup.example.org"], 1, u64::MAX, None)),
            HostName::Unknown,
            "user certificate"
        );
        assert_eq!(name(&certificate(&host, &ca, &["backup.example.org"], 2, 1, None)), HostName::Unknown, "expired");
    }

    #[test]
    fn a_revoked_ca_names_nothing() {
        let (ca, host) = (ed25519_key(25), ed25519_key(26));
        let text = [known_hosts_line("*", &ca.blob, "@cert-authority"), known_hosts_line("*", &ca.blob, "@revoked")]
            .join("\n");
        let cert = certificate(&host, &ca, &["a.example.org"], 2, u64::MAX, None);
        assert_eq!(KnownHosts::parse(&text).name(&parsed(&cert), NOW), HostName::Unknown);
    }

    // real OpenSSH output: a CA line and the certificate ssh-keygen made
    #[test]
    fn a_certificate_made_by_ssh_keygen_is_named_through_its_ca_line() {
        let ca_line = include_str!("../../testdata/ca_ed.pub");
        let ca = ca_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let hosts = KnownHosts::parse(&format!("@cert-authority *.example.org {ca}\n"));
        let blob = STANDARD
            .decode(include_str!("../../testdata/host_ed-cert.pub").split_whitespace().nth(1).expect("field"))
            .expect("base64");
        let key = HostKey::parse(&blob).expect("parses");
        assert_eq!(
            hosts.name(&key, NOW),
            HostName::Named(vec!["host.example.org".into(), "backup.example.org".into()])
        );
        assert_eq!(hosts.name(&key, 1_500_000_000), HostName::Unknown, "not yet valid");
    }

    // R9: a name that cannot be shown as it is is left out, not cleaned
    #[test]
    fn a_name_that_cannot_be_shown_as_it_is_is_left_out() {
        let key = fresh_ed25519_key();
        let long = "a".repeat(201);
        let text = [
            known_hosts_line("good.example.org,evil\u{202E}.org", &key.blob, ""),
            known_hosts_line(&long, &key.blob, ""),
        ]
        .join("\n");
        assert_eq!(KnownHosts::parse(&text).name(&parsed(&key), NOW), HostName::Named(vec!["good.example.org".into()]));
        let only_bad = KnownHosts::parse(&known_hosts_line("evil\u{202E}.org", &key.blob, ""));
        assert_eq!(only_bad.name(&parsed(&key), NOW), HostName::Unknown);
    }

    // ported: the case-insensitive host pattern test
    #[test]
    fn host_patterns_follow_ssh() {
        let patterns = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(host_matches("Backup.Example.ORG", &patterns(&["*.example.org"])));
        assert!(host_matches("a.example.org", &patterns(&["b.example.org", "*.example.org"])));
        assert!(!host_matches("evil.example.org", &patterns(&["*.example.org", "!evil.example.org"])));
        assert!(!host_matches("evil.example.org", &patterns(&["!evil.example.org", "*.example.org"])));
        assert!(!host_matches("a.example.org", &patterns(&["!a.example.org"])), "a negation alone matches nothing");
        assert!(host_matches("host1", &patterns(&["host?"])));
        assert!(!host_matches("host12", &patterns(&["host?"])));
        assert!(host_matches("anything", &patterns(&["*"])));
        assert!(host_matches("", &patterns(&["*"])));
        assert!(!host_matches("a.b", &patterns(&["a.b.c"])));
        assert!(host_matches("a.b.c", &patterns(&["a*b*c"])));
        assert!(!host_matches("a.b.d", &patterns(&["a*b*c"])));
    }

    #[test]
    fn files_are_read_and_too_big_ones_skipped() {
        let dir = std::env::temp_dir().join(format!("p-ledge-known-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = fresh_ed25519_key();
        let small = dir.join("small");
        std::fs::write(&small, known_hosts_line("small.example.org", &key.blob, "")).expect("write");
        let big = dir.join("big");
        let filler = format!("# {}\n", "x".repeat(1024));
        let mut text = filler.repeat(usize::try_from(MAX_FILE_BYTES).expect("fits") / filler.len() + 1);
        text.push_str(&known_hosts_line("big.example.org", &key.blob, ""));
        std::fs::write(&big, text).expect("write");
        let hosts = KnownHosts::load(&[dir.join("missing"), big, small]);
        assert_eq!(hosts.name(&parsed(&key), NOW), HostName::Named(vec!["small.example.org".into()]));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
