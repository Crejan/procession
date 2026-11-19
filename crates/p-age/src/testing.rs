//! Standing up a broker in-process, for the tests of other crates (feature `test-support`; not in a normal build).
//!
//! The site file has a format that changes (`SPEC.md`, "What `page load` reads"); a test that writes it by hand
//! breaks when it does. [`SiteBuilder`] writes the current form, so the tests move with the format:
//!
//! ```ignore
//! let site = SiteBuilder::new()
//!     .person(PersonSpec::new("jan").keys(confirmed, automatic, delegation, connection).groups(&["ops"]))
//!     .host("a.example", host_key)
//!     .build()?;
//! let started = BrokerSetup::new(site, broker_key_path, state_dir).start();
//! let broker = started.broker;
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use serde_json::{Value, json};

use crate::core::{Core, Settings, Trust};
use crate::crypto::{Crypto, SshCrypto};
use crate::log::MemoryLog;
use crate::net::{Broker, Clock, SystemClock, Timeouts};
use crate::site::Site;
use crate::tls;

/// A directory under which a test may bind a Unix socket: `PAGE_TEST_DIR` if set, else `/tmp/claude` if it is there
/// (some sandboxes allow sockets only under one directory), else the system's temporary directory.
#[must_use]
pub fn socket_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PAGE_TEST_DIR") {
        return PathBuf::from(dir);
    }
    let sandbox = PathBuf::from("/tmp/claude");
    if sandbox.is_dir() { sandbox } else { std::env::temp_dir() }
}

/// Write a certificate into the certificates directory the way the site's signing step does:
/// `<login>-<purpose>-cert.pub`, one line, mode 0644; the directory is made (0755) if it is not there. The broker
/// reads person, purpose and key from the certificate, never from the name. The path of the file.
///
/// # Panics
///
/// If the file cannot be written: this is for tests.
pub fn write_certificate(directory: &Path, login: &str, purpose: &str, line: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(directory).expect("certificates directory");
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).expect("certificates directory mode");
    let path = directory.join(format!("{login}-{purpose}{}", crate::certs::SUFFIX));
    std::fs::write(&path, format!("{}\n", line.trim_end())).expect("certificate file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("certificate file mode");
    path
}

/// One person of a site file.
#[derive(Debug, Clone)]
pub struct PersonSpec {
    name: String,
    enabled: bool,
    keys: Option<[String; 4]>,
    groups: Vec<String>,
}

impl PersonSpec {
    /// An active person; without `keys` the builder gives them four keys of its own.
    #[must_use]
    pub fn new(name: &str) -> PersonSpec {
        PersonSpec { name: name.to_owned(), enabled: true, keys: None, groups: Vec::new() }
    }

    /// The person's four keys, as public key lines (`<type> <base64> [comment]`): confirmed, automatic,
    /// delegation, connection.
    #[must_use]
    pub fn keys(mut self, confirmed: &str, automatic: &str, delegation: &str, connection: &str) -> PersonSpec {
        self.keys = Some([confirmed, automatic, delegation, connection].map(|k| k.trim().to_owned()));
        self
    }

    /// The groups the broker carries to the person's pledge.
    #[must_use]
    pub fn groups(mut self, groups: &[&str]) -> PersonSpec {
        self.groups = groups.iter().map(|g| (*g).to_owned()).collect();
        self
    }

    /// A person who is not active: in the site file, not in `active` of `directory.json`.
    #[must_use]
    pub fn disabled(mut self) -> PersonSpec {
        self.enabled = false;
        self
    }
}

/// A site file, written in the form the broker reads today.
#[derive(Debug, Clone, Default)]
pub struct SiteBuilder {
    persons: Vec<PersonSpec>,
    hosts: Vec<(String, String)>,
    members: Option<BTreeMap<String, Vec<String>>>,
}

impl SiteBuilder {
    #[must_use]
    pub fn new() -> SiteBuilder {
        SiteBuilder::default()
    }

    #[must_use]
    pub fn person(mut self, person: PersonSpec) -> SiteBuilder {
        self.persons.push(person);
        self
    }

    /// A host and its public host key line.
    #[must_use]
    pub fn host(mut self, name: &str, key: &str) -> SiteBuilder {
        self.hosts.push((name.to_owned(), key.trim().to_owned()));
        self
    }

    /// Who is in which group: `(group, logins)`. Without this call the file has no `members` (the directory's);
    /// with an empty slice it has an empty one (nobody is in any group).
    #[must_use]
    pub fn members(mut self, members: &[(&str, &[&str])]) -> SiteBuilder {
        self.members =
            Some(members.iter().map(|(g, l)| ((*g).to_owned(), l.iter().map(|s| (*s).to_owned()).collect())).collect());
        self
    }

    /// The four keys of a person who was given none: distinct, and not the ones tests make by hand (bytes 100 and up).
    fn dummy_keys(&self, index: usize) -> [String; 4] {
        let line = |n: u8| {
            let mut raw = vec![0, 0, 0, 11];
            raw.extend_from_slice(b"ssh-ed25519");
            raw.extend_from_slice(&[0, 0, 0, 32]);
            raw.extend_from_slice(&[n; 32]);
            format!("ssh-ed25519 {}", base64_of(&raw))
        };
        let base = u8::try_from(100 + index * 4).unwrap_or(250);
        [line(base), line(base + 1), line(base + 2), line(base + 3)]
    }

    /// The groups the site file names: every group any person is in, and every group `members` has.
    fn group_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.persons.iter().flat_map(|p| p.groups.clone()).collect();
        names.extend(self.members.iter().flat_map(|m| m.keys().cloned()));
        names.sort_unstable();
        names.dedup();
        names
    }

    /// The site file's JSON: persons with their four keys, hosts, and the groups the site names. Nothing about who is
    /// enabled or in which group: that is `directory.json` ([`SiteBuilder::directory_json`]).
    #[must_use]
    pub fn json(&self) -> String {
        let row = |key: &str| json!({"key": key, "verified_on": "2026-11-10"});
        let persons: Vec<Value> = self
            .persons
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let [confirmed, automatic, delegation, connection] =
                    p.keys.clone().unwrap_or_else(|| self.dummy_keys(i));
                json!({"name": p.name, "keys": {"confirmed": row(&confirmed), "automatic": row(&automatic),
                                                "delegation": row(&delegation), "connection": row(&connection)}})
            })
            .collect();
        let hosts: Vec<Value> = self.hosts.iter().map(|(n, k)| json!({"name": n, "key": k})).collect();
        json!({"v": 1, "persons": persons, "hosts": hosts, "groups": self.group_names()}).to_string()
    }

    /// `directory.json`, source `model`, made at `as_of` (UTC to the second): the active persons, and for each group
    /// the site names the persons in it (an explicit `members` call adds to what the persons' own groups give; a person
    /// who is not active is in no group).
    #[must_use]
    pub fn directory_json(&self, as_of: &str) -> String {
        let active: Vec<&str> = self.persons.iter().filter(|p| p.enabled).map(|p| p.name.as_str()).collect();
        let mut members: BTreeMap<String, Vec<String>> =
            self.group_names().into_iter().map(|g| (g, Vec::new())).collect();
        for p in self.persons.iter().filter(|p| p.enabled) {
            for g in &p.groups {
                members.entry(g.clone()).or_default().push(p.name.clone());
            }
        }
        for (g, logins) in self.members.iter().flatten() {
            let slot = members.entry(g.clone()).or_default();
            for l in logins {
                if active.contains(&l.as_str()) && !slot.contains(l) {
                    slot.push(l.clone());
                }
            }
        }
        json!({"v": 1, "source": "model", "as_of": as_of, "active": active, "members": members}).to_string()
    }

    /// The pair, read as the broker reads it, with `directory.json` made now.
    pub fn build(&self) -> Result<Site, crate::site::LoadError> {
        let now = std::time::SystemTime::now();
        Site::from_texts(&self.json(), &self.directory_json(&as_of(now)), now)
    }

    /// The site file on disk (mode 0644, as the broker's settings reader wants), for a test that starts `page`.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        write_0644(path, &self.json())
    }

    /// `directory.json` beside it.
    pub fn write_directory(&self, path: &Path) -> std::io::Result<()> {
        write_0644(path, &self.directory_json(&as_of(std::time::SystemTime::now())))
    }
}

fn write_0644(path: &Path, text: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

/// Standard base64 with padding (the test support has no base64 crate of its own).
fn base64_of(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0_u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A time as `directory.json` writes it.
fn as_of(t: std::time::SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    p_act::Timestamp::from_unix(secs).map_or_else(String::new, |t| t.to_string())
}

/// A broker over a site, with a register in `state_dir`, the broker's key and an in-memory log.
pub struct BrokerSetup {
    site: Site,
    broker_key: PathBuf,
    state_dir: PathBuf,
    settings: Settings,
    timeouts: Timeouts,
    clock: Arc<dyn Clock>,
    crypto: Option<Arc<dyn Crypto>>,
    certificates: Option<crate::certs::CertificateInput>,
    site_ca: Option<p_act::sign::PublicKey>,
}

/// A broker that was started.
pub struct TestBroker {
    pub broker: Arc<Broker>,
    /// What the broker logged, in memory.
    pub log: MemoryLog,
    /// The register file.
    pub register: PathBuf,
    /// The site CA the broker checks against: the one given, or the one the builder made.
    pub site_ca: p_act::sign::PublicKey,
}

/// Make a site CA in `dir` and issue the certificate (`broker`, no extension, valid until 2099) for `broker_key`, in
/// the place `ssh-keygen` finds it: `<broker_key>-cert.pub`. The CA's public key.
fn make_site_ca(dir: &Path, broker_key: &Path) -> p_act::sign::PublicKey {
    let ca = dir.join("test-site-ca");
    let keygen = |args: &[&str]| {
        let out = std::process::Command::new("ssh-keygen")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ssh-keygen");
        assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    if !ca.exists() {
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &ca.to_string_lossy()]);
    }
    let public = format!("{}.pub", broker_key.display());
    keygen(&[
        "-q",
        "-s",
        &ca.to_string_lossy(),
        "-I",
        "broker",
        "-n",
        "broker",
        "-V",
        "20200101Z:20990101Z",
        "-O",
        "clear",
        &public,
    ]);
    p_act::sign::PublicKey::read(&PathBuf::from(format!("{}.pub", ca.display()))).expect("the made site CA")
}

impl BrokerSetup {
    /// `broker_key` is the broker's private key file; its certificate (`broker`, from the site CA) is
    /// `<key>-cert.pub` beside it. `state_dir` holds the register; it is made private (0700).
    #[must_use]
    pub fn new(site: Site, broker_key: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> BrokerSetup {
        BrokerSetup {
            site,
            broker_key: broker_key.into(),
            state_dir: state_dir.into(),
            settings: Settings::default(),
            timeouts: Timeouts::default(),
            clock: Arc::new(SystemClock),
            crypto: None,
            certificates: None,
            site_ca: None,
        }
    }

    #[must_use]
    pub fn settings(mut self, settings: Settings) -> BrokerSetup {
        self.settings = settings;
        self
    }

    #[must_use]
    pub fn timeouts(mut self, timeouts: Timeouts) -> BrokerSetup {
        self.timeouts = timeouts;
        self
    }

    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> BrokerSetup {
        self.clock = clock;
        self
    }

    /// Replace the signature work (a test double, or the real one made slow).
    #[must_use]
    pub fn crypto(mut self, crypto: Arc<dyn Crypto>) -> BrokerSetup {
        self.crypto = Some(crypto);
        self
    }

    /// The site CA the broker's own certificate (`<broker_key>-cert.pub`) and the approval-key certificates are
    /// checked against. There is no broker that does not check its certificate: without this call (or
    /// [`BrokerSetup::certificates`], which names one too) the builder **makes a site CA** in the state directory and
    /// issues the broker's certificate for the key with it (the key's `.pub` must be there); [`TestBroker::site_ca`] is
    /// its public key.
    #[must_use]
    pub fn site_ca(mut self, site_ca: p_act::sign::PublicKey) -> BrokerSetup {
        self.site_ca = Some(site_ca);
        self
    }

    /// The certificates the broker carries to pledge: a directory of `*-cert.pub` files, checked against `site_ca`
    /// (see [`write_certificate`] for the files' names). Without this call none are carried.
    #[must_use]
    pub fn certificates(mut self, site_ca: p_act::sign::PublicKey, directory: impl Into<PathBuf>) -> BrokerSetup {
        self.site_ca = Some(site_ca.clone());
        self.certificates = Some(crate::certs::CertificateInput { site_ca, directory: directory.into() });
        self
    }

    /// Start it: the register is made if there is none (the first start is explicit in the real broker too), and
    /// read.
    ///
    /// # Panics
    ///
    /// If the state directory or the register cannot be made or read: this is for tests.
    #[must_use]
    pub fn start(self) -> TestBroker {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&self.state_dir).expect("state directory");
        std::fs::set_permissions(&self.state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("state directory mode");
        let register = self.state_dir.join("register.json");
        if !register.exists() {
            Core::init_state(&register).expect("the first register");
        }
        let site = Arc::new(self.site);
        let crypto = self.crypto.unwrap_or_else(|| Arc::new(SshCrypto::new(&self.broker_key)));
        let log = MemoryLog::default();
        let site_ca = match self.site_ca {
            Some(site_ca) => site_ca,
            None => make_site_ca(&self.state_dir, &self.broker_key),
        };
        let core = Core::new(
            Arc::clone(&site),
            self.settings,
            Core::read_state(&register).expect("the register"),
            Some(register.clone()),
            Arc::clone(&crypto),
            Box::new(log.clone()),
            Trust { site_ca: site_ca.clone(), now: self.clock.now() },
        );
        let core = match self.certificates {
            Some(input) => core.with_certificates(input, self.clock.now()),
            None => core,
        };
        let broker = Broker::new(core, crypto, site, self.clock, self.timeouts, 8);
        TestBroker { broker, log, register, site_ca }
    }
}

/// A TLS root and a server certificate signed by it, made in memory.
pub struct TestPki {
    /// The root, PEM: what a client trusts.
    pub root_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

impl TestPki {
    /// A new root and a server certificate for `names`.
    ///
    /// # Panics
    ///
    /// If the certificates cannot be made: this is for tests.
    #[must_use]
    pub fn new(names: &[&str]) -> TestPki {
        let ca_key = KeyPair::generate().expect("key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("root");
        let server_key = KeyPair::generate().expect("key");
        let server = CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
            .expect("params")
            .signed_by(&server_key, &Issuer::new(ca_params, &ca_key))
            .expect("server certificate");
        TestPki { root_pem: ca.pem(), server_cert_pem: server.pem(), server_key_pem: server_key.serialize_pem() }
    }

    /// The broker's TLS acceptor: TLS 1.3 only, as `page serve` builds it.
    ///
    /// # Panics
    ///
    /// If the configuration cannot be made.
    #[must_use]
    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        let config =
            tls::server_config(self.server_cert_pem.as_bytes(), self.server_key_pem.as_bytes()).expect("server config");
        tokio_rustls::TlsAcceptor::from(config)
    }

    /// A client configuration that trusts the root: TLS 1.3 only, as pledge's and a service's is.
    ///
    /// # Panics
    ///
    /// If the configuration cannot be made.
    #[must_use]
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        tls::client_config(self.root_pem.as_bytes()).expect("client config")
    }
}
