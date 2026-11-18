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

use crate::core::{Core, Settings};
use crate::crypto::{Crypto, SshCrypto};
use crate::log::MemoryLog;
use crate::net::{Broker, Clock, SystemClock, Timeouts};
use crate::site::{Site, SiteError};
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
    /// An enabled person without keys.
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

    /// A person who is not enabled (the site file has no keys for one).
    #[must_use]
    pub fn disabled(mut self) -> PersonSpec {
        self.enabled = false;
        self.keys = None;
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

    /// The file's JSON.
    #[must_use]
    pub fn json(&self) -> String {
        let row = |key: &str| json!({"key": key, "verified_on": "2026-11-10"});
        let persons: Vec<Value> = self
            .persons
            .iter()
            .map(|p| {
                let mut o = json!({"name": p.name, "enabled": p.enabled, "groups": p.groups});
                if let Some([confirmed, automatic, delegation, connection]) = &p.keys {
                    o["keys"] = json!({"confirmed": row(confirmed), "automatic": row(automatic),
                                       "delegation": row(delegation), "connection": row(connection)});
                }
                o
            })
            .collect();
        let hosts: Vec<Value> = self.hosts.iter().map(|(n, k)| json!({"name": n, "key": k})).collect();
        let mut file = json!({"v": 1, "persons": persons, "hosts": hosts});
        if let Some(members) = &self.members {
            file["members"] = json!(members);
        }
        file.to_string()
    }

    /// The site, read as the broker reads it.
    pub fn build(&self) -> Result<Site, SiteError> {
        Site::from_json(&self.json())
    }

    /// The file on disk (mode 0644, as the broker's settings reader wants), for a test that starts `page`.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, self.json())?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
    }
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

    /// Check the broker's own certificate against the site CA, as `page serve` does: a broker without a valid one issues
    /// no clearance and no standing, and its status says so. Without this call (or [`BrokerSetup::certificates`]) it is
    /// not checked.
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
        let core = Core::new(
            Arc::clone(&site),
            self.settings,
            Core::read_state(&register).expect("the register"),
            Some(register.clone()),
            Arc::clone(&crypto),
            Box::new(log.clone()),
        );
        let core = match self.site_ca {
            Some(site_ca) => core.with_broker_certificate_check(site_ca, self.clock.now()),
            None => core,
        };
        let core = match self.certificates {
            Some(input) => core.with_certificates(input, self.clock.now()),
            None => core,
        };
        let broker = Broker::new(core, crypto, site, self.clock, self.timeouts, 8);
        TestBroker { broker, log, register }
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
