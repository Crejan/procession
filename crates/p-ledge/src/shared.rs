//! The state `pledge serve` shares between its connections: the keys it
//! knows by their public parts, the rules about programs, the record, the
//! dialogs. It belongs to the reader process; it holds no private key.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use p_act::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::agent::host_key::fingerprint;
use crate::answers::Answers;
use crate::approvals::Approvals;
use crate::config::Config;
use crate::delegations::Delegations;
use crate::dialog::Dialogs;
use crate::error::{Error, Result};
use crate::holder::{KeyHolder, KeyType};
use crate::mute::Muter;
use crate::policy::{Policy, Purpose, Standing};
use crate::record::Record;

/// How long a dialog for a login waits (`SPEC.md`, section 5).
pub const LOGIN_DIALOG: Duration = Duration::from_secs(60);

/// What the reader knows about a key, from the description stored beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMeta {
    /// `shared` or `bound`.
    pub purpose: String,
    /// For a bound key: the program it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// For a bound key: the login it is for, `login <user>@<host>`.
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// The comment `ssh-add -l` shows.
    #[serde(default)]
    pub comment: String,
    /// The key type, as [`KeyType::name`].
    #[serde(default)]
    pub key_type: String,
    /// When it was made.
    #[serde(default)]
    pub created: String,
}

/// A key as the reader knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The public key blob.
    pub blob: Vec<u8>,
    /// Its fingerprint, `SHA256:...`.
    pub fingerprint: String,
    /// Its description; `None` if the stored one cannot be read, in which
    /// case the key is offered to nobody.
    pub meta: Option<KeyMeta>,
}

impl KeyInfo {
    /// The line `ssh-keygen` would print for the public key.
    #[must_use]
    pub fn public_line(&self) -> String {
        use base64::Engine as _;
        let mut reader = crate::agent::wire::Reader::new(&self.blob);
        let key_type = reader.utf8().unwrap_or("?");
        let comment = self.meta.as_ref().map_or("", |m| m.comment.as_str());
        format!("{key_type} {} {comment}", base64::engine::general_purpose::STANDARD.encode(&self.blob))
            .trim_end()
            .to_owned()
    }

    fn purpose(&self) -> Option<Purpose> {
        let meta = self.meta.as_ref()?;
        match (meta.purpose.as_str(), &meta.program, &meta.use_) {
            ("shared", _, _) => Some(Purpose::Shared),
            ("bound", Some(program), Some(use_)) => {
                Some(Purpose::Bound { program: program.clone(), use_: use_.clone() })
            }
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct ProgramsFile {
    programs: std::collections::BTreeMap<String, String>,
}

/// Everything the connections share.
pub struct Shared {
    /// The key holder.
    pub holder: Mutex<Box<dyn KeyHolder>>,
    /// The keys, as last listed by the holder.
    pub keys: RwLock<Vec<KeyInfo>>,
    /// The rules about programs.
    pub policy: Mutex<Policy>,
    /// The record.
    pub record: Mutex<Record>,
    /// The dialogs.
    pub dialogs: Arc<dyn Dialogs>,
    /// Who is muted.
    pub muter: Mutex<Muter>,
    /// Where decisions about programs are kept.
    pub programs_file: PathBuf,
    /// The `known_hosts` files that name verified hosts.
    pub known_hosts: Vec<PathBuf>,
    /// How long a login's dialog waits.
    pub dialog_timeout: Duration,
    /// The clock.
    pub clock: Box<dyn Fn() -> Timestamp + Send + Sync>,
    /// Requests, delegations, answers.
    pub approvals: Approvals,
    /// Where private temporary directories are made (for issuing): a directory only the person can enter.
    pub work_dir: PathBuf,
    state_dir: PathBuf,
    /// What pledge keeps of the broker: restrictions, certificates, its own withdrawals.
    pub broker_state: crate::broker_state::BrokerState,
    /// The connection to the broker, if one is configured and started.
    pub link: std::sync::OnceLock<Arc<crate::broker_link::BrokerLink>>,
}

/// What a caller gives [`Shared::new`].
pub struct Parts {
    /// The key holder.
    pub holder: Box<dyn KeyHolder>,
    /// The open record.
    pub record: Record,
    /// The dialogs.
    pub dialogs: Arc<dyn Dialogs>,
    /// Where decisions about programs are kept.
    pub programs_file: PathBuf,
    /// The `known_hosts` files.
    pub known_hosts: Vec<PathBuf>,
    /// The state directory: `config.json`, `delegations.json`, `answers.jsonl`.
    pub state_dir: PathBuf,
    /// Where private temporary directories are made.
    pub work_dir: PathBuf,
}

/// The current time from the system clock.
///
/// # Panics
///
/// If the clock is outside years 0 to 9999.
#[must_use]
pub fn system_clock() -> Timestamp {
    Timestamp::now().expect("the clock is within years 0 to 9999")
}

impl Shared {
    /// Builds the state: lists the keys, loads the remembered decisions.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot list its keys, [`Error::Corrupt`]
    /// if the remembered decisions cannot be read.
    pub fn new(parts: Parts) -> Result<Self> {
        let config = Config::load(&parts.state_dir.join("config.json"))?;
        let now = system_clock().unix();
        let approvals = Approvals::new(
            config,
            Delegations::open(parts.state_dir.join("delegations.json"))?,
            Answers::open(&parts.state_dir.join("answers.jsonl"), now)?,
        );
        let broker_state =
            crate::broker_state::BrokerState::open_unverified(parts.state_dir.join("broker-state.json"))?;
        let shared = Self {
            holder: Mutex::new(parts.holder),
            keys: RwLock::new(Vec::new()),
            policy: Mutex::new(Policy::default()),
            record: Mutex::new(parts.record),
            dialogs: parts.dialogs,
            muter: Mutex::new(Muter::default()),
            programs_file: parts.programs_file,
            known_hosts: parts.known_hosts,
            dialog_timeout: LOGIN_DIALOG,
            clock: Box::new(system_clock),
            approvals,
            work_dir: parts.work_dir,
            state_dir: parts.state_dir.clone(),
            broker_state,
            link: std::sync::OnceLock::new(),
        };
        shared.load_programs()?;
        shared.reload_keys()?;
        shared.reverify_certificates()?;
        Ok(shared)
    }

    /// Judges again the certificates kept from before: with a broker configured, each must still verify
    /// against the site CA for its own key; without one, none is kept.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the file cannot be rewritten.
    pub fn reverify_certificates(&self) -> Result<()> {
        let broker = self.approvals.config.broker.as_ref();
        let person = self.approvals.config.person.clone();
        let ca = broker.and_then(|b| p_act::sign::PublicKey::parse(&b.site_ca).ok());
        let now = self.now().unix();
        self.broker_state.reverify(&|line| {
            let (person, ca) = (person.as_deref()?, ca.as_ref()?);
            crate::certs::check(self, line, person, ca, now).ok().map(|good| good.role.to_owned())
        })
    }

    /// The connection to the broker, if there is one.
    #[must_use]
    pub fn link(&self) -> Option<Arc<crate::broker_link::BrokerLink>> {
        self.link.get().cloned()
    }

    /// The key made for `purpose` (`confirmed`, `automatic`, `delegation`), if there is one.
    #[must_use]
    pub fn key_with_purpose(&self, purpose: &str) -> Option<KeyInfo> {
        self.keys.read().ok()?.iter().find(|key| key.meta.as_ref().is_some_and(|m| m.purpose == purpose)).cloned()
    }

    /// The key with this fingerprint.
    #[must_use]
    pub fn key_by_fingerprint(&self, fingerprint: &str) -> Option<KeyInfo> {
        self.keys.read().ok()?.iter().find(|key| key.fingerprint == fingerprint).cloned()
    }

    /// At start: every `received` entry without an answer is a request pledge was
    /// holding when it went down. Each gets an entry, result `lost`, with when it
    /// was received and the time of the last entry before this start (the latest
    /// pledge is known to have been up). Call before the `started` event.
    pub fn settle_lost(&self) {
        let Ok(report) = crate::record::read_and_verify(&self.state_dir.join("record.jsonl")) else { return };
        let answered: std::collections::HashSet<&str> = report
            .entries
            .iter()
            .filter(|e| e["type"] == "request")
            .filter_map(|e| e["request_hash"].as_str())
            .collect();
        let last_seen = report.entries.last().and_then(|e| e["time"].as_str()).map(str::to_owned);
        for received in report.entries.iter().filter(|e| e["type"] == "received") {
            let Some(hash) = received["request_hash"].as_str().filter(|h| !answered.contains(h)) else { continue };
            let entry = json!({
                "type": "request", "result": "lost", "request_hash": hash,
                "received": received["time"], "last_entry_before_start": last_seen,
                "call": received["call"], "person": received["person"], "delegation": received["delegation"], "service": received["service"],
            });
            if let Err(e) = self.append(entry) {
                eprintln!("pledge: could not record a lost request: {e}");
            }
        }
    }

    /// The time now.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        (self.clock)()
    }

    /// Lists the keys again and declares their purposes to the policy.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot list.
    pub fn reload_keys(&self) -> Result<()> {
        let held = self.holder.lock().map_err(|_| Error::Holder("poisoned".into()))?.list()?;
        let keys: Vec<KeyInfo> = held
            .into_iter()
            .map(|key| KeyInfo {
                fingerprint: fingerprint(&key.blob),
                meta: serde_json::from_slice(&key.meta).ok(),
                blob: key.blob,
            })
            .collect();
        let mut policy = self.policy.lock().map_err(|_| Error::Holder("poisoned".into()))?;
        let previous: Vec<String> =
            self.keys.read().map(|k| k.iter().map(|k| k.fingerprint.clone()).collect()).unwrap_or_default();
        for old in previous {
            policy.remove_purpose(&old);
        }
        for key in &keys {
            if let Some(purpose) = key.purpose() {
                policy.set_purpose(key.fingerprint.clone(), purpose);
            }
        }
        drop(policy);
        *self.keys.write().map_err(|_| Error::Holder("poisoned".into()))? = keys;
        Ok(())
    }

    /// Makes a key with `meta`.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if it cannot be made.
    pub fn create_key(&self, key_type: KeyType, mut meta: KeyMeta) -> Result<KeyInfo> {
        meta.key_type = key_type.name().to_owned();
        meta.created = self.now().to_string();
        let bytes = serde_json::to_vec(&meta).map_err(|e| Error::Holder(e.to_string()))?;
        let blob = self.holder.lock().map_err(|_| Error::Holder("poisoned".into()))?.create(key_type, &bytes)?;
        self.reload_keys()?;
        let keys = self.keys.read().map_err(|_| Error::Holder("poisoned".into()))?;
        keys.iter()
            .find(|key| key.blob == blob)
            .cloned()
            .ok_or_else(|| Error::Holder("the new key is not listed".into()))
    }

    /// Deletes the key with this fingerprint.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] if there is none, [`Error::Holder`] if the holder fails.
    pub fn retire_key(&self, fingerprint: &str) -> Result<KeyInfo> {
        let key = self
            .keys
            .read()
            .map_err(|_| Error::Holder("poisoned".into()))?
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .cloned()
            .ok_or_else(|| Error::Refused("no such key".into()))?;
        self.holder.lock().map_err(|_| Error::Holder("poisoned".into()))?.retire(&key.blob)?;
        self.reload_keys()?;
        Ok(key)
    }

    /// Records an event. A failure is reported on standard error: events
    /// describe what already happened; they do not release anything.
    pub fn event(&self, name: &str, members: Value) {
        let mut entry = json!({"type": "event", "event": name});
        if let (Value::Object(entry), Value::Object(members)) = (&mut entry, members) {
            entry.extend(members);
        }
        if let Err(e) = self.append(entry) {
            eprintln!("pledge: could not record the event {name}: {e}");
        }
    }

    /// Appends an entry to the record, flushed.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be written; then nothing may be signed.
    pub fn append(&self, entry: Value) -> Result<()> {
        let now = self.now();
        self.record.lock().map_err(|_| Error::Refused("the record's lock is poisoned".into()))?.append(now, entry)
    }

    pub(crate) fn load_programs(&self) -> Result<()> {
        let bytes = match fs::read(&self.programs_file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::io(format!("reading {}", self.programs_file.display()))(e)),
        };
        let file: ProgramsFile = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Corrupt { path: self.programs_file.clone(), problem: e.to_string() })?;
        let mut policy = self.policy.lock().map_err(|_| Error::Refused("poisoned".into()))?;
        // Everything read back is checked before any of it counts: a file with a name that breaks the rule, or a
        // standing that is not one of the two, is refused whole, like a damaged one. Nothing of it is repeated.
        let corrupt = |problem: &str| Error::Corrupt { path: self.programs_file.clone(), problem: problem.to_owned() };
        for (program, standing) in &file.programs {
            if program.is_empty() || !crate::agent::text::is_showable(program) {
                return Err(corrupt("a program name in `programs` is empty, too long or holds a control character"));
            }
            if !matches!(standing.as_str(), "admitted" | "blocked") {
                return Err(corrupt("a standing in `programs` is neither admitted nor blocked"));
            }
        }
        for (program, standing) in file.programs {
            policy.set_standing(program, if standing == "admitted" { Standing::Admitted } else { Standing::Blocked });
        }
        Ok(())
    }

    /// Writes the decisions about programs (to a temporary file, then renamed).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if they cannot be written.
    pub fn save_programs(&self) -> Result<()> {
        let programs = self
            .policy
            .lock()
            .map_err(|_| Error::Refused("poisoned".into()))?
            .programs()
            .map(|(program, standing)| {
                (program.to_owned(), if standing == Standing::Admitted { "admitted" } else { "blocked" }.to_owned())
            })
            .collect();
        let bytes = serde_json::to_vec_pretty(&ProgramsFile { programs }).map_err(|e| Error::Refused(e.to_string()))?;
        let temp = self.programs_file.with_extension("json.new");
        let context = format!("writing {}", self.programs_file.display());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(Error::io(context.clone()))?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(Error::io(context.clone()))?;
        fs::rename(&temp, &self.programs_file).map_err(Error::io(context))
    }
}
