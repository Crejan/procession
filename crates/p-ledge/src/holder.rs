//! The key holder: the process that holds the keys and parses nothing
//! (`SPEC.md`, section 7).
//!
//! `pledge serve` (the reader) reads, checks and decides. It starts
//! `pledge key-holder` as a child and talks to it over the child's standard
//! input and output in a fixed binary format: an operation, then strings. The
//! holder receives *what to sign and with which key* and signs it; it never
//! looks inside the data. The reader never opens a key file. In this
//! development form (keys in files) both run as the same user, so the
//! separation protects nothing against that user; it is kept so that it is
//! there when the keys move into hardware.
//!
//! A key is a PKCS#8 file `<id>.pk8` (mode 0600) with a `<id>.meta` file the
//! holder stores and returns unread: the reader's description of the key's
//! purpose.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

use crate::agent::host_key::fingerprint;
use crate::agent::message::{self, read_message};
use crate::agent::wire::{Reader, put_mpint, put_string, put_u32, strings};
use crate::error::{Error, Result};

const OP_LIST: u8 = 1;
const OP_SIGN: u8 = 2;
const OP_CREATE: u8 = 3;
const OP_RETIRE: u8 = 4;
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

/// The key types pledge makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// `ssh-ed25519`
    Ed25519,
    /// `ecdsa-sha2-nistp256`
    EcdsaP256,
}

impl KeyType {
    /// The name used on the command line and in key files.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }

    /// The type from [`name`](Self::name).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }
}

enum Pair {
    Ed25519(Ed25519KeyPair),
    EcdsaP256(EcdsaKeyPair),
}

struct Stored {
    id: String,
    blob: Vec<u8>,
    meta: Vec<u8>,
    pair: Pair,
}

fn blob_of(pair: &Pair) -> Vec<u8> {
    match pair {
        Pair::Ed25519(pair) => strings(&[b"ssh-ed25519", pair.public_key().as_ref()]),
        Pair::EcdsaP256(pair) => strings(&[b"ecdsa-sha2-nistp256", b"nistp256", pair.public_key().as_ref()]),
    }
}

/// The keys in a directory, held by the key holder process.
pub struct KeyStore {
    dir: PathBuf,
    keys: Vec<Stored>,
}

impl KeyStore {
    /// Loads every `*.pk8` in `dir` (created, mode 0700, if missing). A file
    /// that is not a key of a supported type is an error: a key that cannot
    /// be loaded must not be silently absent.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], [`Error::Unsafe`] or [`Error::Corrupt`].
    pub fn open(dir: &Path) -> Result<Self> {
        crate::paths::ensure_private_dir(dir)?;
        let mut keys = Vec::new();
        let mut names: Vec<_> = fs::read_dir(dir)
            .map_err(Error::io(format!("reading {}", dir.display())))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "pk8"))
            .collect();
        names.sort();
        for path in names {
            crate::paths::check_private(&path, false)?;
            let der = fs::read(&path).map_err(Error::io(format!("reading {}", path.display())))?;
            let pair = load_pair(&der).ok_or_else(|| Error::Corrupt {
                path: path.clone(),
                problem: "not an Ed25519 or ECDSA P-256 PKCS#8 key".into(),
            })?;
            let id = path.file_stem().map_or_else(String::new, |s| s.to_string_lossy().into_owned());
            let meta = fs::read(path.with_extension("meta")).unwrap_or_default();
            keys.push(Stored { id, blob: blob_of(&pair), meta, pair });
        }
        Ok(Self { dir: dir.to_owned(), keys })
    }

    /// Makes a key of `key_type` with `meta` stored beside it. Returns its
    /// public blob.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the key cannot be generated, [`Error::Io`] if it
    /// cannot be written.
    pub fn create(&mut self, key_type: KeyType, meta: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let generated = match key_type {
            KeyType::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng).map(|d| d.as_ref().to_vec()),
            KeyType::EcdsaP256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map(|d| d.as_ref().to_vec())
            }
        };
        let der = generated.map_err(|_| Error::Holder("the system's random source failed".into()))?;
        let pair = load_pair(&der).ok_or_else(|| Error::Holder("a key just made does not load".into()))?;
        let blob = blob_of(&pair);
        let id = fingerprint(&blob).trim_start_matches("SHA256:").replace(['/', '+'], "_");
        write_private(&self.dir.join(format!("{id}.pk8")), &der)?;
        write_private(&self.dir.join(format!("{id}.meta")), meta)?;
        self.keys.push(Stored { id, blob: blob.clone(), meta: meta.to_vec(), pair });
        Ok(blob)
    }

    /// Deletes the key with this public blob.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if there is no such key, [`Error::Io`] if its files
    /// cannot be removed.
    pub fn retire(&mut self, blob: &[u8]) -> Result<()> {
        let index =
            self.keys.iter().position(|key| key.blob == blob).ok_or_else(|| Error::Holder("no such key".into()))?;
        let key = self.keys.remove(index);
        for extension in ["pk8", "meta"] {
            let path = self.dir.join(format!("{}.{extension}", key.id));
            fs::remove_file(&path).map_err(Error::io(format!("removing {}", path.display())))?;
        }
        Ok(())
    }

    /// Signs `data` with the key whose blob is `blob`; returns the signature
    /// blob (`string` type, `string` signature).
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if there is no such key or signing fails.
    pub fn sign(&self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let key = self.keys.iter().find(|key| key.blob == blob).ok_or_else(|| Error::Holder("no such key".into()))?;
        match &key.pair {
            Pair::Ed25519(pair) => Ok(strings(&[b"ssh-ed25519", pair.sign(data).as_ref()])),
            Pair::EcdsaP256(pair) => {
                let raw = pair.sign(&SystemRandom::new(), data).map_err(|_| Error::Holder("signing failed".into()))?;
                let (r, s) = raw.as_ref().split_at(32);
                let mut body = Vec::new();
                put_mpint(&mut body, r);
                put_mpint(&mut body, s);
                Ok(strings(&[b"ecdsa-sha2-nistp256", &body]))
            }
        }
    }

    /// Every key: public blob and the stored description.
    #[must_use]
    pub fn list(&self) -> Vec<(&[u8], &[u8])> {
        self.keys.iter().map(|key| (key.blob.as_slice(), key.meta.as_slice())).collect()
    }
}

fn load_pair(der: &[u8]) -> Option<Pair> {
    if let Ok(pair) = Ed25519KeyPair::from_pkcs8(der) {
        return Some(Pair::Ed25519(pair));
    }
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new()).ok().map(Pair::EcdsaP256)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(Error::io(format!("creating {}", path.display())))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(Error::io(format!("writing {}", path.display())))
}

/// Serves the holder's side until `input` ends. Everything it reads is a
/// fixed format of operations and strings; none of it is interpreted.
///
/// # Errors
///
/// [`Error::Holder`] if the connection to the reader breaks.
pub fn serve_holder<R: Read, W: Write>(mut store: KeyStore, mut input: R, mut output: W) -> Result<()> {
    loop {
        let message = match read_message(&mut input) {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(()),
            Err(e) => return Err(Error::Holder(e.to_string())),
        };
        let (status, payload) = match answer(&mut store, &message) {
            Ok(payload) => (STATUS_OK, payload),
            Err(e) => (STATUS_ERROR, e.to_string().into_bytes()),
        };
        output
            .write_all(&message::frame(status, &payload))
            .and_then(|()| output.flush())
            .map_err(|e| Error::Holder(e.to_string()))?;
    }
}

fn answer(store: &mut KeyStore, message: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error::Holder("bad operation".into());
    let (&op, body) = message.split_first().ok_or_else(bad)?;
    let mut reader = Reader::new(body);
    let mut out = Vec::new();
    match op {
        OP_LIST => {
            let list = store.list();
            put_u32(&mut out, u32::try_from(list.len()).map_err(|_| bad())?);
            for (blob, meta) in list {
                put_string(&mut out, blob);
                put_string(&mut out, meta);
            }
        }
        OP_SIGN => {
            let (blob, data) = (reader.string().ok_or_else(bad)?, reader.string().ok_or_else(bad)?);
            put_string(&mut out, &store.sign(blob, data)?);
        }
        OP_CREATE => {
            let name = reader.utf8().ok_or_else(bad)?;
            let meta = reader.string().ok_or_else(bad)?;
            let key_type = KeyType::from_name(name).ok_or_else(bad)?;
            put_string(&mut out, &store.create(key_type, meta)?);
        }
        OP_RETIRE => store.retire(reader.string().ok_or_else(bad)?)?,
        _ => return Err(bad()),
    }
    Ok(out)
}

/// The reader's end: asks the holder to list, sign, make and delete keys.
pub struct HolderClient<R, W> {
    input: R,
    output: W,
    child: Option<Child>,
}

/// A client of a holder started as a child process.
pub type ChildHolder = HolderClient<ChildStdout, ChildStdin>;

/// One key as the holder lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldKey {
    /// The public key blob.
    pub blob: Vec<u8>,
    /// The description stored with it, unread by the holder.
    pub meta: Vec<u8>,
}

impl ChildHolder {
    /// Starts `program key-holder --keys-dir <dir>` as a child.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be started.
    pub fn spawn(program: &Path, keys_dir: &Path) -> Result<Self> {
        let mut child = Command::new(program)
            .arg("key-holder")
            .arg("--keys-dir")
            .arg(keys_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(Error::io(format!("starting {}", program.display())))?;
        let output = child.stdin.take().ok_or_else(|| Error::Holder("no pipe".into()))?;
        let input = child.stdout.take().ok_or_else(|| Error::Holder("no pipe".into()))?;
        Ok(HolderClient { input, output, child: Some(child) })
    }
}

impl<R: Read, W: Write> HolderClient<R, W> {
    /// A client over any pair of streams (a test wires one to an in-process
    /// holder).
    pub fn new(input: R, output: W) -> Self {
        Self { input, output, child: None }
    }

    fn call(&mut self, op: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let failed = |e: &dyn std::fmt::Display| Error::Holder(e.to_string());
        self.output
            .write_all(&message::frame(op, payload))
            .and_then(|()| self.output.flush())
            .map_err(|e| failed(&e))?;
        let reply =
            read_message(&mut self.input).map_err(|e| failed(&e))?.ok_or_else(|| failed(&"the holder has gone"))?;
        match reply.split_first() {
            Some((&STATUS_OK, body)) => Ok(body.to_vec()),
            Some((&STATUS_ERROR, body)) => Err(Error::Holder(String::from_utf8_lossy(body).into_owned())),
            _ => Err(failed(&"empty reply")),
        }
    }

    /// Every key held.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder fails or answers nonsense.
    pub fn list(&mut self) -> Result<Vec<HeldKey>> {
        let body = self.call(OP_LIST, &[])?;
        let bad = || Error::Holder("bad list".into());
        let mut reader = Reader::new(&body);
        let count = reader.u32().ok_or_else(bad)?;
        (0..count)
            .map(|_| {
                let blob = reader.string().ok_or_else(bad)?.to_vec();
                Ok(HeldKey { blob, meta: reader.string().ok_or_else(bad)?.to_vec() })
            })
            .collect()
    }

    /// The signature blob over `data` by the key `blob`.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot sign.
    pub fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let body = self.call(OP_SIGN, &strings(&[blob, data]))?;
        Reader::new(&body).string().map(<[u8]>::to_vec).ok_or_else(|| Error::Holder("bad signature reply".into()))
    }

    /// Makes a key; returns its public blob.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot make it.
    pub fn create(&mut self, key_type: KeyType, meta: &[u8]) -> Result<Vec<u8>> {
        let body = self.call(OP_CREATE, &strings(&[key_type.name().as_bytes(), meta]))?;
        Reader::new(&body).string().map(<[u8]>::to_vec).ok_or_else(|| Error::Holder("bad create reply".into()))
    }

    /// Deletes a key.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if there is no such key.
    pub fn retire(&mut self, blob: &[u8]) -> Result<()> {
        self.call(OP_RETIRE, &strings(&[blob])).map(drop)
    }
}

/// What the reader needs from a key holder; [`HolderClient`] is the one that
/// talks to a process, and a test can supply another.
pub trait KeyHolder: Send {
    /// Every key held.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder fails.
    fn list(&mut self) -> Result<Vec<HeldKey>>;
    /// The signature blob over `data` by the key `blob`.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot sign.
    fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    /// Makes a key; returns its public blob.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the holder cannot make it.
    fn create(&mut self, key_type: KeyType, meta: &[u8]) -> Result<Vec<u8>>;
    /// Deletes a key.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if there is no such key.
    fn retire(&mut self, blob: &[u8]) -> Result<()>;
}

impl<R: Read + Send, W: Write + Send> KeyHolder for HolderClient<R, W> {
    fn list(&mut self) -> Result<Vec<HeldKey>> {
        HolderClient::list(self)
    }
    fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        HolderClient::sign(self, blob, data)
    }
    fn create(&mut self, key_type: KeyType, meta: &[u8]) -> Result<Vec<u8>> {
        HolderClient::create(self, key_type, meta)
    }
    fn retire(&mut self, blob: &[u8]) -> Result<()> {
        HolderClient::retire(self, blob)
    }
}

impl<R, W> Drop for HolderClient<R, W> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Dropping the pipes ends the holder's input; do not leave a zombie.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use ring::signature::{ED25519, UnparsedPublicKey};

    use super::*;
    use crate::agent::host_key::HostKey;
    use crate::testing::TestDir;

    type Client = HolderClient<UnixStream, UnixStream>;

    /// A client wired to a holder running in a thread, over a socket pair.
    fn start(dir: &Path) -> Client {
        let (reader_side, holder_side) = UnixStream::pair().expect("pair");
        let store = KeyStore::open(dir).expect("store");
        let (input, output) = (holder_side.try_clone().expect("clone"), holder_side);
        thread::spawn(move || serve_holder(store, input, output));
        HolderClient::new(reader_side.try_clone().expect("clone"), reader_side)
    }

    #[test]
    fn a_key_is_made_listed_signs_and_is_retired() {
        let dir = TestDir::new("holder");
        let mut client = start(&dir.path().join("keys"));
        assert!(client.list().expect("list").is_empty());
        let blob = client.create(KeyType::Ed25519, b"{\"purpose\":\"shared\"}").expect("create");
        let listed = client.list().expect("list");
        assert_eq!(listed, [HeldKey { blob: blob.clone(), meta: b"{\"purpose\":\"shared\"}".to_vec() }]);
        let signature = client.sign(&blob, b"hello").expect("sign");
        let mut reader = Reader::new(&signature);
        assert_eq!((reader.utf8(), reader.remaining()), (Some("ssh-ed25519"), 4 + 64));
        let public = &blob[4 + 11 + 4..];
        UnparsedPublicKey::new(&ED25519, public).verify(b"hello", reader.string().expect("sig")).expect("verifies");
        client.retire(&blob).expect("retire");
        assert!(client.list().expect("list").is_empty());
        assert!(client.sign(&blob, b"x").is_err());
        assert!(client.retire(&blob).is_err());
    }

    #[test]
    fn an_ecdsa_key_signs_what_the_host_key_code_verifies() {
        let dir = TestDir::new("holder-p256");
        let mut client = start(&dir.path().join("keys"));
        let blob = client.create(KeyType::EcdsaP256, b"").expect("create");
        // The same code that verifies a host's signature verifies ours.
        let key = HostKey::parse(&blob).expect("parses as a P-256 key");
        let signature = client.sign(&blob, b"data").expect("sign");
        assert!(key.verify(&signature, b"data"));
        assert!(!key.verify(&signature, b"other"));
    }

    #[test]
    fn keys_survive_a_restart_and_are_private_files() {
        let dir = TestDir::new("holder-restart");
        let keys = dir.path().join("keys");
        let blob = start(&keys).create(KeyType::Ed25519, b"m").expect("create");
        thread::sleep(std::time::Duration::from_millis(50));
        let again = start(&keys).list().expect("list");
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].blob, blob);
        for entry in fs::read_dir(&keys).expect("dir") {
            let mode =
                std::os::unix::fs::PermissionsExt::mode(&entry.expect("entry").metadata().expect("meta").permissions());
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn a_file_that_is_not_a_key_stops_the_holder_from_starting() {
        let dir = TestDir::new("holder-corrupt");
        let keys = dir.path().join("keys");
        crate::paths::ensure_private_dir(&keys).expect("dir");
        write_private(&keys.join("bad.pk8"), b"garbage").expect("write");
        assert!(matches!(KeyStore::open(&keys), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn garbage_from_the_reader_is_an_error_answer_not_a_crash() {
        let dir = TestDir::new("holder-garbage");
        let mut client = start(&dir.path().join("keys"));
        assert!(client.call(99, b"x").is_err());
        assert!(client.call(OP_SIGN, &[0xFF; 3]).is_err());
        assert!(client.list().is_ok(), "still serving");
    }
}
