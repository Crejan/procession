//! Helpers for the tests of this crate.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory, removed when dropped. It is under `$TMPDIR`, or under
/// `/tmp/claude` when `$TMPDIR` does not let a Unix socket be bound there (the
/// sandbox of this development environment). The path is short, since a Unix
/// socket path is limited to about 100 bytes.
pub struct TestDir(PathBuf);

impl TestDir {
    /// A new empty directory named after `name`.
    ///
    /// # Panics
    ///
    /// If no directory can be made.
    #[must_use]
    pub fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!("pl-{}-{}-{name}", std::process::id() % 100_000, NEXT.fetch_add(1, Ordering::Relaxed));
        let mut candidates = vec![std::env::temp_dir()];
        candidates.push(PathBuf::from("/tmp/claude"));
        for base in candidates {
            let dir = base.join(&unique);
            if std::fs::create_dir_all(&dir).is_ok() && can_bind_socket(&dir) {
                return Self(dir);
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        panic!("no directory where a Unix socket can be bound");
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn can_bind_socket(dir: &Path) -> bool {
    let path = dir.join("probe.sock");
    let ok = std::os::unix::net::UnixListener::bind(&path).is_ok();
    let _ = std::fs::remove_file(path);
    ok
}

#[cfg(test)]
pub(crate) use rig::Rig;

/// A complete `Shared` with an in-process key holder, scripted dialogs and a
/// real record in a temporary directory.
#[cfg(test)]
mod rig {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread;

    use p_act::Timestamp;
    use serde_json::Value;

    use super::TestDir;
    use crate::agent_conn::serve;
    use crate::dialog::{Answer, Outcome, Scripted};
    use crate::holder::{HolderClient, KeyStore, KeyType, serve_holder};
    use crate::record::{Record, read_and_verify};
    use crate::shared::{KeyMeta, Parts, Shared};

    pub const NOW: i64 = 1_800_000_000;

    pub struct Rig {
        pub shared: Arc<Shared>,
        pub dialogs: Arc<Scripted>,
        pub dir: TestDir,
    }

    impl Rig {
        pub fn new(answers: impl IntoIterator<Item = Outcome<Answer>>) -> Self {
            let dir = TestDir::new("conn");
            let dialogs = Arc::new(Scripted::new(answers));
            let (reader_side, holder_side) = UnixStream::pair().expect("pair");
            let store = KeyStore::open(&dir.path().join("keys")).expect("store");
            let (input, output) = (holder_side.try_clone().expect("clone"), holder_side);
            thread::spawn(move || serve_holder(store, input, output));
            let holder = HolderClient::new(reader_side.try_clone().expect("clone"), reader_side);
            let (record, _) = Record::open(&dir.path().join("record.jsonl"), Timestamp::from_unix(NOW).expect("time"))
                .expect("record");
            let mut shared = Shared::new(Parts {
                holder: Box::new(holder),
                record,
                dialogs: Arc::clone(&dialogs) as Arc<dyn crate::dialog::Dialogs>,
                programs_file: dir.path().join("programs.json"),
                known_hosts: vec![dir.path().join("known_hosts")],
            })
            .expect("shared");
            shared.clock = Box::new(|| Timestamp::from_unix(NOW).expect("time"));
            Self { shared: Arc::new(shared), dialogs, dir }
        }

        pub fn key(&self, meta: KeyMeta) -> Vec<u8> {
            self.shared.create_key(KeyType::Ed25519, meta).expect("key").blob
        }

        pub fn shared_key(&self) -> Vec<u8> {
            self.key(KeyMeta {
                purpose: "shared".into(),
                program: None,
                use_: None,
                comment: "shared".into(),
                key_type: String::new(),
                created: String::new(),
            })
        }

        /// Connects as `program`; returns the connection's far end.
        pub fn connect(&self, program: &str) -> UnixStream {
            let (client, server) = UnixStream::pair().expect("pair");
            let shared = Arc::clone(&self.shared);
            let program = program.to_owned();
            thread::spawn(move || serve(&shared, server, Some(&program)));
            client
        }

        pub fn record(&self) -> Vec<Value> {
            let report = read_and_verify(&self.dir.path().join("record.jsonl")).expect("record");
            assert!(report.breaks.is_empty(), "{:?}", report.breaks);
            report.entries
        }

        pub fn shown(&self) -> Vec<String> {
            self.dialogs.shown.lock().expect("lock").clone()
        }
    }
}
