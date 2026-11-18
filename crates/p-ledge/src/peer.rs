//! What was read about the connecting process of `service.sock`, as the record holds it. Reading it is
//! `p_act::peer`; in the development form a program is identified by the path of the connecting process
//! at the time of the question (`SPEC.md`, section 8): the form protects nothing and says so.

/// Information, not a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The user of the connecting account.
    pub uid: u32,
    /// The process, when the platform says (0 or absent across pid namespaces).
    pub pid: Option<i32>,
    /// The program's path, when it could be read (Linux `/proc/<pid>/exe`, macOS `proc_pidpath`).
    pub program: Option<String>,
}

impl Seen {
    /// What the record keeps of `peer`.
    #[must_use]
    pub fn of(peer: &p_act::peer::Peer) -> Self {
        Self { uid: peer.uid(), pid: peer.pid(), program: peer.program().map(str::to_owned) }
    }
}
