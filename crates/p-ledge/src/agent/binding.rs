//! `session-bind@openssh.com`: the client proves, with the server's own
//! signature over the session identifier, that this SSH agent connection
//! belongs to an SSH session with the host holding a given key. And the
//! state of one connection that follows from the binds it made.

use super::Refusal;
use super::host_key::HostKey;
use super::sign_content::{MAX_SESSION_ID_LEN, SignContent};
use super::wire::Reader;

/// The extension's name.
pub const EXTENSION_NAME: &str = "session-bind@openssh.com";

/// Most binds one connection may make.
pub const MAX_BINDINGS: usize = 16;

const VERIFIABLE_SIGNATURE_TYPES: [&str; 5] =
    ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "rsa-sha2-256", "rsa-sha2-512"];

/// A bind whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The host's key.
    pub host_key: HostKey,
    /// The SSH session's identifier.
    pub session_id: Vec<u8>,
    /// True when the client binds the connection for agent forwarding to
    /// that host, rather than for authenticating to it.
    pub is_forwarding: bool,
}

/// What a bind's body turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Well-formed, and the signature verifies.
    Verified(SessionBinding),
    /// Well-formed, but with a host key or signature algorithm the SSH agent
    /// cannot check (DSA, RSA below 2048 bits, SHA-1 RSA, P-521, ...). The
    /// host stays unknown.
    Unverifiable { session_id: Vec<u8>, is_forwarding: bool },
    /// Malformed, or the signature does not verify.
    Invalid,
}

impl SessionBinding {
    /// Parses the extension body (what follows the extension's name):
    ///
    /// ```text
    /// string   hostkey
    /// string   session identifier
    /// string   signature
    /// boolean  is_forwarding
    /// ```
    ///
    /// [`Parsed::Invalid`] unless every field parses, the boolean is 0 or 1
    /// and nothing trails; then [`Parsed::Unverifiable`] if the key or the
    /// signature algorithm is one the SSH agent cannot check, else
    /// [`Parsed::Verified`] only if the signature verifies.
    #[must_use]
    pub fn parse(body: &[u8]) -> Parsed {
        let mut reader = Reader::new(body);
        let (Some(key_blob), Some(session_id), Some(signature), Some(forwarding)) =
            (reader.string(), reader.string(), reader.string(), reader.u8())
        else {
            return Parsed::Invalid;
        };
        if !(1..=MAX_SESSION_ID_LEN).contains(&session_id.len()) || forwarding > 1 || reader.remaining() != 0 {
            return Parsed::Invalid;
        }
        let is_forwarding = forwarding == 1;
        let session_id = session_id.to_vec();
        let signature_type = Reader::new(signature).utf8().filter(|name| VERIFIABLE_SIGNATURE_TYPES.contains(name));
        let (Some(_), Some(host_key)) = (signature_type, HostKey::parse(key_blob)) else {
            return Parsed::Unverifiable { session_id, is_forwarding };
        };
        if host_key.verify(signature, &session_id) {
            Parsed::Verified(Self { host_key, session_id, is_forwarding })
        } else {
            Parsed::Invalid
        }
    }
}

/// One accepted bind on a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The SSH session's identifier.
    pub session_id: Vec<u8>,
    /// Whether it is a forwarding bind.
    pub is_forwarding: bool,
    /// `None` for a bind the SSH agent could not check.
    pub verified: Option<SessionBinding>,
}

/// What the binds of a connection say about where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// No bind at all: the client did not tell which host.
    Unbound,
    /// Bound for authentication, to a host key the SSH agent could not check.
    Unverifiable,
    /// Bound for authentication to a host key the SSH agent verified.
    Direct(SessionBinding),
    /// The connection is an agent-forwarding channel.
    Forwarded,
    /// A bind on this connection was rejected.
    Failed,
}

/// Per-connection state. `ssh` binds a connection before it asks for a
/// userauth signature; the binds decide whether, and for which host, a key
/// signs on this connection.
#[derive(Debug, Clone, Default)]
pub struct Session {
    bindings: Vec<Entry>,
    /// Set by any rejected bind. The connection then never gets a signature:
    /// a client whose bind failed is not one whose destination is known.
    bind_failed: bool,
}

impl Session {
    /// A connection that has made no bind.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The accepted binds, oldest first.
    #[must_use]
    pub fn bindings(&self) -> &[Entry] {
        &self.bindings
    }

    /// What the binds say.
    #[must_use]
    pub fn route(&self) -> Route {
        if self.bind_failed {
            return Route::Failed;
        }
        let Some(last) = self.bindings.last() else { return Route::Unbound };
        if self.bindings.iter().any(|entry| entry.is_forwarding) {
            return Route::Forwarded;
        }
        last.verified.clone().map_or(Route::Unverifiable, Route::Direct)
    }

    /// Applies one `session-bind@openssh.com` body. The rules are those of
    /// OpenSSH's own `ssh-agent`: only forwarding binds may precede another
    /// bind, a session identifier never moves to another host key, and the
    /// list is bounded. Returns whether to answer SUCCESS: an unverifiable
    /// bind is kept but answered with failure, as it could not be checked.
    pub fn bind(&mut self, body: &[u8]) -> bool {
        let new = match SessionBinding::parse(body) {
            Parsed::Invalid => {
                self.bind_failed = true;
                return false;
            }
            Parsed::Unverifiable { session_id, is_forwarding } => Entry { session_id, is_forwarding, verified: None },
            Parsed::Verified(binding) => Entry {
                session_id: binding.session_id.clone(),
                is_forwarding: binding.is_forwarding,
                verified: Some(binding),
            },
        };
        if self.bindings.len() >= MAX_BINDINGS {
            self.bind_failed = true;
            return false;
        }
        for old in &self.bindings {
            if !old.is_forwarding {
                self.bind_failed = true;
                return false;
            }
            if old.session_id == new.session_id {
                let same_key =
                    old.verified.as_ref().map(|b| &b.host_key.blob) == new.verified.as_ref().map(|b| &b.host_key.blob);
                if same_key {
                    return new.verified.is_some();
                }
                self.bind_failed = true;
                return false;
            }
        }
        let verified = new.verified.is_some();
        self.bindings.push(new);
        verified
    }

    /// The binding `content` was made under: a hostbound login whose host
    /// key is the bound one, on a directly bound connection. Only then does a
    /// login signature work solely at that host; with plain `publickey`,
    /// anyone can bind the session identifier with a key of their own.
    #[must_use]
    pub fn verified_host(&self, content: &SignContent) -> Option<SessionBinding> {
        let (Route::Direct(binding), SignContent::Userauth(login)) = (self.route(), content) else { return None };
        (login.session_id == binding.session_id && login.host_key.as_deref() == Some(binding.host_key.blob.as_slice()))
            .then_some(binding)
    }

    /// Why a key may not sign `content` on this connection, or `None` if it
    /// may. `require_binding` is the setting: off lets a login whose host is
    /// not verified go to the dialog, marked so.
    #[must_use]
    pub fn refusal(&self, content: &SignContent, require_binding: bool) -> Option<Refusal> {
        let route = self.route();
        match route {
            Route::Failed => return Some(Refusal::BindFailed),
            Route::Forwarded => return Some(Refusal::Forwarded),
            _ => {}
        }
        let SignContent::Userauth(login) = content else { return None };
        if let Route::Direct(binding) = &route {
            let wrong_host = login.host_key.as_deref().is_some_and(|host_key| host_key != binding.host_key.blob);
            if login.session_id != binding.session_id || wrong_host {
                return Some(Refusal::SessionMismatch);
            }
        }
        (require_binding && self.verified_host(content).is_none()).then_some(Refusal::HostNotVerified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::message::{self, Message};
    use crate::agent::testing::{
        SESSION_ID, TestKey, UserauthData, bind_body, certificate, ecdsa_key, ed25519_key, fresh_ed25519_key, rsa_key,
        sshsig,
    };
    use crate::agent::wire::strings;

    fn login_key() -> Vec<u8> {
        ed25519_key(1).blob
    }

    fn parse(data: &[u8]) -> SignContent {
        SignContent::parse(data, &[&login_key()]).expect("understood")
    }

    fn hostbound_login(session_id: &[u8], host_key: &[u8]) -> SignContent {
        parse(
            &UserauthData { session_id: session_id.to_vec(), ..UserauthData::hostbound(&login_key(), host_key) }
                .build(),
        )
    }

    fn plain_login() -> SignContent {
        parse(&UserauthData::new(&login_key()).build())
    }

    fn git_signature() -> SignContent {
        parse(&sshsig("git"))
    }

    /// A connection bound for authentication to `host` with `SESSION_ID`.
    fn bound(host: &TestKey) -> Session {
        let mut session = Session::new();
        assert!(session.bind(&bind_body(host, &SESSION_ID, 0, None, b"")));
        session
    }

    fn bind(session: &mut Session, host: &TestKey, session_id: &[u8], forwarding: u8) -> bool {
        session.bind(&bind_body(host, session_id, forwarding, None, b""))
    }

    /// What `Message::parse` and `Session::bind` make of a whole message, as the reader process will do.
    fn answer(session: &mut Session, extension: &str, body: &[u8]) -> u8 {
        let mut msg = vec![message::EXTENSION];
        msg.extend(strings(&[extension.as_bytes()]));
        msg.extend_from_slice(body);
        match Message::parse(&msg) {
            Ok(Message::Extension { name: EXTENSION_NAME, body }) if session.bind(body) => message::SUCCESS,
            _ => message::FAILURE,
        }
    }

    // ported: testSessionBind_extensionFraming
    #[test]
    fn the_extension_is_answered_success_or_failure() {
        let host = ed25519_key(30);
        let ok = |body: Vec<u8>, name: &str| answer(&mut Session::new(), name, &body);
        assert_eq!(ok(bind_body(&host, &SESSION_ID, 0, None, b""), EXTENSION_NAME), message::SUCCESS);
        assert_eq!(ok(bind_body(&host, &SESSION_ID, 0, None, b""), "query"), message::FAILURE, "unknown extension");
        assert_eq!(
            ok(bind_body(&host, &SESSION_ID, 0, None, &[0]), EXTENSION_NAME),
            message::FAILURE,
            "trailing bytes"
        );
        assert_eq!(
            ok(bind_body(&host, &SESSION_ID, 2, None, b""), EXTENSION_NAME),
            message::FAILURE,
            "is_forwarding 2"
        );
        let other = ed25519_key(31).sign(&SESSION_ID);
        assert_eq!(
            ok(bind_body(&host, &SESSION_ID, 0, Some(other), b""), EXTENSION_NAME),
            message::FAILURE,
            "bad signature"
        );
        assert_eq!(ok(bind_body(&host, &[], 0, None, b""), EXTENSION_NAME), message::FAILURE, "empty session id");
        assert_eq!(
            ok(bind_body(&host, &[1; 65], 0, None, b""), EXTENSION_NAME),
            message::FAILURE,
            "session id of 65 bytes"
        );
        assert_eq!(ok(vec![], EXTENSION_NAME), message::FAILURE, "empty body");
    }

    #[test]
    fn every_supported_host_key_type_binds() {
        for host in
            [ed25519_key(32), ecdsa_key(false), ecdsa_key(true), rsa_key("rsa-sha2-256"), rsa_key("rsa-sha2-512")]
        {
            let mut session = Session::new();
            assert!(bind(&mut session, &host, &SESSION_ID, 0));
            assert!(matches!(session.route(), Route::Direct(binding) if binding.host_key.blob == host.blob));
        }
    }

    // ported: testSessionBind_directLogin
    #[test]
    fn a_login_on_a_directly_bound_connection() {
        let host = ed25519_key(33);
        let session = bound(&host);
        let login = hostbound_login(&SESSION_ID, &host.blob);
        assert_eq!(session.refusal(&login, true), None, "hostbound login to the bound host");
        assert!(session.verified_host(&login).is_some_and(|binding| binding.host_key.blob == host.blob));
        assert_eq!(
            session.refusal(&plain_login(), true),
            Some(Refusal::HostNotVerified),
            "plain publickey proves no host"
        );
        assert_eq!(session.refusal(&plain_login(), false), None, "with the setting off it goes on, unverified");
        assert!(session.verified_host(&plain_login()).is_none());
        assert_eq!(session.refusal(&hostbound_login(&[0x11; 32], &host.blob), true), Some(Refusal::SessionMismatch));
        assert_eq!(
            session.refusal(&hostbound_login(&SESSION_ID, &ed25519_key(34).blob), true),
            Some(Refusal::SessionMismatch)
        );
        assert_eq!(
            session.refusal(&hostbound_login(&SESSION_ID, &ed25519_key(34).blob), false),
            Some(Refusal::SessionMismatch)
        );
        assert!(matches!(session.route(), Route::Direct(binding) if binding.host_key.blob == host.blob));
    }

    #[test]
    fn a_plain_login_for_another_session_is_a_mismatch_even_with_the_setting_off() {
        let session = bound(&ed25519_key(35));
        let login = parse(&UserauthData { session_id: vec![0x22; 32], ..UserauthData::new(&login_key()) }.build());
        assert_eq!(session.refusal(&login, false), Some(Refusal::SessionMismatch));
    }

    // ported: testSessionBind_unboundFollowsSetting
    #[test]
    fn an_unbound_connection_follows_the_setting_and_signatures_go_on() {
        let session = Session::new();
        assert_eq!(session.route(), Route::Unbound);
        let login = hostbound_login(&SESSION_ID, &ed25519_key(36).blob);
        assert_eq!(session.refusal(&login, true), Some(Refusal::HostNotVerified));
        assert_eq!(session.refusal(&login, false), None);
        assert_eq!(session.refusal(&git_signature(), true), None, "SSHSIG proves no host and needs none");
    }

    // ported: testSessionBind_failedBindBlocksSigning
    #[test]
    fn a_failed_bind_blocks_everything_on_the_connection() {
        let host = ed25519_key(37);
        let mut session = Session::new();
        let forged = ed25519_key(38).sign(&SESSION_ID);
        assert!(!session.bind(&bind_body(&host, &SESSION_ID, 0, Some(forged), b"")));
        assert_eq!(session.route(), Route::Failed);
        assert_eq!(session.refusal(&hostbound_login(&SESSION_ID, &host.blob), false), Some(Refusal::BindFailed));
        assert_eq!(session.refusal(&git_signature(), true), Some(Refusal::BindFailed));
        let mut later = bound(&host);
        assert!(!later.bind(&bind_body(&host, &SESSION_ID, 0, None, &[1])));
        assert_eq!(later.refusal(&hostbound_login(&SESSION_ID, &host.blob), true), Some(Refusal::BindFailed));
    }

    // ported: testSessionBind_forwardedRefused
    #[test]
    fn a_forwarded_connection_signs_nothing() {
        let (hop, host) = (ed25519_key(39), ed25519_key(40));
        let sid_a = [0xA1; 32];
        let mut session = Session::new();
        assert!(bind(&mut session, &hop, &sid_a, 1));
        assert!(bind(&mut session, &host, &SESSION_ID, 0));
        assert_eq!(session.route(), Route::Forwarded, "two hops");
        let login = hostbound_login(&SESSION_ID, &host.blob);
        assert_eq!(session.refusal(&login, false), Some(Refusal::Forwarded));
        assert_eq!(session.refusal(&git_signature(), true), Some(Refusal::Forwarded));
        let mut only = Session::new();
        assert!(bind(&mut only, &hop, &sid_a, 1));
        assert_eq!(
            only.refusal(&hostbound_login(&sid_a, &hop.blob), true),
            Some(Refusal::Forwarded),
            "a forwarding bind alone"
        );
    }

    // ported: testSessionBind_unverifiableKeys
    #[test]
    fn a_host_key_that_cannot_be_checked_is_unverifiable_not_a_failed_bind() {
        let dsa = strings(&[b"ssh-dss", &[1; 128]]);
        let dsa_signature = strings(&[b"ssh-dss", &[2; 40]]);
        let body = |forwarding: u8| {
            let mut out = strings(&[&dsa, &SESSION_ID, &dsa_signature]);
            out.push(forwarding);
            out
        };
        let mut session = Session::new();
        assert!(!session.bind(&body(0)), "answered FAILURE");
        assert_eq!(session.route(), Route::Unverifiable);
        assert_eq!(session.refusal(&plain_login(), true), Some(Refusal::HostNotVerified));
        assert_eq!(session.refusal(&plain_login(), false), None);
        let mut forwarding = Session::new();
        assert!(!forwarding.bind(&body(1)));
        assert_eq!(forwarding.refusal(&plain_login(), false), Some(Refusal::Forwarded), "still counts as forwarding");
    }

    #[test]
    fn sha1_rsa_and_p521_host_signatures_are_unverifiable() {
        let sha1 = rsa_key("ssh-rsa");
        let mut session = Session::new();
        assert!(!bind(&mut session, &sha1, &SESSION_ID, 0));
        assert_eq!(session.route(), Route::Unverifiable);
        let p521 = {
            let line = include_str!("../../testdata/host_p521.pub");
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                line.split_whitespace().nth(1).expect("field"),
            )
            .expect("base64")
        };
        let signature = strings(&[b"ecdsa-sha2-nistp521", &[0; 20]]);
        let mut body = strings(&[&p521, &SESSION_ID, &signature]);
        body.push(0);
        let mut session = Session::new();
        assert!(!session.bind(&body));
        assert_eq!(session.route(), Route::Unverifiable, "P-521 is not supported");
    }

    // ported: testHostCertificate_forgedCASignatureRejected (the binding half)
    #[test]
    fn a_binding_with_a_forged_certificate_cannot_name_a_host() {
        let (ca, host) = (ed25519_key(41), ed25519_key(42));
        let forged = certificate(&host, &ca, &["github.com"], 2, u64::MAX, Some(strings(&[b"ssh-ed25519", &[0; 64]])));
        let mut session = Session::new();
        assert!(!bind(&mut session, &forged, &SESSION_ID, 0));
        assert_eq!(session.route(), Route::Unverifiable);
        assert_eq!(session.refusal(&hostbound_login(&SESSION_ID, &forged.blob), false), None);
        assert!(session.verified_host(&hostbound_login(&SESSION_ID, &forged.blob)).is_none());
        let good = certificate(&host, &ca, &["prod.example.org"], 2, u64::MAX, None);
        let session = bound(&good);
        assert!(session.verified_host(&hostbound_login(&SESSION_ID, &good.blob)).is_some());
    }

    // ported: testSessionBind_bindingRules
    #[test]
    fn the_rules_for_several_binds() {
        let (host, other) = (ed25519_key(43), ed25519_key(44));
        let (sid1, sid2) = ([1; 32], [2; 32]);

        let mut after_auth = Session::new();
        assert!(bind(&mut after_auth, &host, &sid1, 0));
        assert!(!bind(&mut after_auth, &other, &sid2, 0), "a second bind after an authentication bind");
        assert_eq!(after_auth.route(), Route::Failed);

        let mut rebind = Session::new();
        assert!(bind(&mut rebind, &host, &sid1, 1));
        assert!(bind(&mut rebind, &host, &sid1, 1), "the same session id to the same key");
        assert_eq!(rebind.bindings().len(), 1);
        assert!(!bind(&mut rebind, &other, &sid1, 1), "a session id moving to another host key");
        assert_eq!(rebind.route(), Route::Failed);

        let mut many = Session::new();
        for i in 0..MAX_BINDINGS {
            assert!(bind(&mut many, &host, &[u8::try_from(i).expect("small") + 1; 32], 1));
        }
        assert_eq!(many.bindings().len(), 16);
        assert!(!bind(&mut many, &host, &[0xEE; 32], 1), "a seventeenth bind");
        assert_eq!(many.route(), Route::Failed);
    }

    #[test]
    fn sessions_do_not_share_state() {
        let host = fresh_ed25519_key();
        let mut failed = Session::new();
        assert!(!failed.bind(b"garbage"));
        let fine = bound(&host);
        assert_eq!(failed.route(), Route::Failed);
        assert!(matches!(fine.route(), Route::Direct(_)));
    }
}
