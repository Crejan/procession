//! Dialogs. One at a time, text only from what was checked, nothing
//! shortened or altered (`SPEC.md`, section 5; `doc/approvals.md`, R9).
//!
//! A dialog shows labelled fields, one per line, each exactly as it was
//! signed. A field cannot start another line (control characters were
//! refused before), so one field cannot pass for two. The development form
//! asks on the terminal of `pledge serve`: it prints the dialog on standard
//! output and reads the answer from standard input.

use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::agent::binding::SessionBinding;
use crate::agent::known_hosts::HostName;
use crate::agent::sign_content::SignContent;
use crate::policy::Admission;

/// How a dialog ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
    /// The person answered.
    Answer(T),
    /// Nobody answered in time.
    Timeout,
    /// There is nobody to ask (no terminal input).
    Unavailable,
}

/// What a dialog shows: a title and labelled fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// What is being asked for.
    pub title: String,
    /// Label and value, each value exactly as it was signed.
    pub fields: Vec<(&'static str, String)>,
}

impl Description {
    /// The dialog's lines.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = format!("  {}\n", self.title);
        for (label, value) in &self.fields {
            text.push_str(&format!("    {label}: {value}\n"));
        }
        text
    }
}

/// What a signing request is, in the dialog's words, from the parsed data
/// and the host the SSH agent verified (or `None`).
#[must_use]
pub fn describe(content: &SignContent, verified: Option<&SessionBinding>, name: &HostName) -> Description {
    match content {
        SignContent::Sshsig(signature) => Description {
            title: "create an SSH signature".into(),
            fields: vec![("namespace", signature.namespace.clone())],
        },
        SignContent::Userauth(login) => {
            let host = match (verified, name) {
                (None, _) => "NOT verified: this login does not prove which host it is for".to_owned(),
                (Some(binding), HostName::Named(names)) => {
                    format!("{} ({}, verified)", names.join(", "), binding.host_key.fingerprint())
                }
                (Some(binding), HostName::HashedOnly) => {
                    format!("a known host ({}, verified)", binding.host_key.fingerprint())
                }
                (Some(binding), HostName::Unknown) => {
                    format!("an unknown host ({}, verified)", binding.host_key.fingerprint())
                }
            };
            Description { title: "sign in over SSH".into(), fields: vec![("user", login.user.clone()), ("host", host)] }
        }
    }
}

/// Asking the person. Implementations show one dialog at a time.
pub trait Dialogs: Send + Sync {
    /// An unknown program asks to use a key: block, decline once, admit
    /// once, or admit generally.
    fn ask_admission(&self, program: &str, what: &Description, timeout: Duration) -> Outcome<Admission>;
    /// The presence check for one signature. In the development form it is
    /// a question; in the hardware form it is a touch.
    fn presence(&self, program: &str, what: &Description, timeout: Duration) -> Outcome<bool>;
    /// A yes or no to `question`, for what the person asked pledge to do
    /// itself (making or retiring a key): the presence check of those.
    fn confirm(&self, question: &str, timeout: Duration) -> Outcome<bool>;
    /// Tells the person something; nothing is asked.
    fn tell(&self, text: &str);
}

/// Dialogs on a terminal: prompts to a writer, answers from lines read.
pub struct Terminal {
    lines: Mutex<Receiver<String>>,
    out: Mutex<Box<dyn Write + Send>>,
    interactive: bool,
}

impl Terminal {
    /// Dialogs on the terminal of this process.
    #[must_use]
    pub fn stdio() -> Self {
        // SAFETY: isatty only reads the descriptor's type.
        let interactive = unsafe { libc::isatty(0) } == 1;
        Self::new(std::io::stdin(), std::io::stdout(), interactive)
    }

    /// Dialogs that read lines from `input` and write to `output`. When
    /// `interactive`, lines typed while no dialog is open are discarded when
    /// the next one opens, so that a stray line cannot answer it.
    pub fn new<R: Read + Send + 'static, W: Write + Send + 'static>(input: R, output: W, interactive: bool) -> Self {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(input).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self { lines: Mutex::new(receiver), out: Mutex::new(Box::new(output)), interactive }
    }

    fn say(&self, text: &str) {
        if let Ok(mut out) = self.out.lock() {
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        }
    }

    /// Runs one dialog: `body` gets a way to read the next answer line.
    fn dialog<T>(
        &self,
        timeout: Duration,
        prompt: &str,
        body: impl FnOnce(&dyn Fn(&str) -> Outcome<String>) -> Outcome<T>,
    ) -> Outcome<T> {
        let Ok(lines) = self.lines.lock() else { return Outcome::Unavailable };
        if self.interactive {
            while lines.try_recv().is_ok() {}
        }
        self.say(prompt);
        let read = |again: &str| {
            if !again.is_empty() {
                self.say(again);
            }
            match lines.recv_timeout(timeout) {
                Ok(line) => Outcome::Answer(line.trim().to_owned()),
                Err(RecvTimeoutError::Timeout) => Outcome::Timeout,
                Err(RecvTimeoutError::Disconnected) => Outcome::Unavailable,
            }
        };
        let outcome = body(&read);
        if !matches!(outcome, Outcome::Unavailable) {
            self.say("\n");
        }
        outcome
    }
}

impl Dialogs for Terminal {
    fn ask_admission(&self, program: &str, what: &Description, timeout: Duration) -> Outcome<Admission> {
        let prompt = format!(
            "\npledge: an unknown program asks to use your SSH key\n  program: {program}\n{}\
             [b]lock, [d]ecline once (default), admit [o]nce, admit [g]enerally? ",
            what.render()
        );
        self.dialog(timeout, &prompt, |read| match read("") {
            Outcome::Answer(answer) => match answer.as_str() {
                "b" => Outcome::Answer(Admission::Block),
                "o" => Outcome::Answer(Admission::AdmitOnce),
                "g" => match read("Type the program's name to admit it: ") {
                    Outcome::Answer(typed) if typed == program => Outcome::Answer(Admission::AdmitGenerally),
                    Outcome::Answer(_) => Outcome::Answer(Admission::DeclineOnce),
                    Outcome::Timeout => Outcome::Timeout,
                    Outcome::Unavailable => Outcome::Unavailable,
                },
                _ => Outcome::Answer(Admission::DeclineOnce),
            },
            Outcome::Timeout => Outcome::Timeout,
            Outcome::Unavailable => Outcome::Unavailable,
        })
    }

    fn presence(&self, program: &str, what: &Description, timeout: Duration) -> Outcome<bool> {
        let prompt = format!(
            "\npledge: presence check\n  program: {program}\n{}Allow this one signature? [y/N] ",
            what.render()
        );
        self.dialog(timeout, &prompt, |read| match read("") {
            Outcome::Answer(answer) => Outcome::Answer(matches!(answer.as_str(), "y" | "yes")),
            Outcome::Timeout => Outcome::Timeout,
            Outcome::Unavailable => Outcome::Unavailable,
        })
    }

    fn confirm(&self, question: &str, timeout: Duration) -> Outcome<bool> {
        let prompt = format!("\npledge: presence check\n  {question}\nAllow? [y/N] ");
        self.dialog(timeout, &prompt, |read| match read("") {
            Outcome::Answer(answer) => Outcome::Answer(matches!(answer.as_str(), "y" | "yes")),
            Outcome::Timeout => Outcome::Timeout,
            Outcome::Unavailable => Outcome::Unavailable,
        })
    }

    fn tell(&self, text: &str) {
        self.say(&format!("\npledge: {text}\n"));
    }
}

/// Dialogs answered from a script, for tests.
#[cfg(test)]
pub struct Scripted {
    answers: Mutex<std::collections::VecDeque<Outcome<Answer>>>,
    /// Every dialog that was shown: its text.
    pub shown: Mutex<Vec<String>>,
}

/// One scripted answer.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// To an admission question.
    Admission(Admission),
    /// To a presence check or a confirmation.
    Yes(bool),
}

#[cfg(test)]
impl Scripted {
    pub fn new(answers: impl IntoIterator<Item = Outcome<Answer>>) -> Self {
        Self { answers: Mutex::new(answers.into_iter().collect()), shown: Mutex::new(Vec::new()) }
    }

    fn next(&self, text: String) -> Outcome<Answer> {
        self.shown.lock().expect("lock").push(text);
        self.answers.lock().expect("lock").pop_front().unwrap_or(Outcome::Unavailable)
    }
}

#[cfg(test)]
impl Dialogs for Scripted {
    fn ask_admission(&self, program: &str, what: &Description, _: Duration) -> Outcome<Admission> {
        match self.next(format!("admission {program}\n{}", what.render())) {
            Outcome::Answer(Answer::Admission(a)) => Outcome::Answer(a),
            Outcome::Answer(Answer::Yes(_)) | Outcome::Unavailable => Outcome::Unavailable,
            Outcome::Timeout => Outcome::Timeout,
        }
    }
    fn presence(&self, program: &str, what: &Description, _: Duration) -> Outcome<bool> {
        match self.next(format!("presence {program}\n{}", what.render())) {
            Outcome::Answer(Answer::Yes(y)) => Outcome::Answer(y),
            Outcome::Answer(Answer::Admission(_)) | Outcome::Unavailable => Outcome::Unavailable,
            Outcome::Timeout => Outcome::Timeout,
        }
    }
    fn confirm(&self, question: &str, _: Duration) -> Outcome<bool> {
        match self.next(format!("confirm {question}")) {
            Outcome::Answer(Answer::Yes(y)) => Outcome::Answer(y),
            Outcome::Answer(Answer::Admission(_)) | Outcome::Unavailable => Outcome::Unavailable,
            Outcome::Timeout => Outcome::Timeout,
        }
    }
    fn tell(&self, text: &str) {
        self.shown.lock().expect("lock").push(format!("tell {text}"));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A writer whose contents can be read back.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Capture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    fn what() -> Description {
        Description {
            title: "sign in over SSH".into(),
            fields: vec![("user", "jan".into()), ("host", "a.example".into())],
        }
    }

    fn terminal(input: &str) -> (Terminal, Capture) {
        let capture = Capture::default();
        (Terminal::new(Cursor::new(input.to_owned().into_bytes()), capture.clone(), false), capture)
    }

    #[test]
    fn the_four_answers_about_an_unknown_program() {
        for (typed, expected) in [
            ("b\n", Admission::Block),
            ("d\n", Admission::DeclineOnce),
            ("\n", Admission::DeclineOnce),
            ("nonsense\n", Admission::DeclineOnce),
            ("o\n", Admission::AdmitOnce),
            ("g\n/usr/bin/git\n", Admission::AdmitGenerally),
            ("g\n/usr/bin/gi\n", Admission::DeclineOnce),
            ("g\n\n", Admission::DeclineOnce),
        ] {
            let (terminal, _) = terminal(typed);
            assert_eq!(terminal.ask_admission("/usr/bin/git", &what(), SECOND), Outcome::Answer(expected), "{typed:?}");
        }
    }

    #[test]
    fn the_dialog_shows_the_program_and_every_field_as_it_is() {
        let (terminal, capture) = terminal("y\n");
        assert_eq!(terminal.presence("/usr/bin/ssh", &what(), SECOND), Outcome::Answer(true));
        let text = capture.text();
        assert!(text.contains("program: /usr/bin/ssh\n"), "{text}");
        assert!(text.contains("    user: jan\n    host: a.example\n"), "{text}");
    }

    #[test]
    fn only_yes_is_yes() {
        for (typed, expected) in
            [("y\n", true), ("yes\n", true), ("Y\n", false), ("\n", false), ("n\n", false), ("yy\n", false)]
        {
            let (terminal, _) = terminal(typed);
            assert_eq!(terminal.confirm("make a key", SECOND), Outcome::Answer(expected), "{typed:?}");
        }
    }

    #[test]
    fn no_input_is_unavailable_and_silence_is_a_timeout() {
        let (terminal, _) = terminal("");
        assert_eq!(terminal.presence("p", &what(), SECOND), Outcome::Unavailable);
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().expect("pair");
        let silent = Terminal::new(receiver, Capture::default(), false);
        assert_eq!(silent.presence("p", &what(), Duration::from_millis(50)), Outcome::Timeout);
        drop(sender);
    }

    #[test]
    fn an_interactive_terminal_discards_lines_typed_before_the_dialog() {
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().expect("pair");
        let terminal = Terminal::new(reader, Capture::default(), true);
        writer.write_all(b"y\n").expect("write");
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            terminal.presence("p", &what(), Duration::from_millis(100)),
            Outcome::Timeout,
            "the stray y did not answer"
        );
        writer.write_all(b"y\n").expect("write");
        assert_eq!(terminal.presence("p", &what(), SECOND), Outcome::Answer(true));
    }

    #[test]
    fn a_description_of_a_login_says_when_the_host_is_not_verified() {
        use crate::agent::sign_content::Userauth;
        let login = SignContent::Userauth(Userauth {
            session_id: vec![1],
            user: "jan".into(),
            algorithm: "ssh-ed25519".into(),
            host_key: None,
        });
        let text = describe(&login, None, &HostName::Unknown).render();
        assert!(text.contains("host: NOT verified"), "{text}");
        let signature = describe(
            &SignContent::Sshsig(crate::agent::sign_content::Sshsig {
                namespace: "git".into(),
                hash_algorithm: crate::agent::sign_content::HashAlgorithm::Sha512,
                digest: vec![0; 64],
            }),
            None,
            &HostName::Unknown,
        );
        assert_eq!(signature.fields, [("namespace", "git".to_owned())]);
    }
}
