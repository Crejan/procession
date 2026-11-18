//! What can stop a subcommand.

/// Why a subcommand did not produce a report.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A reader of p-roc failed on something the subcommand cannot do without.
    #[error(transparent)]
    Roc(#[from] p_roc::Error),
    /// The configuration file is unreadable or invalid.
    #[error("config {path}: {detail}")]
    Config {
        /// The file.
        path: String,
        /// What is wrong.
        detail: String,
    },
    /// The arguments are outside what the subcommand accepts.
    #[error("refused: {0}")]
    Refused(String),
    /// Writing the output failed.
    #[error("output: {0}")]
    Output(#[from] std::io::Error),
}

impl Error {
    /// The process exit code: 4 for a refusal, 3 for a failed diagnostic.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => 4,
            _ => 3,
        }
    }
}
