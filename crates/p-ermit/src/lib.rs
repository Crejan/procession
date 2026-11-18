//! What may be trusted on a Unix system, checked the same way by every program that asks: a settings file by its
//! owner and mode ([`settings`]), a socket's peer by its credentials ([`peer`]).
//!
//! libc only by default. The feature `toml` adds a reader for TOML settings files (`toml` 0.9 and `serde`).
//! Unix only: on another system the crate is empty.

#[cfg(unix)]
pub mod peer;
#[cfg(unix)]
pub mod settings;
