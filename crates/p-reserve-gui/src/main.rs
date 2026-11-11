//! `preserve-gui`: the desktop app of p-reserve.
//!
//! The app is a client of the daemon, like the CLI: a tray icon whose state
//! is the worst [`Freshness`] band, and a window onto the daemon's views. It
//! holds no backup logic.
//!
//! The toolkit is not chosen yet (`crates/p-reserve/SPEC.md`, "Open
//! decisions"), so this binary only states what it will show.

use std::process::ExitCode;

use p_reserve_core::Freshness;

/// What the tray icon says for a band. The one place the app turns a band
/// into words; the band itself comes from the daemon.
fn tray_label(band: Freshness) -> &'static str {
    match band {
        Freshness::Pending => "First backup pending",
        Freshness::Fresh => "Backups up to date",
        Freshness::Overdue => "Backup overdue",
        Freshness::Stale => "Attention needed",
    }
}

fn main() -> ExitCode {
    eprintln!("preserve-gui: no window yet; the toolkit is an open decision (see crates/p-reserve/SPEC.md).");
    eprintln!("tray states it will show:");
    for band in [Freshness::Pending, Freshness::Fresh, Freshness::Overdue, Freshness::Stale] {
        eprintln!("  {band:?}: {}", tray_label(band));
    }
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overdue_backup_is_never_called_up_to_date() {
        assert_ne!(tray_label(Freshness::Overdue), tray_label(Freshness::Fresh));
        assert_ne!(tray_label(Freshness::Stale), tray_label(Freshness::Fresh));
    }
}
