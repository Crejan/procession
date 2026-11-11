//! How bad an action can be, and what follows for asking the person.
//!
//! A service rates each request on three scales, always for the worst case:
//! what the answer can reveal ([`Exposure`]), what the action can do to what
//! exists ([`Damage`]), and how much it can disturb what is running
//! ([`Disruption`]). A delegation holds two ceilings. [`Ceilings::mode`] is
//! the one place that turns a rating into "sign", "ask" or "refuse".
//!
//! The top of any scale is never signed without the person, whatever the
//! ceilings say: [`Rating::needs_confirmation`].

/// The most sensitive data an action can return, at worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exposure {
    /// What any account on that host may see.
    Open,
    /// How the host or the site is set up and what runs on it.
    Internal,
    /// Other people's data, credentials, memory contents.
    Secret,
}

/// The worst an action can do to what exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Damage {
    /// It changes nothing.
    None,
    /// It changes or removes what can be brought back or rebuilt.
    Recoverable,
    /// It loses data or state for good.
    Lasting,
}

/// How much an action can disturb what is running, at worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Disruption {
    /// Nothing running notices.
    None,
    /// Something is slower, or interrupted for seconds.
    Brief,
    /// Something is down until someone acts.
    Outage,
}

/// An action's exposure, damage and disruption together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rating {
    pub exposure: Exposure,
    pub damage: Damage,
    pub disruption: Disruption,
}

impl Rating {
    /// What a service states when it cannot tell: an arbitrary command.
    pub const WORST: Rating =
        Rating { exposure: Exposure::Secret, damage: Damage::Lasting, disruption: Disruption::Outage };

    /// A query that reveals nothing a local account could not see.
    pub const HARMLESS: Rating =
        Rating { exposure: Exposure::Open, damage: Damage::None, disruption: Disruption::None };

    pub const fn new(exposure: Exposure, damage: Damage, disruption: Disruption) -> Rating {
        Rating { exposure, damage, disruption }
    }

    /// The worse of the two on each scale. For an action whose rating
    /// depends on several parameters: rate each, combine with this.
    pub fn worst_of(self, other: Rating) -> Rating {
        Rating {
            exposure: self.exposure.max(other.exposure),
            damage: self.damage.max(other.damage),
            disruption: self.disruption.max(other.disruption),
        }
    }

    /// Whether this rating is at or below `ceiling` on every scale.
    pub fn within(self, ceiling: Rating) -> bool {
        self.exposure <= ceiling.exposure && self.damage <= ceiling.damage && self.disruption <= ceiling.disruption
    }

    /// Whether only a confirmed approval will do. A service checks this
    /// before it accepts an automatic one; pledge checks it before it signs
    /// one.
    pub fn needs_confirmation(self) -> bool {
        self.exposure == Exposure::Secret || self.damage == Damage::Lasting || self.disruption == Disruption::Outage
    }
}

/// What the person's machine does with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Answer no, without a dialog.
    Refuse,
    /// Show the dialog; sign with the confirmed approval key if the person
    /// agrees.
    Ask,
    /// Sign with the automatic approval key, without a dialog.
    Automatic,
}

/// The two ceilings of a delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceilings {
    automatic: Rating,
    ask: Rating,
}

impl Ceilings {
    /// Only harmless queries run unasked; everything else is asked.
    pub const DEFAULT: Ceilings = Ceilings { automatic: Rating::HARMLESS, ask: Rating::WORST };

    /// The highest an automatic ceiling may be set.
    pub const HIGHEST_AUTOMATIC: Rating =
        Rating { exposure: Exposure::Internal, damage: Damage::Recoverable, disruption: Disruption::Brief };

    /// Ceilings a person chose. `None` if the automatic ceiling reaches the
    /// top of a scale, or lies above the ask ceiling on any.
    pub fn new(automatic: Rating, ask: Rating) -> Option<Ceilings> {
        (automatic.within(Self::HIGHEST_AUTOMATIC) && automatic.within(ask)).then_some(Ceilings { automatic, ask })
    }

    /// The mode for a request with this rating.
    pub fn mode(&self, rating: Rating) -> Mode {
        if rating.within(self.automatic) && !rating.needs_confirmation() {
            Mode::Automatic
        } else if rating.within(self.ask) {
            Mode::Ask
        } else {
            Mode::Refuse
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ_MEMORY: Rating = Rating::new(Exposure::Secret, Damage::None, Disruption::None);
    const READ_CONFIG: Rating = Rating::new(Exposure::Internal, Damage::None, Disruption::None);
    const CLEAR_CACHE: Rating = Rating::new(Exposure::Open, Damage::Recoverable, Disruption::None);
    const FORMAT_DISK: Rating = Rating::new(Exposure::Open, Damage::Lasting, Disruption::Outage);
    const MEASURE_JITTER: Rating = Rating::new(Exposure::Open, Damage::None, Disruption::Brief);
    const STOP_UNIT: Rating = Rating::new(Exposure::Open, Damage::None, Disruption::Outage);

    #[test]
    fn by_default_only_a_harmless_query_runs_unasked() {
        let ceilings = Ceilings::DEFAULT;
        assert_eq!(ceilings.mode(Rating::HARMLESS), Mode::Automatic);
        for asked in [READ_CONFIG, READ_MEMORY, CLEAR_CACHE, FORMAT_DISK, MEASURE_JITTER, STOP_UNIT, Rating::WORST] {
            assert_eq!(ceilings.mode(asked), Mode::Ask, "{asked:?}");
        }
    }

    #[test]
    fn reading_can_need_the_person_and_removing_can_be_automatic() {
        let automatic = Rating::new(Exposure::Open, Damage::Recoverable, Disruption::None);
        let ceilings = Ceilings::new(automatic, Rating::WORST).unwrap();
        assert_eq!(ceilings.mode(CLEAR_CACHE), Mode::Automatic);
        assert_eq!(ceilings.mode(READ_MEMORY), Mode::Ask);
        assert_eq!(ceilings.mode(READ_CONFIG), Mode::Ask);
    }

    #[test]
    fn clearing_caches_unasked_does_not_let_a_host_be_loaded_unasked() {
        let automatic = Rating::new(Exposure::Open, Damage::Recoverable, Disruption::None);
        let ceilings = Ceilings::new(automatic, Rating::WORST).unwrap();
        assert_eq!(ceilings.mode(MEASURE_JITTER), Mode::Ask);
    }

    #[test]
    fn the_top_of_any_scale_is_never_automatic() {
        for top in [READ_MEMORY, Rating::new(Exposure::Open, Damage::Lasting, Disruption::None), STOP_UNIT] {
            assert!(Ceilings::new(top, Rating::WORST).is_none(), "{top:?}");
        }

        let widest = Ceilings::new(Ceilings::HIGHEST_AUTOMATIC, Rating::WORST).unwrap();
        assert_eq!(widest.mode(Ceilings::HIGHEST_AUTOMATIC), Mode::Automatic);
        assert_eq!(widest.mode(MEASURE_JITTER), Mode::Automatic);
        for asked in [READ_MEMORY, FORMAT_DISK, STOP_UNIT] {
            assert_eq!(widest.mode(asked), Mode::Ask, "{asked:?}");
        }
    }

    #[test]
    fn above_the_ask_ceiling_a_request_is_refused() {
        let ask = Rating::new(Exposure::Internal, Damage::Recoverable, Disruption::Brief);
        let cautious = Ceilings::new(Rating::HARMLESS, ask).unwrap();
        assert_eq!(cautious.mode(READ_CONFIG), Mode::Ask);
        assert_eq!(cautious.mode(MEASURE_JITTER), Mode::Ask);
        for refused in [READ_MEMORY, FORMAT_DISK, STOP_UNIT] {
            assert_eq!(cautious.mode(refused), Mode::Refuse, "{refused:?}");
        }
    }

    #[test]
    fn an_automatic_ceiling_above_the_ask_ceiling_is_not_a_delegation() {
        assert!(Ceilings::new(READ_CONFIG, Rating::HARMLESS).is_none());
    }

    #[test]
    fn a_rating_is_the_worst_of_its_parts() {
        assert_eq!(
            READ_MEMORY.worst_of(CLEAR_CACHE).worst_of(MEASURE_JITTER),
            Rating::new(Exposure::Secret, Damage::Recoverable, Disruption::Brief)
        );
        assert_eq!(Rating::HARMLESS.worst_of(Rating::WORST), Rating::WORST);
    }

    #[test]
    fn confirmation_is_needed_exactly_at_the_top_of_a_scale() {
        for top in [READ_MEMORY, FORMAT_DISK, STOP_UNIT] {
            assert!(top.needs_confirmation(), "{top:?}");
        }
        for below in [READ_CONFIG, CLEAR_CACHE, MEASURE_JITTER, Ceilings::HIGHEST_AUTOMATIC] {
            assert!(!below.needs_confirmation(), "{below:?}");
        }
    }
}
