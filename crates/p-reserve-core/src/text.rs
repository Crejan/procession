//! A string that may be shown: no control characters, no bidirectional marks,
//! a bounded length.
//!
//! The character rule is p-act's (`p_act::text::check`: U+0000 to U+001F and
//! U+007F to U+009F, and U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to
//! U+2069), which is not exported from p-act, so it is stated here a second
//! time; replace this with p-act's once it is public.

/// The longest `detail` of an error, in bytes.
pub const MAX_DETAIL: usize = 512;

fn refused(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `text` with every refused character replaced by a space and cut to at most
/// `max` bytes on a character boundary (`…` marks a cut).
pub fn for_display(text: &str, max: usize) -> String {
    let clean: String = text.chars().map(|c| if refused(c) { ' ' } else { c }).collect();
    if clean.len() <= max {
        return clean;
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &clean[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_bidirectional_characters_become_spaces() {
        assert_eq!(for_display("a\nb\u{1b}[31mc\u{202e}d\u{0085}e", 100), "a b [31mc d e");
        assert_eq!(for_display("plain é text", 100), "plain é text");
    }

    #[test]
    fn a_long_text_is_cut_on_a_character_boundary_within_the_bound() {
        let text = "é".repeat(1000);
        let cut = for_display(&text, 101);
        assert!(cut.len() <= 101 && cut.ends_with('…'), "{}", cut.len());
        assert!(for_display("short", 101) == "short");
    }
}
