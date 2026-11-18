//! The deadlines in the scripts the owner runs, against the dispatcher's own rule.
//!
//! `a2-check-rule.sh` once used a fixed deadline in the year 2100 for its ordinary calls; the dispatcher, rightly,
//! refuses a deadline more than ten minutes (and the tolerance) ahead, and the owner's run failed at its first call.
//! Nothing connected the script's numbers to the rule. This does: every `--until` in the scripts is read and
//! judged by `p_robe::dispatch::until_too_far`.

use std::path::Path;

use p_robe::dispatch::until_too_far;

const NOW: i64 = 1_800_000_000;

/// How a script gives a deadline.
#[derive(Debug, PartialEq)]
enum Until {
    /// A plain number: only a deadline in the past makes sense.
    Literal(i64),
    /// `$(( $(date +%s) + N ))`: now plus N seconds.
    Ahead(i64),
    /// A variable the script sets itself, judged where it is set.
    Variable(String),
}

fn parse_until(token_rest: &str) -> Option<Until> {
    let rest = token_rest.trim_start();
    if let Some(expr) = rest.strip_prefix("$(( $(date +%s) + ") {
        let n: String = expr.chars().take_while(char::is_ascii_digit).collect();
        return n.parse().ok().map(Until::Ahead);
    }
    if let Some(var) = rest.strip_prefix('$') {
        let name: String = var.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        return Some(Until::Variable(name));
    }
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok().map(Until::Literal)
}

/// Every deadline in `text`, with the lines around it (a check's name is on the line before its command).
fn deadlines(text: &str) -> Vec<(Until, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        // `--until <value>` in a command, or `NAME=$(( $(date +%s) + N ))` assigning a deadline variable.
        if let Some(at) = line.find("--until ") {
            if let Some(until) = parse_until(&line[at + "--until ".len()..]) {
                let context = lines[index.saturating_sub(3)..=index].join("\n");
                found.push((until, context));
            }
        }
        if let Some((name, value)) = line.split_once("=$(( $(date +%s) + ") {
            if name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                let n: String = value.chars().take_while(char::is_ascii_digit).collect();
                let context = lines[index.saturating_sub(1)..=index].join("\n");
                found.push((Until::Ahead(n.parse().unwrap()), format!("{name}\n{context}")));
            }
        }
    }
    found
}

#[test]
fn no_script_holds_a_deadline_the_dispatcher_would_refuse_unless_that_is_the_check() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "sh") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // A fixed epoch time anywhere: a deadline that will be wrong tomorrow.
        for word in text.split(|c: char| !c.is_ascii_digit()).filter(|w| w.len() >= 10) {
            let n: i64 = word.parse().unwrap_or(0);
            assert!(!(1_000_000_000..10_000_000_000).contains(&n), "{}: a fixed time, {n}", path.display());
        }
        for (until, context) in deadlines(&text) {
            checked += 1;
            let expects_refusal = context.contains("more than ten minutes");
            match until {
                Until::Literal(n) => {
                    assert!(n < 1000, "{}: a literal deadline {n} that is not a past one\n{context}", path.display())
                }
                Until::Ahead(n) => assert_eq!(
                    until_too_far(NOW + n, NOW),
                    expects_refusal,
                    "{}: `now + {n}` is {} by the dispatcher, but the check around it {}\n{context}",
                    path.display(),
                    if until_too_far(NOW + n, NOW) { "refused" } else { "accepted" },
                    if expects_refusal { "expects a refusal" } else { "expects it to run" },
                ),
                Until::Variable(_) => {}
            }
        }
    }
    assert!(checked >= 8, "the scripts' deadlines were found ({checked}): the reading is broken if this fails");
}

#[test]
fn the_reading_finds_what_it_should_and_judges_the_old_mistake() {
    assert_eq!(parse_until("$(( $(date +%s) + 300 )) sys kit"), Some(Until::Ahead(300)));
    assert_eq!(parse_until("1 sys kit"), Some(Until::Literal(1)));
    assert_eq!(parse_until("$DEADLINE sys kit"), Some(Until::Variable("DEADLINE".into())));
    // The mistake: a fixed deadline in the year 2100.
    let old = "FAR=4102444800\n  \"sudo -n $PROBE --within open,none,none --call $U1 --until $FAR sys kit\"";
    assert_eq!(deadlines(old).iter().filter(|(u, _)| matches!(u, Until::Variable(v) if v == "FAR")).count(), 1);
    assert!(old.split(|c: char| !c.is_ascii_digit()).any(|w| w == "4102444800"));
    // The bound itself.
    assert!(!until_too_far(NOW + 300, NOW) && until_too_far(NOW + 3600, NOW));
}
