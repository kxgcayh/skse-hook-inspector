//! Fallback for an empty monospace font family.
//!
//! The overlay builds the Monospace family only from `consola.ttf` and `segoeui.ttf` in the
//! Windows font folder. Under CrossOver a bottle may have neither, so the family is empty and every
//! monospace glyph draws as a box. This module decides, without touching egui or the disk itself,
//! what the family should be instead.

use std::collections::BTreeMap;

/// The two families the decision looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Proportional,
    Monospace,
}

/// Font files tried for the monospace family, first readable wins (file names in the Windows font folder).
pub const MONO_CANDIDATES: [&str; 4] = ["consola.ttf", "cour.ttf", "AndaleMo.TTF", "lucon.ttf"];

/// What to apply: an optional new font file, and the monospace family's font names in fallback order.
#[derive(Debug, PartialEq, Eq)]
pub struct MonoFix {
    /// The file name chosen and its bytes; `None` when the family just reuses the proportional fonts.
    pub file: Option<(String, Vec<u8>)>,
    /// The new Monospace family: the chosen font (if any) then the proportional fonts as glyph fallback.
    pub monospace: Vec<String>,
}

/// The name a loaded candidate is stored under in the font data.
#[must_use]
pub fn font_name(file: &str) -> String {
    format!("hook-inspector-mono:{file}")
}

/// `None` when Monospace already has fonts (leave it alone). Otherwise the first candidate that
/// `read` returns non-empty bytes for and `parses` accepts, followed by the proportional fonts;
/// with no usable candidate, the proportional fonts alone. Never panics.
///
/// `parses` must be the parser the renderer uses (epaint panics on a font it cannot parse, and the
/// plugin build aborts on panic), so bytes it rejects are skipped like an unreadable file.
pub fn plan_monospace(
    families: &BTreeMap<Kind, Vec<String>>,
    candidates: &[&str],
    mut read: impl FnMut(&str) -> Option<Vec<u8>>,
    parses: impl Fn(&[u8]) -> bool,
) -> Option<MonoFix> {
    if families.get(&Kind::Monospace).is_some_and(|f| !f.is_empty()) {
        return None;
    }
    let proportional = families.get(&Kind::Proportional).cloned().unwrap_or_default();
    for file in candidates {
        let Some(bytes) = read(file).filter(|b| !b.is_empty() && parses(b)) else { continue };
        let name = font_name(file);
        let mut monospace = vec![name.clone()];
        monospace.extend(proportional.iter().filter(|p| **p != name).cloned());
        return Some(MonoFix { file: Some((name, bytes)), monospace });
    }
    Some(MonoFix { file: None, monospace: proportional })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn families(prop: &[&str], mono: &[&str]) -> BTreeMap<Kind, Vec<String>> {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        BTreeMap::from([(Kind::Proportional, own(prop)), (Kind::Monospace, own(mono))])
    }

    #[test]
    fn empty_monospace_uses_cour_then_proportional() {
        let f = families(&["futura", "segoe"], &[]);
        let mut asked = Vec::new();
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |n| {
            asked.push(n.to_owned());
            (n == "cour.ttf").then(|| vec![1, 2, 3])
        }, |_| true)
        .expect("fix");
        assert_eq!(asked, ["consola.ttf", "cour.ttf"]);
        assert_eq!(fix.file, Some(("hook-inspector-mono:cour.ttf".to_owned(), vec![1, 2, 3])));
        assert_eq!(fix.monospace, ["hook-inspector-mono:cour.ttf", "futura", "segoe"]);
    }

    #[test]
    fn first_candidate_wins_and_later_are_not_read() {
        let f = families(&["futura"], &[]);
        let mut asked = 0;
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |_| {
            asked += 1;
            Some(vec![9])
        }, |_| true)
        .expect("fix");
        assert_eq!(asked, 1);
        assert_eq!(fix.monospace[0], "hook-inspector-mono:consola.ttf");
    }

    #[test]
    fn nothing_readable_falls_back_to_proportional() {
        let f = families(&["futura", "segoe"], &[]);
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |_| None, |_| true).expect("fix");
        assert_eq!(fix, MonoFix { file: None, monospace: vec!["futura".to_owned(), "segoe".to_owned()] });
    }

    #[test]
    fn empty_file_counts_as_unreadable() {
        let f = families(&["futura"], &[]);
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |n| (n == "lucon.ttf").then(Vec::new), |_| true).expect("fix");
        assert_eq!(fix.file, None);
    }

    #[test]
    fn non_empty_monospace_is_untouched() {
        let f = families(&["futura"], &["consolas"]);
        let mut called = false;
        assert_eq!(
            plan_monospace(&f, &MONO_CANDIDATES, |_| {
                called = true;
                Some(vec![1])
            }, |_| true),
            None
        );
        assert!(!called, "no file is read when Monospace has fonts");
    }

    #[test]
    fn missing_monospace_key_counts_as_empty() {
        let f = BTreeMap::from([(Kind::Proportional, vec!["futura".to_owned()])]);
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |_| None, |_| true).expect("fix");
        assert_eq!(fix.monospace, ["futura"]);
    }

    #[test]
    fn no_families_at_all_gives_empty_list_without_panic() {
        let fix = plan_monospace(&BTreeMap::new(), &MONO_CANDIDATES, |_| None, |_| true).expect("fix");
        assert!(fix.monospace.is_empty() && fix.file.is_none());
    }

    #[test]
    fn unparsable_candidate_is_skipped_and_next_taken() {
        let f = families(&["futura"], &[]);
        let truncated = vec![0, 1, 0, 0, 0, 3]; // sfnt magic, then cut off
        let good = vec![0xAA, 1, 2, 3];
        let mut asked = Vec::new();
        let fix = plan_monospace(
            &f,
            &MONO_CANDIDATES,
            |n| {
                asked.push(n.to_owned());
                match n {
                    "consola.ttf" => Some(truncated.clone()),
                    "cour.ttf" => Some(b"garbage, not a font".to_vec()),
                    "AndaleMo.TTF" => Some(good.clone()),
                    _ => Some(vec![0xAA, 9]),
                }
            },
            |b| b.first() == Some(&0xAA),
        )
        .expect("fix");
        assert_eq!(asked, ["consola.ttf", "cour.ttf", "AndaleMo.TTF"]);
        assert_eq!(fix.file, Some(("hook-inspector-mono:AndaleMo.TTF".to_owned(), good)));
        assert_eq!(fix.monospace, ["hook-inspector-mono:AndaleMo.TTF", "futura"]);
    }

    #[test]
    fn all_candidates_unparsable_falls_back_to_proportional() {
        let f = families(&["futura"], &[]);
        let fix = plan_monospace(&f, &MONO_CANDIDATES, |_| Some(vec![1, 2, 3]), |_| false).expect("fix");
        assert_eq!(fix, MonoFix { file: None, monospace: vec!["futura".to_owned()] });
    }
}
