//! Pinned official-client localization; attribution and adaptations are in UPSTREAM.json.

mod upstream {
    pub(super) mod lang;
}

pub use upstream::lang::{translate_locale, translate_locale_with_preference};

pub fn langs() -> Vec<(&'static str, String)> {
    let hide_cjk = upstream::lang::cjk_ui_unavailable();
    let mut languages: Vec<(&str, String)> = upstream::lang::LANGS
        .iter()
        .filter(|entry| !hide_cjk || !upstream::lang::is_cjk_lang(entry.0))
        .map(|entry| (entry.0, format!("{} ({})", entry.1, entry.0)))
        .collect();
    languages.sort_by(|left, right| left.0.cmp(right.0));
    languages
}
