//! watchword's messages as a [phrasebook] 0.1 catalog, [`L10N`].
//!
//! This is the text of watchword's Yew components, kept here so a tool that
//! only needs the messages, such as an app's localization checker, takes them
//! without building a frontend. watchword-yew023 re-exports [`L10N`].
//!
//! [phrasebook]: https://docs.rs/phrasebook

use phrasebook01::{Catalog, Lang, Source};

/// watchword's messages, in English, with every id under the `watchword-`
/// prefix.
///
/// watchword's components look their text up in the `Phrases` the app
/// provides with `ContextProvider<Phrases>`, and fall back to these messages
/// for any id the app's phrasebook lacks, or when nothing is provided. An app
/// that translates watchword adds the `watchword-*` ids of
/// [`locales/en-US.ftl`][ftl] to its own catalog for each language, and adds
/// this catalog after its own, so its translations win:
///
/// ```ignore
/// use phrasebook::{Catalog, Lang, Phrasebook, Source};
///
/// const SV_SE: Lang = Lang::new("sv-SE");
///
/// static APP: Catalog = Catalog::new("app", &[
///     Source::new(Lang::EN_US, include_str!("../locales/en-US.ftl")),
///     Source::new(SV_SE, include_str!("../locales/sv-SE.ftl")),
/// ]);
///
/// let book = Phrasebook::builder()
///     .language(Lang::EN_US, "English")
///     .language(SV_SE, "Svenska")
///     .catalog(&APP)
///     .catalog(&auth::phrasebook01::L10N)
///     .build();
/// ```
///
/// A tool that checks an app's `.ftl` against the libraries it takes lists
/// these ids with `phrasebook::check::ids(&L10N, lang)` for each of
/// `L10N.languages()`.
///
/// [ftl]: https://github.com/udoprog/watchword/blob/main/crates/watchword-core/locales/en-US.ftl
pub static L10N: Catalog = Catalog::new(
    "watchword",
    &[Source::new(
        Lang::EN_US,
        include_str!("../locales/en-US.ftl"),
    )],
)
.with_prefix("watchword-");

#[cfg(test)]
mod tests {
    use phrasebook01::check;

    use super::L10N;

    /// The catalog parses, every id has the prefix, and every message formats.
    #[test]
    fn catalog() {
        check::catalog(&L10N).unwrap();
    }
}
