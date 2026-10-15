use phrasebook01::args;
use yew::prelude::*;

use super::browser;
use super::l10n::{placed, use_phrases};
use watchword_core::CloudflareConfig;

/// The properties of [`CloudflareSettings`].
#[derive(Properties, PartialEq)]
pub struct CloudflareSettingsProps {
    /// The settings shown.
    pub value: CloudflareConfig,
    /// Called with the changed settings on each change: a toggle, or a text
    /// field once it is left. The app stores them in its own settings,
    /// applies them with `Auth::set_cloudflare`, and passes them back as
    /// `value`.
    pub on_change: Callback<CloudflareConfig>,
    /// The app's name, used in the setup instructions. Defaults to the
    /// message `watchword-cloudflare-the-app`, "the app".
    #[prop_or_default]
    pub app_name: Option<AttrValue>,
    /// Disables the form, such as while saving.
    #[prop_or_default]
    pub disabled: bool,
    /// Classes added to the outermost element.
    #[prop_or_default]
    pub class: Classes,
}

/// The Cloudflare Access settings form: setup instructions, whether signing
/// in through Access is enabled, the team domain and audience, whether to
/// verify the Access token and trust the email header, and a warning when
/// the header is trusted without verifying the token.
#[function_component]
pub fn CloudflareSettings(props: &CloudflareSettingsProps) -> Html {
    let phrases = use_phrases();
    let value = &props.value;
    let disabled = props.disabled;
    let app = match &props.app_name {
        Some(app) => app.clone(),
        None => AttrValue::from(phrases.text("watchword-cloudflare-the-app")),
    };
    let with_app = |id: &str| phrases.msg(id, &args!(app = app.as_str()));
    let team_domain_step = placed(
        &phrases,
        "watchword-cloudflare-step-team-domain",
        "host",
        "<team>.cloudflareaccess.com",
        |host| html! { <code>{host}</code> },
    );

    let update = |apply: fn(&mut CloudflareConfig, &Event)| {
        let value = props.value.clone();
        let on_change = props.on_change.clone();

        Callback::from(move |e: Event| {
            let mut value = value.clone();
            apply(&mut value, &e);
            on_change.emit(value);
        })
    };

    let on_enabled = update(|c, e| c.enabled = browser::checked(e));
    let on_team_domain = update(|c, e| c.team_domain = browser::event_value(e).trim().to_owned());
    let on_audience = update(|c, e| c.audience = browser::event_value(e).trim().to_owned());
    let on_verify_jwt = update(|c, e| c.verify_jwt = browser::checked(e));
    let on_trust_email_header = update(|c, e| c.trust_email_header = browser::checked(e));

    html! {
        <section class={classes!("auth-cloudflare-settings", props.class.clone())}>
            <h2 class="auth-heading">{phrases.text("watchword-cloudflare-heading")}</h2>

            <div class="auth-instructions">
                <p>{with_app("watchword-cloudflare-intro")}</p>
                <ol>
                    <li>{with_app("watchword-cloudflare-step-protect")}</li>
                    <li>{team_domain_step}</li>
                    <li>{phrases.text("watchword-cloudflare-step-audience")}</li>
                    <li>{phrases.text("watchword-cloudflare-step-users")}</li>
                    <li>{phrases.text("watchword-cloudflare-step-enable")}</li>
                </ol>
            </div>

            <div class="auth-form">
                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.enabled} onchange={on_enabled} {disabled} />
                        {phrases.text("watchword-cloudflare-enabled")}
                    </label>
                    <span class="auth-hint">{phrases.text("watchword-cloudflare-enabled-hint")}</span>
                </div>

                <div class="auth-field">
                    <label for="auth-cloudflare-team-domain">{phrases.text("watchword-cloudflare-team-domain")}</label>
                    <input
                        id="auth-cloudflare-team-domain"
                        class="auth-input"
                        type="text"
                        placeholder="yourteam.cloudflareaccess.com"
                        autocapitalize="none"
                        spellcheck="false"
                        value={value.team_domain.clone()}
                        onchange={on_team_domain}
                        {disabled}
                    />
                    <span class="auth-hint">{phrases.text("watchword-cloudflare-team-domain-hint")}</span>
                </div>

                <div class="auth-field">
                    <label for="auth-cloudflare-audience">{phrases.text("watchword-cloudflare-audience")}</label>
                    <input
                        id="auth-cloudflare-audience"
                        class="auth-input"
                        type="text"
                        autocapitalize="none"
                        spellcheck="false"
                        value={value.audience.clone()}
                        onchange={on_audience}
                        {disabled}
                    />
                    <span class="auth-hint">{with_app("watchword-cloudflare-audience-hint")}</span>
                </div>

                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.verify_jwt} onchange={on_verify_jwt} {disabled} />
                        {phrases.text("watchword-cloudflare-verify-jwt")}
                    </label>
                    <span class="auth-hint">{phrases.text("watchword-cloudflare-verify-jwt-hint")}</span>
                </div>

                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.trust_email_header} onchange={on_trust_email_header} {disabled} />
                        {phrases.text("watchword-cloudflare-trust-email")}
                    </label>
                    <span class="auth-hint">{phrases.text("watchword-cloudflare-trust-email-hint")}</span>
                </div>

                if header_unverified(value) {
                    <p class="auth-error" role="alert">
                        {phrases.text("watchword-cloudflare-unverified-warning")}
                    </p>
                }
            </div>
        </section>
    }
}

/// Whether the settings trust the email header without verifying the token,
/// which lets anyone who reaches the server directly sign in as any user.
pub(super) fn header_unverified(config: &CloudflareConfig) -> bool {
    config.enabled && config.trust_email_header && !config.verify_jwt
}
