use yew::prelude::*;

use super::browser;
use crate::types::CloudflareConfig;

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
    /// The app's name, used in the setup instructions.
    #[prop_or(AttrValue::Static("the app"))]
    pub app_name: AttrValue,
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
    let value = &props.value;
    let disabled = props.disabled;
    let app = props.app_name.clone();

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
            <h2 class="auth-heading">{"Cloudflare Access"}</h2>

            <div class="auth-instructions">
                <p>
                    {format!("Signs people in with their Cloudflare Zero Trust login when {app} sits behind Cloudflare Access. To set it up:")}
                </p>
                <ol>
                    <li>{format!("In the Zero Trust dashboard, protect {app} with a self-hosted application under Access → Applications.")}</li>
                    <li>
                        {"Enter your team domain below: the "}
                        <code>{"<team>.cloudflareaccess.com"}</code>
                        {" host. The server fetches Cloudflare's signing keys from it and checks that tokens were issued by it."}
                    </li>
                    <li>
                        {"Copy the application's Application Audience (AUD) Tag from its overview into Audience. Every application in your team is signed with the same keys, so the tag is what stops a token for another application from signing in here."}
                    </li>
                    <li>
                        {"Give each person's account the email they sign in to Cloudflare with, on the Users page. Access only signs in existing users; it never creates them."}
                    </li>
                    <li>{"Turn on Sign in through Access."}</li>
                </ol>
            </div>

            <div class="auth-form">
                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.enabled} onchange={on_enabled} {disabled} />
                        {"Sign in through Access"}
                    </label>
                    <span class="auth-hint">
                        {"Signs in the existing user whose email Cloudflare Access reports. Users are never created."}
                    </span>
                </div>

                <div class="auth-field">
                    <label for="auth-cloudflare-team-domain">{"Team domain"}</label>
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
                    <span class="auth-hint">
                        {"The host of your Zero Trust team, such as yourteam.cloudflareaccess.com."}
                    </span>
                </div>

                <div class="auth-field">
                    <label for="auth-cloudflare-audience">{"Audience"}</label>
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
                    <span class="auth-hint">
                        {format!("The Application Audience (AUD) Tag from the Access application protecting {app}: a long hex string.")}
                    </span>
                </div>

                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.verify_jwt} onchange={on_verify_jwt} {disabled} />
                        {"Verify token"}
                    </label>
                    <span class="auth-hint">
                        {"Checks the signed Access token against your team's keys. Keep this on unless the server is only reachable through Cloudflare."}
                    </span>
                </div>

                <div class="auth-field auth-toggle">
                    <label>
                        <input type="checkbox" checked={value.trust_email_header} onchange={on_trust_email_header} {disabled} />
                        {"Trust email header"}
                    </label>
                    <span class="auth-hint">
                        {"Accepts the email header Access adds. With token verification on, the two must match."}
                    </span>
                </div>

                if header_unverified(value) {
                    <p class="auth-error" role="alert">
                        {"Without Verify token, anyone who can reach the server without going through Cloudflare can sign in as any user by sending this header."}
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
