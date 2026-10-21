use std::borrow::ToOwned;

use phrasebook02::yew023::{html_around, use_phrases_with};
use phrasebook02::{Args, Phrases, args};
use yew::platform::spawn_local;
use yew::prelude::*;

use super::browser;
use super::context::use_auth;
use super::http::Error;
use super::l10n::{self, error_message};
use watchword_core::phrasebook02::L10N;
use watchword_core::{AuthError, CloudflareConfig};

/// The properties of [`AdminCloudflare`].
#[derive(Properties, PartialEq)]
pub struct AdminCloudflareProps {
    /// The app's name, used in the setup instructions, as for
    /// [`CloudflareSettings`].
    #[prop_or_default]
    pub app_name: Option<AttrValue>,
    /// Called with the settings as stored, each time a change is saved.
    #[prop_or_default]
    pub on_saved: Option<Callback<CloudflareConfig>>,
    /// Classes added to the outermost element.
    #[prop_or_default]
    pub class: Classes,
}

/// The settings as loaded, while loading, or why they could not be.
#[derive(Clone, PartialEq)]
enum Loaded {
    Loading,
    Settings(CloudflareConfig),
    Failed(AttrValue),
}

#[derive(Clone, PartialEq)]
enum Message {
    Error(AttrValue),
    Notice(AttrValue),
}

/// The Cloudflare Access settings page for admins, which loads and saves the
/// settings the server keeps itself, over the `/api/auth/cloudflare` routes
/// (`GET` and `PUT`).
///
/// It shows [`CloudflareSettings`] once the settings are loaded and saves
/// each change as it is made: a toggle, or a text field once it is left.
/// While a change saves, the form is disabled; a failed save puts the
/// settings back as they were and says why. After a save, the
/// [`AuthContext`](super::AuthContext) fetches the config again, since
/// whether Access can sign anyone in may have changed. A server built
/// without Cloudflare Access is reported as such.
///
/// Use it inside [`AuthProvider`](super::AuthProvider), for an admin. With
/// the `musliweb05` feature and a socket handed to
/// [`AuthContext::set_socket`](super::AuthContext::set_socket), its requests
/// go over the socket while it is open.
///
/// An app that places the fields in a form of its own, and stores the
/// settings itself, uses [`CloudflareSettings`] instead.
#[function_component]
pub fn AdminCloudflare(props: &AdminCloudflareProps) -> Html {
    let auth = use_auth();
    let phrases = use_phrases_with(&L10N);
    let loaded = use_state(|| Loaded::Loading);
    let saving = use_state(|| false);
    let message = use_state(|| None::<Message>);

    {
        let auth = auth.clone();
        let phrases = phrases.clone();
        let loaded = loaded.clone();

        use_effect_with((), move |()| {
            spawn_local(async move {
                match auth.client().cloudflare_settings().await {
                    Ok(settings) => loaded.set(Loaded::Settings(settings)),
                    Err(error) => {
                        let text = failure(&phrases, &error, "watchword-failed-loading-cloudflare");
                        loaded.set(Loaded::Failed(text));

                        if error.is_unauthorized() {
                            auth.check_session();
                        }
                    }
                }
            });
        });
    }

    let on_change = {
        let auth = auth.clone();
        let phrases = phrases.clone();
        let loaded = loaded.clone();
        let saving = saving.clone();
        let message = message.clone();
        let on_saved = props.on_saved.clone();

        Callback::from(move |settings: CloudflareConfig| {
            if *saving {
                return;
            }

            let Loaded::Settings(previous) = (*loaded).clone() else {
                return;
            };

            // Shown at once, so a toggle does not flip back while saving.
            loaded.set(Loaded::Settings(settings.clone()));
            saving.set(true);
            message.set(None);

            let auth = auth.clone();
            let phrases = phrases.clone();
            let loaded = loaded.clone();
            let saving = saving.clone();
            let message = message.clone();
            let on_saved = on_saved.clone();

            spawn_local(async move {
                match auth.client().set_cloudflare_settings(&settings).await {
                    Ok(stored) => {
                        loaded.set(Loaded::Settings(stored.clone()));
                        message.set(Some(Message::Notice(l10n::text(
                            &phrases,
                            "watchword-saved",
                        ))));
                        // Whether Access can sign anyone in may have changed.
                        auth.refresh();

                        if let Some(on_saved) = &on_saved {
                            on_saved.emit(stored);
                        }
                    }
                    Err(error) => {
                        loaded.set(Loaded::Settings(previous));
                        message.set(Some(Message::Error(failure(
                            &phrases,
                            &error,
                            "watchword-failed-saving",
                        ))));

                        if error.is_unauthorized() {
                            auth.check_session();
                        }
                    }
                }

                saving.set(false);
            });
        })
    };

    let body = match &*loaded {
        Loaded::Loading => html! {
            <p class="auth-status" role="status">{phrases.text("watchword-cloudflare-loading")}</p>
        },
        Loaded::Failed(error) => html! {
            <div class="auth-message" role="alert">
                <p class="auth-error">{error.clone()}</p>
            </div>
        },
        Loaded::Settings(settings) => html! {
            <>
                <div class="auth-message" role="alert">
                    {match &*message {
                        Some(Message::Error(error)) => html! { <p class="auth-error">{error.clone()}</p> },
                        Some(Message::Notice(notice)) => html! { <p class="auth-notice">{notice.clone()}</p> },
                        None => Html::default(),
                    }}
                </div>
                <CloudflareSettings
                    value={settings.clone()}
                    {on_change}
                    app_name={props.app_name.clone()}
                    disabled={*saving}
                />
            </>
        },
    };

    html! {
        <section class={classes!("auth-admin-cloudflare", props.class.clone())}>
            {body}
        </section>
    }
}

/// The message for a failed request of [`AdminCloudflare`], where
/// `failed_id` is the `watchword-failed-` message for an unexpected failure.
pub(super) fn failure(phrases: &Phrases, error: &Error, failed_id: &str) -> AttrValue {
    match error {
        // The server has no settings routes: it is built without Access.
        Error::Auth(AuthError::NotFound) => l10n::text(phrases, "watchword-cloudflare-unavailable"),
        error => error_message(phrases, error, failed_id),
    }
}

/// The properties of [`CloudflareSettings`].
#[derive(Properties, PartialEq)]
pub struct CloudflareSettingsProps {
    /// The settings shown.
    pub value: CloudflareConfig,
    /// Called with the changed settings on each change: a toggle, or a text
    /// field once it is left. The app saves them, such as with
    /// [`http::set_cloudflare_settings`](super::http::set_cloudflare_settings)
    /// (which [`AdminCloudflare`] does for it), and passes them back as
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
    let phrases = use_phrases_with(&L10N);
    let value = &props.value;
    let disabled = props.disabled;
    let app = match &props.app_name {
        Some(app) => app.clone(),
        None => AttrValue::from(phrases.text("watchword-cloudflare-the-app")),
    };
    let with_app = |id: &str| phrases.msg(id, &args!(app = app.as_str()));
    let team_domain_step = html_around(
        &phrases,
        "watchword-cloudflare-step-team-domain",
        &Args::new(),
        "host",
        html! { <code>{"<team>.cloudflareaccess.com"}</code> },
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
