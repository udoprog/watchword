use std::borrow::ToOwned;
use std::collections::HashMap;
use std::ops::Range;
use std::rc::Rc;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

use jiff::Timestamp;
use phrasebook02::yew023::{PhrasesContext, html_around};
use phrasebook02::{Args, Phrases, args};
use yew::context::ContextHandle;
use yew::prelude::*;

use super::Error;
use super::browser;
use super::context::AuthContext;
use super::form::{identity_change, optional};
use super::l10n::{self, error_message, role_name};
use super::listener::Listener;
use super::service::AuthService;
use super::users::{Users, UsersStore, retain_links};
use watchword_core::phrasebook02::L10N;
use watchword_core::{
    Access, CreatedUser, Link, Method, NewUser, Role, UserChange, UserEntry, UserId, UserInfo,
};

/// The default `page_size` of [`AdminUsers`].
pub const PAGE_SIZE: usize = 25;

/// The filter and page of [`AdminUsers`], which an app can keep in its URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsersQuery {
    /// Only users whose login or email contains this, ignoring case. Empty
    /// shows every user.
    pub filter: String,
    /// The page, counted from 0.
    pub page: usize,
}

/// The properties of [`AdminUsers`].
#[derive(Properties, PartialEq)]
pub struct AdminUsersProps {
    /// The signed-in admin, whose own row offers no role change, sign out,
    /// revoke, impersonate or delete. Defaults to the user of the
    /// [`AuthContext`]; only needed outside an
    /// [`AuthProvider`](super::AuthProvider).
    #[prop_or_default]
    pub me: Option<Rc<UserInfo>>,
    /// Offers Impersonate when set, which the server must enable. It is
    /// called with the user once this browser is signed in as them; the app
    /// then reloads the user, such as with [`AuthContext::refresh`], and
    /// leaves the admin page.
    #[prop_or_default]
    pub on_impersonate: Option<Callback<UserInfo>>,
    /// Bump it to fetch the users again, such as when the app learns of a
    /// change made elsewhere; the same as [`Users::reload`]. Not needed once
    /// the app hands its musli-web socket to [`AuthContext::set_socket`]
    /// (feature `musliweb05`): the list then follows the server's broadcasts
    /// itself.
    #[prop_or_default]
    pub refresh: u64,
    /// Renders app content under a user, such as their groups.
    #[prop_or_default]
    pub extra: Option<Callback<UserInfo, Html>>,
    /// The filter and page. Without `on_query_change` this is only where the
    /// list starts, and the component keeps the query itself.
    #[prop_or_default]
    pub query: UsersQuery,
    /// Called with the new query when the user filters or pages, which makes
    /// `query` the one shown: the app keeps it, such as in its URL, and
    /// passes it back.
    #[prop_or_default]
    pub on_query_change: Option<Callback<UsersQuery>>,
    /// How many users a page shows.
    #[prop_or(PAGE_SIZE)]
    pub page_size: usize,
    /// Classes added to the outermost element.
    #[prop_or_default]
    pub class: Classes,
}

/// Admin user management over the `/api/auth/users` routes.
///
/// It lists the users with a filter and pages, each with their account state,
/// sign-in method and link state, and offers:
///
/// - Add user, which shows the new user's registration link once, with Copy;
/// - editing a user's login (when the app uses logins) and email;
/// - the role, except on the admin's own row;
/// - a new link, shown once with Copy, which also restores a revoked user,
///   and revoking a live link;
/// - Sign out everywhere, Revoke access, Impersonate (with `on_impersonate`)
///   and Delete, except on the admin's own row. Revoke access and Delete ask
///   for confirmation.
///
/// Use it inside [`AuthProvider`](super::AuthProvider): the context gives the
/// admin (unless `me` is set), says whether the app uses logins, keeps the
/// admin's own user current when they edit themselves, and signs out when a
/// request finds the session ended.
///
/// It shows the provider's shared [`Users`], so an app component that shows
/// the users too, through [`use_users`](super::use_users), does not fetch
/// them again, and sees the changes made here. Outside a provider it keeps a
/// list of its own.
///
/// With the `musliweb05` feature and a socket handed to
/// [`AuthContext::set_socket`], the list follows the server's
/// `AuthBroadcast`: users created, changed or deleted elsewhere, such as by
/// another admin, change in the list in place. A broadcast does not carry
/// link state, so the list is fetched again when it cannot be known: for a
/// user created elsewhere, and when a user's account state or sign-in method
/// changes, which uses up their links. It makes its requests with the
/// provider's [`AuthService`], so they go over the socket while it is open,
/// except Impersonate.
///
/// Its text comes from the [`Phrases`](phrasebook02::Phrases) the app
/// provides, falling back to watchword's English (see [`L10N`](super::L10N)).
pub struct AdminUsers {
    /// The list as last told.
    users: Users,
    /// Where the list comes from: the provider's, or this one's own.
    store: UsersStore,
    _users: Listener,
    /// The failed loads already shown.
    failures: u64,
    /// The context, when inside a provider.
    auth: Option<AuthContext>,
    /// Keeps this subscribed to the context.
    _context: Option<ContextHandle<AuthContext>>,
    /// The service the requests are made with.
    service: AuthService,
    /// Keeps this subscribed to the service.
    _service: Option<ContextHandle<AuthService>>,
    /// The app's phrases, with watchword's catalog as the backstop.
    l10n: PhrasesContext,
    /// The query when the app does not keep it.
    query: UsersQuery,
    adding: Option<UserForm>,
    editing: Option<(UserId, UserForm)>,
    confirm: Option<(UserId, Action)>,
    /// Links issued here, whose tokens are shown only this once.
    links: HashMap<UserId, Link>,
    busy: bool,
    message: Option<Message>,
}

/// The fields of the add and edit forms.
#[derive(Clone, PartialEq)]
struct UserForm {
    login: String,
    email: String,
    role: Role,
}

/// An action on a user that answers with nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    RevokeLink,
    SignOut,
    RevokeAccess,
    Impersonate,
    Delete,
}

#[derive(Clone, PartialEq)]
enum Message {
    Error(AttrValue),
    Notice(AttrValue),
}

/// Which field of a form an input is for.
#[derive(Clone, Copy)]
pub enum Field {
    Login,
    Email,
}

/// The messages of [`AdminUsers`].
pub enum Msg {
    Load,
    Users(Users),
    Filter(String),
    Page(usize),
    StartAdd,
    CancelAdd,
    AddInput(Field, String),
    AddRole(Role),
    SubmitAdd,
    Added(Result<CreatedUser, Error>),
    StartEdit(UserId),
    CancelEdit,
    EditInput(Field, String),
    SubmitEdit,
    SetRole(UserId, Role),
    /// With the id of the notice shown on success.
    Updated(Result<UserInfo, Error>, &'static str),
    IssueLink(UserId),
    Issued(UserId, Result<Link, Error>),
    Confirm(UserId, Action),
    CancelConfirm,
    Act(UserId, Action),
    Done(UserId, Action, Result<(), Error>),
    Copy(String),
    Copied(bool),
    Context(AuthContext),
    Service(AuthService),
    Phrases(Phrases),
}

impl Component for AdminUsers {
    type Message = Msg;
    type Properties = AdminUsersProps;

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link();

        let l10n = PhrasesContext::new_with(link, link.callback(Msg::Phrases), &L10N);

        let context = link.context::<AuthContext>(link.callback(Msg::Context));
        let (auth, _context) = context.unzip();

        let store = match &auth {
            Some(auth) => auth.users.clone(),
            None => UsersStore::new(AuthService::default(), Callback::noop()),
        };

        let (service, _service) = match link.context::<AuthService>(link.callback(Msg::Service)) {
            Some((service, handle)) => (service, Some(handle)),
            None => (AuthService::default(), None),
        };

        let (users, _users) = store.subscribe(link.callback(Msg::Users));

        Self {
            failures: users.failures(),
            users,
            store,
            _users,
            auth,
            _context,
            service,
            _service,
            l10n,
            query: ctx.props().query.clone(),
            adding: None,
            editing: None,
            confirm: None,
            links: HashMap::new(),
            busy: false,
            message: None,
        }
    }

    fn changed(&mut self, ctx: &Context<Self>, old: &Self::Properties) -> bool {
        if ctx.props().refresh != old.refresh {
            self.store.load();
        }

        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Load => {
                self.store.load();
                return false;
            }
            Msg::Users(users) => {
                // Links that are no longer live are no use to show.
                if let Some(entries) = users.entries() {
                    retain_links(&mut self.links, entries);
                }

                // A list already shown stays; say why it is stale.
                if users.failures() != self.failures {
                    self.failures = users.failures();

                    if let (Some(..), Some(error)) = (users.entries(), users.error()) {
                        self.message = Some(Message::Error(error_message(
                            self.l10n.phrases(),
                            error,
                            "watchword-failed-loading-users",
                        )));
                    }
                }

                self.users = users;
            }
            Msg::Filter(filter) => {
                self.set_query(ctx, UsersQuery { filter, page: 0 });
            }
            Msg::Page(page) => {
                let filter = self.query(ctx).filter.clone();
                self.set_query(ctx, UsersQuery { filter, page });
            }
            Msg::StartAdd => {
                self.adding = Some(UserForm {
                    login: String::new(),
                    email: String::new(),
                    role: Role::Regular,
                });
                self.message = None;
            }
            Msg::CancelAdd => {
                self.adding = None;
            }
            Msg::AddInput(field, value) => {
                if let Some(form) = &mut self.adding {
                    form.set(field, value);
                }
            }
            Msg::AddRole(role) => {
                if let Some(form) = &mut self.adding {
                    form.role = role;
                }
            }
            Msg::SubmitAdd => {
                let Some(form) = &self.adding else {
                    return false;
                };

                if self.busy {
                    return false;
                }

                let logins = self.logins(ctx);
                let login = logins.then(|| optional(&form.login)).flatten();
                let email = optional(&form.email);

                if let Err(error) =
                    identity_change((None, None), login.clone(), email.clone(), logins)
                {
                    self.message = Some(Message::Error(AttrValue::from(l10n::invalid(
                        self.l10n.phrases(),
                        &error,
                    ))));
                    return true;
                }

                let new = NewUser {
                    login,
                    email,
                    role: form.role,
                };

                self.busy = true;
                self.message = None;
                let service = self.service.clone();
                ctx.link()
                    .send_future(async move { Msg::Added(service.create_user(new).await) });
            }
            Msg::Added(result) => {
                self.busy = false;

                match result {
                    Ok(CreatedUser { entry, link }) => {
                        let id = entry.user.id;
                        let filter = entry.user.name().to_owned();

                        // The broadcast of the new user may have come first.
                        self.store.modify(|users| {
                            match users.iter_mut().find(|e| e.user.id == id) {
                                Some(existing) => *existing = entry,
                                None => users.push(entry),
                            }
                        });

                        self.links.insert(id, link);
                        self.adding = None;
                        self.message = Some(Message::Notice(l10n::text(
                            self.l10n.phrases(),
                            "watchword-user-added",
                        )));
                        // Show the new user, wherever they sort.
                        self.set_query(ctx, UsersQuery { filter, page: 0 });
                    }
                    Err(error) => {
                        self.message = Some(Message::Error(error_message(
                            self.l10n.phrases(),
                            &error,
                            "watchword-failed-adding-user",
                        )));
                        self.check_unauthorized(&error);
                    }
                }
            }
            Msg::StartEdit(id) => {
                let Some(entry) = self.entry(id) else {
                    return false;
                };

                let user = &entry.user;

                self.editing = Some((
                    id,
                    UserForm {
                        login: user.login.clone().unwrap_or_default(),
                        email: user.email.clone().unwrap_or_default(),
                        role: user.role,
                    },
                ));
                self.confirm = None;
                self.message = None;
            }
            Msg::CancelEdit => {
                self.editing = None;
            }
            Msg::EditInput(field, value) => {
                if let Some((_, form)) = &mut self.editing {
                    form.set(field, value);
                }
            }
            Msg::SubmitEdit => {
                let Some((id, form)) = &self.editing else {
                    return false;
                };

                let Some(entry) = self.entry(*id) else {
                    return false;
                };

                if self.busy {
                    return false;
                }

                let logins = self.logins(ctx);
                let user = &entry.user;
                let login = if logins {
                    optional(&form.login)
                } else {
                    user.login.clone()
                };

                let change = match identity_change(
                    (user.login.as_deref(), user.email.as_deref()),
                    login,
                    optional(&form.email),
                    logins,
                ) {
                    Ok(change) => change,
                    Err(error) => {
                        self.message = Some(Message::Error(AttrValue::from(l10n::invalid(
                            self.l10n.phrases(),
                            &error,
                        ))));
                        return true;
                    }
                };

                if change == UserChange::default() {
                    self.editing = None;
                    return true;
                }

                self.update_user(ctx, *id, change, "watchword-saved");
            }
            Msg::SetRole(id, role) => {
                if self.busy {
                    return true;
                }

                let change = UserChange {
                    role: Some(role),
                    ..UserChange::default()
                };

                self.update_user(ctx, id, change, "watchword-role-changed");
            }
            Msg::Updated(result, notice) => {
                self.busy = false;

                match result {
                    Ok(user) => {
                        if self.me_id(ctx) == Some(user.id)
                            && let Some(auth) = &self.auth
                        {
                            auth.set_user(user.clone());
                        }

                        if self.editing.as_ref().is_some_and(|(id, _)| *id == user.id) {
                            self.editing = None;
                        }

                        self.store.modify(|users| {
                            if let Some(entry) = users.iter_mut().find(|e| e.user.id == user.id) {
                                entry.user = user;
                            }
                        });

                        self.message =
                            Some(Message::Notice(l10n::text(self.l10n.phrases(), notice)));
                    }
                    Err(error) => {
                        self.message = Some(Message::Error(error_message(
                            self.l10n.phrases(),
                            &error,
                            "watchword-failed-saving",
                        )));
                        self.check_unauthorized(&error);
                    }
                }
            }
            Msg::IssueLink(id) => {
                if self.busy {
                    return false;
                }

                self.busy = true;
                self.message = None;
                let service = self.service.clone();
                ctx.link()
                    .send_future(async move { Msg::Issued(id, service.issue_link(id).await) });
            }
            Msg::Issued(id, result) => {
                self.busy = false;

                match result {
                    Ok(link) => {
                        let expires_at = link.expires_at;

                        self.store.modify(|users| {
                            if let Some(entry) = users.iter_mut().find(|e| e.user.id == id) {
                                entry.link_expires_at = Some(expires_at);

                                // A new link restores a revoked user.
                                if entry.user.access == Access::Revoked {
                                    entry.user.access = Access::Pending;
                                }
                            }
                        });

                        self.links.insert(id, link);
                        self.message = None;
                        // The account state may have changed with it.
                        self.store.load();
                    }
                    Err(error) => {
                        self.message = Some(Message::Error(error_message(
                            self.l10n.phrases(),
                            &error,
                            "watchword-failed-issuing-link",
                        )));
                        self.check_unauthorized(&error);
                    }
                }
            }
            Msg::Confirm(id, action) => {
                self.confirm = Some((id, action));
                self.editing = None;
            }
            Msg::CancelConfirm => {
                self.confirm = None;
            }
            Msg::Act(id, action) => {
                if self.busy {
                    return false;
                }

                self.busy = true;
                self.confirm = None;
                self.message = None;

                let service = self.service.clone();

                ctx.link().send_future(async move {
                    let result = match action {
                        Action::RevokeLink => service.revoke_link(id).await,
                        Action::SignOut => service.sign_out_user(id).await,
                        Action::RevokeAccess => service.revoke_access(id).await.map(drop),
                        // The provider's transport stops using a socket that
                        // speaks for the session this replaced.
                        Action::Impersonate => service.impersonate(id).await.map(drop),
                        Action::Delete => service.delete_user(id).await,
                    };

                    Msg::Done(id, action, result)
                });
            }
            Msg::Done(id, action, result) => {
                self.busy = false;

                if let Err(error) = result {
                    self.message = Some(Message::Error(error_message(
                        self.l10n.phrases(),
                        &error,
                        action.failed(),
                    )));
                    self.check_unauthorized(&error);
                    return true;
                }

                self.message = Some(Message::Notice(l10n::text(
                    self.l10n.phrases(),
                    action.done(),
                )));

                match action {
                    Action::RevokeLink => {
                        self.links.remove(&id);

                        self.store.modify(|users| {
                            if let Some(entry) = users.iter_mut().find(|e| e.user.id == id) {
                                entry.link_expires_at = None;
                            }
                        });
                    }
                    Action::SignOut => {}
                    Action::RevokeAccess => {
                        self.links.remove(&id);
                        self.store.load();
                    }
                    Action::Impersonate => {
                        let user = self.entry(id).map(|e| e.user.clone());

                        if let (Some(user), Some(on_impersonate)) =
                            (user, &ctx.props().on_impersonate)
                        {
                            on_impersonate.emit(user);
                        }
                    }
                    Action::Delete => {
                        self.links.remove(&id);
                        self.store.modify(|users| users.retain(|e| e.user.id != id));
                    }
                }
            }
            Msg::Copy(text) => {
                ctx.link()
                    .send_future(async move { Msg::Copied(browser::copy_text(&text).await) });
                return false;
            }
            Msg::Copied(ok) => {
                self.message = Some(if ok {
                    Message::Notice(l10n::text(self.l10n.phrases(), "watchword-link-copied"))
                } else {
                    Message::Error(l10n::text(self.l10n.phrases(), "watchword-copy-refused"))
                });
            }
            Msg::Context(auth) => {
                // A provider keeps its list, so this only changes with the
                // provider.
                if auth.users != self.store {
                    self.store = auth.users.clone();
                    let (users, listener) = self.store.subscribe(ctx.link().callback(Msg::Users));
                    self.failures = users.failures();
                    self.users = users;
                    self._users = listener;
                }

                self.auth = Some(auth);
            }
            Msg::Service(service) => {
                self.service = service;
                return false;
            }
            Msg::Phrases(phrases) => return self.l10n.set(phrases),
        }

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = ctx.props();
        let link = ctx.link();
        let query = self.query(ctx);
        let phrases = self.l10n.phrases();

        let message = html! {
            <div class="auth-message" role="alert">
                {match &self.message {
                    Some(Message::Error(error)) => html! { <p class="auth-error">{error.clone()}</p> },
                    Some(Message::Notice(notice)) => html! { <p class="auth-notice">{notice.clone()}</p> },
                    None => Html::default(),
                }}
            </div>
        };

        let body = match (self.users.entries(), self.users.error()) {
            (Some(users), _) => self.view_users(ctx, users, query),
            (None, Some(error)) if !self.users.is_loading() => html! {
                <div class="auth-message" role="alert">
                    <p class="auth-error">{error_message(phrases, error, "watchword-failed-loading-users")}</p>
                    <button type="button" class="auth-retry" onclick={link.callback(|_| Msg::Load)}>{phrases.text("watchword-retry")}</button>
                </div>
            },
            (None, _) => html! {
                <p class="auth-status" role="status">{phrases.text("watchword-users-loading")}</p>
            },
        };

        html! {
            <section class={classes!("auth-admin-users", props.class.clone())}>
                <div class="auth-toolbar">
                    <h2 class="auth-heading">{phrases.text("watchword-users")}</h2>

                    if self.adding.is_none() {
                        <button type="button" class="auth-add" onclick={link.callback(|_| Msg::StartAdd)}>
                            {phrases.text("watchword-add-user")}
                        </button>
                    }
                </div>

                {message}
                {self.view_add(ctx)}

                <div class="auth-filter">
                    <input
                        class="auth-input"
                        type="search"
                        placeholder={phrases.text("watchword-filter")}
                        aria-label={phrases.text("watchword-filter-users")}
                        value={query.filter.clone()}
                        oninput={link.callback(|e: InputEvent| Msg::Filter(browser::input_value(&e)))}
                    />

                    if !query.filter.is_empty() {
                        <button type="button" class="auth-clear" onclick={link.callback(|_| Msg::Filter(String::new()))}>
                            {phrases.text("watchword-clear-filter")}
                        </button>
                    }
                </div>

                {body}
            </section>
        }
    }
}

impl AdminUsers {
    /// The signed-in admin: `me`, or the context's user.
    fn me<'a>(&'a self, ctx: &'a Context<Self>) -> Option<&'a UserInfo> {
        match &ctx.props().me {
            Some(me) => Some(me),
            None => self.auth.as_ref().map(|auth| &*auth.user),
        }
    }

    fn me_id(&self, ctx: &Context<Self>) -> Option<UserId> {
        self.me(ctx).map(|me| me.id)
    }

    /// Whether the app uses logins.
    fn logins(&self, ctx: &Context<Self>) -> bool {
        match &self.auth {
            Some(auth) => auth.config.logins,
            // Outside a provider, show logins when the admin has one.
            None => self.me(ctx).is_some_and(|me| me.login.is_some()),
        }
    }

    /// A 401 means the session may have ended, which the provider checks.
    fn check_unauthorized(&self, error: &Error) {
        if error.is_unauthorized()
            && let Some(auth) = &self.auth
        {
            auth.check_session();
        }
    }

    /// The query shown: the app's when it keeps it, otherwise this
    /// component's.
    fn query<'a>(&'a self, ctx: &'a Context<Self>) -> &'a UsersQuery {
        if ctx.props().on_query_change.is_some() {
            &ctx.props().query
        } else {
            &self.query
        }
    }

    fn set_query(&mut self, ctx: &Context<Self>, query: UsersQuery) {
        match &ctx.props().on_query_change {
            Some(on_query_change) => on_query_change.emit(query),
            None => self.query = query,
        }
    }

    fn entry(&self, id: UserId) -> Option<&UserEntry> {
        self.users.get(id)
    }

    fn update_user(
        &mut self,
        ctx: &Context<Self>,
        id: UserId,
        change: UserChange,
        notice: &'static str,
    ) {
        // `notice` is a message id.
        self.busy = true;
        self.message = None;
        let service = self.service.clone();
        ctx.link().send_future(async move {
            Msg::Updated(service.update_user(id, change).await, notice)
        });
    }

    fn view_add(&self, ctx: &Context<Self>) -> Html {
        let Some(form) = &self.adding else {
            return Html::default();
        };

        let link = ctx.link();
        let logins = self.logins(ctx);
        let phrases = self.l10n.phrases();

        let onsubmit = link.callback(|e: SubmitEvent| {
            e.prevent_default();
            Msg::SubmitAdd
        });

        html! {
            <form class="auth-form auth-add-user" {onsubmit}>
                <h3 class="auth-subheading">{phrases.text("watchword-add-user")}</h3>

                if logins {
                    <div class="auth-field">
                        <label for="auth-new-login">{phrases.text("watchword-login")}</label>
                        <input
                            id="auth-new-login"
                            class="auth-input"
                            type="text"
                            autocapitalize="none"
                            spellcheck="false"
                            value={form.login.clone()}
                            oninput={link.callback(|e: InputEvent| Msg::AddInput(Field::Login, browser::input_value(&e)))}
                            disabled={self.busy}
                        />
                    </div>
                }

                <div class="auth-field">
                    <label for="auth-new-email">{phrases.text("watchword-email")}</label>
                    <input
                        id="auth-new-email"
                        class="auth-input"
                        type="email"
                        required={!logins}
                        value={form.email.clone()}
                        oninput={link.callback(|e: InputEvent| Msg::AddInput(Field::Email, browser::input_value(&e)))}
                        disabled={self.busy}
                    />

                    if logins {
                        <span class="auth-hint">{phrases.text("watchword-new-email-hint")}</span>
                    }
                </div>

                <div class="auth-field">
                    <label for="auth-new-role">{phrases.text("watchword-role")}</label>
                    {role_select(phrases, "auth-new-role", form.role, self.busy, link.callback(Msg::AddRole))}
                </div>

                <p class="auth-hint">{phrases.text("watchword-new-user-hint")}</p>

                <div class="auth-actions">
                    <button type="button" onclick={link.callback(|_| Msg::CancelAdd)} disabled={self.busy}>{phrases.text("watchword-cancel")}</button>
                    <button type="submit" class="auth-submit" disabled={self.busy}>{phrases.text("watchword-add-user")}</button>
                </div>
            </form>
        }
    }

    fn view_users(&self, ctx: &Context<Self>, users: &[UserEntry], query: &UsersQuery) -> Html {
        let link = ctx.link();
        let logins = self.logins(ctx);
        let phrases = self.l10n.phrases();

        let mut shown = users
            .iter()
            .filter(|e| matches_filter(&e.user, &query.filter))
            .collect::<Vec<_>>();

        shown.sort_by(|a, b| {
            a.user
                .name()
                .cmp(b.user.name())
                .then(a.user.id.cmp(&b.user.id))
        });

        let page_size = ctx.props().page_size.max(1);
        let (page, pages, range) = page_bounds(shown.len(), page_size, query.page);
        let now = Timestamp::now();

        if shown.is_empty() {
            let text = if users.is_empty() {
                "watchword-users-none"
            } else {
                "watchword-users-no-match"
            };

            return html! { <p class="auth-status">{phrases.text(text)}</p> };
        }

        let labels = Labels::new(phrases);

        html! {
            <>
                <table class="auth-users">
                    <thead>
                        <tr>
                            if logins {
                                <th scope="col">{labels.login.clone()}</th>
                            }
                            <th scope="col">{labels.email.clone()}</th>
                            <th scope="col">{labels.role.clone()}</th>
                            <th scope="col">{labels.status.clone()}</th>
                            <th scope="col">{labels.link.clone()}</th>
                            <th scope="col"><span class="auth-hidden">{labels.actions.clone()}</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {for shown[range].iter().map(|e| self.view_user(ctx, e, now, &labels))}
                    </tbody>
                </table>

                if pages > 1 {
                    <nav class="auth-pages" aria-label={phrases.text("watchword-pages")}>
                        <button
                            type="button"
                            class="auth-previous"
                            disabled={page == 0}
                            onclick={link.callback(move |_| Msg::Page(page.saturating_sub(1)))}
                        >
                            {phrases.text("watchword-previous-page")}
                        </button>
                        <span class="auth-page-number">{phrases.msg("watchword-page-number", &args!(page = page + 1, pages = pages))}</span>
                        <button
                            type="button"
                            class="auth-next"
                            disabled={page + 1 >= pages}
                            onclick={link.callback(move |_| Msg::Page(page + 1))}
                        >
                            {phrases.text("watchword-next-page")}
                        </button>
                    </nav>
                }
            </>
        }
    }

    fn view_user(
        &self,
        ctx: &Context<Self>,
        entry: &UserEntry,
        now: Timestamp,
        labels: &Labels,
    ) -> Html {
        let props = ctx.props();
        let link = ctx.link();
        let logins = self.logins(ctx);
        let user = &entry.user;
        let id = user.id;
        let me = self.me_id(ctx) == Some(user.id);
        let name = user.name().to_owned();
        let busy = self.busy;
        let phrases = self.l10n.phrases();

        let editing = self
            .editing
            .as_ref()
            .filter(|(edit, _)| *edit == id)
            .map(|(_, form)| form);

        let (login_cell, email_cell) = match editing {
            Some(form) => (
                html! {
                    <input
                        class="auth-input"
                        type="text"
                        aria-label={phrases.text("watchword-login")}
                        autocapitalize="none"
                        spellcheck="false"
                        value={form.login.clone()}
                        oninput={link.callback(|e: InputEvent| Msg::EditInput(Field::Login, browser::input_value(&e)))}
                        disabled={busy}
                    />
                },
                html! {
                    <input
                        class="auth-input"
                        type="email"
                        aria-label={phrases.text("watchword-email")}
                        value={form.email.clone()}
                        oninput={link.callback(|e: InputEvent| Msg::EditInput(Field::Email, browser::input_value(&e)))}
                        disabled={busy}
                    />
                },
            ),
            None => (
                html! {
                    <span class="auth-value">{user.login.clone().unwrap_or_default()}</span>
                },
                match &user.email {
                    Some(email) => html! { <span class="auth-value">{email.clone()}</span> },
                    None => {
                        html! { <span class="auth-muted">{phrases.text("watchword-no-email")}</span> }
                    }
                },
            ),
        };

        let badge =
            me.then(|| html! { <span class="auth-badge">{phrases.text("watchword-you")}</span> });
        let extra = props.extra.as_ref().map(|extra| {
            html! { <div class="auth-user-extra">{extra.emit(user.clone())}</div> }
        });

        // The first cell names the user, so the badge and extra go there.
        let (login_cell, email_cell) = if logins {
            (
                Some(html! {
                    <td class="auth-user-login" data-label={labels.login.clone()}>{login_cell}{badge}{extra}</td>
                }),
                html! { <td class="auth-user-email" data-label={labels.email.clone()}>{email_cell}</td> },
            )
        } else {
            (
                None,
                html! {
                    <td class="auth-user-email" data-label={labels.email.clone()}>{email_cell}{badge}{extra}</td>
                },
            )
        };

        let role = if me {
            html! { <span class="auth-value">{role_name(phrases, user.role)}</span> }
        } else {
            role_select(
                phrases,
                &format!("auth-role-{id}"),
                user.role,
                busy,
                link.callback(move |role| Msg::SetRole(id, role)),
            )
        };

        let (access_class, access_label, access_title) = access(phrases, user);

        html! {
            <tr class={classes!("auth-user", me.then_some("auth-me"))}>
                {for login_cell}
                {email_cell}
                <td class="auth-user-role" data-label={labels.role.clone()}>{role}</td>
                <td class="auth-user-access" data-label={labels.status.clone()}>
                    <span class={classes!("auth-access", access_class)} title={access_title}>{access_label}</span>
                </td>
                <td class="auth-user-link" data-label={labels.link.clone()}>{self.view_link(ctx, entry, now)}</td>
                <td class="auth-user-actions" data-label={labels.actions.clone()}>
                    {self.view_actions(ctx, entry, me, &name, editing.is_some())}
                </td>
            </tr>
        }
    }

    fn view_link(&self, ctx: &Context<Self>, entry: &UserEntry, now: Timestamp) -> Html {
        let link = ctx.link();
        let name = entry.user.name();
        let phrases = self.l10n.phrases();

        if let Some(issued) = self.links.get(&entry.user.id) {
            let url = link_url(&browser::origin(), &issued.token);
            let copy = url.clone();

            return html! {
                <div class="auth-link">
                    <input class="auth-input auth-link-url" type="text" readonly=true value={url} title={phrases.msg("watchword-link-for", &args!(name = name))} />
                    <button
                        type="button"
                        class="auth-copy"
                        title={phrases.msg("watchword-copy-link-for", &args!(name = name))}
                        onclick={link.callback(move |_| Msg::Copy(copy.clone()))}
                    >
                        {phrases.text("watchword-copy")}
                    </button>
                    <span class="auth-hint">
                        {phrases.msg("watchword-link-send", &args!(name = name, expires = relative_time(phrases, now, issued.expires_at)))}
                    </span>
                </div>
            };
        }

        match entry.link_expires_at {
            Some(at) => html! {
                <span class="auth-link-state" title={at.to_string()}>{phrases.msg("watchword-link-expires", &args!(expires = relative_time(phrases, now, at)))}</span>
            },
            None => {
                html! { <span class="auth-link-state auth-muted">{phrases.text("watchword-no-link")}</span> }
            }
        }
    }

    fn view_actions(
        &self,
        ctx: &Context<Self>,
        entry: &UserEntry,
        me: bool,
        name: &str,
        editing: bool,
    ) -> Html {
        let props = ctx.props();
        let link = ctx.link();
        let user = &entry.user;
        let id = user.id;
        let busy = self.busy;
        let phrases = self.l10n.phrases();
        let named = |id: &str| phrases.msg(id, &args!(name = name));

        if editing {
            return html! {
                <div class="auth-actions">
                    <button type="button" onclick={link.callback(|_| Msg::CancelEdit)} disabled={busy}>{phrases.text("watchword-discard-changes")}</button>
                    <button type="button" class="auth-submit" onclick={link.callback(|_| Msg::SubmitEdit)} disabled={busy}>{phrases.text("watchword-save")}</button>
                </div>
            };
        }

        if let Some((_, action)) = self.confirm.filter(|(confirm, _)| *confirm == id) {
            let prompt = match action {
                Action::Delete => "watchword-confirm-delete",
                _ => "watchword-confirm-revoke-access",
            };
            let prompt = html_around(
                phrases,
                prompt,
                &Args::new(),
                "name",
                html! { <strong>{name}</strong> },
            );

            return html! {
                <div class="auth-confirm" role="group">
                    <span>{prompt}</span>
                    <button type="button" class="auth-confirm-no" onclick={link.callback(|_| Msg::CancelConfirm)}>{phrases.text("watchword-no")}</button>
                    <button type="button" class="auth-confirm-yes auth-danger" onclick={link.callback(move |_| Msg::Act(id, action))} disabled={busy}>{phrases.text("watchword-yes")}</button>
                </div>
            };
        }

        let live_link = entry.link_expires_at.is_some();
        let revoked = user.access == Access::Revoked;

        html! {
            <div class="auth-actions">
                <button type="button" title={named("watchword-edit-user")} onclick={link.callback(move |_| Msg::StartEdit(id))} disabled={busy}>
                    {phrases.text("watchword-edit")}
                </button>

                <button type="button" title={named("watchword-new-link-for")} onclick={link.callback(move |_| Msg::IssueLink(id))} disabled={busy}>
                    {phrases.text(if live_link { "watchword-new-link" } else { "watchword-link" })}
                </button>

                if live_link {
                    <button type="button" title={named("watchword-revoke-link-for")} onclick={link.callback(move |_| Msg::Act(id, Action::RevokeLink))} disabled={busy}>
                        {phrases.text("watchword-revoke-link")}
                    </button>
                }

                if !me {
                    <button type="button" title={named("watchword-sign-out-everywhere-user")} onclick={link.callback(move |_| Msg::Act(id, Action::SignOut))} disabled={busy}>
                        {phrases.text("watchword-sign-out-everywhere")}
                    </button>

                    if !revoked {
                        <button type="button" class="auth-danger" title={named("watchword-revoke-access-for")} onclick={link.callback(move |_| Msg::Confirm(id, Action::RevokeAccess))} disabled={busy}>
                            {phrases.text("watchword-revoke-access")}
                        </button>
                    }

                    if props.on_impersonate.is_some() && !revoked {
                        <button type="button" title={named("watchword-impersonate-user")} onclick={link.callback(move |_| Msg::Act(id, Action::Impersonate))} disabled={busy}>
                            {phrases.text("watchword-impersonate")}
                        </button>
                    }

                    <button type="button" class="auth-danger" title={named("watchword-delete-user")} onclick={link.callback(move |_| Msg::Confirm(id, Action::Delete))} disabled={busy}>
                        {phrases.text("watchword-delete")}
                    </button>
                }
            </div>
        }
    }
}

impl UserForm {
    fn set(&mut self, field: Field, value: String) {
        match field {
            Field::Login => self.login = value,
            Field::Email => self.email = value,
        }
    }
}

impl Action {
    /// The id of the message for its unexpected failure.
    fn failed(self) -> &'static str {
        match self {
            Action::RevokeLink => "watchword-failed-revoking-link",
            Action::SignOut => "watchword-failed-signing-out",
            Action::RevokeAccess => "watchword-failed-revoking-access",
            Action::Impersonate => "watchword-failed-impersonating",
            Action::Delete => "watchword-failed-deleting",
        }
    }

    /// The id of the notice once it is done.
    fn done(self) -> &'static str {
        match self {
            Action::RevokeLink => "watchword-link-revoked",
            Action::SignOut => "watchword-signed-out-everywhere",
            Action::RevokeAccess => "watchword-access-revoked",
            Action::Impersonate => "watchword-signed-in-as-user",
            Action::Delete => "watchword-user-deleted",
        }
    }
}

fn role_select(
    phrases: &Phrases,
    id: &str,
    role: Role,
    disabled: bool,
    onchange: Callback<Role>,
) -> Html {
    let onchange = Callback::from(move |e: Event| {
        if let Ok(role) = browser::select_value(&e).parse::<Role>() {
            onchange.emit(role);
        }
    });

    html! {
        <select id={id.to_owned()} class="auth-select" aria-label={phrases.text("watchword-role")} {onchange} {disabled}>
            {for [Role::Regular, Role::Admin].into_iter().map(|option| html! {
                <option value={option.as_str()} selected={option == role}>{role_name(phrases, option)}</option>
            })}
        </select>
    }
}

/// The column names of the users table, looked up once per render for its
/// header and the `data-label` of every body cell.
struct Labels {
    login: AttrValue,
    email: AttrValue,
    role: AttrValue,
    status: AttrValue,
    link: AttrValue,
    actions: AttrValue,
}

impl Labels {
    fn new(phrases: &Phrases) -> Self {
        Self {
            login: l10n::text(phrases, "watchword-login"),
            email: l10n::text(phrases, "watchword-email"),
            role: l10n::text(phrases, "watchword-role"),
            status: l10n::text(phrases, "watchword-status"),
            link: l10n::text(phrases, "watchword-link"),
            actions: l10n::text(phrases, "watchword-actions"),
        }
    }
}

/// The class, label and title of a user's account state.
fn access(phrases: &Phrases, user: &UserInfo) -> (&'static str, Rc<str>, String) {
    let method = match user.method {
        Method::Password => "password",
        Method::Google => "google",
    };

    let (class, label, title) = match user.access {
        Access::Pending => (
            "auth-pending",
            "watchword-access-pending",
            "watchword-access-pending-title",
        ),
        Access::Active => (
            "auth-active",
            "watchword-access-active",
            "watchword-access-active-title",
        ),
        Access::Revoked => (
            "auth-revoked",
            "watchword-access-revoked-label",
            "watchword-access-revoked-title",
        ),
    };

    (
        class,
        phrases.text(label),
        phrases.msg(title, &args!(method = method)),
    )
}

/// Whether a user's login or email contains the filter, ignoring case.
pub(super) fn matches_filter(user: &UserInfo, filter: &str) -> bool {
    let filter = filter.trim().to_lowercase();

    if filter.is_empty() {
        return true;
    }

    [&user.login, &user.email]
        .into_iter()
        .flatten()
        .any(|value| value.to_lowercase().contains(&filter))
}

/// The page actually shown (the last one when `page` is past it), the number
/// of pages, and the range of items on it.
pub(super) fn page_bounds(
    len: usize,
    page_size: usize,
    page: usize,
) -> (usize, usize, Range<usize>) {
    let pages = len.div_ceil(page_size).max(1);
    let page = page.min(pages - 1);
    let start = page * page_size;
    (page, pages, start..len.min(start + page_size))
}

/// The frontend URL a link's token is used at.
pub(super) fn link_url(origin: &str, token: &str) -> String {
    format!("{origin}/register/{token}")
}

/// When `at` is, from `now`, such as "in 7 days".
pub(super) fn relative_time(phrases: &Phrases, now: Timestamp, at: Timestamp) -> String {
    let seconds = at.as_second() - now.as_second();

    let (count, id) = match seconds {
        ..=0 => return phrases.text("watchword-time-now").to_string(),
        1..60 => return phrases.text("watchword-time-soon").to_string(),
        60..3_600 => (seconds / 60, "watchword-time-minutes"),
        3_600..86_400 => (seconds / 3_600, "watchword-time-hours"),
        _ => (seconds / 86_400, "watchword-time-days"),
    };

    phrases.msg(id, &args!(count = count))
}
