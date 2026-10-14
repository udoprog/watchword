use std::collections::HashMap;
use std::ops::Range;
use std::rc::Rc;

use jiff::Timestamp;
use yew::prelude::*;

use super::account::role_name;
use super::browser;
use super::context::AuthContext;
use super::form::{error_message, identity_change, optional};
use super::http::{self, CreatedUser, Error};
use crate::types::{Access, Link, Method, NewUser, Role, UserChange, UserEntry, UserId, UserInfo};

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
    /// revoke, impersonate or delete.
    pub me: Rc<UserInfo>,
    /// Offers Impersonate when set, which the server must enable. It is
    /// called with the user once this browser is signed in as them; the app
    /// then reloads the user, such as with [`AuthContext::refresh`], and
    /// leaves the admin page.
    #[prop_or_default]
    pub on_impersonate: Option<Callback<UserInfo>>,
    /// Bump it to fetch the users again, such as when the app forwards an
    /// `AuthEvent` from the server.
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
/// Use it inside [`AuthProvider`](super::AuthProvider): the context says
/// whether the app uses logins, keeps the admin's own user current when they
/// edit themselves, and signs out when a request finds the session ended.
pub struct AdminUsers {
    users: Users,
    /// Bumped on each load, so an older answer is dropped.
    generation: u64,
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

enum Users {
    Loading,
    Loaded(Vec<UserEntry>),
    Failed(AttrValue),
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
    Loaded(u64, Result<Vec<UserEntry>, Error>),
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
    Updated(Result<UserInfo, Error>, &'static str),
    IssueLink(UserId),
    Issued(UserId, Result<Link, Error>),
    Confirm(UserId, Action),
    CancelConfirm,
    Act(UserId, Action),
    Done(UserId, Action, Result<(), Error>),
    Copy(String),
    Copied(bool),
}

impl Component for AdminUsers {
    type Message = Msg;
    type Properties = AdminUsersProps;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::Load);

        Self {
            users: Users::Loading,
            generation: 0,
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
            ctx.link().send_message(Msg::Load);
        }

        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Load => {
                self.generation += 1;
                let generation = self.generation;

                if !matches!(self.users, Users::Loaded(..)) {
                    self.users = Users::Loading;
                }

                ctx.link()
                    .send_future(async move { Msg::Loaded(generation, http::users().await) });
            }
            Msg::Loaded(generation, result) => {
                if generation != self.generation {
                    return false;
                }

                match result {
                    Ok(users) => {
                        // Links that are no longer live are no use to show.
                        self.links.retain(|id, _| {
                            users
                                .iter()
                                .any(|e| e.user.id == *id && e.link_expires_at.is_some())
                        });
                        self.users = Users::Loaded(users);
                    }
                    Err(error) => {
                        let message = error_message(&error, "Loading the users");

                        // Keep a list already shown, and say why it is stale.
                        if matches!(self.users, Users::Loaded(..)) {
                            self.message = Some(Message::Error(message));
                        } else {
                            self.users = Users::Failed(message);
                        }

                        check_unauthorized(ctx, &error);
                    }
                }
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

                let logins = logins(ctx);
                let login = logins.then(|| optional(&form.login)).flatten();
                let email = optional(&form.email);

                if let Err(error) =
                    identity_change((None, None), login.clone(), email.clone(), logins)
                {
                    self.message = Some(Message::Error(AttrValue::Static(error)));
                    return true;
                }

                let new = NewUser {
                    login,
                    email,
                    role: form.role,
                };

                self.busy = true;
                self.message = None;
                ctx.link()
                    .send_future(async move { Msg::Added(http::create_user(&new).await) });
            }
            Msg::Added(result) => {
                self.busy = false;

                match result {
                    Ok(CreatedUser { entry, link }) => {
                        let id = entry.user.id;
                        let filter = entry.user.name().to_owned();

                        if let Users::Loaded(users) = &mut self.users {
                            users.push(entry);
                        }

                        self.links.insert(id, link);
                        self.adding = None;
                        self.message = Some(Message::Notice(AttrValue::from(
                            "User added. Send them their link below.",
                        )));
                        // Show the new user, wherever they sort.
                        self.set_query(ctx, UsersQuery { filter, page: 0 });
                    }
                    Err(error) => {
                        self.message =
                            Some(Message::Error(error_message(&error, "Adding the user")));
                        check_unauthorized(ctx, &error);
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

                let logins = logins(ctx);
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
                        self.message = Some(Message::Error(AttrValue::Static(error)));
                        return true;
                    }
                };

                if change == UserChange::default() {
                    self.editing = None;
                    return true;
                }

                self.update_user(ctx, *id, change, "Saved.");
            }
            Msg::SetRole(id, role) => {
                if self.busy {
                    return true;
                }

                let change = UserChange {
                    role: Some(role),
                    ..UserChange::default()
                };

                self.update_user(ctx, id, change, "Role changed.");
            }
            Msg::Updated(result, notice) => {
                self.busy = false;

                match result {
                    Ok(user) => {
                        if user.id == ctx.props().me.id
                            && let Some((auth, _)) =
                                ctx.link().context::<AuthContext>(Callback::noop())
                        {
                            auth.set_user(user.clone());
                        }

                        if self.editing.as_ref().is_some_and(|(id, _)| *id == user.id) {
                            self.editing = None;
                        }

                        if let Some(entry) = self.entry_mut(user.id) {
                            entry.user = user;
                        }

                        self.message = Some(Message::Notice(AttrValue::Static(notice)));
                    }
                    Err(error) => {
                        self.message = Some(Message::Error(error_message(&error, "Saving")));
                        check_unauthorized(ctx, &error);
                    }
                }
            }
            Msg::IssueLink(id) => {
                if self.busy {
                    return false;
                }

                self.busy = true;
                self.message = None;
                ctx.link()
                    .send_future(async move { Msg::Issued(id, http::issue_link(id).await) });
            }
            Msg::Issued(id, result) => {
                self.busy = false;

                match result {
                    Ok(link) => {
                        if let Some(entry) = self.entry_mut(id) {
                            entry.link_expires_at = Some(link.expires_at);

                            // A new link restores a revoked user.
                            if entry.user.access == Access::Revoked {
                                entry.user.access = Access::Pending;
                            }
                        }

                        self.links.insert(id, link);
                        self.message = None;
                        // The account state may have changed with it.
                        ctx.link().send_message(Msg::Load);
                    }
                    Err(error) => {
                        self.message =
                            Some(Message::Error(error_message(&error, "Issuing a link")));
                        check_unauthorized(ctx, &error);
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

                ctx.link().send_future(async move {
                    let result = match action {
                        Action::RevokeLink => http::revoke_link(id).await,
                        Action::SignOut => http::sign_out_user(id).await,
                        Action::RevokeAccess => http::revoke_access(id).await,
                        Action::Impersonate => http::impersonate(id).await,
                        Action::Delete => http::delete_user(id).await,
                    };

                    Msg::Done(id, action, result)
                });
            }
            Msg::Done(id, action, result) => {
                self.busy = false;

                if let Err(error) = result {
                    self.message = Some(Message::Error(error_message(&error, action.failed())));
                    check_unauthorized(ctx, &error);
                    return true;
                }

                self.message = Some(Message::Notice(AttrValue::Static(action.done())));

                match action {
                    Action::RevokeLink => {
                        self.links.remove(&id);

                        if let Some(entry) = self.entry_mut(id) {
                            entry.link_expires_at = None;
                        }
                    }
                    Action::SignOut => {}
                    Action::RevokeAccess => {
                        self.links.remove(&id);
                        ctx.link().send_message(Msg::Load);
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

                        if let Users::Loaded(users) = &mut self.users {
                            users.retain(|e| e.user.id != id);
                        }
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
                    Message::Notice(AttrValue::Static("Link copied."))
                } else {
                    Message::Error(AttrValue::Static(
                        "The browser did not allow copying. Select the link and copy it instead.",
                    ))
                });
            }
        }

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = ctx.props();
        let link = ctx.link();
        let query = self.query(ctx);

        let message = html! {
            <div class="auth-message" role="alert">
                {match &self.message {
                    Some(Message::Error(error)) => html! { <p class="auth-error">{error.clone()}</p> },
                    Some(Message::Notice(notice)) => html! { <p class="auth-notice">{notice.clone()}</p> },
                    None => Html::default(),
                }}
            </div>
        };

        let body = match &self.users {
            Users::Loading => html! {
                <p class="auth-status" role="status">{"Loading users…"}</p>
            },
            Users::Failed(error) => html! {
                <div class="auth-message" role="alert">
                    <p class="auth-error">{error.clone()}</p>
                    <button type="button" class="auth-retry" onclick={link.callback(|_| Msg::Load)}>{"Retry"}</button>
                </div>
            },
            Users::Loaded(users) => self.view_users(ctx, users, query),
        };

        html! {
            <section class={classes!("auth-admin-users", props.class.clone())}>
                <div class="auth-toolbar">
                    <h2 class="auth-heading">{"Users"}</h2>

                    if self.adding.is_none() {
                        <button type="button" class="auth-add" onclick={link.callback(|_| Msg::StartAdd)}>
                            {"Add user"}
                        </button>
                    }
                </div>

                {message}
                {self.view_add(ctx)}

                <div class="auth-filter">
                    <input
                        class="auth-input"
                        type="search"
                        placeholder="Filter"
                        aria-label="Filter users"
                        value={query.filter.clone()}
                        oninput={link.callback(|e: InputEvent| Msg::Filter(browser::input_value(&e)))}
                    />

                    if !query.filter.is_empty() {
                        <button type="button" class="auth-clear" onclick={link.callback(|_| Msg::Filter(String::new()))}>
                            {"Clear filter"}
                        </button>
                    }
                </div>

                {body}
            </section>
        }
    }
}

impl AdminUsers {
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
        match &self.users {
            Users::Loaded(users) => users.iter().find(|e| e.user.id == id),
            _ => None,
        }
    }

    fn entry_mut(&mut self, id: UserId) -> Option<&mut UserEntry> {
        match &mut self.users {
            Users::Loaded(users) => users.iter_mut().find(|e| e.user.id == id),
            _ => None,
        }
    }

    fn update_user(
        &mut self,
        ctx: &Context<Self>,
        id: UserId,
        change: UserChange,
        notice: &'static str,
    ) {
        self.busy = true;
        self.message = None;
        ctx.link()
            .send_future(async move { Msg::Updated(http::update_user(id, &change).await, notice) });
    }

    fn view_add(&self, ctx: &Context<Self>) -> Html {
        let Some(form) = &self.adding else {
            return Html::default();
        };

        let link = ctx.link();
        let logins = logins(ctx);

        let onsubmit = link.callback(|e: SubmitEvent| {
            e.prevent_default();
            Msg::SubmitAdd
        });

        html! {
            <form class="auth-form auth-add-user" {onsubmit}>
                <h3 class="auth-subheading">{"Add user"}</h3>

                if logins {
                    <div class="auth-field">
                        <label for="auth-new-login">{"Login"}</label>
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
                    <label for="auth-new-email">{"Email"}</label>
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
                        <span class="auth-hint">{"Optional. Lets them sign in with it, or through Cloudflare Access."}</span>
                    }
                </div>

                <div class="auth-field">
                    <label for="auth-new-role">{"Role"}</label>
                    {role_select("auth-new-role", form.role, self.busy, link.callback(Msg::AddRole))}
                </div>

                <p class="auth-hint">{"They get a link to choose a password with."}</p>

                <div class="auth-actions">
                    <button type="button" onclick={link.callback(|_| Msg::CancelAdd)} disabled={self.busy}>{"Cancel"}</button>
                    <button type="submit" class="auth-submit" disabled={self.busy}>{"Add user"}</button>
                </div>
            </form>
        }
    }

    fn view_users(&self, ctx: &Context<Self>, users: &[UserEntry], query: &UsersQuery) -> Html {
        let link = ctx.link();
        let logins = logins(ctx);

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
                "There are no users."
            } else {
                "No user matches the filter."
            };

            return html! { <p class="auth-status">{text}</p> };
        }

        html! {
            <>
                <table class="auth-users">
                    <thead>
                        <tr>
                            if logins {
                                <th scope="col">{"Login"}</th>
                            }
                            <th scope="col">{"Email"}</th>
                            <th scope="col">{"Role"}</th>
                            <th scope="col">{"Status"}</th>
                            <th scope="col">{"Link"}</th>
                            <th scope="col"><span class="auth-hidden">{"Actions"}</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {for shown[range].iter().map(|e| self.view_user(ctx, e, now))}
                    </tbody>
                </table>

                if pages > 1 {
                    <nav class="auth-pages" aria-label="Pages">
                        <button
                            type="button"
                            class="auth-previous"
                            disabled={page == 0}
                            onclick={link.callback(move |_| Msg::Page(page.saturating_sub(1)))}
                        >
                            {"Previous page"}
                        </button>
                        <span class="auth-page-number">{format!("{} / {pages}", page + 1)}</span>
                        <button
                            type="button"
                            class="auth-next"
                            disabled={page + 1 >= pages}
                            onclick={link.callback(move |_| Msg::Page(page + 1))}
                        >
                            {"Next page"}
                        </button>
                    </nav>
                }
            </>
        }
    }

    fn view_user(&self, ctx: &Context<Self>, entry: &UserEntry, now: Timestamp) -> Html {
        let props = ctx.props();
        let link = ctx.link();
        let logins = logins(ctx);
        let user = &entry.user;
        let id = user.id;
        let me = user.id == props.me.id;
        let name = user.name().to_owned();
        let busy = self.busy;

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
                        aria-label="Login"
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
                        aria-label="Email"
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
                    None => html! { <span class="auth-muted">{"No email"}</span> },
                },
            ),
        };

        let badge = me.then(|| html! { <span class="auth-badge">{"you"}</span> });
        let extra = props.extra.as_ref().map(|extra| {
            html! { <div class="auth-user-extra">{extra.emit(user.clone())}</div> }
        });

        // The first cell names the user, so the badge and extra go there.
        let (login_cell, email_cell) = if logins {
            (
                Some(html! { <td class="auth-user-login">{login_cell}{badge}{extra}</td> }),
                html! { <td class="auth-user-email">{email_cell}</td> },
            )
        } else {
            (
                None,
                html! { <td class="auth-user-email">{email_cell}{badge}{extra}</td> },
            )
        };

        let role = if me {
            html! { <span class="auth-value">{role_name(user.role)}</span> }
        } else {
            role_select(
                &format!("auth-role-{id}"),
                user.role,
                busy,
                link.callback(move |role| Msg::SetRole(id, role)),
            )
        };

        let (access_class, access_label, access_title) = access(user);

        html! {
            <tr class={classes!("auth-user", me.then_some("auth-me"))}>
                {for login_cell}
                {email_cell}
                <td class="auth-user-role">{role}</td>
                <td class="auth-user-access">
                    <span class={classes!("auth-access", access_class)} title={access_title}>{access_label}</span>
                </td>
                <td class="auth-user-link">{self.view_link(ctx, entry, now)}</td>
                <td class="auth-user-actions">{self.view_actions(ctx, entry, me, &name, editing.is_some())}</td>
            </tr>
        }
    }

    fn view_link(&self, ctx: &Context<Self>, entry: &UserEntry, now: Timestamp) -> Html {
        let link = ctx.link();
        let name = entry.user.name();

        if let Some(issued) = self.links.get(&entry.user.id) {
            let url = link_url(&browser::origin(), &issued.token);
            let copy = url.clone();

            return html! {
                <div class="auth-link">
                    <input class="auth-input auth-link-url" type="text" readonly=true value={url} title={format!("Link for {name}")} />
                    <button
                        type="button"
                        class="auth-copy"
                        title={format!("Copy the link for {name}")}
                        onclick={link.callback(move |_| Msg::Copy(copy.clone()))}
                    >
                        {"Copy"}
                    </button>
                    <span class="auth-hint">
                        {format!("Send this to {name}. It works once and expires {}. It is not shown again.", relative_time(now, issued.expires_at))}
                    </span>
                </div>
            };
        }

        match entry.link_expires_at {
            Some(at) => html! {
                <span class="auth-link-state" title={at.to_string()}>{format!("Link expires {}", relative_time(now, at))}</span>
            },
            None => html! { <span class="auth-link-state auth-muted">{"No link"}</span> },
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

        if editing {
            return html! {
                <div class="auth-actions">
                    <button type="button" onclick={link.callback(|_| Msg::CancelEdit)} disabled={busy}>{"Discard changes"}</button>
                    <button type="button" class="auth-submit" onclick={link.callback(|_| Msg::SubmitEdit)} disabled={busy}>{"Save"}</button>
                </div>
            };
        }

        if let Some((_, action)) = self.confirm.filter(|(confirm, _)| *confirm == id) {
            let prompt = match action {
                Action::Delete => "Delete",
                _ => "Revoke access for",
            };

            return html! {
                <div class="auth-confirm" role="group">
                    <span>{prompt}{" "}<strong>{name.to_owned()}</strong>{"?"}</span>
                    <button type="button" class="auth-confirm-no" onclick={link.callback(|_| Msg::CancelConfirm)}>{"No"}</button>
                    <button type="button" class="auth-confirm-yes auth-danger" onclick={link.callback(move |_| Msg::Act(id, action))} disabled={busy}>{"Yes"}</button>
                </div>
            };
        }

        let live_link = entry.link_expires_at.is_some();
        let revoked = user.access == Access::Revoked;

        html! {
            <div class="auth-actions">
                <button type="button" title={format!("Edit {name}")} onclick={link.callback(move |_| Msg::StartEdit(id))} disabled={busy}>
                    {"Edit"}
                </button>

                <button type="button" title={format!("New link for {name}")} onclick={link.callback(move |_| Msg::IssueLink(id))} disabled={busy}>
                    {if live_link { "New link" } else { "Link" }}
                </button>

                if live_link {
                    <button type="button" title={format!("Revoke the link for {name}")} onclick={link.callback(move |_| Msg::Act(id, Action::RevokeLink))} disabled={busy}>
                        {"Revoke link"}
                    </button>
                }

                if !me {
                    <button type="button" title={format!("Sign {name} out everywhere")} onclick={link.callback(move |_| Msg::Act(id, Action::SignOut))} disabled={busy}>
                        {"Sign out everywhere"}
                    </button>

                    if !revoked {
                        <button type="button" class="auth-danger" title={format!("Revoke access for {name}")} onclick={link.callback(move |_| Msg::Confirm(id, Action::RevokeAccess))} disabled={busy}>
                            {"Revoke access"}
                        </button>
                    }

                    if props.on_impersonate.is_some() && !revoked {
                        <button type="button" title={format!("Impersonate {name}")} onclick={link.callback(move |_| Msg::Act(id, Action::Impersonate))} disabled={busy}>
                            {"Impersonate"}
                        </button>
                    }

                    <button type="button" class="auth-danger" title={format!("Delete {name}")} onclick={link.callback(move |_| Msg::Confirm(id, Action::Delete))} disabled={busy}>
                        {"Delete"}
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
    fn failed(self) -> &'static str {
        match self {
            Action::RevokeLink => "Revoking the link",
            Action::SignOut => "Signing out",
            Action::RevokeAccess => "Revoking access",
            Action::Impersonate => "Impersonating",
            Action::Delete => "Deleting",
        }
    }

    fn done(self) -> &'static str {
        match self {
            Action::RevokeLink => "Link revoked.",
            Action::SignOut => "Signed out everywhere.",
            Action::RevokeAccess => "Access revoked.",
            Action::Impersonate => "Signed in as the user.",
            Action::Delete => "User deleted.",
        }
    }
}

fn logins(ctx: &Context<AdminUsers>) -> bool {
    match ctx.link().context::<AuthContext>(Callback::noop()) {
        Some((auth, _)) => auth.config.logins,
        // Outside a provider, show logins when the admin has one.
        None => ctx.props().me.login.is_some(),
    }
}

fn check_unauthorized(ctx: &Context<AdminUsers>, error: &Error) {
    if error.is_unauthorized()
        && let Some((auth, _)) = ctx.link().context::<AuthContext>(Callback::noop())
    {
        auth.check_session();
    }
}

fn role_select(id: &str, role: Role, disabled: bool, onchange: Callback<Role>) -> Html {
    let onchange = Callback::from(move |e: Event| {
        if let Ok(role) = browser::select_value(&e).parse::<Role>() {
            onchange.emit(role);
        }
    });

    html! {
        <select id={id.to_owned()} class="auth-select" aria-label="Role" {onchange} {disabled}>
            {for [Role::Regular, Role::Admin].into_iter().map(|option| html! {
                <option value={option.as_str()} selected={option == role}>{role_name(option)}</option>
            })}
        </select>
    }
}

/// The class, label and title of a user's account state.
fn access(user: &UserInfo) -> (&'static str, &'static str, String) {
    let method = match user.method {
        Method::Password => "password",
        Method::Google => "Google",
    };

    match user.access {
        Access::Pending => (
            "auth-pending",
            "Pending",
            format!("Pending registration ({method} sign-in)"),
        ),
        Access::Active => (
            "auth-active",
            "Active",
            format!("Active ({method} sign-in)"),
        ),
        Access::Revoked => (
            "auth-revoked",
            "Revoked",
            format!("Access revoked ({method} sign-in)"),
        ),
    }
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
pub(super) fn relative_time(now: Timestamp, at: Timestamp) -> String {
    let seconds = at.as_second() - now.as_second();

    if seconds <= 0 {
        return "now".to_owned();
    }

    let (n, unit) = match seconds {
        1..60 => return "in less than a minute".to_owned(),
        60..3_600 => (seconds / 60, "minute"),
        3_600..86_400 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };

    let s = if n == 1 { "" } else { "s" };
    format!("in {n} {unit}{s}")
}
