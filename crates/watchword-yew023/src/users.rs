//! The users list that [`AdminUsers`](super::AdminUsers) and the app share.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::vec::Vec;

use yew::prelude::*;

#[cfg(feature = "musliweb05")]
use watchword_core::musliweb05::AuthUpdate;
use watchword_core::{Link, UserEntry, UserId};

use super::Error;
use super::context::use_auth;
use super::listener::{Listener, Slots};
use super::service::AuthService;

/// The users list as last known, shared by [`AdminUsers`](super::AdminUsers)
/// and the app's own components inside the same
/// [`AuthProvider`](super::AuthProvider), so a page that shows both fetches
/// it once. Get it with [`use_users`], or with
/// [`AuthContext::subscribe_users`](super::AuthContext::subscribe_users) in
/// a struct component.
///
/// Only an admin may list the users; for anyone else the load fails with
/// [`AuthError::Forbidden`](watchword_core::AuthError::Forbidden).
///
/// The list is fetched when the first component asks for it, and dropped
/// when the last one stops, so the next one fetches it again. In between it
/// is kept current: by what [`AdminUsers`](super::AdminUsers) changes, and,
/// with a socket handed to
/// [`AuthContext::set_socket`](super::AuthContext::set_socket) (feature
/// `musliweb05`), by the server's `AuthBroadcast`, fetching it again when a
/// broadcast cannot say enough, such as after `Resync`. Without a socket, an
/// app that learns of a change made elsewhere calls
/// [`reload`](Users::reload). It is also fetched again, or dropped, when the
/// signed-in user, their role or the impersonation changes.
///
/// Each change is a new `Users`, so comparing two says whether anything
/// changed.
#[derive(Clone)]
pub struct Users {
    state: Rc<State>,
    store: Weak<RefCell<Store>>,
}

#[derive(Clone, Default)]
struct State {
    entries: Option<Vec<UserEntry>>,
    error: Option<Error>,
    loading: bool,
    /// Counts the failed loads, so a component can tell a new failure from
    /// one it has shown.
    failures: u64,
}

impl Users {
    /// The users, with their link state, in no particular order. `None`
    /// until the list is first fetched, or when that failed. A list kept
    /// across a failed [`reload`](Users::reload) stays, with the
    /// [`error`](Users::error).
    pub fn entries(&self) -> Option<&[UserEntry]> {
        self.state.entries.as_deref()
    }

    /// The user with `id`, if listed.
    pub fn get(&self, id: UserId) -> Option<&UserEntry> {
        self.entries()?.iter().find(|entry| entry.user.id == id)
    }

    /// Whether the list is being fetched.
    pub fn is_loading(&self) -> bool {
        self.state.loading
    }

    /// Why the last fetch failed, until one succeeds. A 401 also makes the
    /// provider [check the session](super::AuthContext::check_session).
    pub fn error(&self) -> Option<&Error> {
        self.state.error.as_ref()
    }

    /// Fetches the list again for every component showing it. A fetch in
    /// flight is superseded.
    pub fn reload(&self) {
        if let Some(store) = self.store.upgrade() {
            UsersStore { inner: store }.load();
        }
    }

    pub(super) fn failures(&self) -> u64 {
        self.state.failures
    }
}

impl PartialEq for Users {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.state, &other.state)
    }
}

/// Where [`Users`] comes from: one per provider, shared through the
/// context. Equal when shared.
#[derive(Clone)]
pub(super) struct UsersStore {
    inner: Rc<RefCell<Store>>,
}

struct Store {
    state: Rc<State>,
    /// Bumped on each load, so an older answer is dropped.
    generation: u64,
    /// The generation of the last load answered; a load is in flight while
    /// it differs from `generation`.
    loaded: u64,
    subscribers: Slots<Users>,
    service: AuthService,
    check_session: Callback<()>,
}

impl PartialEq for UsersStore {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
}

impl UsersStore {
    /// A store that fetches with `service`, and calls `check_session` when a
    /// fetch is refused with a 401.
    pub(super) fn new(service: AuthService, check_session: Callback<()>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Store {
                state: Rc::default(),
                generation: 0,
                loaded: 0,
                subscribers: Slots::default(),
                service,
                check_session,
            })),
        }
    }

    /// The list as it is now.
    pub(super) fn users(&self) -> Users {
        Users {
            state: self.inner.borrow().state.clone(),
            store: Rc::downgrade(&self.inner),
        }
    }

    /// Calls `callback` with the list each time it changes, until the
    /// listener is dropped, fetching it first if nobody has. Dropping the
    /// last listener drops the list.
    pub(super) fn subscribe(&self, callback: Callback<Users>) -> (Users, Listener) {
        let fetch = {
            let store = self.inner.borrow();
            store.state.entries.is_none() && !store.state.loading
        };

        // Before subscribing, so the callback is not called while the
        // component is still being made.
        if fetch {
            self.load();
        }

        let id = self.inner.borrow_mut().subscribers.insert(callback);
        let inner = Rc::downgrade(&self.inner);

        let listener = Listener::new(move || {
            let Some(inner) = inner.upgrade() else {
                return;
            };

            let store = UsersStore { inner };
            let empty = {
                let mut inner = store.inner.borrow_mut();
                inner.subscribers.remove(id);
                inner.subscribers.is_empty()
            };

            if empty {
                store.clear();
            }
        });

        (self.users(), listener)
    }

    /// Fetches the list with `service` from now on.
    pub(super) fn set_service(&self, service: AuthService) {
        self.inner.borrow_mut().service = service;
    }

    /// Fetches the list, superseding a fetch in flight.
    pub(super) fn load(&self) {
        let (generation, service) = {
            let mut store = self.inner.borrow_mut();
            store.generation += 1;
            (store.generation, store.service.clone())
        };

        self.change(|state| state.loading = true);

        let inner = Rc::downgrade(&self.inner);

        yew::platform::spawn_local(async move {
            let result = service.users().await;

            if let Some(inner) = inner.upgrade() {
                UsersStore { inner }.loaded(generation, result);
            }
        });
    }

    fn loaded(&self, generation: u64, result: Result<Vec<UserEntry>, Error>) {
        {
            let mut store = self.inner.borrow_mut();

            if generation != store.generation {
                return;
            }

            store.loaded = generation;
        }

        let unauthorized = result.as_ref().is_err_and(Error::is_unauthorized);

        self.change(|state| {
            state.loading = false;

            match result {
                Ok(entries) => {
                    state.entries = Some(entries);
                    state.error = None;
                }
                Err(error) => {
                    // A list already shown stays, with why it is stale.
                    state.error = Some(error);
                    state.failures += 1;
                }
            }
        });

        if unauthorized {
            let check_session = self.inner.borrow().check_session.clone();
            check_session.emit(());
        }
    }

    /// Changes the users as `f` does, when the list is loaded, such as after
    /// a request made here succeeded.
    pub(super) fn modify(&self, f: impl FnOnce(&mut Vec<UserEntry>)) {
        if self.inner.borrow().state.entries.is_none() {
            return;
        }

        self.change(|state| {
            if let Some(entries) = &mut state.entries {
                f(entries);
            }
        });
    }

    /// Applies an update from the server to the list, fetching it again when
    /// the update cannot say enough. A list still loading comes with the
    /// change; a failed one is fetched again by [`Users::reload`].
    #[cfg(feature = "musliweb05")]
    pub(super) fn apply(&self, update: AuthUpdate) {
        // The provider's.
        if matches!(update, AuthUpdate::Me(..)) {
            return;
        }

        let in_flight = {
            let store = self.inner.borrow();

            if store.state.entries.is_none() {
                return;
            }

            store.loaded != store.generation
        };

        let mut reload = false;

        self.change(|state| {
            if let Some(entries) = &mut state.entries {
                reload = apply_update(entries, update);
            }
        });

        // A load in flight may answer with the list from before the
        // change, so it is asked again.
        if reload || in_flight {
            self.load();
        }
    }

    /// The signed-in user, their role or the impersonation changed: what
    /// was listed was for someone else, so it is fetched again for the
    /// components showing it, and dropped when none are.
    pub(super) fn invalidate(&self) {
        let shown = !self.inner.borrow().subscribers.is_empty();
        self.clear();

        if shown {
            self.load();
        }
    }

    /// Drops the list and any fetch in flight.
    pub(super) fn clear(&self) {
        {
            let mut store = self.inner.borrow_mut();

            let empty = store.state.entries.is_none()
                && store.state.error.is_none()
                && !store.state.loading;

            if empty {
                return;
            }

            store.generation += 1;
            store.loaded = store.generation;
        }

        self.change(|state| *state = State::default());
    }

    /// Replaces the state with a copy changed by `f`, and tells the
    /// subscribers.
    fn change(&self, f: impl FnOnce(&mut State)) {
        let callbacks = {
            let mut store = self.inner.borrow_mut();
            let mut state = State::clone(&store.state);
            f(&mut state);
            store.state = Rc::new(state);
            store.subscribers.callbacks()
        };

        // Nothing is borrowed, since a callback may call back in.
        let users = self.users();

        for callback in callbacks {
            callback.emit(users.clone());
        }
    }
}

/// Applies a live change to the list of `users`, returning whether the list
/// must be fetched again for what the broadcast does not carry: the link
/// state of a user created elsewhere, of a user whose account state or
/// sign-in method changed (registering and revoking access use up the
/// links), any change to a user not in the list, and updates the server
/// missed (`Resync`).
#[cfg(feature = "musliweb05")]
pub(super) fn apply_update(users: &mut Vec<UserEntry>, update: AuthUpdate) -> bool {
    match update {
        // The provider's.
        AuthUpdate::Me(..) => false,
        AuthUpdate::UserCreated(user) => match users.iter_mut().find(|e| e.user.id == user.id) {
            // Added here, with the link the answer carried.
            Some(entry) => {
                entry.user = user;
                false
            }
            None => {
                users.push(UserEntry {
                    user,
                    link_expires_at: None,
                });
                true
            }
        },
        AuthUpdate::UserChanged(user) => {
            let Some(entry) = users.iter_mut().find(|e| e.user.id == user.id) else {
                return true;
            };

            let uses_links = entry.user.access != user.access || entry.user.method != user.method;

            if uses_links {
                entry.link_expires_at = None;
            }

            entry.user = user;
            uses_links
        }
        AuthUpdate::UserDeleted(id) => {
            users.retain(|e| e.user.id != id);
            false
        }
        // Updates were missed, so the whole list is fetched again.
        AuthUpdate::Resync(..) => true,
    }
}

/// Keeps only the `links` issued here that are still live in `users`: a
/// user deleted, or whose link was used up or revoked, has no link to show.
pub(super) fn retain_links(links: &mut HashMap<UserId, Link>, users: &[UserEntry]) {
    links.retain(|id, _| {
        users
            .iter()
            .any(|e| e.user.id == *id && e.link_expires_at.is_some())
    });
}

/// The users list shared inside the [`AuthProvider`](super::AuthProvider),
/// fetched when the first component asks for it. The component renders
/// again whenever it changes. See [`Users`].
///
/// ```ignore
/// #[function_component]
/// fn GroupMembers() -> Html {
///     let users = use_users();
///
///     match users.entries() {
///         Some(entries) => html! { <p>{format!("{} users", entries.len())}</p> },
///         None => html! { <p>{"Loading users"}</p> },
///     }
/// }
/// ```
///
/// # Panics
///
/// Panics outside an `AuthProvider`.
#[hook]
pub fn use_users() -> Users {
    let auth = use_auth();
    let update = use_force_update();

    let _listener = use_memo(auth.users.clone(), move |store| {
        store
            .subscribe(Callback::from(move |_| update.force_update()))
            .1
    });

    auth.users.users()
}
