//! The filter of `Connection::update`, over `MemoryStore`; `socket` tests
//! `Connection::handle` over a real WebSocket.

mod parity;
mod socket;

use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use musli_web06::api::Metadata;
use musli_web06::ws::Refuse;

use super::{AuthUpdate, Connection, SESSION_ENDED};
use crate::axum08::SignedIn;
use crate::types::{AuthError, Impersonator, NewUser, RegisterRequest, Role, UserInfo};
use crate::{
    Auth, AuthEvent, BootstrapAdmin, MemoryStore, PAGE_SESSION_HEADER, generate_session_key,
};

const PASSWORD: &str = "password1";

fn auth() -> Auth {
    Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .build()
}

/// The bootstrap admin `root`, signed in.
async fn root(auth: &Auth) -> SignedIn {
    let link = auth
        .bootstrap_admin(&BootstrapAdmin::login("root"))
        .await
        .unwrap()
        .link()
        .cloned()
        .unwrap();
    register(auth, &link.token).await
}

/// A user created by `admin` with `role` and still pending, without a
/// session.
async fn pending(auth: &Auth, admin: &SignedIn, login: &str, role: Role) -> (UserInfo, String) {
    let new = NewUser {
        login: Some(login.to_owned()),
        email: None,
        role,
    };
    let (entry, link) = auth
        .create_user(&admin.user, &admin.session, &new)
        .await
        .unwrap();
    (entry.user, link.token)
}

/// A user created by `admin` with `role`, registered and signed in.
async fn user(auth: &Auth, admin: &SignedIn, login: &str, role: Role) -> SignedIn {
    let (_, token) = pending(auth, admin, login, role).await;
    register(auth, &token).await
}

async fn register(auth: &Auth, token: &str) -> SignedIn {
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    let (user, session) = auth.register(token, &request).await.unwrap();
    SignedIn { user, session }
}

/// A connection signed in as `signed_in`, accepted without metadata, as
/// musli-web does before any request.
async fn accepted(auth: &Auth, signed_in: &SignedIn) -> Connection {
    let conn = Connection::new(auth.clone(), signed_in);
    conn.accept(&Metadata::new()).await.unwrap();
    conn
}

/// The user-list events about `other`, which only an admin's connection
/// passes on.
fn list_events(other: &UserInfo) -> Vec<(AuthEvent, AuthUpdate)> {
    vec![
        (
            AuthEvent::UserCreated(other.clone()),
            AuthUpdate::UserCreated(other.clone()),
        ),
        (
            AuthEvent::UserChanged(other.clone()),
            AuthUpdate::UserChanged(other.clone()),
        ),
        (
            AuthEvent::UserDeleted(other.id),
            AuthUpdate::UserDeleted(other.id),
        ),
    ]
}

/// Events that end sessions, which no connection passes on.
fn ending_events(conn: &SignedIn) -> Vec<AuthEvent> {
    vec![
        AuthEvent::SessionEnded(conn.session.id.clone()),
        AuthEvent::SessionEnded("other".to_owned()),
        AuthEvent::UserSessionsEnded {
            user: conn.user.id,
            keep: None,
        },
        AuthEvent::UserSessionsEnded {
            user: conn.user.id,
            keep: Some(conn.session.id.clone()),
        },
    ]
}

#[tokio::test]
async fn an_admin_sees_itself_and_the_user_list() {
    let auth = auth();
    let root = root(&auth).await;
    let (other, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &root).await;

    let me = AuthEvent::UserChanged(root.user.info());
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(root.user.info()))
    );

    for (event, update) in list_events(&other) {
        assert_eq!(
            conn.update(&event).await.unwrap(),
            Some(update),
            "{event:?}"
        );
    }

    for event in ending_events(&root) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }
}

/// The events an operation emits, as the app's loop receives them.
#[tokio::test]
async fn an_admin_sees_real_operations() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let conn = accepted(&auth, &ada).await;
    let mut events = auth.events();

    let new = NewUser {
        login: Some("erin".to_owned()),
        email: None,
        role: Role::Regular,
    };
    let (entry, _) = auth
        .create_user(&root.user, &root.session, &new)
        .await
        .unwrap();
    let event = events.recv().await.unwrap();
    assert_eq!(
        conn.update(&event).await.unwrap(),
        Some(AuthUpdate::UserCreated(entry.user.clone()))
    );

    auth.delete_user(&root.user, &root.session, entry.user.id)
        .await
        .unwrap();
    let mut updates = Vec::new();

    while let Ok(event) = events.try_recv() {
        updates.extend(conn.update(&event).await.unwrap());
    }

    assert_eq!(updates, [AuthUpdate::UserDeleted(entry.user.id)]);
}

#[tokio::test]
async fn a_regular_user_sees_only_itself() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &erin).await;

    let me = AuthEvent::UserChanged(erin.user.info());
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(erin.user.info()))
    );

    for (event, _) in list_events(&root.user.info()) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }

    for event in ending_events(&erin) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }
}

/// A user's own change reaches them as `Me` with their stored state, which
/// is what the event carries.
#[tokio::test]
async fn me_follows_a_role_change() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &erin).await;

    let promoted = auth
        .set_role(&root.user, &root.session, erin.user.id, Role::Admin)
        .await
        .unwrap();
    let me = AuthEvent::UserChanged(promoted.info());
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(promoted.info()))
    );

    // Promoted on an open socket, the user now sees the user list.
    let (event, update) = list_events(&root.user.info()).remove(0);
    assert_eq!(conn.update(&event).await.unwrap(), Some(update));
}

#[tokio::test]
async fn an_impersonated_session_keeps_its_marker() {
    let auth = auth();
    let root = root(&auth).await;
    let (erin, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let page = auth
        .impersonate(&root.user, &root.session, erin.id)
        .await
        .unwrap();
    let info = erin;
    let conn = Connection::new(auth.clone(), &root);
    conn.accept(&page_metadata(&page.credential)).await.unwrap();

    let mut expected = info.clone();
    expected.impersonated_by = Some(Impersonator {
        id: root.user.id,
        name: "root".to_owned(),
    });

    let me = AuthEvent::UserChanged(info);
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(expected))
    );

    // The impersonating admin's rights do not carry into the session.
    for (event, _) in list_events(&root.user.info()) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }
}

#[tokio::test]
async fn a_demoted_admin_stops_seeing_the_user_list() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let (erin, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &ada).await;

    let (event, update) = list_events(&erin).remove(0);
    assert_eq!(conn.update(&event).await.unwrap(), Some(update));

    let demoted = auth
        .set_role(&root.user, &root.session, ada.user.id, Role::Regular)
        .await
        .unwrap();

    for (event, _) in list_events(&erin) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }

    let me = AuthEvent::UserChanged(demoted.info());
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(demoted.info()))
    );
}

/// Once the session has ended, nothing is passed on; the guard ends the
/// socket.
#[tokio::test]
async fn an_ended_session_sees_nothing() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let (erin, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &ada).await;

    let revoked = auth
        .revoke_access(&root.user, &root.session, ada.user.id)
        .await
        .unwrap();

    let me = AuthEvent::UserChanged(revoked.info());
    assert_eq!(conn.update(&me).await.unwrap(), None);

    for (event, _) in list_events(&erin) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }

    // Signed out.
    let conn = accepted(&auth, &root).await;
    auth.sign_out(&root.session.id).await.unwrap();
    let me = AuthEvent::UserChanged(root.user.info());
    assert_eq!(conn.update(&me).await.unwrap(), None);

    for (event, _) in list_events(&erin) {
        assert_eq!(conn.update(&event).await.unwrap(), None, "{event:?}");
    }
}

/// After a lag an admin is told to fetch the user list again, with their own
/// user as it is now; anyone else gets only their own user.
#[tokio::test]
async fn a_lag_resyncs_an_admin_and_refreshes_anyone_else() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;

    let conn = accepted(&auth, &root).await;
    assert_eq!(
        conn.lagged().await.unwrap(),
        Some(AuthUpdate::Resync(root.user.info()))
    );

    let conn = accepted(&auth, &erin).await;
    assert_eq!(
        conn.lagged().await.unwrap(),
        Some(AuthUpdate::Me(erin.user.info()))
    );

    // The missed change itself shows in the user carried.
    let conn = accepted(&auth, &ada).await;
    let demoted = auth
        .set_role(&root.user, &root.session, ada.user.id, Role::Regular)
        .await
        .unwrap();
    assert_eq!(
        conn.lagged().await.unwrap(),
        Some(AuthUpdate::Me(demoted.info()))
    );

    // An impersonated session keeps its marker and not the admin's rights.
    let page = auth
        .impersonate(&root.user, &root.session, erin.user.id)
        .await
        .unwrap();
    let mut expected = erin.user.info();
    expected.impersonated_by = Some(Impersonator {
        id: root.user.id,
        name: "root".to_owned(),
    });
    let conn = Connection::new(auth.clone(), &root);
    conn.accept(&page_metadata(&page.credential)).await.unwrap();
    assert_eq!(conn.lagged().await.unwrap(), Some(AuthUpdate::Me(expected)));
}

/// An ended session gets nothing after a lag; the guard ends the socket.
#[tokio::test]
async fn a_lag_on_an_ended_session_sends_nothing() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;

    let conn = accepted(&auth, &ada).await;
    auth.revoke_access(&root.user, &root.session, ada.user.id)
        .await
        .unwrap();
    assert_eq!(conn.lagged().await.unwrap(), None);

    let conn = accepted(&auth, &root).await;
    auth.sign_out(&root.session.id).await.unwrap();
    assert_eq!(conn.lagged().await.unwrap(), None);
}

/// The refusal inside `result`, if it is one; panics on a store failure.
fn refusal<T: std::fmt::Debug>(result: crate::core::Result<T>) -> Option<AuthError> {
    match result {
        Ok(_) => None,
        Err(crate::core::Error::Auth(error)) => Some(error),
        Err(error) => panic!("not a refusal: {error:?}"),
    }
}

/// The public checks read the stored user per call, as the HTTP extractors
/// do, so a role change or a sign-out applies to the next one.
#[tokio::test]
async fn the_checks_follow_the_stored_user() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let conn = accepted(&auth, &erin).await;

    assert_eq!(conn.user_id(), erin.user.id);
    assert_eq!(conn.session_id(), erin.session.id);

    let (user, session) = conn.signed_in().await.unwrap();
    assert_eq!(user.id, erin.user.id);
    assert_eq!(session.id, erin.session.id);
    assert_eq!(
        refusal(conn.require_admin().await),
        Some(AuthError::Forbidden)
    );

    auth.set_role(&root.user, &root.session, erin.user.id, Role::Admin)
        .await
        .unwrap();
    assert_eq!(conn.require_admin().await.unwrap().id, erin.user.id);

    auth.set_role(&root.user, &root.session, erin.user.id, Role::Regular)
        .await
        .unwrap();
    assert_eq!(
        refusal(conn.require_admin().await),
        Some(AuthError::Forbidden)
    );

    auth.sign_out(&erin.session.id).await.unwrap();
    assert_eq!(
        refusal(conn.signed_in().await),
        Some(AuthError::Unauthorized)
    );
    assert_eq!(
        refusal(conn.require_admin().await),
        Some(AuthError::Unauthorized)
    );
}

/// Long enough for a spawned guard to notice a change.
const WAIT: core::time::Duration = core::time::Duration::from_secs(5);

/// Short enough to show that nothing is ready.
const BRIEFLY: core::time::Duration = core::time::Duration::from_millis(50);

/// `Updates` yields what the connection may see, skipping the rest, and
/// ends with the session.
#[tokio::test]
async fn updates_follow_the_session() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;

    let mut admin = accepted(&auth, &root).await.updates();
    let mut regular = accepted(&auth, &erin).await.updates();
    assert_eq!(admin.connection().user_id(), root.user.id);
    assert_eq!(admin.guard().user(), root.user.info());

    // Nothing yet, and a cancelled call loses nothing.
    assert!(tokio::time::timeout(BRIEFLY, admin.next()).await.is_err());

    let (pat, _) = pending(&auth, &root, "pat", Role::Regular).await;
    let next = tokio::time::timeout(WAIT, admin.next()).await.unwrap();
    assert_eq!(next, Some(AuthUpdate::UserCreated(pat.clone())));

    // The regular user skips the user list and sees its own change.
    assert!(tokio::time::timeout(BRIEFLY, regular.next()).await.is_err());

    let erin_changed = auth
        .set_role(&root.user, &root.session, erin.user.id, Role::Admin)
        .await
        .unwrap();
    let next = tokio::time::timeout(WAIT, regular.next()).await.unwrap();
    assert_eq!(next, Some(AuthUpdate::Me(erin_changed.info())));

    let next = tokio::time::timeout(WAIT, admin.next()).await.unwrap();
    assert_eq!(next, Some(AuthUpdate::UserChanged(erin_changed.info())));

    // Signing out ends the updates, for good.
    auth.sign_out(&root.session.id).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, admin.next()).await.unwrap(),
        None
    );
    assert_eq!(
        tokio::time::timeout(WAIT, admin.next()).await.unwrap(),
        None
    );
}

/// Missed events become one `Resync` for an admin, after which the updates
/// carry on.
#[tokio::test]
async fn updates_resync_after_a_lag() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Regular).await;
    let mut updates = accepted(&auth, &root).await.updates();

    // More changes than the event channel holds.
    let mut last = None;

    for n in 0..300 {
        let role = if n % 2 == 0 {
            Role::Admin
        } else {
            Role::Regular
        };
        last = Some(
            auth.set_role(&root.user, &root.session, ada.user.id, role)
                .await
                .unwrap(),
        );
    }

    let next = tokio::time::timeout(WAIT, updates.next()).await.unwrap();
    assert_eq!(next, Some(AuthUpdate::Resync(root.user.info())));

    // What the channel kept follows, ending with the last change.
    let last = AuthUpdate::UserChanged(last.unwrap().info());

    loop {
        let next = tokio::time::timeout(WAIT, updates.next()).await.unwrap();
        assert!(
            matches!(next, Some(AuthUpdate::UserChanged(..))),
            "{next:?}"
        );

        if next.as_ref() == Some(&last) {
            break;
        }
    }
}

/// `unless_ended` runs a step only while the session lasts.
#[tokio::test]
async fn unless_ended_stops_with_the_session() {
    let auth = auth();
    let root = root(&auth).await;
    let updates = accepted(&auth, &root).await.updates();

    assert_eq!(updates.unless_ended(async { 1 }).await, Some(1));

    // A step that never finishes is given up once the session ends.
    let stalled = updates.unless_ended(core::future::pending::<()>());
    let sign_out = async {
        tokio::time::sleep(BRIEFLY).await;
        auth.sign_out(&root.session.id).await.unwrap();
    };
    let (stalled, ()) = tokio::time::timeout(WAIT, async { tokio::join!(stalled, sign_out) })
        .await
        .unwrap();
    assert_eq!(stalled, None);

    // And not started after.
    assert_eq!(updates.unless_ended(async { 1 }).await, None);
}

/// A session that ended before its updates were taken gets none.
#[tokio::test]
async fn updates_of_an_ended_session_end_at_once() {
    let auth = auth();
    let root = root(&auth).await;
    let conn = accepted(&auth, &root).await;
    auth.sign_out(&root.session.id).await.unwrap();

    let mut updates = conn.updates();
    assert_eq!(
        tokio::time::timeout(WAIT, updates.next()).await.unwrap(),
        None
    );
}

/// Connection metadata stating the page credential `credential`.
fn page_metadata(credential: &str) -> Metadata {
    let mut metadata = Metadata::new();
    metadata.insert(PAGE_SESSION_HEADER, credential);
    metadata
}

/// Refused with `SESSION_ENDED`, `session ended`.
fn ended(result: Result<(), Refuse>) -> bool {
    matches!(result, Err(refuse) if refuse.code() == SESSION_ENDED && refuse.reason() == "session ended")
}

/// `root` impersonating a new regular user `erin` in a page: the page's
/// credential and the impersonated user.
async fn impersonating(auth: &Auth, root: &SignedIn) -> (String, UserInfo) {
    let (erin, _) = pending(auth, root, "erin", Role::Regular).await;
    let page = auth
        .impersonate(&root.user, &root.session, erin.id)
        .await
        .unwrap();
    (page.credential, erin)
}

/// Without the page's entry the connection keeps the upgrade's session.
#[tokio::test]
async fn accept_keeps_the_upgrades_session() {
    let auth = auth();
    let root = root(&auth).await;
    let conn = Connection::new(auth.clone(), &root);

    conn.accept(&Metadata::new()).await.unwrap();
    assert_eq!(conn.session_id(), root.session.id);
    assert_eq!(conn.user_id(), root.user.id);
    assert_eq!(conn.signed_in().await.unwrap().0.id, root.user.id);

    // The same again stands; a page credential after it does not.
    conn.accept(&Metadata::new()).await.unwrap();
    let (credential, _) = impersonating(&auth, &root).await;
    assert!(ended(conn.accept(&page_metadata(&credential)).await));
    assert_eq!(conn.session_id(), root.session.id);
}

/// An upgrade signed in with an impersonated session needs no metadata to
/// be refused: only a page states one, and only beside its admin's cookie.
#[tokio::test]
async fn accept_refuses_an_impersonated_upgrade() {
    let auth = auth();
    let root = root(&auth).await;
    let (erin, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let (user, session) = auth
        .impersonate_session(&root.user, &root.session, erin.id)
        .await
        .unwrap();
    let upgrade = SignedIn { user, session };

    let conn = Connection::new(auth.clone(), &upgrade);
    assert!(ended(conn.accept(&Metadata::new()).await));
    assert_eq!(
        refusal(conn.signed_in().await),
        Some(AuthError::Unauthorized)
    );

    // Not even with the page's own credential.
    let credential = auth
        .impersonate(&root.user, &root.session, erin.id)
        .await
        .unwrap()
        .credential;
    let conn = Connection::new(auth.clone(), &upgrade);
    assert!(ended(conn.accept(&page_metadata(&credential)).await));
}

/// The page's credential beside its admin's cookie switches the connection,
/// and the clones made before, to the page's session.
#[tokio::test]
async fn accept_switches_to_the_pages_session() {
    let auth = auth();
    let root = root(&auth).await;
    let (credential, erin) = impersonating(&auth, &root).await;
    let conn = Connection::new(auth.clone(), &root);
    let clone = conn.clone();

    conn.accept(&page_metadata(&credential)).await.unwrap();

    for conn in [&conn, &clone] {
        assert_eq!(conn.user_id(), erin.id);
        assert_ne!(conn.session_id(), root.session.id);

        let (user, session) = conn.signed_in().await.unwrap();
        assert_eq!(user.id, erin.id);
        assert_eq!(session.impersonator, Some(root.user.id));

        // The admin's rights do not carry into the page.
        assert_eq!(
            refusal(conn.require_admin().await),
            Some(AuthError::Forbidden)
        );
    }

    // The same credential again stands; the upgrade's session does not.
    clone.accept(&page_metadata(&credential)).await.unwrap();
    assert!(ended(clone.accept(&Metadata::new()).await));
    assert_eq!(conn.user_id(), erin.id);
}

/// Anything but a live page session of the upgrade's admin refuses, and the
/// refused connection speaks for nobody, the admin included.
#[tokio::test]
async fn accept_refuses_a_failing_credential() {
    let key = generate_session_key();
    let auth = Auth::builder(MemoryStore::new(), key)
        .impersonation(true)
        .build();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let (credential, _) = impersonating(&auth, &root).await;

    // Not a page credential: garbage, a cookie value, and a credential
    // signed with another key.
    let cookie = auth.cookie_header(&root.session.id);
    let cookie = cookie
        .to_str()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    let session = auth.verify_page_credential(&credential).unwrap();
    let other = crate::core::page_credential(&generate_session_key(), session);

    for bad in ["garbage", &cookie, &other, ""] {
        let conn = Connection::new(auth.clone(), &root);
        assert!(ended(conn.accept(&page_metadata(bad)).await), "{bad:?}");
        assert_eq!(
            refusal(conn.signed_in().await),
            Some(AuthError::Unauthorized)
        );
        assert_eq!(
            refusal(conn.require_admin().await),
            Some(AuthError::Unauthorized)
        );
        assert_eq!(
            conn.update(&AuthEvent::UserChanged(root.user.info()))
                .await
                .unwrap(),
            None
        );
        assert_eq!(conn.lagged().await.unwrap(), None);
    }

    // Beside another admin's cookie.
    let conn = Connection::new(auth.clone(), &ada);
    assert!(ended(conn.accept(&page_metadata(&credential)).await));

    // A page credential of a session that is not impersonated.
    let plain = crate::core::page_credential(&key, &ada.session.id);
    let conn = Connection::new(auth.clone(), &root);
    assert!(ended(conn.accept(&page_metadata(&plain)).await));

    // The admin's cookie session ended.
    let conn = Connection::new(auth.clone(), &root);
    auth.sign_out(&root.session.id).await.unwrap();
    assert!(ended(conn.accept(&page_metadata(&credential)).await));
}

/// A page session that ended refuses, even beside its admin's live cookie.
#[tokio::test]
async fn accept_refuses_an_ended_page_session() {
    let auth = auth();
    let root = root(&auth).await;
    let (credential, _) = impersonating(&auth, &root).await;
    let page = auth.verify_page_credential(&credential).unwrap().to_owned();
    auth.sign_out(&page).await.unwrap();

    let conn = Connection::new(auth.clone(), &root);
    assert!(ended(conn.accept(&page_metadata(&credential)).await));
}

/// Updates taken before `accept` follow the page's session once switched,
/// and end when it ends, the admin's session still live.
#[tokio::test]
async fn updates_follow_the_pages_session() {
    let auth = auth();
    let root = root(&auth).await;
    let (credential, erin) = impersonating(&auth, &root).await;
    let conn = Connection::new(auth.clone(), &root);
    let mut updates = conn.updates();
    assert_eq!(updates.guard().user(), root.user.info());

    conn.accept(&page_metadata(&credential)).await.unwrap();
    assert_eq!(updates.guard().user().id, erin.id);

    // The page's own change, as the page's user.
    let changed = auth
        .set_role(&root.user, &root.session, erin.id, Role::Admin)
        .await
        .unwrap();
    let next = tokio::time::timeout(WAIT, updates.next()).await.unwrap();
    assert!(
        matches!(&next, Some(AuthUpdate::Me(info)) if info.id == changed.id && info.impersonated_by.is_some()),
        "{next:?}"
    );

    let page = auth.verify_page_credential(&credential).unwrap().to_owned();
    auth.sign_out(&page).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, updates.next()).await.unwrap(),
        None
    );
    assert!(auth.session(&root.session.id).await.unwrap().is_some());
}

/// Once switched, the admin's cookie session ending ends the page's socket
/// too, even while waiting.
#[tokio::test]
async fn updates_end_with_the_admins_session() {
    let auth = auth();
    let root = root(&auth).await;
    let (credential, _) = impersonating(&auth, &root).await;
    let conn = Connection::new(auth.clone(), &root);
    let mut updates = conn.updates();

    let next = updates.next();
    let accept = async {
        tokio::time::sleep(BRIEFLY).await;
        conn.accept(&page_metadata(&credential)).await.unwrap();
        tokio::time::sleep(BRIEFLY).await;
        auth.sign_out(&root.session.id).await.unwrap();
    };
    let (next, ()) = tokio::time::timeout(WAIT, async { tokio::join!(next, accept) })
        .await
        .unwrap();
    assert_eq!(next, None);

    assert!(updates.unless_ended(async {}).await.is_none());
}

/// A refused connection's updates end at once, whether taken before or
/// after the refusal.
#[tokio::test]
async fn updates_of_a_refused_connection_end() {
    let auth = auth();
    let root = root(&auth).await;
    let conn = Connection::new(auth.clone(), &root);
    let mut before = conn.updates();
    let pending_next = before.next();

    let refuse = async {
        tokio::time::sleep(BRIEFLY).await;
        assert!(ended(conn.accept(&page_metadata("garbage")).await));
    };
    let (next, ()) = tokio::time::timeout(WAIT, async { tokio::join!(pending_next, refuse) })
        .await
        .unwrap();
    assert_eq!(next, None);

    let mut after = conn.updates();
    assert_eq!(
        tokio::time::timeout(WAIT, after.next()).await.unwrap(),
        None
    );
    assert_eq!(after.unless_ended(async { 1 }).await, None);
}

/// Until `accept` settled it, a connection speaks for no session: an app
/// that forgot to call it fails safe.
#[tokio::test]
async fn an_unsettled_connection_speaks_for_nobody() {
    let auth = auth();
    let root = root(&auth).await;
    let conn = Connection::new(auth.clone(), &root);

    // The ids are the upgrade's, but nothing passes.
    assert_eq!(conn.session_id(), root.session.id);
    assert_eq!(conn.user_id(), root.user.id);
    assert_eq!(
        refusal(conn.signed_in().await),
        Some(AuthError::Unauthorized)
    );
    assert_eq!(
        refusal(conn.require_admin().await),
        Some(AuthError::Unauthorized)
    );
    let me = AuthEvent::UserChanged(root.user.info());
    assert_eq!(conn.update(&me).await.unwrap(), None);
    assert_eq!(conn.lagged().await.unwrap(), None);

    conn.accept(&Metadata::new()).await.unwrap();
    assert_eq!(conn.signed_in().await.unwrap().0.id, root.user.id);
    assert_eq!(conn.require_admin().await.unwrap().id, root.user.id);
    assert_eq!(
        conn.update(&me).await.unwrap(),
        Some(AuthUpdate::Me(root.user.info()))
    );
}

/// Updates taken before `accept` yield nothing until it settles, then what
/// was sent meanwhile; they end unsettled only with the upgrade's session.
#[tokio::test]
async fn updates_wait_for_accept() {
    let auth = auth();
    let root = root(&auth).await;
    let conn = Connection::new(auth.clone(), &root);
    let mut updates = conn.updates();

    let (pat, _) = pending(&auth, &root, "pat", Role::Regular).await;
    assert!(tokio::time::timeout(BRIEFLY, updates.next()).await.is_err());

    conn.accept(&Metadata::new()).await.unwrap();
    let next = tokio::time::timeout(WAIT, updates.next()).await.unwrap();
    assert_eq!(next, Some(AuthUpdate::UserCreated(pat)));

    let conn = Connection::new(auth.clone(), &root);
    let mut updates = conn.updates();
    assert!(tokio::time::timeout(BRIEFLY, updates.next()).await.is_err());
    auth.sign_out(&root.session.id).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, updates.next()).await.unwrap(),
        None
    );
}
