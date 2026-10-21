## watchword's messages for its Yew components, in English.
##
## Every id starts with `watchword-`. An app translates them by adding the
## same ids to its own catalog, which it adds before watchword's.

## Shared

watchword-retry = Retry
watchword-sign-in = Sign in
watchword-sign-out = Sign out
watchword-login = Login
watchword-email = Email
watchword-password = Password
watchword-role = Role
watchword-save = Save
watchword-saved = Saved.
watchword-cancel = Cancel
watchword-account = Account
watchword-users = Users
watchword-passwords-differ = The passwords do not match.
watchword-set-password = Set password
watchword-role-admin = Administrator
watchword-role-regular = Regular user
watchword-method-password = Password
watchword-method-google = Google

## Failed requests

watchword-session-ended = Your session has ended. Sign in again.
watchword-error-login-taken = That login is already taken.
watchword-error-email-taken = That email is already taken.
watchword-error-forbidden = You are not allowed to do that.
watchword-error-user-not-found = That user no longer exists.
watchword-error-unreachable = Could not reach the server.
watchword-error-unreachable-reload = Could not reach the server. Reload to try again.

# What failed, with $error the cause from the watchword-cause- messages.
watchword-failed-saving = Saving failed: { $error }.
watchword-failed-loading-users = Loading the users failed: { $error }.
watchword-failed-loading-cloudflare = Loading the Cloudflare Access settings failed: { $error }.
watchword-failed-adding-user = Adding the user failed: { $error }.
watchword-failed-issuing-link = Issuing a link failed: { $error }.
watchword-failed-revoking-link = Revoking the link failed: { $error }.
watchword-failed-signing-out = Signing out failed: { $error }.
watchword-failed-revoking-access = Revoking access failed: { $error }.
watchword-failed-impersonating = Impersonating failed: { $error }.
watchword-failed-deleting = Deleting failed: { $error }.
watchword-failed-changing-password = Changing the password failed: { $error }.
watchword-failed-stopping = Stopping failed: { $error }.
watchword-failed-signing-in = Signing in failed: { $error }.
watchword-failed-setting-password = Setting the password failed: { $error }.
watchword-failed-checking-link = The link could not be checked: { $error }.
watchword-failed-checking-session = The server could not be asked who is signed in: { $error }.

# The cause of a failure, placed in a watchword-failed- message.
watchword-cause-status = the server answered with HTTP { $status }
watchword-cause-network = could not reach the server: { $detail }
watchword-cause-socket = the request over the socket failed: { $detail }
watchword-cause-unauthorized = not signed in
watchword-cause-forbidden = not allowed
watchword-cause-not-found = not found
watchword-cause-gone = the link was used or has expired
watchword-cause-too-many-requests = too many attempts, try again later
watchword-cause-login-taken = the login is already taken
watchword-cause-email-taken = the email is already taken

# Why the server found a request invalid.
watchword-invalid-password-too-short = { $min ->
    [one] Must be at least { $min } character.
   *[other] Must be at least { $min } characters.
}
watchword-invalid-password-incorrect = The current password is incorrect.
watchword-invalid-email-required = An email is required.
watchword-invalid-login-or-email-required = A login or an email is required.
watchword-invalid-login-empty = The login cannot be empty.
watchword-invalid-logins-disabled = Login names are not used.
watchword-invalid-email-managed-by-google = Your email is managed by your Google account.
watchword-invalid-google-account-taken = This Google account is already linked to another user.
watchword-invalid-role-not-changeable = The role cannot be changed here.
watchword-invalid-malformed-request = The request is malformed.
# A reason this version does not know, from a newer server.
watchword-invalid-unknown = The request is invalid.

## Sign in

watchword-login-or-email = Login or email
watchword-sign-in-cloudflare = Sign in with Cloudflare
watchword-sign-in-google = Sign in with Google
watchword-sign-in-none = No way to sign in is enabled.
watchword-sign-in-wrong-login = Wrong login or password.
watchword-sign-in-wrong-email = Wrong email or password.
watchword-sign-in-too-many = Too many failed sign-ins. Try again in a few minutes.
watchword-sign-in-forbidden = This account may not sign in.
watchword-sign-in-cloudflare-failed = Cloudflare could not sign you in. Reload to try again.
# The ?error= codes the server redirects to the sign-in page with.
watchword-query-auth-failed = Authentication failed.
watchword-query-user-not-found = User not found.
watchword-query-failed = Signing in failed.

## Registration

watchword-register-heading = Choose a password
watchword-register-checking = Checking the link…
watchword-confirm-password = Confirm password
watchword-sign-up-google = Sign up with Google
watchword-link-invalid = This link is not valid.
watchword-link-gone = This link has already been used or has expired. Ask an administrator for a new one.

## User menu

watchword-stop-impersonating = Stop impersonating
watchword-impersonating = Impersonating { $user }.
watchword-impersonating-as = Impersonating { $user } as { $admin }.
watchword-stop-forbidden = You can no longer return to your admin account. Sign out instead.

## Account

watchword-signs-in-with = Signs in with
watchword-switch-google = Switch to Google
watchword-switch-google-other = Switch to another Google account
watchword-switch-google-hint = Switching to Google removes your password and signs you out everywhere else.
watchword-profile = Profile
watchword-login-hint = Sign in with this name or your email.
watchword-email-google = Your email is the one of your Google account.
watchword-email-optional = Optional. Leave empty to remove it.
watchword-change-password = Change password
watchword-set-a-password = Set a password
watchword-password-hint = Changing the password signs you out everywhere else.
watchword-password-google-hint = Setting a password switches you from Google to the password and signs you out everywhere else.
watchword-current-password = Current password
watchword-new-password = New password
watchword-confirm-new-password = Confirm new password
watchword-password-changed = Password changed. Your other sessions were signed out.
watchword-password-set = Password set. Your other sessions were signed out.
watchword-password-wrong = The current password is wrong.

## User management

watchword-add-user = Add user
watchword-users-loading = Loading users…
watchword-users-none = There are no users.
watchword-users-no-match = No user matches the filter.
watchword-filter = Filter
watchword-filter-users = Filter users
watchword-clear-filter = Clear filter
watchword-new-email-hint = Optional. Lets them sign in with it, or through Cloudflare Access.
watchword-new-user-hint = They get a link to choose a password with.
watchword-user-added = User added. Send them their link below.
watchword-role-changed = Role changed.
watchword-status = Status
watchword-link = Link
watchword-actions = Actions
watchword-pages = Pages
watchword-previous-page = Previous page
watchword-next-page = Next page
watchword-page-number = { $page } / { $pages }
watchword-no-email = No email
# The badge on the admin's own row.
watchword-you = you
watchword-no-link = No link
watchword-new-link = New link
watchword-copy = Copy
watchword-link-copied = Link copied.
watchword-copy-refused = The browser did not allow copying. Select the link and copy it instead.
watchword-link-for = Link for { $name }
watchword-copy-link-for = Copy the link for { $name }
# $expires is a watchword-time- message.
watchword-link-send = Send this to { $name }. It works once and expires { $expires }. It is not shown again.
watchword-link-expires = Link expires { $expires }
watchword-discard-changes = Discard changes
watchword-confirm-delete = Delete { $name }?
watchword-confirm-revoke-access = Revoke access for { $name }?
watchword-no = No
watchword-yes = Yes
watchword-edit = Edit
watchword-edit-user = Edit { $name }
watchword-new-link-for = New link for { $name }
watchword-revoke-link = Revoke link
watchword-revoke-link-for = Revoke the link for { $name }
watchword-sign-out-everywhere = Sign out everywhere
watchword-sign-out-everywhere-user = Sign { $name } out everywhere
watchword-revoke-access = Revoke access
watchword-revoke-access-for = Revoke access for { $name }
watchword-impersonate = Impersonate
watchword-impersonate-user = Impersonate { $name }
watchword-delete = Delete
watchword-delete-user = Delete { $name }
watchword-link-revoked = Link revoked.
watchword-signed-out-everywhere = Signed out everywhere.
watchword-access-revoked = Access revoked.
watchword-signed-in-as-user = Signed in as the user.
watchword-user-deleted = User deleted.
# A user's account state, and its title with their sign-in $method:
# password or google.
watchword-access-pending = Pending
watchword-access-active = Active
watchword-access-revoked-label = Revoked
watchword-access-pending-title = { $method ->
    [google] Pending registration (Google sign-in)
   *[password] Pending registration (password sign-in)
}
watchword-access-active-title = { $method ->
    [google] Active (Google sign-in)
   *[password] Active (password sign-in)
}
watchword-access-revoked-title = { $method ->
    [google] Access revoked (Google sign-in)
   *[password] Access revoked (password sign-in)
}
# When a link expires.
watchword-time-now = now
watchword-time-soon = in less than a minute
watchword-time-minutes = { $count ->
    [one] in { $count } minute
   *[other] in { $count } minutes
}
watchword-time-hours = { $count ->
    [one] in { $count } hour
   *[other] in { $count } hours
}
watchword-time-days = { $count ->
    [one] in { $count } day
   *[other] in { $count } days
}

## Cloudflare Access settings

watchword-cloudflare-heading = Cloudflare Access
# The default name of the app in these messages' $app.
watchword-cloudflare-the-app = the app
watchword-cloudflare-loading = Loading the Cloudflare Access settings…
watchword-cloudflare-unavailable = This server does not offer Cloudflare Access sign-in.
watchword-cloudflare-intro = Signs people in with their Cloudflare Zero Trust login when { $app } sits behind Cloudflare Access. To set it up:
watchword-cloudflare-step-protect = In the Zero Trust dashboard, protect { $app } with a self-hosted application under Access → Applications.
# $host is shown as code.
watchword-cloudflare-step-team-domain = Enter your team domain below: the { $host } host. The server fetches Cloudflare's signing keys from it and checks that tokens were issued by it.
watchword-cloudflare-step-audience = Copy the application's Application Audience (AUD) Tag from its overview into Audience. Every application in your team is signed with the same keys, so the tag is what stops a token for another application from signing in here.
watchword-cloudflare-step-users = Give each person's account the email they sign in to Cloudflare with, on the Users page. Access only signs in existing users; it never creates them.
watchword-cloudflare-step-enable = Turn on Sign in through Access.
watchword-cloudflare-enabled = Sign in through Access
watchword-cloudflare-enabled-hint = Signs in the existing user whose email Cloudflare Access reports. Users are never created.
watchword-cloudflare-team-domain = Team domain
watchword-cloudflare-team-domain-hint = The host of your Zero Trust team, such as yourteam.cloudflareaccess.com.
watchword-cloudflare-audience = Audience
watchword-cloudflare-audience-hint = The Application Audience (AUD) Tag from the Access application protecting { $app }: a long hex string.
watchword-cloudflare-verify-jwt = Verify token
watchword-cloudflare-verify-jwt-hint = Checks the signed Access token against your team's keys. Keep this on unless the server is only reachable through Cloudflare.
watchword-cloudflare-trust-email = Trust email header
watchword-cloudflare-trust-email-hint = Accepts the email header Access adds. With token verification on, the two must match.
watchword-cloudflare-unverified-warning = Without Verify token, anyone who can reach the server without going through Cloudflare can sign in as any user by sending this header.
