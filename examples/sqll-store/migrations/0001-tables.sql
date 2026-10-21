-- The app's tables. Their names and shape are the app's own: watchword only
-- sees the records the store maps them into. Timestamps are INTEGER
-- milliseconds since the Unix epoch.

-- `display_name` is the app's own column, with no default: the store fills
-- it when it creates an account, from what it knows.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE,
    email TEXT UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    access TEXT NOT NULL,
    method TEXT NOT NULL,
    password_hash TEXT,
    google_sub TEXT UNIQUE,
    created_at INTEGER NOT NULL
);

-- `impersonator_id` is the admin acting as `account_id`, for a session
-- created by impersonation.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    impersonator_id INTEGER REFERENCES accounts (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX sessions_account ON sessions (account_id);
CREATE INDEX sessions_impersonator ON sessions (impersonator_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- Registration and reset links. `kind` is 'registration' or 'reset'.
CREATE TABLE links (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE INDEX links_account ON links (account_id);

-- Settings watchword keeps, such as `session_key`.
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
