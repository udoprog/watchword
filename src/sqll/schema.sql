-- The tables SqllStore reads and writes, for a new database. Timestamps are
-- INTEGER milliseconds since the Unix epoch. An app may add its own columns
-- to `users` (with defaults) and its own tables referencing `users (id)`.

-- A user has a unique login, a unique normalized email, or both.
-- `role` is 'admin' or 'regular'; `access` is 'pending', 'active' or
-- 'revoked'; `method` is 'password' or 'google'.
CREATE TABLE IF NOT EXISTS
    users (
        id INTEGER PRIMARY KEY,
        login TEXT UNIQUE,
        email TEXT UNIQUE,
        role TEXT NOT NULL,
        access TEXT NOT NULL DEFAULT 'pending',
        method TEXT NOT NULL DEFAULT 'password',
        password_hash TEXT,
        google_sub TEXT UNIQUE,
        created_at INTEGER NOT NULL
    );

CREATE TABLE IF NOT EXISTS
    sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- Registration and reset links. `kind` is 'registration' or 'reset'.
CREATE TABLE IF NOT EXISTS
    auth_tokens (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    );

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens (user_id);

-- Settings such as `session_key`.
CREATE TABLE IF NOT EXISTS
    config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
