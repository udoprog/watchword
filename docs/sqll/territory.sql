-- Moves territory's auth tables (as of territory 154ff85) onto SqllStore's
-- schema. Add it to territory's migrations as one file; it runs inside one
-- transaction and works with foreign keys on or off, since it never drops or
-- rebuilds `users`.
--
-- Territory's timestamps are RFC 3339 TEXT, as jiff writes them; they become
-- INTEGER milliseconds, truncated to the millisecond as SqllStore stores
-- times. A timestamp SQLite cannot parse fails the migration (NOT NULL
-- constraint) rather than being lost.

-- users: an optional unique login, `auth_method` becomes `method` with 'plain'
-- renamed to 'password', and created_at becomes INTEGER ms. The `email NOT
-- NULL` and role CHECK constraints stay; SqllStore never writes a NULL email
-- for territory, which runs with logins off. The `method` default stays
-- 'plain'; SqllStore never relies on it, since it always writes the method.
ALTER TABLE users
ADD COLUMN login TEXT;

CREATE UNIQUE INDEX users_login ON users (login);

ALTER TABLE users
RENAME COLUMN auth_method TO method;

UPDATE users
SET
    method = 'password'
WHERE
    method = 'plain';

ALTER TABLE users
ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0;

UPDATE users
SET
    created_at_ms = CAST(strftime('%s', created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', created_at), 4) AS INTEGER);

ALTER TABLE users
DROP COLUMN created_at;

ALTER TABLE users
RENAME COLUMN created_at_ms TO created_at;

-- sessions: rebuilt with INTEGER ms timestamps. Nothing references sessions.
CREATE TABLE
    sessions_new (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

INSERT INTO
    sessions_new (id, user_id, created_at, expires_at)
SELECT
    id,
    user_id,
    CAST(strftime('%s', created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', created_at), 4) AS INTEGER),
    CAST(strftime('%s', expires_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', expires_at), 4) AS INTEGER)
FROM
    sessions;

DROP TABLE sessions;

ALTER TABLE sessions_new
RENAME TO sessions;

CREATE INDEX idx_sessions_user ON sessions (user_id);

-- registration_tokens becomes auth_tokens, with INTEGER ms timestamps.
CREATE TABLE
    auth_tokens (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    );

INSERT INTO
    auth_tokens (id, user_id, kind, expires_at, used_at)
SELECT
    id,
    user_id,
    kind,
    CAST(strftime('%s', expires_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', expires_at), 4) AS INTEGER),
    CAST(strftime('%s', used_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', used_at), 4) AS INTEGER)
FROM
    registration_tokens;

DROP TABLE registration_tokens;

CREATE INDEX idx_auth_tokens_user ON auth_tokens (user_id);

-- config (key, value) already matches.
