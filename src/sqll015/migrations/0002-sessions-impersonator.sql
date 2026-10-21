-- watchword-0002-sessions-impersonator: sessions record the admin behind an
-- impersonation. Existing sessions get NULL: none of them is marked as
-- impersonated.
ALTER TABLE sessions
ADD COLUMN impersonator_id INTEGER REFERENCES users (id) ON DELETE CASCADE;
