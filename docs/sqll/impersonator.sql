-- Adds `sessions.impersonator_id` to a database created with SqllStore's
-- schema before sessions recorded the admin behind an impersonation. Run it
-- once, as one of the app's migrations, before opening the store. A database
-- created with the current schema, or migrated with one of the other
-- migrations in this directory, already has the column.
--
-- Existing sessions get NULL: none of them is marked as impersonated.
ALTER TABLE sessions
ADD COLUMN impersonator_id INTEGER REFERENCES users (id) ON DELETE CASCADE;
