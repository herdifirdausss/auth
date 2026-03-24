-- Migration: Add password_salt to password_history
-- Issue: S-3 Fix Password History Verification

ALTER TABLE password_history ADD COLUMN password_salt text;

-- For existing records, we can't recover the salt, but Argon2id needs it.
-- Future records will have it. 
-- For now, we allow NULL or leave it empty, but the repository should handle it.
-- Actually, it's better to make it NOT NULL for future consistency.
-- But since there might be data, let's add it as nullable first, then maybe backfill.
-- On this fresh system, we can just make it NOT NULL if there's no data.

-- Let's make it NOT NULL with a default empty string for safety if data exists.
ALTER TABLE password_history ALTER COLUMN password_salt SET NOT NULL;
ALTER TABLE password_history ALTER COLUMN password_salt SET DEFAULT '';
