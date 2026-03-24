-- Migration 003: Add user_agent to security_tokens
ALTER TABLE security_tokens ADD COLUMN IF NOT EXISTS user_agent text;
