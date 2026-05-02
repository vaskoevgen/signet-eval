# Session-scope preflight rules via SIGNET_SESSION

## Context

signet-eval's preflight system (self-imposed constraints before starting work) stores preflights in a shared SQLite database. When multiple Claude Code instances run concurrently in different projects, preflights from one session leak into others. A preflight filed for "refactor auth in TalentSync" blocks unrelated tool calls in "update docs for signet-eval."

The `SIGNET_SESSION` envvar is already configured in `~/.profile` — it defaults to `$PWD` when launching Claude Code via the `cl` function.

## Requirements

### 1. Add session_id to Preflight struct
- Add `session_id: Option<String>` field to `Preflight` (vault.rs)
- Default to `None` for backward compatibility with existing preflights
- Serialize/deserialize with serde (skip_serializing_if = is_none for clean YAML)

### 2. Capture SIGNET_SESSION on preflight submit
- In `handle_preflight_submit` (mcp_server.rs), read `std::env::var("SIGNET_SESSION")`
- Store the value in the preflight's `session_id` field
- If env var is unset or empty, store `None` (global scope — backward compatible)

### 3. Filter active_preflight by session
- In `active_preflight` (vault.rs), read current `SIGNET_SESSION` at query time
- If SIGNET_SESSION is set: only return preflights where `session_id` matches OR `session_id` is NULL (global preflights still apply everywhere)
- If SIGNET_SESSION is unset: return any active preflight (current behavior)

### 4. Scope deactivation to session
- In `store_preflight` (vault.rs), the "deactivate previous" step should only deactivate preflights with the SAME session_id (or NULL)
- A global preflight should not be deactivated when a session-scoped one is filed

### 5. DB schema migration
- Add `session_id TEXT` column to `preflights` table
- Handle migration gracefully (ALTER TABLE IF NOT EXISTS pattern)
- Add index: `CREATE INDEX IF NOT EXISTS idx_preflight_session ON preflights(session_id)`

### 6. Update all preflight handlers
- `is_preflight_locked` — scope to session
- `preflight_history` — optionally filter by session
- `handle_preflight_active` — scope to session
- Hook evaluation (hook.rs) — scope to session

### 7. MCP tool updates
- `signet_preflight_active` should show the session_id
- `signet_preflight_submit` should show the captured session_id in response

## Non-requirements
- No changes to hard policy rules (policy.rs condition functions, rule evaluation)
- No changes to vault passphrase, credentials, or spending systems
- No changes to CLI subcommands (main.rs) beyond what's needed for preflight display

## Constraints
- All 138 existing tests must continue to pass
- When SIGNET_SESSION is unset, behavior is identical to current (backward compatible)
- Preflight HMAC must still cover the session_id (it's in the serialized payload)
- No new dependencies
