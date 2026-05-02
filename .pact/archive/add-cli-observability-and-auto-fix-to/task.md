# Add CLI observability and auto-fix to signet-eval

## Context

signet-eval has pause/disable/enable commands for temporarily relaxing policy enforcement, but the `status` command doesn't show what's paused or disabled. The `validate` command shows diagnostics with fix hints, but the existing `fix_policy()` function has no CLI surface. The `enable` command doesn't clear all overrides in one shot.

## Requirements

### 1. validate --fix / --dry-run
- Add `--fix` flag to `Validate` CLI command
- Add `--dry-run` flag (only valid with `--fix`)
- `--fix` calls `fix_policy()`, writes updated policy, re-signs if vault exists
- `--dry-run` prints what would change without writing
- Must be idempotent (C014)
- Must not fix structural errors — only mechanical clamping (C016)

### 2. enable clears all overrides
- `signet-eval enable` (no `--session`) clears global disable AND all session disables
- Reports what was cleared
- If nothing disabled, prints "Not currently disabled."

### 3. status shows enforcement state
- Show global disable state
- Show disabled sessions (from `list_disabled_sessions()`)
- Show global pause with expiry (from `is_paused_file()` + `pause_until_file()`)
- Show per-rule/per-session pauses (from `list_pauses()`)
- Show enforcement overrides even without a vault (C019)
- Omit sections when nothing is active

## Constraints
- C014-C019 in constraints.yaml
- All 128 existing tests must pass
- Changes scoped to src/main.rs only (vault.rs and policy.rs already have the needed functions)
