# CLI Observability and Auto-Fix for signet-eval

## System Context

signet-eval is a Rust binary that enforces deterministic policy on AI agent tool calls. It sits between Claude Code and the tools the agent uses (Bash, file editing, etc). Every tool call passes through signet-eval as a PreToolUse hook. The CLI provides subcommands for managing policy, vault, credentials, and enforcement state (pause/disable/enable).

Recent additions include per-session disable (`signet-eval disable --session $SESSION`), per-rule and per-session pause, and a `fix_policy()` function in policy.rs that can auto-fix clampable validation issues.

## Consequence Map

- **High**: User forgets which sessions are disabled or paused, loses trust in the tool, and either disables it entirely or operates unprotected without realizing. Quote: "if I forget which sessions are disabled or paused, I am powerless."
- **Medium**: `validate` reports errors with fix hints but the user must manually edit YAML. The fix_policy() function exists but has no CLI surface — wasted implementation.
- **Low**: Running `enable` doesn't fully clear all overrides in one shot, requiring the user to know about both global and session disables and run the command twice.

## What We're Building

### 1. validate --fix / --dry-run

Expose the existing `fix_policy()` function (policy.rs:674) through CLI flags on the `Validate` subcommand.

- `signet-eval validate` — current behavior, print diagnostics
- `signet-eval validate --fix` — apply auto-fixes (clamp numeric values, remove locked:false), write policy, re-sign if vault exists
- `signet-eval validate --fix --dry-run` — show what --fix would change without writing

fix_policy() already handles: clamping gate.within to 1-500, clamping ensure.timeout to 1-30, removing serialized locked:false. It returns a `PolicyFix` struct with a list of modifications and counts.

### 2. enable clears all overrides

`signet-eval enable` (no --session flag) should clear:
1. Global disable file (if set)
2. All session disables (if any)

In one invocation. Report what was cleared. If nothing was disabled, print "Not currently disabled."

Current bug: main.rs:556-570 checks global disable first; if found, clears it and returns. Session disables are only cleared if no global disable exists.

### 3. status shows enforcement overrides

`signet-eval status` should display active pauses and disables alongside existing vault info.

New sections (only shown when overrides are active):
- **Enforcement**: "DISABLED" or "active" or "paused until <time>"
- **Pauses**: list from list_pauses() — shows rule name, session, expiry
- **Disabled sessions**: list from list_disabled_sessions()
- **Global disable**: from is_disabled_file()
- **Global pause**: from is_paused_file() with pause_until_file() expiry

These functions already exist in vault.rs. The status command just doesn't call them.

Even without a vault (no setup), enforcement overrides should still be shown since they're file-based.

## Boundary Conditions

### Scope
- 3 changes to main.rs (Validate flags, Enable logic, Status output)
- No changes to policy.rs (fix_policy already exists)
- No changes to vault.rs (list_pauses, list_disabled_sessions already exist)

### Non-Goals
- Adding new auto-fix capabilities beyond what fix_policy() already does
- Changing MCP server behavior (MCP validate tool already exposes fix mode)
- Adding new pause/disable mechanisms

### Constraints
- C014: fix must be idempotent
- C015: dry-run must not write to disk
- C016: fix only handles mechanical issues, not structural errors
- C017: enable clears all overrides in one call
- C018: status shows complete enforcement state
- C019: status works even without vault

## Done When

1. `signet-eval validate --fix` applies fixes, writes policy, re-signs, prints what changed
2. `signet-eval validate --fix --dry-run` prints what would change, exits 0
3. Running --fix twice produces no changes on second run (idempotent)
4. `signet-eval enable` clears both global disable and all session disables
5. `signet-eval status` shows pauses and disabled sessions when present
6. `signet-eval status` shows enforcement overrides even without a vault
7. All existing 128 tests pass
8. New tests for: --fix, --dry-run, enable-all, status output
