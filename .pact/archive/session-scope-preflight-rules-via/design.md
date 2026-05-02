# Design: signet-eval

*Version 1 — Auto-maintained by pact*

## Decomposition

- [C] **CLI Observability and Auto-Fix for signet-eval** (`cli_observability_and_fix`)
  Single-module implementation scoped to src/main.rs (plus integration tests in tests/integration_cli.rs). Three cohesive changes to the existing CLI command dispatch:

1. **validate --fix / --dry-run**: Add `--fix` and `--dry-run` flags to the existing Validate CLI variant. When `--fix` is set, call `fix_policy()` (which returns a new Policy), diff against the original. If no changes, exit 0. If changes exist and `--dry-run`, print human-readable diff and exit 0 without writing. Otherwise write the new policy file; if vault is initialized, re-sign (rollback on signing failure). If vault absent, skip re-signing. `--dry-run` without `--fix` is a hard error (exit 1). Structural errors are passed through as diagnostics unchanged — only mechanical clamping results from fix_policy() are applied (C016). Operation is idempotent (C014).

2. **enable clears all overrides**: Modify the `enable` command handler so that when invoked without `--session`, it clears global disable state AND iterates `list_disabled_sessions()` to clear each session disable. Accumulate cleared items and print each. If nothing was disabled, print 'Not currently disabled.' and exit 0.

3. **status shows enforcement state**: Extend the `status` command handler to query `is_paused_file()`, `pause_until_file()`, `list_pauses()`, `list_disabled_sessions()`, and global disable state. Render each category as a plain-text section with headers matching existing CLI output patterns. Omit sections with no active overrides. Must work without a vault present (C019).

All three features share the same CLI arg parsing infrastructure, the same error handling patterns, and the same data model (Policy, Vault, pause/disable state files). No independent subsystems — just three extensions to existing match arms in main.rs.

## Engineering Decisions

### 
**Decision:** 
**Rationale:** 

### 
**Decision:** 
**Rationale:** 

### 
**Decision:** 
**Rationale:** 

### 
**Decision:** 
**Rationale:** 

### 
**Decision:** 
**Rationale:** 
