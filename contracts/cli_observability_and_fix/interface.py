# === CLI Observability and Auto-Fix for signet-eval (cli_observability_and_fix) v1 ===
# Single-module implementation scoped to src/main.rs (plus integration tests in tests/integration_cli.rs). Three cohesive extensions to existing CLI command dispatch: (1) validate --fix / --dry-run for mechanical policy auto-correction with atomic write and optional vault re-signing; (2) enable command that clears global disable state AND all per-session disables; (3) status command that queries and renders all enforcement override/pause state as plain-text sections. All features share CLI arg parsing infrastructure, error handling patterns, and the Policy/Vault/pause-disable data model. No unsafe code; deterministic policy evaluation; exit code always 0 in hook mode.

# Module invariants:
#   - C014: handle_validate in Fix mode is idempotent — running fix on an already-fixed policy produces no changes and no writes.
#   - C016: fix_policy() applies only mechanical clamping fixes; structural errors are never modified and pass through as diagnostics with fixable=false.
#   - C019: handle_status and query_enforcement_state must succeed without a vault present; vault_present=false is a normal state, not an error.
#   - No unsafe code in any implementation.
#   - All errors on user input paths are handled — no unwrap() on fallible operations derived from user input.
#   - Exit code is always 0 in hook mode, enforced at outermost CLI dispatch level.
#   - Policy evaluation (including fix_policy) is deterministic and side-effect-free.
#   - Atomic write semantics: in Fix mode, policy is written to tempfile first, signature computed, then tempfile renamed over original. On signing failure, tempfile is deleted and original is untouched.
#   - Signing order: vault re-sign is attempted BEFORE atomic rename of tempfile over original policy. Rename only occurs on signing success.
#   - --dry-run without --fix always produces exit code 1 (InvalidArguments).
#   - handle_enable is idempotent: clearing already-cleared state is a no-op that reports 'Not currently disabled.'
#   - render_enforcement_state omits sections with no active overrides; if all sections empty, outputs 'No active overrides.'
#   - All 128 existing tests continue to pass; new features have integration tests in tests/integration_cli.rs.

class PolicyPath:
    """Validated filesystem path to a policy file. Must be non-empty and end with .toml or .yaml."""
    value: str                               # required, length(min=1), regex(\.(toml|yaml)$), Absolute or relative path to the policy file.

SessionId = primitive  # Opaque string identifier for an evaluation session.

class RuleId:
    """Identifier for a policy rule. Non-empty, alphanumeric with underscores/hyphens."""
    value: str                               # required, length(min=1,max=128), regex(^[a-zA-Z0-9_-]+$), Rule identifier string.

class FieldPath:
    """Dot-delimited path to a field within a policy rule configuration."""
    value: str                               # required, length(min=1,max=512), regex(^[a-zA-Z0-9_.\[\]]+$), Dot-delimited field path, e.g. 'rules.max_tokens.limit'.

class Timestamp:
    """RFC 3339 UTC timestamp string."""
    value: str                               # required, regex(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$), RFC 3339 formatted UTC timestamp.

class ValidateMode(Enum):
    """Operational mode for the validate command."""
    DiagnoseOnly = "DiagnoseOnly"
    Fix = "Fix"
    DryRun = "DryRun"

class CliExitCode(Enum):
    """Well-known CLI exit codes for all commands."""
    Success = "Success"
    ValidationFailure = "ValidationFailure"
    UsageError = "UsageError"
    InternalError = "InternalError"

class Policy:
    """Deserialized policy document governing evaluation constraints and rules."""
    path: PathBuf                            # required, Filesystem location from which the policy was loaded.
    rules: PolicyRuleList                    # required, Ordered list of enforcement rules in this policy.
    raw_bytes: String                        # required, Original serialized policy content for diffing.

class DiagnosticSeverity(Enum):
    """Severity level of a validation diagnostic."""
    Error = "Error"
    Warning = "Warning"
    Info = "Info"

class Diagnostic:
    """A single validation diagnostic emitted by validate, with optional fix hint."""
    severity: DiagnosticSeverity             # required, Severity level of this diagnostic.
    rule_id: String                          # required, Constraint ID this diagnostic pertains to (e.g. 'C016').
    message: String                          # required, Human-readable diagnostic message.
    fixable: Bool                            # required, True if this diagnostic is mechanically fixable (not structural).

DiagnosticList = list[Diagnostic]
# Ordered collection of Diagnostic entries from a validation pass.

class FixChange:
    """A single mechanical change applied by fix_policy()."""
    rule_id: String                          # required, Constraint ID that triggered this fix.
    field_path: String                       # required, Dot-delimited path to the field that was changed.
    old_value: String                        # required, Serialized previous value.
    new_value: String                        # required, Serialized replacement value.

FixChangeList = list[FixChange]
# Ordered collection of FixChange entries.

class FixResult:
    """Result of calling fix_policy(): the corrected policy and a summary of changes."""
    original: Policy                         # required, The policy before fixes were applied.
    fixed: Policy                            # required, The policy after mechanical clamping fixes.
    changes: FixChangeList                   # required, List of individual changes applied.
    has_changes: Bool                        # required, True if fixed differs from original (convenience flag).

class ClearedOverrideKind(Enum):
    """Discriminant for what type of override was cleared by enable."""
    GlobalDisable = "GlobalDisable"
    SessionDisable = "SessionDisable"

class ClearedOverride:
    """A single override that was cleared by the enable command."""
    kind: ClearedOverrideKind                # required, What kind of override was cleared.
    session_id: OptionalSessionId = None     # optional, Session ID if this was a session-level disable.

ClearedOverrideList = list[ClearedOverride]
# Collection of overrides cleared by a single enable invocation.

class EnableResult:
    """Result of the enable command: what was cleared, or nothing."""
    cleared: ClearedOverrideList             # required, Overrides that were cleared.
    was_disabled: Bool                       # required, True if anything was actually disabled before enable ran.

SessionIdList = list[SessionId]
# List of session identifiers.

class PauseScope(Enum):
    """Scope discriminant for a PauseEntry."""
    Global = "Global"
    Rule = "Rule"
    Session = "Session"
    RuleSession = "RuleSession"

class PauseEntry:
    """A single active pause record (global, per-rule, or per-session)."""
    scope: PauseScope                        # required, What this pause applies to.
    rule_id: OptionalString = None           # optional, If scope is Rule or RuleSession, the rule ID.
    session_id: OptionalSessionId = None     # optional, If scope is Session or RuleSession, the session ID.
    expires_at: OptionalInstant = None       # optional, When this pause expires; None means indefinite.

PauseEntryList = list[PauseEntry]
# Ordered collection of active PauseEntry records.

class EnforcementState:
    """Complete snapshot of enforcement overrides for the status command."""
    globally_disabled: Bool                  # required, True if enforcement is globally disabled.
    disabled_sessions: SessionIdList         # required, Sessions with enforcement individually disabled.
    global_pause: OptionalInstant = None     # optional, If globally paused, the expiry instant; None if not paused.
    active_pauses: PauseEntryList            # required, All per-rule and per-session pause entries currently active.
    vault_present: Bool                      # required, Whether a vault is present (C019: status works without vault).

class DiffLine:
    """A single line in the human-readable diff output for --dry-run."""
    rule_id: str                             # required, Rule affected.
    field_path: str                          # required, Dot-delimited field path.
    old_value: str                           # required, Original value as string.
    new_value: str                           # required, Corrected value as string.

String = primitive  # UTF-8 string primitive.

Bool = primitive  # Boolean primitive.

PathBuf = primitive  # Filesystem path (std::path::PathBuf).

PolicyRuleList = list[PolicyRule]
# Ordered collection of PolicyRule entries.

OptionalString = String | None

OptionalSessionId = SessionId | None

OptionalInstant = Instant | None

Instant = primitive  # Wall-clock timestamp (e.g. chrono::DateTime<Utc> or std::time::SystemTime).

class PolicyRule:
    """A single named enforcement rule within a Policy."""
    id: String                               # required, Unique rule identifier (e.g. 'C014').
    description: String                      # required, Human-readable description of the rule.

def derive_validate_mode(
    fix: bool,
    dry_run: bool,
) -> ValidateMode:
    """
    Derives the ValidateMode from the parsed CLI flags --fix and --dry-run. Enforces the constraint that --dry-run without --fix is a hard error (exit 1). Pure function with no side effects.

    Preconditions:
      - fix and dry_run are booleans parsed from CLI args

    Postconditions:
      - If !fix && !dry_run → DiagnoseOnly
      - If fix && dry_run → DryRun
      - If fix && !dry_run → Fix
      - If !fix && dry_run → error (InvalidArguments)

    Errors:
      - dry_run_without_fix (CliExitCode::InvalidArguments): dry_run is true but fix is false
          message: --dry-run requires --fix

    Side effects: none
    Idempotent: yes
    """
    ...

def fix_policy(
    policy: Policy,
) -> FixResult:
    """
    Pure function: applies mechanical clamping fixes to a policy (C016). Returns a FixResult containing the corrected policy, the list of changes, and whether any changes were made. Only mechanical clamping is applied; structural errors are not modified. Deterministic and side-effect-free.

    Preconditions:
      - policy is a valid deserialized policy object (may contain clamping violations but not parse errors)

    Postconditions:
      - has_changes == !changes.is_empty()
      - If has_changes is false, fixed_policy is semantically identical to input policy
      - Each FixChange in changes has distinct (rule_id, field_path) pair
      - All changes represent mechanical clamping only — no structural modifications
      - Function is deterministic: same input always produces same output

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_validate(
    policy_path: PolicyPath,
    mode: ValidateMode,
) -> CliExitCode:
    """
    Handler for the validate command match arm. Runs existing validation to produce diagnostics, then branches on ValidateMode: DiagnoseOnly emits diagnostics and exits; DryRun computes fix and renders structured diff without writing; Fix computes fix, writes via atomic tempfile, re-signs if vault present (rollback on signing failure), and emits remaining unfixable diagnostics. Idempotent (C014).

    Preconditions:
      - policy_path points to an existing, readable file
      - mode has been validated by derive_validate_mode (no InvalidArguments state)

    Postconditions:
      - DiagnoseOnly: diagnostics emitted to stdout, no filesystem writes
      - DryRun: structured diff emitted to stdout, no filesystem writes, exit Success
      - Fix with no changes: 'No fixable issues' emitted, exit Success, no writes
      - Fix with changes and vault present: policy written atomically, re-signed, exit Success
      - Fix with changes and vault absent: policy written atomically, re-signing skipped, exit Success
      - Fix with changes and signing failure: tempfile deleted, exit InternalError, original policy unchanged
      - Diagnostics with fixable=false are always passed through unchanged

    Errors:
      - policy_file_not_found (CliExitCode::InvalidArguments): policy_path does not exist on the filesystem
          message: Policy file not found
      - policy_parse_error (CliExitCode::ValidationFailure): Policy file cannot be deserialized
          message: Failed to parse policy file
      - tempfile_write_failure (CliExitCode::InternalError): Cannot create or write to tempfile during Fix mode
          message: Failed to write temporary policy file
      - signing_failure (CliExitCode::InternalError): Vault re-signing fails after writing fixed policy
          message: Failed to re-sign policy; changes rolled back
      - persist_failure (CliExitCode::InternalError): Atomic rename of tempfile over original fails
          message: Failed to persist fixed policy file

    Side effects: Reads policy file from disk, Writes corrected policy via atomic tempfile in Fix mode, Calls vault re-sign in Fix mode when vault is present, Prints diagnostics and/or diff to stdout
    Idempotent: yes
    """
    ...

def handle_enable() -> CliExitCode:
    """
    Handler for the enable command match arm (when invoked without --session). Clears global disable state, then iterates list_disabled_sessions() to clear each session disable. Accumulates cleared items into EnableResult. If nothing was disabled, prints 'Not currently disabled.' and exits 0. Otherwise prints each cleared item and exits 0. Best-effort: errors clearing individual sessions are accumulated but do not halt processing.

    Preconditions:
      - Command was invoked without --session flag

    Postconditions:
      - Global disable state file is removed if it existed
      - All per-session disable state files are removed if they existed
      - If no overrides were active, 'Not currently disabled.' is printed to stdout
      - If overrides were cleared, each cleared override is printed to stdout
      - Exit code is always Success (0)

    Errors:
      - state_dir_inaccessible (CliExitCode::InternalError): Cannot read the disable state directory
          message: Failed to access enforcement state directory
      - session_clear_failure (CliExitCode::InternalError): One or more per-session disable files could not be removed
          message: Failed to clear one or more session disables

    Side effects: Deletes global disable state file, Deletes per-session disable state files, Prints cleared override list to stdout
    Idempotent: yes
    """
    ...

def handle_status() -> CliExitCode:
    """
    Handler for the status command match arm. Queries all enforcement override and pause state: global disable, per-session disables, global pause (is_paused_file, pause_until_file), and all active pauses (list_pauses). Constructs EnforcementState and renders sorted, section-based plain text to stdout. Sections with no active overrides are omitted. Must work without a vault present (C019).

    Postconditions:
      - EnforcementState is fully populated from filesystem queries
      - Sections with no active overrides are not printed
      - Output uses existing CLI output header style (plain text, section headers)
      - Pauses within each section are sorted by scope then expiry
      - vault_present reflects actual vault state; absence does not cause error
      - Exit code is always Success (0)

    Errors:
      - state_query_failure (CliExitCode::InternalError): Cannot read one or more state files or directories
          message: Failed to query enforcement state

    Side effects: Reads global disable state, Reads per-session disable state files, Reads pause state files, Reads vault metadata for presence check, Prints enforcement state to stdout
    Idempotent: yes
    """
    ...

def render_fix_diff(
    changes: FixChangeList,
) -> str:
    """
    Pure function: renders a FixChangeList into a human-readable structured diff for --dry-run output. Each line formatted as 'rule_id: field_path: old → new'. Output order matches change list order.

    Preconditions:
      - changes is a valid FixChangeList (possibly empty)

    Postconditions:
      - Output is a newline-delimited string with one line per change
      - If changes is empty, output is the empty string
      - Each line matches format: '{rule_id}: {field_path}: {old_value} → {new_value}'

    Side effects: none
    Idempotent: yes
    """
    ...

def render_enforcement_state(
    state: EnforcementState,
) -> str:
    """
    Pure function: renders an EnforcementState into plain-text sectioned output matching existing CLI output patterns. Omits sections with no active overrides. Sections: 'Enforcement' (globally disabled), 'Disabled Sessions' (list), 'Global Pause' (until timestamp), 'Active Pauses' (list with scope/rule/session/expiry). Pauses sorted by scope then expiry.

    Preconditions:
      - state is a valid EnforcementState

    Postconditions:
      - Output is a newline-delimited string with section headers and content
      - Sections with no active overrides are omitted entirely
      - If all sections empty, output is 'No active overrides.'
      - Pauses within Active Pauses section sorted by scope (Global < Rule < Session) then expiry ascending
      - Section headers match existing CLI output style

    Side effects: none
    Idempotent: yes
    """
    ...

def build_enable_result(
    global_was_disabled: bool,
    cleared_sessions: SessionIdList,
) -> EnableResult:
    """
    Pure function: constructs an EnableResult from the global disable state and list of cleared session overrides. Determines was_disabled from whether any overrides were cleared.

    Postconditions:
      - was_disabled == (global_was_disabled || !cleared_sessions.is_empty())
      - cleared list contains GlobalDisable entry iff global_was_disabled
      - cleared list contains one SessionDisable entry per session in cleared_sessions
      - Order: GlobalDisable first (if present), then SessionDisable entries in input order

    Side effects: none
    Idempotent: yes
    """
    ...

def query_enforcement_state() -> EnforcementState:
    """
    Queries all enforcement state from the filesystem: global disable, per-session disables, global pause, pause-until, all active pauses, and vault presence. Aggregates into EnforcementState. Vault absence is not an error (C019).

    Postconditions:
      - All fields of EnforcementState are populated from current filesystem state
      - vault_present is false if vault directory does not exist or is uninitialized
      - active_pauses includes only non-expired pauses at time of query
      - disabled_sessions contains exactly the sessions returned by list_disabled_sessions()

    Errors:
      - state_dir_read_failure (CliExitCode::InternalError): Cannot read the state directory or its contents
          message: Failed to read enforcement state from filesystem

    Side effects: Reads enforcement state files from disk, Reads vault metadata from disk
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['PolicyPath', 'RuleId', 'FieldPath', 'Timestamp', 'ValidateMode', 'CliExitCode', 'Policy', 'DiagnosticSeverity', 'Diagnostic', 'DiagnosticList', 'FixChange', 'FixChangeList', 'FixResult', 'ClearedOverrideKind', 'ClearedOverride', 'ClearedOverrideList', 'EnableResult', 'SessionIdList', 'PauseScope', 'PauseEntry', 'PauseEntryList', 'EnforcementState', 'DiffLine', 'PolicyRuleList', 'OptionalString', 'OptionalSessionId', 'OptionalInstant', 'PolicyRule', 'derive_validate_mode', 'CliExitCode::InvalidArguments', 'fix_policy', 'handle_validate', 'CliExitCode::ValidationFailure', 'CliExitCode::InternalError', 'handle_enable', 'handle_status', 'render_fix_diff', 'render_enforcement_state', 'build_enable_result', 'query_enforcement_state']
