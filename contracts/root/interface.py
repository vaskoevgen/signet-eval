# === Main (root) v1 ===
# Session-scoped preflight rules via SIGNET_SESSION. Adds session_id to the Preflight struct and threads session-awareness through all preflight operations (submit, query, deactivation, history, hook evaluation) so that concurrent Claude Code instances in different projects do not interfere with each other's preflights. When SIGNET_SESSION is unset, all behavior is backward-compatible with the current global-scope model. DB schema migration adds a nullable session_id TEXT column and index, wrapped in a transaction with hook-safe error handling.

# Module invariants:
#   - When SIGNET_SESSION is unset or empty, all preflight behavior is identical to pre-session-scoping implementation (backward compatible)
#   - session_id stored in the database is always either NULL or a non-empty string — empty strings are normalized to NULL
#   - Only one preflight per unique session_id value may be active at any time (enforced by store_preflight deactivation)
#   - Global preflights (session_id IS NULL) are visible in all session scopes (Scoped queries match session_id = sid OR session_id IS NULL)
#   - Session-scoped deactivation uses exact match semantics: filing with session_id = X deactivates only active preflights with session_id = X; filing with session_id = NULL deactivates only active preflights with session_id IS NULL
#   - HMAC covers the full serialized Preflight payload including session_id when present
#   - skip_serializing_if = Option::is_none on session_id ensures pre-migration preflights with session_id = None serialize identically to their original form, preserving HMAC validity
#   - In hook mode, exit code is always 0 regardless of database errors, migration failures, or query failures
#   - migrate_preflight_schema is idempotent and safe to call on every connection open
#   - No unsafe code is used anywhere in the implementation
#   - All 138 existing tests continue to pass without modification
#   - Policy evaluation (policy.rs) is not modified — it remains deterministic and side-effect-free
#   - No new crate dependencies are introduced

SessionId = primitive  # Opaque string identifier for an evaluation session.

OptionalSessionId = SessionId | None

class PreflightSessionFilter(Enum):
    """Determines how preflight queries are scoped. Computed from SIGNET_SESSION at each call site via current_session_filter(). Scoped(sid): match preflights with session_id = sid OR session_id IS NULL. Unscoped: match any active preflight (backward-compatible behavior when SIGNET_SESSION is unset)."""
    Scoped = "Scoped"
    Unscoped = "Unscoped"

class PreflightDeactivationScope(Enum):
    """Controls which preflights are deactivated when a new one is filed. ExactSession(sid): deactivate only WHERE session_id = sid. GlobalOnly: deactivate only WHERE session_id IS NULL. Derived from the incoming preflight's session_id field."""
    ExactSession = "ExactSession"
    GlobalOnly = "GlobalOnly"

class Preflight:
    """A self-imposed constraint record filed before starting work. Stored in SQLite preflights table. HMAC covers the full serialized payload including session_id when present."""
    id: str                                  # required, regex(^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$), Unique preflight identifier (UUID v4).
    task_description: str                    # required, length(min=1), Human-readable description of the task this preflight constrains.
    constraints: list                        # required, List of self-imposed constraint strings.
    filed_at: str                            # required, ISO 8601 UTC timestamp of when the preflight was filed.
    active: bool                             # required, Whether this preflight is currently active. Only one preflight per (session_id) scope may be active at a time.
    session_id: OptionalSessionId = None     # optional, Session scope for this preflight. None means global scope (applies to all sessions). When set, this preflight only applies to the matching session. Serialized with #[serde(default, skip_serializing_if = "Option::is_none")] to preserve HMAC compatibility with pre-migration preflights.
    hmac: str                                # required, HMAC-SHA256 covering the serialized preflight payload (including session_id when present). Ensures tamper detection.

PreflightList = list[Preflight]
# A list of Preflight records, used for history queries.

class PreflightHistoryFilter:
    """Optional filtering parameters for preflight history queries."""
    session_filter: PreflightSessionFilter   # required, Session scope filter. When Scoped, returns preflights matching that session_id plus global preflights. When Unscoped, returns all preflights.
    limit: int = 50                          # optional, range(min=1,max=1000), Maximum number of preflights to return, ordered by filed_at DESC.
    active_only: bool = false                # optional, If true, return only active preflights.

class McpToolResponse:
    """Standard MCP tool response structure for preflight operations."""
    success: bool                            # required, Whether the operation succeeded.
    message: str                             # required, Human-readable status message.
    preflight: Preflight = None              # optional, The preflight record, if applicable.
    session_id: OptionalSessionId = None     # optional, The session_id that was captured or matched. Echoed in responses so callers can verify session scope.

class MigrationResult(Enum):
    """Outcome of the database schema migration for session_id support."""
    AlreadyMigrated = "AlreadyMigrated"
    MigrationApplied = "MigrationApplied"
    MigrationFailed = "MigrationFailed"

class PreflightError(Enum):
    """Error types produced by preflight operations."""
    DatabaseError = "DatabaseError"
    SerializationError = "SerializationError"
    HmacVerificationFailed = "HmacVerificationFailed"
    MigrationFailed = "MigrationFailed"
    InvalidSessionId = "InvalidSessionId"

def current_session_id() -> OptionalSessionId:
    """
    Reads the SIGNET_SESSION environment variable and returns an OptionalSessionId. Returns None if the env var is unset or empty. Single canonical implementation; called at each use site, never cached. Equivalent to: std::env::var("SIGNET_SESSION").ok().filter(|s| !s.is_empty()).

    Postconditions:
      - Returns None if SIGNET_SESSION is unset
      - Returns None if SIGNET_SESSION is set to empty string
      - Returns Some(sid) where sid is non-empty if SIGNET_SESSION is set to a non-empty value
      - Result is not cached — each call re-reads the environment

    Side effects: none
    Idempotent: yes
    """
    ...

def current_session_filter() -> PreflightSessionFilter:
    """
    Derives a PreflightSessionFilter from the current SIGNET_SESSION env var. Returns Scoped(sid) when SIGNET_SESSION is set and non-empty, Unscoped otherwise. Convenience wrapper around current_session_id().

    Postconditions:
      - Returns Scoped(sid) iff current_session_id() returns Some(sid)
      - Returns Unscoped iff current_session_id() returns None

    Side effects: none
    Idempotent: yes
    """
    ...

def migrate_preflight_schema(
    db_connection: any,
    hook_mode: bool,
) -> MigrationResult:
    """
    Ensures the preflights table has the session_id TEXT column and the idx_preflight_session index. Checks PRAGMA table_info(preflights) for column existence. If absent, executes ALTER TABLE preflights ADD COLUMN session_id TEXT within a transaction. Always executes CREATE INDEX IF NOT EXISTS idx_preflight_session ON preflights(session_id). In hook mode, errors are caught and logged (never propagated) to maintain exit code 0 invariant.

    Preconditions:
      - db_connection is a valid, open SQLite connection
      - preflights table already exists (base schema created by vault init)

    Postconditions:
      - On MigrationApplied: session_id TEXT column exists on preflights table
      - On MigrationApplied: idx_preflight_session index exists on preflights(session_id)
      - On AlreadyMigrated: no schema changes made
      - On MigrationFailed with hook_mode=true: error is logged, function returns MigrationFailed without panicking
      - Existing rows have session_id = NULL after migration
      - No data in existing rows is modified

    Errors:
      - migration_sql_error (PreflightError::MigrationFailed): ALTER TABLE or CREATE INDEX SQL statement fails
          detail: SQLite error message from failed DDL statement
      - pragma_read_error (PreflightError::DatabaseError): PRAGMA table_info(preflights) query fails
          detail: Cannot inspect preflights table schema

    Side effects: none
    Idempotent: yes
    """
    ...

def store_preflight(
    db_connection: any,
    preflight: Preflight,
) -> bool:
    """
    Persists a new Preflight to the SQLite database. Before inserting, deactivates previous preflights with exact session_id match: if the incoming preflight has session_id = Some(sid), deactivates only WHERE session_id = sid AND active = 1; if session_id = None, deactivates only WHERE session_id IS NULL AND active = 1. This ensures session-scoped filings never deactivate global preflights and vice versa. The deactivation and insert are wrapped in a single transaction.

    Preconditions:
      - preflight.hmac is a valid HMAC-SHA256 over the serialized payload including session_id
      - preflight.active is true
      - preflight.session_id is either None or a non-empty string
      - migrate_preflight_schema has been called on this connection

    Postconditions:
      - The new preflight is persisted with active = 1
      - All previously active preflights with the SAME session_id are now active = 0
      - Preflights with a DIFFERENT session_id are unmodified
      - Global preflights (session_id IS NULL) are unmodified when incoming preflight has session_id = Some(_)
      - Session-scoped preflights are unmodified when incoming preflight has session_id = None
      - The entire operation (deactivate + insert) is atomic (single transaction)

    Errors:
      - database_write_error (PreflightError::DatabaseError): SQLite INSERT or UPDATE fails (disk full, locked, etc.)
          detail: SQLite error message
      - transaction_commit_error (PreflightError::DatabaseError): Transaction commit fails
          detail: Transaction commit failed

    Side effects: none
    Idempotent: no
    """
    ...

def active_preflight(
    db_connection: any,
    filter: PreflightSessionFilter,
) -> Preflight:
    """
    Queries the SQLite database for the currently active preflight, scoped by session. When filter is Scoped(sid): SELECT ... WHERE active = 1 AND (session_id = ?1 OR session_id IS NULL) ORDER BY filed_at DESC LIMIT 1. When filter is Unscoped: SELECT ... WHERE active = 1 ORDER BY filed_at DESC LIMIT 1. Returns the most recently filed matching active preflight, or None if no active preflight exists in scope.

    Preconditions:
      - migrate_preflight_schema has been called on this connection

    Postconditions:
      - If Some(p) returned: p.active == true
      - If Some(p) returned and filter is Scoped(sid): p.session_id == Some(sid) OR p.session_id == None
      - If None returned: no active preflight exists matching the filter criteria
      - When filter is Unscoped: behavior is identical to pre-session-scoping implementation
      - HMAC of returned preflight is not verified by this function (caller responsibility)

    Errors:
      - database_read_error (PreflightError::DatabaseError): SQLite SELECT query fails
          detail: SQLite error message
      - deserialization_error (PreflightError::SerializationError): Stored preflight row cannot be deserialized into Preflight struct
          detail: Failed to deserialize preflight from database row

    Side effects: none
    Idempotent: yes
    """
    ...

def is_preflight_locked(
    db_connection: any,
) -> bool:
    """
    Returns whether there is an active preflight in the current session scope. Delegates to active_preflight(current_session_filter()). Returns true if an active preflight exists, false otherwise. Used by hook evaluation to determine if preflight constraints apply.

    Preconditions:
      - migrate_preflight_schema has been called on this connection

    Postconditions:
      - Returns true iff active_preflight(db_connection, current_session_filter()) returns Some(_)
      - Returns false iff active_preflight(db_connection, current_session_filter()) returns None

    Errors:
      - database_read_error (PreflightError::DatabaseError): Underlying active_preflight query fails
          detail: SQLite error message

    Side effects: none
    Idempotent: yes
    """
    ...

def preflight_history(
    db_connection: any,
    filter: PreflightHistoryFilter,
) -> PreflightList:
    """
    Returns a list of preflights ordered by filed_at DESC, optionally filtered by session scope and active status. When filter.session_filter is Scoped(sid): returns preflights where session_id = sid OR session_id IS NULL. When Unscoped: returns all preflights.

    Preconditions:
      - migrate_preflight_schema has been called on this connection
      - filter.limit >= 1 and filter.limit <= 1000

    Postconditions:
      - Returned list length <= filter.limit
      - Returned list is ordered by filed_at DESC
      - If filter.active_only is true: all returned preflights have active == true
      - If filter.session_filter is Scoped(sid): all returned preflights have session_id == Some(sid) OR session_id == None

    Errors:
      - database_read_error (PreflightError::DatabaseError): SQLite SELECT query fails
          detail: SQLite error message

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_preflight_submit(
    db_connection: any,
    task_description: str,     # length(min=1)
    constraints: list,         # length(min=1)
) -> McpToolResponse:
    """
    MCP tool handler for signet_preflight_submit. Reads SIGNET_SESSION via current_session_id(), sets it on the Preflight struct, computes HMAC over the full serialized payload (including session_id), then delegates to store_preflight(). Returns an McpToolResponse echoing the captured session_id.

    Preconditions:
      - task_description is non-empty
      - constraints list is non-empty
      - migrate_preflight_schema has been called on this connection

    Postconditions:
      - On success: response.success == true
      - On success: response.preflight is the stored Preflight with HMAC computed
      - On success: response.session_id matches current_session_id() at time of call
      - On success: response.preflight.session_id == response.session_id
      - Previous active preflights with the same session_id are deactivated
      - Previous active preflights with a different session_id are unmodified

    Errors:
      - empty_task_description (PreflightError::SerializationError): task_description is empty
          detail: task_description must not be empty
      - empty_constraints (PreflightError::SerializationError): constraints list is empty
          detail: At least one constraint must be provided
      - database_error (PreflightError::DatabaseError): store_preflight fails
          detail: Failed to store preflight

    Side effects: none
    Idempotent: no
    """
    ...

def handle_preflight_active(
    db_connection: any,
) -> McpToolResponse:
    """
    MCP tool handler for signet_preflight_active. Reads current session via current_session_filter(), delegates to active_preflight(), returns McpToolResponse with the active preflight (if any) including its session_id field.

    Preconditions:
      - migrate_preflight_schema has been called on this connection

    Postconditions:
      - response.success == true (even if no active preflight exists)
      - If active preflight exists in scope: response.preflight is set and response.session_id reflects its session_id
      - If no active preflight in scope: response.message indicates none active, response.preflight is not set

    Errors:
      - database_error (PreflightError::DatabaseError): active_preflight query fails
          detail: Failed to query active preflight

    Side effects: none
    Idempotent: yes
    """
    ...

def evaluate_preflight_in_hook(
    db_connection: any,
    tool_name: str,
    tool_input: str,
) -> McpToolResponse:
    """
    Hook-mode preflight evaluation. Reads current session scope, queries active_preflight, and evaluates whether the pending tool call is consistent with the active preflight's constraints. In hook mode, ALL errors are caught and logged — the function NEVER propagates errors and NEVER causes a non-zero exit code. If no active preflight matches the session scope, evaluation is a no-op pass.

    Postconditions:
      - Function NEVER panics
      - Function NEVER returns an error that would cause non-zero exit code
      - If SIGNET_SESSION is set: only preflights matching that session (or global) are considered
      - If SIGNET_SESSION is unset: any active preflight is considered (backward compatible)
      - If no active preflight in scope: response.success == true with pass-through message
      - If database errors occur: they are logged to stderr and the tool call is allowed (fail-open in hook mode)

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['OptionalSessionId', 'PreflightSessionFilter', 'PreflightDeactivationScope', 'Preflight', 'PreflightList', 'PreflightHistoryFilter', 'McpToolResponse', 'MigrationResult', 'PreflightError', 'current_session_id', 'current_session_filter', 'migrate_preflight_schema', 'PreflightError::MigrationFailed', 'PreflightError::DatabaseError', 'store_preflight', 'active_preflight', 'PreflightError::SerializationError', 'is_preflight_locked', 'preflight_history', 'handle_preflight_submit', 'handle_preflight_active', 'evaluate_preflight_in_hook']
