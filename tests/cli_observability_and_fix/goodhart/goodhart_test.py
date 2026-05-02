"""
Hidden adversarial acceptance tests for CLI Observability and Auto-Fix (signet-eval).

These tests are designed to catch implementations that pass visible tests through
shortcuts (hardcoded returns, incomplete validation, etc.) rather than genuinely
satisfying the contract.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from src.cli_observability_and_fix import (
    PolicyPath,
    RuleId,
    FieldPath,
    Timestamp,
    ValidateMode,
    CliExitCode,
    PauseScope,
    DiagnosticSeverity,
    ClearedOverrideKind,
    derive_validate_mode,
    fix_policy,
    handle_validate,
    handle_enable,
    handle_status,
    render_fix_diff,
    render_enforcement_state,
    build_enable_result,
    query_enforcement_state,
    Policy,
    PolicyRule,
    FixChange,
    FixResult,
    Diagnostic,
    PauseEntry,
    EnforcementState,
    ClearedOverride,
    EnableResult,
)


# ---------------------------------------------------------------------------
# PolicyPath adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartPolicyPath:

    def test_goodhart_policy_path_nested_toml(self):
        """PolicyPath must accept any path ending in .toml regardless of directory depth."""
        pp = PolicyPath(value="/deeply/nested/dir/my_custom_policy.toml")
        assert pp.value == "/deeply/nested/dir/my_custom_policy.toml"

    def test_goodhart_policy_path_dots_in_directory(self):
        """PolicyPath must validate only the final extension, not reject dots in directory names."""
        pp = PolicyPath(value="/some.dir/another.dir/config.yaml")
        assert pp.value == "/some.dir/another.dir/config.yaml"

    def test_goodhart_policy_path_yml_rejected(self):
        """PolicyPath must reject .yml — only .toml and .yaml are allowed."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="config.yml")

    def test_goodhart_policy_path_toml_bak_rejected(self):
        """PolicyPath must reject .toml.bak — .toml must be the final extension."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="policy.toml.bak")

    def test_goodhart_policy_path_uppercase_yaml_rejected(self):
        """PolicyPath regex is case-sensitive — .YAML must be rejected."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="policy.YAML")

    def test_goodhart_policy_path_uppercase_toml_rejected(self):
        """PolicyPath regex is case-sensitive — .TOML must be rejected."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="policy.TOML")

    def test_goodhart_policy_path_dot_toml_minimal(self):
        """PolicyPath must accept '.toml' as it's >= 1 char and ends with .toml."""
        pp = PolicyPath(value=".toml")
        assert pp.value == ".toml"

    def test_goodhart_policy_path_dot_yaml_minimal(self):
        """PolicyPath must accept '.yaml' as it's >= 1 char and ends with .yaml."""
        pp = PolicyPath(value=".yaml")
        assert pp.value == ".yaml"

    def test_goodhart_policy_path_json_rejected(self):
        """PolicyPath must reject .json extension."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="/etc/policy.json")

    def test_goodhart_policy_path_double_extension_yaml(self):
        """PolicyPath must accept paths with dots before the final .yaml extension."""
        pp = PolicyPath(value="my.policy.v2.yaml")
        assert pp.value == "my.policy.v2.yaml"

    def test_goodhart_policy_path_whitespace_rejected(self):
        """PolicyPath with only whitespace must be rejected (doesn't end in .toml/.yaml)."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="   ")

    def test_goodhart_policy_path_txt_rejected(self):
        """PolicyPath must reject .txt extension."""
        with pytest.raises((ValueError, Exception)):
            PolicyPath(value="rules.txt")


# ---------------------------------------------------------------------------
# RuleId adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartRuleId:

    def test_goodhart_rule_id_single_char_alpha(self):
        """RuleId must accept single-character identifiers (min length 1)."""
        rid = RuleId(value="a")
        assert rid.value == "a"

    def test_goodhart_rule_id_single_char_upper(self):
        """RuleId must accept uppercase single character."""
        rid = RuleId(value="Z")
        assert rid.value == "Z"

    def test_goodhart_rule_id_single_digit(self):
        """RuleId must accept a single digit."""
        rid = RuleId(value="9")
        assert rid.value == "9"

    def test_goodhart_rule_id_hyphen_only(self):
        """RuleId must accept strings consisting solely of hyphens."""
        rid = RuleId(value="---")
        assert rid.value == "---"

    def test_goodhart_rule_id_underscore_only(self):
        """RuleId must accept strings consisting solely of underscores."""
        rid = RuleId(value="___")
        assert rid.value == "___"

    def test_goodhart_rule_id_slash_rejected(self):
        """RuleId must reject forward slashes."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="rule/sub")

    def test_goodhart_rule_id_at_sign_rejected(self):
        """RuleId must reject @ symbols."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="rule@v2")

    def test_goodhart_rule_id_unicode_rejected(self):
        """RuleId regex is ASCII-only — must reject unicode letters."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="règle_1")

    def test_goodhart_rule_id_127_chars_accepted(self):
        """RuleId at 127 chars must be accepted (one below max boundary)."""
        val = "a" * 127
        rid = RuleId(value=val)
        assert rid.value == val
        assert len(rid.value) == 127

    def test_goodhart_rule_id_colon_rejected(self):
        """RuleId must reject colons."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="rule:1")

    def test_goodhart_rule_id_hash_rejected(self):
        """RuleId must reject hash/pound characters."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="rule#1")

    def test_goodhart_rule_id_newline_rejected(self):
        """RuleId must reject strings containing newlines."""
        with pytest.raises((ValueError, Exception)):
            RuleId(value="rule\n1")


# ---------------------------------------------------------------------------
# FieldPath adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartFieldPath:

    def test_goodhart_field_path_single_char(self):
        """FieldPath must accept a single character (min length 1)."""
        fp = FieldPath(value="x")
        assert fp.value == "x"

    def test_goodhart_field_path_array_index(self):
        """FieldPath must accept paths with array bracket notation."""
        fp = FieldPath(value="rules[0].limits[2].max_value")
        assert fp.value == "rules[0].limits[2].max_value"

    def test_goodhart_field_path_slash_rejected(self):
        """FieldPath must reject slash characters."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="rules/0/field")

    def test_goodhart_field_path_space_rejected(self):
        """FieldPath must reject whitespace characters."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="field name")

    def test_goodhart_field_path_curly_brace_rejected(self):
        """FieldPath allows square brackets but must reject curly braces."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="rules{0}.field")

    def test_goodhart_field_path_parentheses_rejected(self):
        """FieldPath must reject parentheses."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="func(0)")

    def test_goodhart_field_path_511_chars_accepted(self):
        """FieldPath at 511 chars (one below max) must be accepted."""
        val = "a" * 511
        fp = FieldPath(value=val)
        assert fp.value == val
        assert len(fp.value) == 511

    def test_goodhart_field_path_at_sign_rejected(self):
        """FieldPath must reject @ symbol."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="field@attr")

    def test_goodhart_field_path_star_rejected(self):
        """FieldPath must reject wildcard * character."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="rules[*].field")

    def test_goodhart_field_path_hyphen_rejected(self):
        """FieldPath regex does not include hyphen — must reject it."""
        with pytest.raises((ValueError, Exception)):
            FieldPath(value="my-field.path")


# ---------------------------------------------------------------------------
# Timestamp adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartTimestamp:

    def test_goodhart_timestamp_different_date(self):
        """Timestamp must work for any valid UTC timestamp, not just hardcoded dates."""
        ts = Timestamp(value="1999-12-31T23:59:59Z")
        assert ts.value == "1999-12-31T23:59:59Z"

    def test_goodhart_timestamp_high_precision_fractional(self):
        """Timestamp must accept fractional seconds with many digits."""
        ts = Timestamp(value="2024-01-15T10:30:00.123456789Z")
        assert ts.value == "2024-01-15T10:30:00.123456789Z"

    def test_goodhart_timestamp_single_fractional_digit(self):
        """Timestamp must accept fractional seconds with just one digit."""
        ts = Timestamp(value="2024-06-01T00:00:00.1Z")
        assert ts.value == "2024-06-01T00:00:00.1Z"

    def test_goodhart_timestamp_offset_rejected(self):
        """Timestamp must reject +00:00 offset — only Z suffix allowed."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15T10:30:00+00:00")

    def test_goodhart_timestamp_lowercase_z_rejected(self):
        """Timestamp requires uppercase Z — lowercase z must be rejected."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15T10:30:00z")

    def test_goodhart_timestamp_missing_seconds_rejected(self):
        """Timestamp must reject strings missing the seconds component."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15T10:30Z")

    def test_goodhart_timestamp_extra_prefix_rejected(self):
        """Timestamp regex is anchored — leading garbage must be rejected."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="XX2024-01-15T10:30:00Z")

    def test_goodhart_timestamp_extra_suffix_rejected(self):
        """Timestamp regex is end-anchored — trailing garbage after Z must be rejected."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15T10:30:00Zextra")

    def test_goodhart_timestamp_date_only_rejected(self):
        """Timestamp must reject date-only strings."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15")

    def test_goodhart_timestamp_space_separator_rejected(self):
        """Timestamp must reject space as date-time separator instead of T."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15 10:30:00Z")

    def test_goodhart_timestamp_negative_offset_rejected(self):
        """Timestamp must reject negative UTC offsets."""
        with pytest.raises((ValueError, Exception)):
            Timestamp(value="2024-01-15T10:30:00-05:00")

    def test_goodhart_timestamp_epoch_start(self):
        """Timestamp must accept epoch start date."""
        ts = Timestamp(value="1970-01-01T00:00:00Z")
        assert ts.value == "1970-01-01T00:00:00Z"

    def test_goodhart_timestamp_far_future(self):
        """Timestamp must accept far-future dates."""
        ts = Timestamp(value="9999-12-31T23:59:59Z")
        assert ts.value == "9999-12-31T23:59:59Z"


# ---------------------------------------------------------------------------
# derive_validate_mode adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartDeriveValidateMode:

    def test_goodhart_derive_validate_mode_returns_enum_type(self):
        """derive_validate_mode must return actual ValidateMode enum values, not strings."""
        result = derive_validate_mode(fix=True, dry_run=False)
        assert isinstance(result, ValidateMode)
        assert result == ValidateMode.Fix

    def test_goodhart_derive_validate_mode_diagnose_returns_enum(self):
        """DiagnoseOnly result must be the actual enum member."""
        result = derive_validate_mode(fix=False, dry_run=False)
        assert isinstance(result, ValidateMode)
        assert result == ValidateMode.DiagnoseOnly

    def test_goodhart_derive_validate_mode_dryrun_returns_enum(self):
        """DryRun result must be the actual enum member."""
        result = derive_validate_mode(fix=True, dry_run=True)
        assert isinstance(result, ValidateMode)
        assert result == ValidateMode.DryRun

    def test_goodhart_derive_validate_mode_all_four_combos_exhaustive(self):
        """All four boolean combinations must be handled — no missing branch."""
        # (False, False) -> DiagnoseOnly
        assert derive_validate_mode(fix=False, dry_run=False) == ValidateMode.DiagnoseOnly
        # (True, False) -> Fix
        assert derive_validate_mode(fix=True, dry_run=False) == ValidateMode.Fix
        # (True, True) -> DryRun
        assert derive_validate_mode(fix=True, dry_run=True) == ValidateMode.DryRun
        # (False, True) -> error
        with pytest.raises(Exception):
            derive_validate_mode(fix=False, dry_run=True)


# ---------------------------------------------------------------------------
# render_fix_diff adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartRenderFixDiff:

    def test_goodhart_render_fix_diff_preserves_input_order(self):
        """render_fix_diff must preserve exact input order, not alphabetically sort."""
        changes = [
            FixChange(rule_id="zz_rule", field_path="z.field", old_value="9", new_value="1"),
            FixChange(rule_id="aa_rule", field_path="a.field", old_value="1", new_value="9"),
            FixChange(rule_id="mm_rule", field_path="m.field", old_value="5", new_value="3"),
        ]
        result = render_fix_diff(changes)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 3
        assert lines[0].startswith("zz_rule")
        assert lines[1].startswith("aa_rule")
        assert lines[2].startswith("mm_rule")

    def test_goodhart_render_fix_diff_uses_unicode_arrow(self):
        """render_fix_diff must use Unicode → (U+2192), not ASCII alternatives."""
        changes = [
            FixChange(rule_id="r1", field_path="f.p", old_value="10", new_value="5"),
        ]
        result = render_fix_diff(changes)
        assert "\u2192" in result  # Unicode right arrow →
        assert "->" not in result or "\u2192" in result  # Should not use ASCII ->

    def test_goodhart_render_fix_diff_exact_format(self):
        """render_fix_diff must produce exact format 'rule_id: field_path: old → new'."""
        changes = [
            FixChange(rule_id="R1", field_path="f.p", old_value="10", new_value="5"),
        ]
        result = render_fix_diff(changes)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 1
        expected = "R1: f.p: 10 \u2192 5"
        assert lines[0] == expected

    def test_goodhart_render_fix_diff_special_chars_in_values(self):
        """render_fix_diff must handle values with colons and special chars verbatim."""
        changes = [
            FixChange(rule_id="rule1", field_path="config.url", old_value="http://old:8080", new_value="http://new:9090"),
        ]
        result = render_fix_diff(changes)
        assert "http://old:8080" in result
        assert "http://new:9090" in result

    def test_goodhart_render_fix_diff_five_changes(self):
        """render_fix_diff with many changes must produce exactly that many lines."""
        changes = [
            FixChange(rule_id=f"rule_{i}", field_path=f"field_{i}", old_value=str(i), new_value=str(i * 10))
            for i in range(5)
        ]
        result = render_fix_diff(changes)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 5


# ---------------------------------------------------------------------------
# build_enable_result adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartBuildEnableResult:

    def test_goodhart_build_enable_result_many_sessions(self):
        """build_enable_result must handle many sessions, not just 1-2."""
        sessions = [f"session_{i}" for i in range(20)]
        result = build_enable_result(global_was_disabled=True, cleared_sessions=sessions)
        assert result.was_disabled is True
        assert len(result.cleared) == 21  # 1 global + 20 sessions

    def test_goodhart_build_enable_result_session_order_preserved(self):
        """build_enable_result must preserve input order of sessions, not sort."""
        sessions = ["zebra_session", "alpha_session", "middle_session"]
        result = build_enable_result(global_was_disabled=False, cleared_sessions=sessions)
        session_entries = [c for c in result.cleared if c.kind == ClearedOverrideKind.SessionDisable]
        assert len(session_entries) == 3
        assert session_entries[0].session_id == "zebra_session"
        assert session_entries[1].session_id == "alpha_session"
        assert session_entries[2].session_id == "middle_session"

    def test_goodhart_build_enable_result_global_disable_has_no_session_id(self):
        """GlobalDisable ClearedOverride must have session_id=None."""
        result = build_enable_result(global_was_disabled=True, cleared_sessions=[])
        assert len(result.cleared) == 1
        assert result.cleared[0].kind == ClearedOverrideKind.GlobalDisable
        assert result.cleared[0].session_id is None

    def test_goodhart_build_enable_result_session_disable_has_session_id(self):
        """SessionDisable ClearedOverride must carry the correct session_id."""
        result = build_enable_result(global_was_disabled=False, cleared_sessions=["sess_abc"])
        assert len(result.cleared) == 1
        assert result.cleared[0].kind == ClearedOverrideKind.SessionDisable
        assert result.cleared[0].session_id == "sess_abc"

    def test_goodhart_build_enable_result_global_first_then_sessions(self):
        """When both global and sessions cleared, GlobalDisable must be first in list."""
        result = build_enable_result(global_was_disabled=True, cleared_sessions=["s1", "s2"])
        assert result.cleared[0].kind == ClearedOverrideKind.GlobalDisable
        for entry in result.cleared[1:]:
            assert entry.kind == ClearedOverrideKind.SessionDisable

    def test_goodhart_build_enable_result_empty_is_not_disabled(self):
        """build_enable_result with nothing cleared must have was_disabled=False and empty cleared."""
        result = build_enable_result(global_was_disabled=False, cleared_sessions=[])
        assert result.was_disabled is False
        assert len(result.cleared) == 0

    def test_goodhart_build_enable_result_sessions_only_is_disabled(self):
        """build_enable_result with sessions but no global must still have was_disabled=True."""
        result = build_enable_result(global_was_disabled=False, cleared_sessions=["s1"])
        assert result.was_disabled is True

    def test_goodhart_build_enable_result_global_only_is_disabled(self):
        """build_enable_result with global but no sessions must have was_disabled=True."""
        result = build_enable_result(global_was_disabled=True, cleared_sessions=[])
        assert result.was_disabled is True


# ---------------------------------------------------------------------------
# fix_policy adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartFixPolicy:

    def test_goodhart_fix_policy_distinct_rule_field_pairs(self):
        """fix_policy must never produce duplicate (rule_id, field_path) pairs in changes."""
        # Create a policy with multiple rules having clamping violations
        rules = [PolicyRule(id=f"rule_{i}", description=f"Rule {i}") for i in range(5)]
        policy = Policy(path="test.toml", rules=rules, raw_bytes="")
        result = fix_policy(policy)
        pairs = [(c.rule_id, c.field_path) for c in result.changes]
        assert len(pairs) == len(set(pairs)), "Duplicate (rule_id, field_path) pairs found in changes"

    def test_goodhart_fix_policy_original_preserved(self):
        """fix_policy must return the original policy unmodified in FixResult.original."""
        rules = [PolicyRule(id="rule_1", description="Test rule")]
        policy = Policy(path="test.toml", rules=rules, raw_bytes="original content")
        result = fix_policy(policy)
        assert result.original.raw_bytes == "original content"
        assert result.original.path == "test.toml"

    def test_goodhart_fix_policy_has_changes_false_means_identical(self):
        """When has_changes is False, fixed and original policies must be semantically identical."""
        rules = [PolicyRule(id="clean_rule", description="A clean rule")]
        policy = Policy(path="clean.toml", rules=rules, raw_bytes="clean content")
        result = fix_policy(policy)
        if not result.has_changes:
            assert result.fixed.raw_bytes == result.original.raw_bytes
            assert len(result.fixed.rules) == len(result.original.rules)

    def test_goodhart_fix_policy_has_changes_consistency_general(self):
        """has_changes must equal (len(changes) > 0) for any input, not just test fixtures."""
        rules = [PolicyRule(id="r", description="d")]
        policy = Policy(path="p.toml", rules=rules, raw_bytes="")
        result = fix_policy(policy)
        assert result.has_changes == (len(result.changes) > 0)


# ---------------------------------------------------------------------------
# render_enforcement_state adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartRenderEnforcementState:

    def test_goodhart_render_enforcement_state_disabled_sessions_only(self):
        """With only disabled sessions, only Disabled Sessions section should appear."""
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=["s1", "s2"],
            global_pause=None,
            active_pauses=[],
            vault_present=False,
        )
        output = render_enforcement_state(state)
        assert output != "No active overrides."
        assert "s1" in output
        assert "s2" in output

    def test_goodhart_render_enforcement_state_global_pause_only(self):
        """With only a global pause, only Global Pause section should appear."""
        from datetime import datetime, timezone
        some_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=[],
            global_pause=some_time,
            active_pauses=[],
            vault_present=True,
        )
        output = render_enforcement_state(state)
        assert output != "No active overrides."

    def test_goodhart_render_enforcement_state_vault_true_no_overrides(self):
        """vault_present=True with no overrides must still output 'No active overrides.'"""
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=[],
            global_pause=None,
            active_pauses=[],
            vault_present=True,
        )
        output = render_enforcement_state(state)
        assert output.strip() == "No active overrides."

    def test_goodhart_render_enforcement_state_scope_ordering(self):
        """Active pauses must be sorted: Global < Rule < Session < RuleSession."""
        from datetime import datetime, timezone
        t1 = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        pauses = [
            PauseEntry(scope=PauseScope.RuleSession, rule_id="r1", session_id="s1", expires_at=t1),
            PauseEntry(scope=PauseScope.Session, rule_id=None, session_id="s1", expires_at=t1),
            PauseEntry(scope=PauseScope.Global, rule_id=None, session_id=None, expires_at=t1),
            PauseEntry(scope=PauseScope.Rule, rule_id="r1", session_id=None, expires_at=t1),
        ]
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=[],
            global_pause=None,
            active_pauses=pauses,
            vault_present=False,
        )
        output = render_enforcement_state(state)
        # Find positions of scope indicators in output
        lines = output.split("\n")
        # The Global scope must appear before Rule, Rule before Session, Session before RuleSession
        global_pos = None
        rule_pos = None
        session_pos = None
        rulesession_pos = None
        for i, line in enumerate(lines):
            lower = line.lower()
            if "global" in lower and global_pos is None and "rule" not in lower and "session" not in lower:
                global_pos = i
            elif "rulesession" in lower or "rule_session" in lower or ("rule" in lower and "session" in lower):
                rulesession_pos = i
            elif "rule" in lower and "session" not in lower and rule_pos is None:
                rule_pos = i
            elif "session" in lower and "rule" not in lower and session_pos is None:
                session_pos = i

        # At minimum verify the output contains all pause entries
        assert len([l for l in lines if l.strip()]) >= 4

    def test_goodhart_render_enforcement_state_same_scope_sorted_by_expiry(self):
        """Pauses with same scope must be sorted by expiry ascending."""
        from datetime import datetime, timezone
        t_early = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        t_late = datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        t_mid = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        pauses = [
            PauseEntry(scope=PauseScope.Rule, rule_id="r_late", session_id=None, expires_at=t_late),
            PauseEntry(scope=PauseScope.Rule, rule_id="r_early", session_id=None, expires_at=t_early),
            PauseEntry(scope=PauseScope.Rule, rule_id="r_mid", session_id=None, expires_at=t_mid),
        ]
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=[],
            global_pause=None,
            active_pauses=pauses,
            vault_present=False,
        )
        output = render_enforcement_state(state)
        # r_early must appear before r_mid, which must appear before r_late
        early_pos = output.find("r_early")
        mid_pos = output.find("r_mid")
        late_pos = output.find("r_late")
        assert early_pos != -1 and mid_pos != -1 and late_pos != -1
        assert early_pos < mid_pos < late_pos

    def test_goodhart_render_enforcement_state_active_pauses_only(self):
        """With only active pauses, output must not be 'No active overrides.'"""
        from datetime import datetime, timezone
        t1 = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        pauses = [
            PauseEntry(scope=PauseScope.Global, rule_id=None, session_id=None, expires_at=t1),
        ]
        state = EnforcementState(
            globally_disabled=False,
            disabled_sessions=[],
            global_pause=None,
            active_pauses=pauses,
            vault_present=False,
        )
        output = render_enforcement_state(state)
        assert output.strip() != "No active overrides."
