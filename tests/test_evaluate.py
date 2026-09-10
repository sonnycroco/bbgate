"""Verdict routing: the cases that decide whether a finding can be sent."""
from __future__ import annotations

import re

from bbgate.evaluate import evaluate
from bbgate.mutate import override_repro

from conftest import BLOCK, DIFFERENTIAL, OK, UNKNOWN, VERIFICATION, WARN, art, failed, make_project


def test_condition_only_holds_on_check_3(project, write_finding, add_manifest):
    """An exposed key with no impact artifact is a condition, not a consequence."""
    fp = write_finding("leaked-key", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])  # verification only, nothing evidencing impact
    v = evaluate("leaked-key", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_3" in failed(v)
    assert v.next_artifact, "the missing artifact must be named, not just refused"


def test_idor_single_account_holds_on_check_4(project, write_finding, add_manifest):
    """A privileged response from one account is impact, but it is not two-principal proof."""
    fp = write_finding("idor-single")
    add_manifest(fp, [art("http_exchange", priv=True), VERIFICATION])
    v = evaluate("idor-single", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_4" in failed(v)
    assert "check_3" not in failed(v)


def test_idor_differential_is_ready(project, write_finding, add_manifest):
    fp = write_finding("idor-good")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("idor-good", project, scope_fn=OK)
    assert v.verdict == "READY", failed(v)
    assert not failed(v)


def test_missing_finding_drops(project):
    v = evaluate("no-such-finding", project, scope_fn=OK)
    assert v.verdict == "DROP"
    assert "no-such-finding" in v.drop_reason


def test_severity_subdirectory_still_resolves(tmp_path, write_finding, add_manifest):
    """Severity directories are optional here, but a vault-style tree must still work."""
    cfg = make_project(tmp_path)
    fp = write_finding("nested", severity="high")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("nested", cfg, scope_fn=OK).verdict == "READY"


# Program policy


def test_excluded_class_drops(tmp_path, write_finding, add_manifest):
    cfg = make_project(tmp_path, programs={"example-bbp": {"excludes": ["idor"]}})
    fp = write_finding("idor-excluded")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("idor-excluded", cfg, scope_fn=OK)
    assert v.verdict == "DROP"
    assert "exclude" in v.drop_reason.lower()


def test_unknown_exclude_slug_is_inert(tmp_path, write_finding, add_manifest):
    """A typo in excludes must not quietly widen or narrow anything."""
    cfg = make_project(tmp_path, programs={"example-bbp": {"excludes": ["idorr"]}})
    fp = write_finding("idor-typo-exclude")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("idor-typo-exclude", cfg, scope_fn=OK).verdict == "READY"


# check_8, the reason this tool exists


def test_verification_predates_ai_draft_holds(project, write_finding, add_manifest):
    fp = write_finding("stale-verify", ai_drafted_at="2026-06-30T13:00:00")
    add_manifest(fp, [DIFFERENTIAL, art("screen_recording", captured_at="2026-06-30T12:00:00")])
    v = evaluate("stale-verify", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_8" in failed(v)


def test_verification_equal_to_ai_draft_holds(project, write_finding, add_manifest):
    """Same second is not after. The reason must not claim the verification is older."""
    fp = write_finding("tied-verify", ai_drafted_at="2026-06-30T12:00:00")
    add_manifest(fp, [DIFFERENTIAL, art("screen_recording", captured_at="2026-06-30T12:00:00")])
    v = evaluate("tied-verify", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_8" in failed(v)
    reason = next(c.reason for c in v.checks if c.cid == "check_8")
    assert "same timestamp" in reason
    assert "predates" not in reason


def test_unstamped_ai_drafted_at_is_ambiguous_hold(project, write_finding, add_manifest):
    """Unstamped is ambiguous, and ambiguous fails. It must never be a silent pass."""
    fp = write_finding("no-stamp")
    fp.write_text(re.sub(r"ai_drafted_at:.*\n", "", fp.read_text()), encoding="utf-8")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("no-stamp", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_8" in failed(v)


def test_unparseable_ai_drafted_at_holds(project, write_finding, add_manifest):
    fp = write_finding("bad-stamp", ai_drafted_at="last tuesday")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("bad-stamp", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_8" in failed(v)


def test_verification_without_timestamp_holds(project, write_finding, add_manifest):
    fp = write_finding("no-capture-time")
    add_manifest(fp, [DIFFERENTIAL, art("screen_recording", captured_at="")])
    v = evaluate("no-capture-time", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_8" in failed(v)


def test_screenshot_is_not_a_verification_artifact(project, write_finding, add_manifest):
    fp = write_finding("screenshot-only")
    add_manifest(fp, [DIFFERENTIAL, art("screenshot", captured_at="2026-06-30T12:00:00")])
    v = evaluate("screenshot-only", project, scope_fn=OK)
    assert "check_8" in failed(v)


# Class guard


def test_unknown_class_holds_and_does_not_clear_check_4(project, write_finding, add_manifest):
    fp = write_finding("typo-class", vuln_class="typoo")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("typo-class", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "class_known" in failed(v)
    check_4 = next(c for c in v.checks if c.cid == "check_4")
    assert not check_4.passed, "an unknown class must not clear the differential requirement"


def test_unset_class_holds(project, write_finding, add_manifest):
    fp = write_finding("no-class", vuln_class="")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("no-class", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "class_known" in failed(v)


# check_7 routing


def test_scope_warn_holds(project, write_finding, add_manifest):
    fp = write_finding("warn-host")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("warn-host", project, scope_fn=WARN)
    assert v.verdict == "HOLD"
    assert "check_7" in failed(v)


def test_scope_unknown_holds(project, write_finding, add_manifest):
    fp = write_finding("unknown-host")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("unknown-host", project, scope_fn=UNKNOWN)
    assert v.verdict == "HOLD"
    assert "check_7" in failed(v)


def test_scope_block_drops(project, write_finding, add_manifest):
    fp = write_finding("blocked-host")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("blocked-host", project, scope_fn=BLOCK)
    assert v.verdict == "DROP"


def test_drop_outranks_hold(project, write_finding, add_manifest):
    """A blocked host that is also a suspected duplicate is a DROP, not a HOLD."""
    fp = write_finding("block-and-dup", suspected_duplicate=True)
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("block-and-dup", project, scope_fn=BLOCK).verdict == "DROP"


def test_suspected_duplicate_holds(project, write_finding, add_manifest):
    fp = write_finding("dup", suspected_duplicate=True)
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("dup", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_7" in failed(v)


def test_missing_target_host_never_calls_scope(project, write_finding, add_manifest):
    def explode(host, program=""):
        raise AssertionError("scope must not be consulted without a target host")

    fp = write_finding("hostless", target_host="")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("hostless", project, scope_fn=explode)
    assert v.verdict == "HOLD"
    assert "check_7" in failed(v)


# Tiers


def test_theoretical_tier_drops(project, write_finding, add_manifest):
    fp = write_finding("theory", impact_tier="theoretical")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("theory", project, scope_fn=OK).verdict == "DROP"


def test_precondition_forces_conditional_hold(project, write_finding, add_manifest):
    """You cannot claim demonstrated while admitting an unverified precondition."""
    fp = write_finding(
        "conditional",
        impact={
            "attacker_position": "free-tier authenticated user",
            "action": "increment customer_id",
            "asset": "another customer's personal data",
            "precondition": "requires the victim to click a link",
        },
    )
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("conditional", project, scope_fn=OK)
    assert v.verdict == "HOLD"
    assert "check_1" in failed(v)


def test_incomplete_impact_statement_holds(project, write_finding, add_manifest):
    fp = write_finding(
        "no-asset",
        impact={
            "attacker_position": "anonymous user",
            "action": "read the endpoint",
            "asset": "",
            "precondition": "",
        },
    )
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("no-asset", project, scope_fn=OK)
    assert "check_2" in failed(v)


def test_missing_clean_run_holds(project, write_finding, add_manifest):
    fp = write_finding("no-clean-run", clean_state_runs=[])
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("no-clean-run", project, scope_fn=OK)
    assert "check_5" in failed(v)


def test_clean_run_with_deviations_does_not_count(project, write_finding, add_manifest):
    fp = write_finding(
        "deviated",
        clean_state_runs=[
            {
                "ran_at": "2026-06-30T11:00:00",
                "from_state": "fresh",
                "result": "reproduced",
                "deviations": ["had to retry the login twice"],
            }
        ],
    )
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert "check_5" in failed(evaluate("deviated", project, scope_fn=OK))


# check_6 lint and its override


def test_repro_lint_holds_then_override_clears(project, write_finding, add_manifest):
    fp = write_finding(
        "stateful-repro", repro=["Already logged in as admin", "Hit the endpoint"]
    )
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("stateful-repro", project, scope_fn=OK)
    assert v.verdict == "HOLD" and "check_6" in failed(v)

    check_6 = next(c for c in v.checks if c.cid == "check_6")
    assert check_6.fail_route == "hold", "the repro lint is crude and must never drop a finding"

    ok, _ = override_repro(
        project, "stateful-repro", reason="the admin account is created in step 1 of this repro"
    )
    assert ok
    assert evaluate("stateful-repro", project, scope_fn=OK).verdict == "READY"


def test_empty_repro_holds(project, write_finding, add_manifest):
    fp = write_finding("no-repro", repro=[])
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert "check_6" in failed(evaluate("no-repro", project, scope_fn=OK))


# Reporting shape


def test_hold_reason_leads_with_the_missing_artifact(project, write_finding, add_manifest):
    """The first thing a person reads should tell them what to go capture."""
    fp = write_finding("ordering", vuln_class="info-disclosure", impact_tier="inferred")
    add_manifest(fp, [VERIFICATION])
    v = evaluate("ordering", project, scope_fn=OK)
    assert v.hold_reason
    check_3 = next(c for c in v.checks if c.cid == "check_3")
    assert v.hold_reason.startswith(check_3.reason)


def test_next_artifact_empty_when_artifacts_are_not_the_problem(
    project, write_finding, add_manifest
):
    fp = write_finding("scope-only")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    v = evaluate("scope-only", project, scope_fn=WARN)
    assert v.verdict == "HOLD"
    assert v.next_artifact == ""


def test_verdict_serialises(project, write_finding, add_manifest):
    fp = write_finding("json-me")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    data = evaluate("json-me", project, scope_fn=OK).to_dict()
    assert data["verdict"] == "READY"
    assert data["failed"] == []
    assert len(data["checks"]) == 9


def test_exit_codes(project, write_finding, add_manifest):
    fp = write_finding("codes")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("codes", project, scope_fn=OK).exit_code == 0
    assert evaluate("codes", project, scope_fn=WARN).exit_code == 1
    assert evaluate("codes", project, scope_fn=BLOCK).exit_code == 2


def test_program_name_matches_case_insensitively(tmp_path, write_finding, add_manifest):
    """A capitalised program name must not skip the excludes list."""
    cfg = make_project(tmp_path, programs={"example-bbp": {"excludes": ["idor"]}})
    fp = write_finding("idor-caps", program="Example-BBP")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert evaluate("idor-caps", cfg, scope_fn=OK).verdict == "DROP"


def test_scope_reasons_of_any_shape_are_displayed_not_fatal(project, write_finding, add_manifest):
    """The engine's reasons field is external JSON. It must never raise."""
    fp = write_finding("odd-reasons")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    for odd in ("a plain string", 42, None, [1, 2], {"k": "v"}, [None, ""]):
        def scope(host, program="", odd=odd):
            return {"verdict": "warn", "reasons": odd}

        v = evaluate("odd-reasons", project, scope_fn=scope)
        assert v.verdict == "HOLD"
        assert "check_7" in failed(v)
