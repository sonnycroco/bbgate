"""The nine check predicates.

Every function here is pure: it reads a finding's frontmatter and its already
parsed artifact manifest and returns a CheckResult. Nothing in this module opens
a socket, runs a scan or touches a target. That is what makes the verdict
reproducible from disk alone.

Failure reasons are the product's user interface. Each one says what is missing
and, where a command exists, names it.
"""
from __future__ import annotations

from .config import Config
from .model import (
    DIFFERENTIAL_TYPES,
    PREEXISTING_STATE_PHRASES,
    TIER_CONDITIONAL,
    TIER_DEMONSTRATED,
    Artifact,
    CheckResult,
)
from .timeutil import parse_ts

_TRUE_WORDS = {"true", "1", "yes", "y"}


def _truthy(value) -> bool:
    return str(value).strip().lower() in _TRUE_WORDS


def effective_tier(fm: dict) -> str:
    """The tier the gate actually uses, which is not always the declared one.

    A non-empty `impact.precondition` forces conditional. The point is that the
    precondition field stays meaningful at gate time rather than only at
    set-impact time: you cannot claim demonstrated while admitting a
    precondition you never verified.
    """
    declared = str(fm.get("impact_tier") or "").strip().lower()
    impact = fm.get("impact") or {}
    precondition = ""
    if isinstance(impact, dict):
        precondition = str(impact.get("precondition") or "").strip()
    if precondition:
        return TIER_CONDITIONAL
    return declared


def class_guard(vuln_class: str, class_known: bool) -> CheckResult | None:
    """Fail ahead of the class-dependent checks when the label is not usable.

    Returns None when there is nothing to report. An unusable class routes to
    HOLD, never DROP: the finding may well be real, the label is what is wrong.
    """
    if vuln_class and class_known:
        return None
    if vuln_class:
        return CheckResult(
            "class_known",
            False,
            f"unknown vuln_class '{vuln_class}'. It is not in the class list, "
            f"so the class-dependent checks cannot run. Fix the label.",
            fail_route="hold",
        )
    return CheckResult(
        "class_known",
        False,
        "vuln_class is unset, so the class-dependent checks cannot run. "
        "Set vuln_class on the finding.",
        fail_route="hold",
    )


def check_1_impact_demonstrated(tier: str) -> CheckResult:
    if tier == TIER_DEMONSTRATED:
        return CheckResult("check_1", True, "impact_tier is demonstrated")
    return CheckResult(
        "check_1",
        False,
        f"impact_tier is '{tier or 'unset'}', not demonstrated. Only a "
        f"demonstrated finding can reach READY.",
    )


def check_2_statement_complete(fm: dict) -> CheckResult:
    impact = fm.get("impact") or {}
    if not isinstance(impact, dict):
        impact = {}
    missing = [
        k for k in ("attacker_position", "action", "asset")
        if not str(impact.get(k) or "").strip()
    ]
    if not missing:
        return CheckResult(
            "check_2", True, "impact statement complete (position, action, asset)"
        )
    return CheckResult(
        "check_2",
        False,
        f"impact statement incomplete, empty: {', '.join(missing)}. "
        f"Set them with `bbgate set-impact`.",
    )


def check_3_impact_artifact_exists(
    artifacts: list[Artifact], vuln_class: str, cfg: Config
) -> CheckResult:
    if any(a.evidences_impact(cfg.impact_artifact_types) for a in artifacts):
        return CheckResult(
            "check_3", True, "at least one impact-evidencing artifact is present"
        )
    return CheckResult(
        "check_3",
        False,
        f"no impact artifact. A screenshot of the exposed thing does not count. "
        f"Need: {cfg.next_artifact_hint(vuln_class)}",
    )


def check_4_differential_for_authz(
    artifacts: list[Artifact], vuln_class: str, class_known: bool, cfg: Config
) -> CheckResult:
    # An unrecognised class must not clear this. Without a real label there is no
    # way to know whether two-principal proof was required, and the cheapest way
    # to pass an authz check would otherwise be to mislabel the finding.
    if not class_known:
        return CheckResult(
            "check_4",
            False,
            "vuln_class is unknown, so the two-principal differential "
            "requirement cannot be confirmed either way. Fix the label.",
        )
    if vuln_class not in cfg.authz_classes:
        return CheckResult(
            "check_4", True, f"not applicable, {vuln_class} is not an authz class"
        )
    if any(a.type in DIFFERENTIAL_TYPES for a in artifacts):
        return CheckResult(
            "check_4",
            True,
            "two-principal proof present (differential_pair or forged_token)",
        )
    return CheckResult(
        "check_4",
        False,
        f"authz class {vuln_class} needs a differential_pair or a forged_token: "
        f"A acting on B's object, plus the negative control.",
    )


def check_5_clean_state(fm: dict) -> CheckResult:
    runs = fm.get("clean_state_runs") or []
    if not isinstance(runs, list):
        runs = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        from_state = str(run.get("from_state") or "").strip().lower()
        result = str(run.get("result") or "").strip().lower()
        deviations = run.get("deviations")
        no_deviations = deviations is None or (
            isinstance(deviations, list) and len(deviations) == 0
        )
        if from_state == "fresh" and result == "reproduced" and no_deviations:
            return CheckResult(
                "check_5",
                True,
                "clean-state run reproduced from fresh with no deviations",
            )
    return CheckResult(
        "check_5",
        False,
        "no clean-state run (from_state=fresh, result=reproduced, deviations=[]). "
        "Record one with `bbgate clean-run --from fresh --result reproduced`.",
    )


def check_6_repro_self_contained(fm: dict) -> CheckResult:
    # A phrase lint, and deliberately a crude one. It routes to HOLD so a person
    # reads the steps; it never drops a finding, and a recorded override clears
    # it for the cases where the wording is fine.
    override = fm.get("repro_override")
    if isinstance(override, dict):
        reason = str(override.get("reason") or "").strip()
        if reason:
            return CheckResult("check_6", True, f"repro lint overridden: {reason}")

    repro = fm.get("repro") or []
    if not isinstance(repro, list) or not [s for s in repro if str(s).strip()]:
        return CheckResult(
            "check_6",
            False,
            "repro steps are empty. Add a reproduction someone can follow from "
            "a cold start.",
        )
    for line in repro:
        lowered = str(line).lower()
        for phrase in PREEXISTING_STATE_PHRASES:
            if phrase in lowered:
                return CheckResult(
                    "check_6",
                    False,
                    f"repro may lean on state from an earlier session: "
                    f"\"{str(line).strip()}\" matches '{phrase}'. If it is "
                    f"legitimate, clear it with `bbgate override-repro --reason \"...\"`.",
                )
    return CheckResult("check_6", True, "repro steps are self-contained")


def check_7_scope_clear(
    fm: dict,
    vuln_class: str,
    class_known: bool,
    excludes: list[str],
    scope: dict,
) -> CheckResult:
    """Route the scope and policy result to PASS, HOLD or DROP.

    The DROP conditions are tested first on purpose. When several apply, the
    policy-final one wins: there is no point telling someone to go get a human
    call on a host they are not allowed to touch.
    """
    host = str(fm.get("target_host") or "").strip()
    verdict = str(scope.get("verdict") or "unknown").strip().lower()
    reasons = "; ".join(scope.get("reasons") or []) or "no reason given"

    duplicate = fm.get("suspected_duplicate")
    if isinstance(duplicate, str):
        # A string here is usually the duplicate report's id or URL, so anything
        # non-empty counts as the flag being set. An empty string does not.
        duplicate_flag = bool(duplicate.strip())
    else:
        duplicate_flag = _truthy(duplicate)

    # Policy-final refusals.
    if verdict == "block":
        return CheckResult(
            "check_7",
            False,
            f"scope BLOCK for {host}: {reasons}",
            fail_route="drop",
        )
    if class_known and vuln_class in excludes:
        return CheckResult(
            "check_7",
            False,
            f"vuln_class '{vuln_class}' is on the program's excludes list, "
            f"so it is out of scope by policy.",
            fail_route="drop",
        )

    # Recoverable refusals.
    if verdict == "warn":
        return CheckResult(
            "check_7",
            False,
            f"scope WARN for {host}: {reasons}. A human call is needed.",
            fail_route="hold",
        )
    if verdict == "unknown":
        # The reasons are carried through here because the commonest unknown is
        # a finding with no target_host at all, and "scope UNKNOWN for ." on its
        # own tells the reader nothing.
        return CheckResult(
            "check_7",
            False,
            f"scope UNKNOWN for {host or '(no target_host)'}: {reasons}. "
            f"Add or confirm the scope entry for it.",
            fail_route="hold",
        )
    if duplicate_flag:
        return CheckResult(
            "check_7",
            False,
            "flagged as a suspected duplicate. Confirm it is not one before "
            "submitting.",
            fail_route="hold",
        )

    return CheckResult("check_7", True, f"scope ok for {host}, class not excluded")


def check_8_human_verified(
    fm: dict, artifacts: list[Artifact], cfg: Config
) -> CheckResult:
    """A person verified this after the last machine-written draft.

    This is the check the tool exists for. Every branch below fails rather than
    passing on absent information: a stamp that is missing or unreadable makes
    the ordering unknowable, and unknowable is not the same as fine.
    """
    verifications = [a for a in artifacts if a.type in cfg.verification_types]
    if not verifications:
        return CheckResult(
            "check_8",
            False,
            "no manual verification artifact. Add a terminal_log or a "
            "screen_recording captured after the last draft.",
        )

    raw_stamp = str(fm.get("ai_drafted_at") or "").strip()
    drafted_at = parse_ts(raw_stamp)
    if raw_stamp and drafted_at is None:
        return CheckResult(
            "check_8",
            False,
            "ai_drafted_at is present but unparseable, so the draft time cannot "
            "be trusted. Restamp it with `bbgate stamp-ai`.",
        )
    if drafted_at is None:
        return CheckResult(
            "check_8",
            False,
            "ai_drafted_at is unstamped, so there is no way to prove the "
            "verification postdates the draft. Stamp it with `bbgate stamp-ai`.",
        )

    captured = [parse_ts(a.captured_at) for a in verifications]
    latest = max((c for c in captured if c is not None), default=None)
    if latest is None:
        return CheckResult(
            "check_8",
            False,
            "the verification artifact has no parseable captured_at, so it "
            "cannot be placed after the draft.",
        )
    if latest > drafted_at:
        return CheckResult(
            "check_8", True, "manual verification postdates the draft"
        )
    # Equal timestamps are their own case. Saying "predates" when the two read
    # identically looks like a bug in the tool and sends people looking for one,
    # so name the real problem: the order cannot be established either way.
    if latest == drafted_at:
        return CheckResult(
            "check_8",
            False,
            f"the verification and the draft carry the same timestamp "
            f"({latest.isoformat()}), so there is nothing to show the "
            f"verification came after it. Re-verify and capture again.",
        )
    return CheckResult(
        "check_8",
        False,
        f"the verification ({latest.isoformat()}) predates the draft "
        f"({drafted_at.isoformat()}), so it proves nothing about what the draft "
        f"now says. Re-verify and capture again.",
    )


def check_9_confidence_floor(tier: str) -> CheckResult:
    if tier == TIER_DEMONSTRATED:
        return CheckResult("check_9", True, "confidence floor met (demonstrated)")
    return CheckResult(
        "check_9",
        False,
        f"confidence floor: tier '{tier or 'unset'}' is below demonstrated",
    )
