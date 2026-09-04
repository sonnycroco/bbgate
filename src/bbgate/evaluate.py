"""Aggregation of the nine checks into a single verdict.

The verdict is derived here on every call from the finding's frontmatter and its
artifact manifest. Nothing is cached and nothing is read back from a previous
run, so editing the note or capturing an artifact is all it takes to change the
answer.
"""
from __future__ import annotations

from .checks import (
    check_1_impact_demonstrated,
    check_2_statement_complete,
    check_3_impact_artifact_exists,
    check_4_differential_for_authz,
    check_5_clean_state,
    check_6_repro_self_contained,
    check_7_scope_clear,
    check_8_human_verified,
    check_9_confidence_floor,
    class_guard,
    effective_tier,
)
from .config import Config
from .frontmatter import read_note
from .model import DROP, HOLD, HOLD_ORDER, READY, TIER_THEORETICAL, CheckResult, Verdict
from .scope import resolver
from .store import find_finding, read_manifest

# Anything not named in HOLD_ORDER sorts last rather than raising, so adding a
# check without touching the order list degrades quietly instead of crashing.
_ORDER_FALLBACK = len(HOLD_ORDER)


def _hold_reason(failing: list[CheckResult]) -> str:
    ordered = sorted(
        failing,
        key=lambda c: HOLD_ORDER.index(c.cid) if c.cid in HOLD_ORDER else _ORDER_FALLBACK,
    )
    # Reasons are written as sentences and most already end in a full stop, so
    # trim it before joining. Otherwise the list reads as "... run.. Then ...".
    return ". ".join(c.reason.strip().rstrip(".") for c in ordered)


def evaluate(slug: str, cfg: Config, *, scope_fn=None) -> Verdict:
    """Recompute one finding's verdict from frontmatter plus manifest.

    `scope_fn` is injectable so tests never reach a subprocess. It takes
    (host, program) and returns a dict with "verdict" and "reasons".
    """
    path = find_finding(cfg, slug)
    if path is None:
        return Verdict(slug, DROP, drop_reason=f"no finding file for slug '{slug}'")

    fm, _body = read_note(path)
    artifacts = read_manifest(path)

    vuln_class = str(fm.get("vuln_class") or "").strip().lower()
    program = str(fm.get("program") or "").strip()
    host = str(fm.get("target_host") or "").strip()
    class_known = vuln_class in cfg.classes
    tier = effective_tier(fm)
    excludes = cfg.excludes_for(program)

    if host:
        scope = (scope_fn or resolver(cfg))(host, program)
    else:
        # No host means there is nothing to ask about, so the scope resolver is
        # never called. Answering "unknown" here keeps the finding on HOLD.
        scope = {"verdict": "unknown", "reasons": ["no target_host on the finding"]}

    checks = [
        check_1_impact_demonstrated(tier),
        check_2_statement_complete(fm),
        check_3_impact_artifact_exists(artifacts, vuln_class, cfg),
        check_4_differential_for_authz(artifacts, vuln_class, class_known, cfg),
        check_5_clean_state(fm),
        check_6_repro_self_contained(fm),
        check_7_scope_clear(fm, vuln_class, class_known, excludes, scope),
        check_8_human_verified(fm, artifacts, cfg),
        check_9_confidence_floor(tier),
    ]
    guard = class_guard(vuln_class, class_known)
    if guard is not None:
        checks = [guard, *checks]

    by_id = {c.cid: c for c in checks}

    # The hint is only useful when a missing artifact is the thing standing in
    # the way. Printing it beside an unset field or a scope problem sends people
    # to capture evidence they already have.
    needs_hint = not by_id["check_3"].passed or (
        not by_id["check_4"].passed and vuln_class in cfg.authz_classes
    )
    next_artifact = cfg.next_artifact_hint(vuln_class) if needs_hint else ""

    drop_bits: list[str] = []
    if tier == TIER_THEORETICAL:
        drop_bits.append("impact_tier is theoretical, the consequence is unproven")
    check_7 = by_id["check_7"]
    if not check_7.passed and check_7.fail_route == "drop":
        drop_bits.append(check_7.reason)
    if drop_bits:
        return Verdict(
            slug,
            DROP,
            checks=checks,
            next_artifact=next_artifact,
            drop_reason=" and ".join(drop_bits),
        )

    if all(c.passed for c in checks):
        return Verdict(slug, READY, checks=checks)

    return Verdict(
        slug,
        HOLD,
        checks=checks,
        next_artifact=next_artifact,
        hold_reason=_hold_reason([c for c in checks if not c.passed]),
    )
