"""The refusal path. This is the one behaviour that must never regress.

If the gate emits a submission for a finding that is not READY, the tool has no
reason to exist. Every non-READY route is asserted to write no file at all.
"""
from __future__ import annotations

import pytest

from bbgate.mutate import stamp_ai
from bbgate.package import build_package, package_path_for

from conftest import BLOCK, DIFFERENTIAL, OK, VERIFICATION, art, make_project

STALE_VERIFICATION = art("screen_recording", captured_at="2026-06-30T09:00:00")

REFUSAL_CASES = [
    pytest.param("info-disclosure", [VERIFICATION], OK, {}, id="no-impact-artifact"),
    pytest.param(
        "idor", [art("http_exchange", priv=True), VERIFICATION], OK, {}, id="no-differential"
    ),
    pytest.param("idor", [DIFFERENTIAL, VERIFICATION], BLOCK, {}, id="scope-block"),
    pytest.param(
        "idor", [DIFFERENTIAL, STALE_VERIFICATION], OK, {}, id="verification-predates-draft"
    ),
    pytest.param(
        "idor", [DIFFERENTIAL, VERIFICATION], OK, {"impact_tier": "theoretical"}, id="theoretical"
    ),
    pytest.param(
        "idor", [DIFFERENTIAL, VERIFICATION], OK, {"suspected_duplicate": True}, id="suspected-dup"
    ),
    pytest.param("typoo", [DIFFERENTIAL, VERIFICATION], OK, {}, id="unknown-class"),
]


@pytest.mark.parametrize("vuln_class,manifest,scope_fn,overrides", REFUSAL_CASES)
def test_package_refuses_and_writes_nothing(
    project, write_finding, add_manifest, vuln_class, manifest, scope_fn, overrides
):
    fp = write_finding("refuseme", vuln_class=vuln_class, **overrides)
    add_manifest(fp, manifest)
    target = package_path_for(fp)
    assert not target.exists()

    ok, message, path = build_package(project, "refuseme", scope_fn=scope_fn)

    assert ok is False
    assert path is None
    assert "REFUSED" in message
    assert not target.exists(), "a refused finding must leave no submission on disk"


def test_package_writes_on_ready(project, write_finding, add_manifest):
    fp = write_finding("ready-one")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    ok, _message, path = build_package(project, "ready-one", scope_fn=OK)
    assert ok is True
    assert path is not None and path.exists()

    text = path.read_text(encoding="utf-8")
    assert "api.example.com" in text
    assert "free-tier authenticated user" in text  # the impact statement is rendered
    assert "differential_pair" in text  # the evidence table lists the artifacts
    assert "Body text." in text  # the finding body is carried over


def test_package_refusal_names_the_missing_artifact(project, write_finding, add_manifest):
    fp = write_finding("named-refusal", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])
    ok, message, _ = build_package(project, "named-refusal", scope_fn=OK)
    assert not ok
    assert len(message) > len("REFUSED (HOLD): "), "the refusal has to say what is missing"


def test_package_on_missing_finding_refuses(project):
    ok, message, path = build_package(project, "ghost", scope_fn=OK)
    assert not ok and path is None
    assert "REFUSED" in message


def test_package_does_not_become_a_finding(tmp_path, write_finding, add_manifest):
    """A written submission sits next to the finding and must not be picked up as one."""
    from bbgate.store import all_slugs

    cfg = make_project(tmp_path)
    fp = write_finding("packaged")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    build_package(cfg, "packaged", scope_fn=OK)
    assert all_slugs(cfg) == ["packaged"]


def test_refusal_warns_about_a_stale_submission(project, write_finding, add_manifest):
    """A finding can be packaged while READY and lapse afterwards.

    The old submission stays on disk looking sendable, so the refusal has to
    point at it. It is not deleted, because refusing must touch nothing.
    """
    fp = write_finding("lapsed")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    ok, _, path = build_package(project, "lapsed", scope_fn=OK)
    assert ok and path.exists()

    # Something re-drafts the writeup after the last verification.
    stamp_ai(project, "lapsed", when="2026-07-01T09:00:00")

    ok, message, _ = build_package(project, "lapsed", scope_fn=OK)
    assert not ok
    assert "still on disk" in message
    assert path.exists(), "a refusal must not delete anything either"
