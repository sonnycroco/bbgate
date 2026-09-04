"""Shared fixtures.

Every test builds a throwaway project under tmp_path and injects `scope_fn`, so
nothing here touches a subprocess, a network, or the user's real files.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest
import yaml

from bbgate.config import load_config
from bbgate.store import MANIFEST_FIELDS, artifacts_dir

# Scope stubs. The real resolver returns the same shape.
OK = lambda host, program="": {"host": host, "verdict": "ok", "reasons": ["in scope"]}
WARN = lambda host, program="": {"host": host, "verdict": "warn", "reasons": ["edge case"]}
UNKNOWN = lambda host, program="": {"host": host, "verdict": "unknown", "reasons": ["no match"]}
BLOCK = lambda host, program="": {"host": host, "verdict": "block", "reasons": ["gov suffix"]}


def make_project(root: Path, *, programs: dict | None = None, **config_over):
    """Write a minimal project and return its loaded Config."""
    (root / ".bbgate").mkdir(parents=True, exist_ok=True)
    (root / "findings").mkdir(parents=True, exist_ok=True)
    cfg = {"findings_dir": "findings", "programs": programs or {}}
    cfg.update(config_over)
    (root / ".bbgate" / "config.yaml").write_text(
        yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8"
    )
    return load_config(root)


@pytest.fixture
def project(tmp_path):
    return make_project(tmp_path)


@pytest.fixture
def write_finding(tmp_path):
    """A finding that is READY once a differential and a postdated verification land."""

    def _write(slug, *, severity="", **fm_over):
        fm = {
            "title": f"Test finding {slug}",
            "vuln_class": "idor",
            "target_host": "api.example.com",
            "program": "example-bbp",
            "ai_drafted_at": "2026-06-30T10:00:00",
            "impact_tier": "demonstrated",
            "impact": {
                "attacker_position": "free-tier authenticated user",
                "action": "increment customer_id in GET /api/v2/customers/{id}",
                "asset": "name, email and home address of any other customer",
                "precondition": "",
            },
            "repro": [
                "Register account A, capture its session token",
                "GET /api/v2/customers/<B_id> with A's token",
                "Observe B's personal data in the response",
            ],
            "clean_state_runs": [
                {
                    "ran_at": "2026-06-30T11:00:00",
                    "from_state": "fresh",
                    "result": "reproduced",
                    "deviations": [],
                }
            ],
        }
        fm.update(fm_over)
        parent = tmp_path / "findings" / severity if severity else tmp_path / "findings"
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / f"{slug}.md"
        path.write_text(
            "---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\nBody text.\n",
            encoding="utf-8",
        )
        return path

    return _write


@pytest.fixture
def add_manifest():
    def _add(finding_path: Path, rows: list[dict]):
        adir = artifacts_dir(finding_path)
        adir.mkdir(parents=True, exist_ok=True)
        with (adir / "manifest.tsv").open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=MANIFEST_FIELDS, delimiter="\t", lineterminator="\n"
            )
            writer.writeheader()
            for row in rows:
                full = {key: "" for key in MANIFEST_FIELDS}
                full.update(row)
                writer.writerow(full)

    return _add


def art(atype, *, captured_at="2026-06-30T11:30:00", priv=False, name=None):
    return {
        "type": atype,
        "path": name or f"{atype}.bin",
        "sha256": "deadbeef",
        "captured_at": captured_at,
        "capture_method": "manual",
        "shows_privileged_data": "true" if priv else "false",
    }


DIFFERENTIAL = art("differential_pair")
VERIFICATION = art("screen_recording", captured_at="2026-06-30T12:00:00")


def failed(verdict):
    return {c.cid for c in verdict.checks if not c.passed}
