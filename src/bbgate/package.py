"""Submission package builder: the only sanctioned way to emit a submission.

Everything else in the tool reports. This writes a file a person is about to
paste into a bug bounty platform, so it is the one place where being wrong has a
cost outside the project. It refuses on anything but READY and, on refusal,
writes nothing at all: no partial file, no stub, nothing to mistake for output.
"""
from __future__ import annotations

from pathlib import Path

from . import frontmatter
from .config import Config
from .evaluate import evaluate
from .model import READY
from .store import find_finding, read_manifest

_SHA_PREFIX = 16


def package_path_for(finding_path: Path) -> Path:
    """The submission file for a finding sits next to it as <stem>.submission.md."""
    return finding_path.parent / f"{finding_path.stem}.submission.md"


def _or_dash(value) -> str:
    text = str(value).strip() if value is not None else ""
    return text or "-"


def _stale_package(cfg: Config, slug: str) -> Path | None:
    """An existing submission file for a finding that is no longer READY."""
    finding_path = find_finding(cfg, slug)
    if finding_path is None:
        return None
    existing = package_path_for(finding_path)
    return existing if existing.exists() else None


def build_package(cfg: Config, slug: str, *, scope_fn=None) -> tuple[bool, str, Path | None]:
    """Write the submission markdown for `slug`, or refuse.

    Returns (True, message, path) on READY. On any other verdict returns
    (False, "REFUSED (<verdict>): <what is missing>", None) having written
    nothing.
    """
    verdict = evaluate(slug, cfg, scope_fn=scope_fn)
    if verdict.verdict != READY:
        missing = (verdict.next_artifact or verdict.hold_reason
                   or verdict.drop_reason or "not READY")
        message = f"REFUSED ({verdict.verdict}): {missing}"
        # A finding can be packaged while READY and lapse afterwards, most often
        # because something re-drafted the writeup after the last verification.
        # The old submission is still sitting on disk looking sendable, so say so.
        # It is not deleted here: refusing has to mean this call touched nothing.
        stale = _stale_package(cfg, slug)
        if stale is not None:
            message += (
                f". A submission from an earlier run is still on disk at "
                f"{stale.name} and no longer reflects this verdict. Do not send it."
            )
        return False, message, None

    finding_path = find_finding(cfg, slug)
    if finding_path is None:
        return False, f"REFUSED (HOLD): no finding named '{slug}'", None

    fm, body = frontmatter.read_note(finding_path)
    artifacts = read_manifest(finding_path)
    impact = fm.get("impact") if isinstance(fm.get("impact"), dict) else {}

    out = [
        f"# Submission: {fm.get('title') or slug}",
        "",
        f"- **Program:** {_or_dash(fm.get('program'))}",
        f"- **Target host:** {_or_dash(fm.get('target_host'))}",
        f"- **Class:** {_or_dash(fm.get('vuln_class'))}",
        (
            f"- **Severity:** {_or_dash(fm.get('severity'))} "
            f"(CVSS {_or_dash(fm.get('cvss-score'))})"
        ),
        "",
        "## Demonstrated impact",
        (
            f"As a **{impact.get('attacker_position', '')}**, "
            f"**{impact.get('action', '')}**, obtaining "
            f"**{impact.get('asset', '')}**."
        ),
        "",
        "## Reproduction",
    ]
    for number, step in enumerate(fm.get("repro") or [], 1):
        out.append(f"{number}. {step}")
    out.extend([
        "",
        "## Evidence artifacts",
        "| type | file | sha256 | captured_at |",
        "|---|---|---|---|",
    ])
    for artifact in artifacts:
        out.append(
            f"| {artifact.type} | {artifact.path} | "
            f"`{artifact.sha256[:_SHA_PREFIX]}...` | {artifact.captured_at} |"
        )
    out.extend(["", "## Detail", body.strip(), ""])

    out_path = package_path_for(finding_path)
    frontmatter.write_text_atomic(out_path, "\n".join(out))
    try:
        shown = out_path.relative_to(cfg.root)
    except ValueError:
        shown = out_path
    return True, f"submission package written: {shown}", out_path
