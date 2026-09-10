"""State writers.

Everything here rewrites a finding's frontmatter or appends a manifest row. No
mutator runs a scan, touches a target, or decides a verdict: the verdict is
recomputed from what these leave on disk. Each returns (ok, message) so the CLI
can print one line and pick an exit code without catching exceptions.
"""
from __future__ import annotations

from pathlib import Path

from . import frontmatter, store, timeutil
from .config import Config
from .model import TIER_CONDITIONAL, TIER_INFERRED, TIERS

_BODY_TEMPLATE = """## Summary

<one paragraph: who can do what to whose data>

## Detail

<the steps, the requests, what came back>
"""


def _no_finding(slug: str) -> tuple[bool, str]:
    return False, f"no finding file for slug '{slug}'"


def new_finding(
    cfg: Config,
    slug: str,
    *,
    title: str = "",
    vuln_class: str = "",
    target_host: str = "",
    program: str = "",
) -> tuple[bool, str]:
    """Create a finding skeleton.

    The skeleton is deliberately a HOLD: inferred tier, empty impact statement,
    no repro, no clean-state run. Every check has to be earned by doing the work
    and recording it, so a fresh file must never start out looking submittable.
    """
    if not store.valid_slug(slug):
        return False, (
            f"'{slug}' is not a usable slug. Use letters, digits, dots, dashes and "
            f"underscores, starting with a letter or digit."
        )
    path = cfg.findings_dir / f"{slug}.md"
    if path.exists():
        return False, f"{path} already exists"

    fm = {
        "title": title or slug,
        "vuln_class": (vuln_class or "").strip().lower(),
        "target_host": target_host.strip(),
        "program": program.strip(),
        "ai_drafted_at": "",
        "impact_tier": TIER_INFERRED,
        "impact": {
            "attacker_position": "",
            "action": "",
            "asset": "",
            "precondition": "",
        },
        "repro": [],
        "clean_state_runs": [],
        "suspected_duplicate": False,
        "repro_override": {},
    }
    frontmatter.write_text_atomic(
        path, frontmatter.serialize_frontmatter(fm) + "\n" + _BODY_TEMPLATE
    )
    return True, f"created {path}"


def set_impact(
    cfg: Config,
    slug: str,
    *,
    position: str,
    action: str,
    asset: str,
    precondition: str = "",
    tier: str = "",
) -> tuple[bool, str]:
    """Write the impact statement, and the tier it implies."""
    path = store.find_finding(cfg, slug)
    if path is None:
        return _no_finding(slug)

    fm, _ = frontmatter.read_note(path)
    fm["impact"] = {
        "attacker_position": position,
        "action": action,
        "asset": asset,
        "precondition": precondition,
    }
    if tier:
        wanted = tier.strip().lower()
        if wanted not in TIERS:
            return False, f"unknown tier '{tier}' (use: {', '.join(sorted(TIERS))})"
        fm["impact_tier"] = wanted
    elif precondition.strip():
        # Admitting an unverified precondition is what conditional means. Set it
        # here so the tier matches the statement without waiting for the check.
        fm["impact_tier"] = TIER_CONDITIONAL

    frontmatter.write_frontmatter(path, fm)
    current = fm.get("impact_tier")
    suffix = f" (tier={current})" if current else ""
    return True, f"{slug}: impact statement set{suffix}"


def add_clean_run(
    cfg: Config,
    slug: str,
    *,
    from_state: str = "fresh",
    result: str = "reproduced",
    deviations: list[str] | None = None,
) -> tuple[bool, str]:
    """Record one attempt to reproduce the finding from a stated starting state."""
    path = store.find_finding(cfg, slug)
    if path is None:
        return _no_finding(slug)

    fm, _ = frontmatter.read_note(path)
    runs = fm.get("clean_state_runs")
    if not isinstance(runs, list):
        runs = []
    runs.append({
        "ran_at": timeutil.now_iso(),
        "from_state": from_state,
        "result": result,
        "deviations": list(deviations or []),
    })
    fm["clean_state_runs"] = runs
    frontmatter.write_frontmatter(path, fm)
    return True, f"{slug}: clean-state run recorded (from={from_state}, result={result})"


def add_artifact(
    cfg: Config,
    slug: str,
    *,
    atype: str,
    src: str,
    capture_method: str = "manual",
    shows_privileged_data: bool = False,
    captured_at: str = "",
) -> tuple[bool, str]:
    """Copy an evidence file into the finding and append its manifest row."""
    path = store.find_finding(cfg, slug)
    if path is None:
        return _no_finding(slug)

    # Relative to the working directory, not the project root: people run this
    # pointing at a file they just captured, wherever they happen to be.
    source = Path(src).expanduser()
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.is_file():
        return False, f"artifact source not found: {src}"

    dest = store.ingest_artifact_file(path, source)
    digest = store.sha256_file(dest)
    row = {
        "type": atype.strip().lower(),
        "path": dest.name,
        "sha256": digest,
        "captured_at": captured_at.strip() or timeutil.now_iso(),
        "capture_method": capture_method.strip() or "manual",
        "shows_privileged_data": "true" if shows_privileged_data else "false",
    }
    try:
        store.append_manifest_row(path, row, cfg.lock_dir)
    except OSError as exc:
        return False, f"could not record the artifact: {exc}"
    return True, f"{slug}: {row['type']} ({dest.name}, sha256:{digest[:12]})"


def stamp_ai(cfg: Config, slug: str, when: str = "") -> tuple[bool, str]:
    """Record when a model last edited the writeup, which check_8 measures against."""
    path = store.find_finding(cfg, slug)
    if path is None:
        return _no_finding(slug)

    fm, _ = frontmatter.read_note(path)
    fm["ai_drafted_at"] = when.strip() or timeutil.now_iso()
    frontmatter.write_frontmatter(path, fm)
    return True, f"{slug}: ai_drafted_at = {fm['ai_drafted_at']}"


def override_repro(cfg: Config, slug: str, *, reason: str) -> tuple[bool, str]:
    """Clear the pre-existing-state lint, on the record.

    The reason is required because the override is stored in the finding and
    read back later by whoever is deciding whether to trust the repro.
    """
    path = store.find_finding(cfg, slug)
    if path is None:
        return _no_finding(slug)
    if not reason.strip():
        return False, "override reason is required"

    fm, _ = frontmatter.read_note(path)
    fm["repro_override"] = {"reason": reason.strip(), "at": timeutil.now_iso()}
    frontmatter.write_frontmatter(path, fm)
    return True, f"{slug}: repro lint overridden, reason recorded"
