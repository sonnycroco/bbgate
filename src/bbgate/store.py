"""On-disk layout: finding lookup, the artifact manifest, and artifact ingest.

Nothing here executes anything. Hashing is done in-process with hashlib rather
than by calling out to sha256sum, because the no-execution guarantee the gate
makes has exactly one exception and it lives in scope.py.
"""
from __future__ import annotations

import csv
import hashlib
import shutil
from pathlib import Path

from . import frontmatter
from .config import Config
from .model import Artifact

MANIFEST_FIELDS = [
    "type", "path", "sha256", "captured_at", "capture_method", "shows_privileged_data",
]

MANIFEST_NAME = "manifest.tsv"
ARTIFACTS_DIRNAME = "artifacts"

# Filenames that live among findings without being one.
SKIPPED_STEMS = {"readme", "index", "queue"}

# Frontmatter status values that assert a finding is sendable. The assertion is
# typed by hand and is the thing most worth contradicting, so it is the filter
# `gate --all --claimed` uses.
READY_CLAIMS = {"ready-to-submit", "ready", "submit"}

_CHUNK = 65536

_TRUTHY = {"true", "1", "yes", "y"}


def find_finding(cfg: Config, slug: str) -> Path | None:
    """Resolve a slug to its finding file, or None.

    Severity subdirectories are optional here, so a flat `findings/<slug>.md`
    is checked before the graded layouts. Matches are sorted so a slug that
    somehow exists twice always resolves to the same file.
    """
    base = cfg.findings_dir
    if not base.exists():
        return None

    direct = base / f"{slug}.md"
    if direct.is_file():
        return direct

    graded = sorted(p for p in base.glob(f"*/{slug}.md") if p.is_file())
    if graded:
        return graded[0]

    # Captured evidence is sometimes markdown, and an evidence file named after
    # the finding would otherwise resolve as the finding itself.
    deep = sorted(
        p for p in base.glob(f"**/{slug}.md")
        if p.is_file() and ARTIFACTS_DIRNAME not in p.relative_to(base).parts[:-1]
    )
    return deep[0] if deep else None


def artifacts_dir(finding_path: Path) -> Path:
    """Artifacts live beside the finding, in a directory named for its slug."""
    return finding_path.parent / finding_path.stem / ARTIFACTS_DIRNAME


def manifest_path(finding_path: Path) -> Path:
    return artifacts_dir(finding_path) / MANIFEST_NAME


def _to_bool(value) -> bool:
    return str(value).strip().lower() in _TRUTHY


def read_manifest(finding_path: Path) -> list[Artifact]:
    """Read the manifest rows, tolerating a finding that has none yet."""
    path = manifest_path(finding_path)
    if not path.exists():
        return []

    rows: list[Artifact] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        for raw in csv.DictReader(fh, delimiter="\t"):
            atype = (raw.get("type") or "").strip().lower()
            if not atype:
                continue
            rows.append(Artifact(
                type=atype,
                path=(raw.get("path") or "").strip(),
                sha256=(raw.get("sha256") or "").strip(),
                captured_at=(raw.get("captured_at") or "").strip(),
                capture_method=(raw.get("capture_method") or "").strip(),
                shows_privileged_data=_to_bool(raw.get("shows_privileged_data")),
            ))
    return rows


def append_manifest_row(finding_path: Path, row: dict, lock_dir: Path) -> None:
    """Append one row, writing the header if the manifest is new."""
    path = manifest_path(finding_path)
    with frontmatter.locked(path, lock_dir):
        new_file = not path.exists()
        with path.open("a", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=MANIFEST_FIELDS,
                delimiter="\t",
                lineterminator="\n",
                extrasaction="ignore",
            )
            if new_file:
                writer.writeheader()
            writer.writerow(row)


def all_slugs(cfg: Config) -> list[str]:
    """Every finding slug in the project, sorted.

    Three exclusions, all learned the hard way. `package` writes
    `<slug>.submission.md` next to the finding, and counting those as findings
    gave every READY finding a phantom HOLD twin in the queue. Markdown inside
    an artifacts directory is captured evidence, not a finding. A README is
    documentation, and people do keep one next to their findings, so gating it
    just prints a permanent HOLD for a file nobody will ever submit.
    """
    base = cfg.findings_dir
    if not base.exists():
        return []

    slugs: list[str] = []
    for path in sorted(base.rglob("*.md")):
        if not path.is_file():
            continue
        if path.name.endswith(".submission.md"):
            continue
        if path.stem.lower() in SKIPPED_STEMS:
            continue
        if ARTIFACTS_DIRNAME in path.relative_to(base).parts[:-1]:
            continue
        slugs.append(path.stem)
    return slugs


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_artifact_file(finding_path: Path, src: Path) -> Path:
    """Copy `src` into the finding's artifacts directory, returning the destination.

    An existing file of the same name is never overwritten. Two captures very
    often share a basename (screenshot.png, response.txt), and clobbering left
    an earlier manifest row pointing at bytes that no longer hashed to its
    recorded sha256, breaking the evidence chain the gate exists to guarantee.
    Identical bytes are treated as the same artifact and reused; anything else
    gets a -2, -3 suffix.
    """
    dest_dir = artifacts_dir(finding_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name

    if src.resolve() == dest.resolve():
        return dest

    if dest.exists() and sha256_file(dest) != sha256_file(src):
        stem, suffix = src.stem, src.suffix
        n = 2
        while dest.exists():
            dest = dest_dir / f"{stem}-{n}{suffix}"
            n += 1

    if not dest.exists():
        shutil.copy2(src, dest)
    return dest


def claimed_ready(cfg: Config) -> list[str]:
    """Slugs whose frontmatter claims they are ready to send.

    A status field is a claim, not a verdict. Gating every finding is noisy,
    because most of them are legitimately unfinished. Gating the ones that say
    they are finished is the check worth failing a build over.
    """
    out = []
    for slug in all_slugs(cfg):
        path = find_finding(cfg, slug)
        if path is None:
            continue
        status = str(frontmatter.read_frontmatter(path).get("status") or "").strip().lower()
        if status in READY_CLAIMS:
            out.append(slug)
    return out
