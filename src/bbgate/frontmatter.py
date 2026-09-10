"""YAML frontmatter read and rewrite, plus the small file primitives around it.

Findings are the irreplaceable part of a project using this tool, so every
rewrite here goes through a temp file and a rename. A plain write truncates the
target first, and an interrupt at the wrong moment leaves an empty finding.
"""
from __future__ import annotations

import hashlib
import os
import re
from contextlib import contextmanager
from pathlib import Path

import yaml

# The trailing run is [ \t]* rather than \s*, which would swallow the blank line
# most people leave between the closing fence and the body. That newline belongs
# to the body, and eating it means a rewrite silently reflows the file.
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n(.*)\Z", re.DOTALL)


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Split note text into (frontmatter, body).

    Returns ({}, text) when there is nothing parseable, so a malformed block
    degrades to "no frontmatter" instead of a write that corrupts the file.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        fm = yaml.safe_load(m.group(1) or "")
    except yaml.YAMLError:
        return {}, text
    if not isinstance(fm, dict):
        return {}, text
    return fm, m.group(2)


def serialize_frontmatter(fm: dict) -> str:
    """Render a frontmatter dict as a fenced YAML block.

    safe_dump rather than a hand-rolled emitter: values holding colons, quotes,
    newlines or a leading YAML sigil need real quoting and escaping.
    """
    block = yaml.safe_dump(
        fm,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=4096,  # stop long scalars being reflowed onto continuation lines
    )
    return f"---\n{block}---\n"


def read_note(path: Path) -> tuple[dict, str]:
    return split_frontmatter(path.read_text(encoding="utf-8"))


def read_frontmatter(path: Path) -> dict:
    try:
        fm, _ = read_note(path)
    except OSError:
        return {}
    return fm


def write_text_atomic(path: Path, content: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def write_frontmatter(path: Path, fm: dict) -> None:
    """Rewrite only the frontmatter block. Body bytes are preserved verbatim."""
    _, body = read_note(path)
    write_text_atomic(path, serialize_frontmatter(fm) + body)


def lock_path_for(path: Path, lock_dir: Path) -> Path:
    """Where the lock file for `path` lives.

    Lock files are kept together under the project's `.bbgate/locks/` rather
    than beside the file they guard. A lock next to the manifest sat in the
    evidence directory looking like evidence, and ended up committed.
    """
    digest = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:16]
    return lock_dir / f"{path.name}.{digest}.lock"


@contextmanager
def locked(path: Path, lock_dir: Path):
    """Advisory lock around an append to `path`.

    The manifest and the gate log are append-only and two processes appending at
    once can interleave a row. fcntl is missing on Windows, where this degrades
    to no locking rather than refusing to run.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_dir.mkdir(parents=True, exist_ok=True)
    with open(lock_path_for(path, lock_dir), "w") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
