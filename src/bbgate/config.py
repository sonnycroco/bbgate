"""Project discovery and configuration.

A bbgate project is any directory containing a `.bbgate/` directory, found by
walking up from the working directory the same way git finds a repo. Everything
opinionated in the gate (the rubric, which checks are load bearing, which
classes need two-principal proof, which artifact types count) is loaded here
from shipped defaults that a project can override. The gate should read as a
tool you configure, not a policy you submit to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import (
    DEFAULT_AUTHZ_CLASSES,
    DEFAULT_IMPACT_ARTIFACT_TYPES,
    DEFAULT_LOAD_BEARING,
    DEFAULT_NEXT_ARTIFACT,
    DEFAULT_VERIFICATION_TYPES,
)

PROJECT_MARKER = ".bbgate"
LOCKS_DIRNAME = "locks"
CONFIG_NAME = "config.yaml"
DATA_DIR = Path(__file__).resolve().parent / "data"


class ProjectNotFound(Exception):
    """No .bbgate directory at or above the given path."""


@dataclass(frozen=True)
class RubricEntry:
    """What a class looks like when it is only a condition, and what clears it."""

    condition: str
    bar: str
    next_artifact: str


@dataclass
class Config:
    root: Path
    findings_dir: Path
    queue_path: Path
    log_path: Path
    classes: set[str]
    rubric: dict[str, RubricEntry]
    load_bearing: set[str] = field(default_factory=lambda: set(DEFAULT_LOAD_BEARING))
    authz_classes: set[str] = field(default_factory=lambda: set(DEFAULT_AUTHZ_CLASSES))
    impact_artifact_types: set[str] = field(
        default_factory=lambda: set(DEFAULT_IMPACT_ARTIFACT_TYPES)
    )
    verification_types: set[str] = field(
        default_factory=lambda: set(DEFAULT_VERIFICATION_TYPES)
    )
    scope_mode: str = "none"
    scope_command: str = ""
    programs: dict = field(default_factory=dict)

    @property
    def lock_dir(self) -> Path:
        return self.root / PROJECT_MARKER / LOCKS_DIRNAME

    def next_artifact_hint(self, vuln_class: str) -> str:
        entry = self.rubric.get(vuln_class)
        return entry.next_artifact if entry else DEFAULT_NEXT_ARTIFACT

    def excludes_for(self, program: str) -> list[str]:
        """Class slugs the program declares out of scope.

        Only slugs that are real classes are honoured. An unknown entry cannot
        match a real vuln_class anyway, so dropping it is inert rather than a
        silent widening.
        """
        if not program:
            return []
        # Matched case-insensitively, like class slugs. A finding that says
        # `program: Example-BBP` against a config key of `example-bbp` was
        # silently skipping the excludes list, which is the wrong direction to
        # fail in.
        wanted = program.strip().lower()
        entry = next(
            (v for k, v in self.programs.items() if str(k).strip().lower() == wanted),
            None,
        ) or {}
        raw = entry.get("excludes") if isinstance(entry, dict) else None
        if not isinstance(raw, list):
            return []
        return [str(x).strip().lower() for x in raw
                if str(x).strip().lower() in self.classes]


def find_root(start: Path | None = None) -> Path:
    """Walk up from `start` looking for a .bbgate directory."""
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / PROJECT_MARKER).is_dir():
            return candidate
    raise ProjectNotFound(
        f"no {PROJECT_MARKER}/ directory at or above {here}. Run `bbgate init` first."
    )


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_classes(path: Path | None = None) -> set[str]:
    """Flatten the class file into a slug set.

    The file is grouped by surface purely so it reads well when someone opens it
    to add their own class. Only the flattened set is ever used.
    """
    data = _load_yaml(path or (DATA_DIR / "classes.yaml"))
    groups = data.get("classes")
    if not isinstance(groups, dict):
        return set()
    out: set[str] = set()
    for members in groups.values():
        for slug in members or []:
            out.add(str(slug).strip().lower())
    return out


def load_rubric(path: Path | None = None) -> dict[str, RubricEntry]:
    data = _load_yaml(path or (DATA_DIR / "rubric.yaml"))
    entries = data.get("rubric")
    if not isinstance(entries, dict):
        return {}
    out: dict[str, RubricEntry] = {}
    for slug, body in entries.items():
        if not isinstance(body, dict):
            continue
        out[str(slug).strip().lower()] = RubricEntry(
            condition=str(body.get("condition") or "").strip(),
            bar=str(body.get("bar") or "").strip(),
            next_artifact=str(body.get("next_artifact") or "").strip()
            or DEFAULT_NEXT_ARTIFACT,
        )
    return out


def _resolve(root: Path, value, default: str) -> Path:
    raw = str(value or default)
    p = Path(raw)
    return p if p.is_absolute() else (root / p)


def _as_set(value, default: set) -> set:
    if not isinstance(value, list):
        return set(default)
    return {str(x).strip().lower() for x in value if str(x).strip()}


def load_config(root: Path | None = None) -> Config:
    """Load a project's config, filling every absent key from the defaults."""
    root = root.resolve() if root else find_root()
    raw = _load_yaml(root / PROJECT_MARKER / CONFIG_NAME)

    classes_override = str(raw.get("classes") or "").strip()
    rubric_override = str(raw.get("rubric") or "").strip()
    scope = raw.get("scope") if isinstance(raw.get("scope"), dict) else {}
    programs = raw.get("programs") if isinstance(raw.get("programs"), dict) else {}

    return Config(
        root=root,
        findings_dir=_resolve(root, raw.get("findings_dir"), "findings"),
        queue_path=_resolve(root, raw.get("queue_path"), "QUEUE.md"),
        log_path=_resolve(root, raw.get("log_path"), ".bbgate/gate-log.tsv"),
        classes=load_classes(_resolve(root, classes_override, "") if classes_override else None),
        rubric=load_rubric(_resolve(root, rubric_override, "") if rubric_override else None),
        load_bearing=_as_set(raw.get("load_bearing"), DEFAULT_LOAD_BEARING),
        authz_classes=_as_set(raw.get("authz_classes"), DEFAULT_AUTHZ_CLASSES),
        impact_artifact_types=_as_set(
            raw.get("impact_artifact_types"), DEFAULT_IMPACT_ARTIFACT_TYPES
        ),
        verification_types=_as_set(
            raw.get("verification_artifact_types"), DEFAULT_VERIFICATION_TYPES
        ),
        scope_mode=str(scope.get("mode") or "none").strip().lower(),
        scope_command=str(scope.get("command") or "").strip(),
        programs=programs,
    )
