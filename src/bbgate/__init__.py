"""bbgate: a pre-submission gate for bug bounty findings.

Reads a finding's frontmatter and its artifact manifest, then derives
READY, HOLD or DROP. It refuses to produce a submission for anything that
proves a condition instead of a demonstrated consequence.

The verdict is never stored. It is recomputed from disk on every call, so a
`status: ready-to-submit` typed by hand is a claim, not a verdict.
"""
from .config import Config, ConfigError, ProjectNotFound, find_root, load_config
from .evaluate import evaluate
from .model import (
    DROP,
    HOLD,
    READY,
    TIER_CONDITIONAL,
    TIER_DEMONSTRATED,
    TIER_INFERRED,
    TIER_THEORETICAL,
    TIERS,
    Artifact,
    CheckResult,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "Artifact",
    "CheckResult",
    "Config",
    "ConfigError",
    "ProjectNotFound",
    "Verdict",
    "READY",
    "HOLD",
    "DROP",
    "TIERS",
    "TIER_DEMONSTRATED",
    "TIER_INFERRED",
    "TIER_CONDITIONAL",
    "TIER_THEORETICAL",
    "evaluate",
    "find_root",
    "load_config",
    "__version__",
]
