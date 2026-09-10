"""Data model for the gate: tiers, artifact classification, check and verdict types."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# Impact tiers. Only DEMONSTRATED can reach READY.
TIER_DEMONSTRATED = "demonstrated"
TIER_INFERRED = "inferred"
TIER_CONDITIONAL = "conditional"
TIER_THEORETICAL = "theoretical"
TIERS = {TIER_DEMONSTRATED, TIER_INFERRED, TIER_CONDITIONAL, TIER_THEORETICAL}

# Verdicts.
READY = "READY"
HOLD = "HOLD"
DROP = "DROP"

# An http_exchange is worth nothing on its own. It evidences impact only when the
# capturing operator flagged that the response body holds data they should not
# have been able to read.
CONDITIONAL_IMPACT_TYPE = "http_exchange"

# Two-principal proof. Either you show A acting on B's object next to a negative
# control, or you show a token you minted being accepted.
DIFFERENTIAL_TYPES = frozenset({"differential_pair", "forged_token"})

# Defaults. A project can override each of these in .bbgate/config.yaml.
DEFAULT_IMPACT_ARTIFACT_TYPES = frozenset({
    "differential_pair", "oob_callback", "poc_html", "forged_token",
})
DEFAULT_VERIFICATION_TYPES = frozenset({"terminal_log", "screen_recording"})
DEFAULT_AUTHZ_CLASSES = frozenset({"idor", "bola", "bfla", "oauth", "jwt"})
DEFAULT_LOAD_BEARING = frozenset({"check_1", "check_3", "check_5", "check_8"})

# Phrases in a repro that suggest it leans on state from an earlier session. This
# is a crude lint and it is meant to be: it routes to HOLD for a human look, never
# to DROP, and `override-repro` clears it with a recorded reason.
PREEXISTING_STATE_PHRASES = (
    "already logged in", "from earlier", "as before", "previously created",
    "existing session", "still logged in", "reuse the session",
    "from the previous", "left over from", "carried over",
)

# Order the HOLD reasons are surfaced in. The point is that the first line a
# person reads is the one telling them what to go capture, not a scolding about
# an unset field.
HOLD_ORDER = (
    "class_known", "check_3", "check_4", "check_8", "check_5",
    "check_1", "check_9", "check_2", "check_6", "check_7",
)

# The check table. The id is what the config, the log and the JSON output key
# on; the name is what a person reads. `meaning` is one plain sentence saying
# what the check wants, used by `bbgate checks` so nobody has to open the
# README to learn what check_8 is.
CHECK_NAMES = {
    "class_known": "class_known",
    "check_1": "impact_demonstrated",
    "check_2": "statement_complete",
    "check_3": "impact_artifact_exists",
    "check_4": "differential_for_authz",
    "check_5": "clean_state",
    "check_6": "repro_self_contained",
    "check_7": "scope_clear",
    "check_8": "human_verified",
    "check_9": "confidence_floor",
}

CHECK_MEANINGS = {
    "check_1": "The impact tier is demonstrated: an evidence file shows the "
               "consequence, not just the bug.",
    "check_2": "The impact statement says who the attacker is, what they do, "
               "and what they get.",
    "check_3": "At least one evidence file proves the impact. A screenshot "
               "does not count.",
    "check_4": "For access-control bugs (IDOR and friends), the evidence shows "
               "one user reaching another user's data, next to the same request "
               "being refused.",
    "check_5": "Someone reproduced the bug from a fresh account or session, "
               "following the written steps exactly.",
    "check_6": "The repro steps stand on their own. Nothing relies on a "
               "session or object left over from earlier testing.",
    "check_7": "The host is in scope, the program pays for this class, and "
               "the finding is not flagged as a likely duplicate.",
    "check_8": "A person re-ran the repro and recorded it (terminal log or "
               "screen recording) after the last time a model touched the "
               "writeup.",
    "check_9": "Same bar as check_1, kept separate so a project can make one "
               "of them advisory and keep the other load bearing.",
}

DEFAULT_NEXT_ARTIFACT = (

    "an artifact proving the consequence: differential_pair, oob_callback, "
    "poc_html with the captured value, forged_token, or an http_exchange "
    "flagged shows_privileged_data"
)


@dataclass
class Artifact:
    """One row of a finding's artifact manifest."""

    type: str
    path: str
    sha256: str
    captured_at: str
    capture_method: str
    shows_privileged_data: bool

    def evidences_impact(self, impact_types: Iterable[str]) -> bool:
        if self.type in set(impact_types):
            return True
        return self.type == CONDITIONAL_IMPACT_TYPE and self.shows_privileged_data


@dataclass
class CheckResult:
    cid: str
    passed: bool
    reason: str
    fail_route: str = "hold"  # "hold" or "drop", only read when not passed

    @property
    def name(self) -> str:
        return CHECK_NAMES.get(self.cid, self.cid)

    def to_dict(self) -> dict:
        return {
            "id": self.cid,
            "name": self.name,
            "passed": self.passed,

            "reason": self.reason,
            "fail_route": self.fail_route,
        }


@dataclass
class Verdict:
    slug: str
    verdict: str
    checks: list[CheckResult] = field(default_factory=list)
    next_artifact: str = ""
    hold_reason: str = ""
    drop_reason: str = ""

    def failed_cids(self) -> list[str]:
        return [c.cid for c in self.checks if not c.passed]

    @property
    def exit_code(self) -> int:
        return {READY: 0, HOLD: 1, DROP: 2}.get(self.verdict, 2)

    def to_dict(self) -> dict:
        return {
            "finding": self.slug,
            "verdict": self.verdict,
            "checks": [c.to_dict() for c in self.checks],
            "failed": self.failed_cids(),
            "next_artifact": self.next_artifact,
            "hold_reason": self.hold_reason,
            "drop_reason": self.drop_reason,
        }
