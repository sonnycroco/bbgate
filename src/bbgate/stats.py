"""The gate log: one appended row per gate run, and the rollup over it.

This is the only state the tool persists. A verdict is never stored, so the log
answers a different question: not "is this finding ready" but "which check kills
my findings", which is the number that changes how you work.
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta

from . import frontmatter, timeutil
from .config import Config
from .model import Verdict

LOG_FIELDS = ["ts", "finding", "verdict", "failed_checks"]


def write_log(cfg: Config, slug: str, verdict: Verdict) -> None:
    """Append one row for this gate run, writing the header on first use."""
    row = {
        "ts": timeutil.now_iso(),
        "finding": slug,
        "verdict": verdict.verdict,
        "failed_checks": ",".join(verdict.failed_cids()),
    }
    path = cfg.log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with frontmatter.locked(path, cfg.lock_dir):
        new_file = not path.exists()
        with path.open("a", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=LOG_FIELDS,
                delimiter="\t",
                lineterminator="\n",
                extrasaction="ignore",
            )
            if new_file:
                writer.writeheader()
            writer.writerow(row)


def rollup(cfg: Config, days: int) -> dict:
    """Count verdicts and per-check deaths over the last `days` days.

    Rows with an unparseable timestamp are skipped rather than counted. A row
    that cannot be placed in time cannot be placed in the window either, and
    quietly folding it into the current one would overstate recent activity.
    """
    path = cfg.log_path
    if not path.exists():
        return {"rows": 0, "verdicts": {}, "deaths": {}}

    cutoff = datetime.now() - timedelta(days=days)
    verdicts: dict[str, int] = {}
    deaths: dict[str, int] = {}
    rows = 0

    with path.open("r", encoding="utf-8", newline="") as fh:
        for record in csv.DictReader(fh, delimiter="\t"):
            stamp = timeutil.parse_ts(record.get("ts") or "")
            if stamp is None or stamp < cutoff:
                continue
            rows += 1
            name = (record.get("verdict") or "?").strip() or "?"
            verdicts[name] = verdicts.get(name, 0) + 1
            for raw_cid in (record.get("failed_checks") or "").split(","):
                cid = raw_cid.strip()
                if cid:
                    deaths[cid] = deaths.get(cid, 0) + 1

    return {"rows": rows, "verdicts": verdicts, "deaths": deaths}
