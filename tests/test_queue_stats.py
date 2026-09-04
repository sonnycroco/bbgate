"""Queue rendering and the gate log rollup."""
from __future__ import annotations

from bbgate.evaluate import evaluate
from bbgate.queue import render_queue, write_queue
from bbgate.stats import rollup, write_log

from conftest import DIFFERENTIAL, OK, VERIFICATION, make_project


def _two_findings(write_finding, add_manifest):
    ready = write_finding("q-ready")
    add_manifest(ready, [DIFFERENTIAL, VERIFICATION])
    held = write_finding("q-hold", vuln_class="info-disclosure")
    add_manifest(held, [VERIFICATION])
    return ready, held


def test_queue_is_idempotent(project, write_finding, add_manifest):
    """Rendering twice over unchanged findings must give identical bytes.

    Anything time-varying in the body would show up as a diff on every run and
    make the file useless to commit.
    """
    _two_findings(write_finding, add_manifest)
    first = render_queue(project, scope_fn=OK)
    second = render_queue(project, scope_fn=OK)
    assert first == second
    assert "q-ready" in first and "q-hold" in first


def test_queue_orders_ready_before_hold(project, write_finding, add_manifest):
    _two_findings(write_finding, add_manifest)
    body = render_queue(project, scope_fn=OK)
    assert body.index("q-ready") < body.index("q-hold")


def test_queue_names_the_next_artifact_for_held_findings(project, write_finding, add_manifest):
    _two_findings(write_finding, add_manifest)
    held_row = next(
        line for line in render_queue(project, scope_fn=OK).splitlines() if "q-hold" in line
    )
    assert len(held_row) > len("| q-hold | HOLD |  |")


def test_queue_cell_escapes_pipes(project, write_finding, add_manifest):
    fp = write_finding("pipey", vuln_class="info-disclosure", target_host="a|b.example.com")
    add_manifest(fp, [VERIFICATION])
    for line in render_queue(project, scope_fn=OK).splitlines():
        if line.startswith("| pipey"):
            assert line.count("|") == line.count("\\|") + 4


def test_write_queue_lands_at_the_configured_path(project, write_finding, add_manifest):
    _two_findings(write_finding, add_manifest)
    path = write_queue(project, scope_fn=OK)
    assert path == project.queue_path
    assert path.read_text(encoding="utf-8") == render_queue(project, scope_fn=OK)


def test_empty_project_renders_a_queue(project):
    body = render_queue(project, scope_fn=OK)
    assert body.strip()


# Telemetry


def test_rollup_counts_verdicts_and_deaths(project, write_finding, add_manifest):
    fp = write_finding("stat-hold", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])
    verdict = evaluate("stat-hold", project, scope_fn=OK)
    write_log(project, "stat-hold", verdict)
    write_log(project, "stat-hold", verdict)

    stats = rollup(project, 90)
    assert stats["rows"] == 2
    assert stats["verdicts"].get("HOLD") == 2
    assert stats["deaths"].get("check_3") == 2


def test_rollup_on_an_empty_log(project):
    stats = rollup(project, 90)
    assert stats["rows"] == 0
    assert stats["verdicts"] == {}


def test_rollup_ignores_rows_outside_the_window(tmp_path, write_finding, add_manifest):
    cfg = make_project(tmp_path)
    fp = write_finding("old-row", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])
    write_log(cfg, "old-row", evaluate("old-row", cfg, scope_fn=OK))

    log = cfg.log_path
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[-1] = lines[-1].replace(lines[-1].split("\t")[0], "2019-01-01T00:00:00")
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert rollup(cfg, 90)["rows"] == 0
