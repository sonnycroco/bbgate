"""CLI behaviour, with exit codes treated as part of the contract.

Exit codes are how this gets used in CI, so they are asserted as carefully as
the verdicts themselves.
"""
from __future__ import annotations

import json
import os

from click.testing import CliRunner

from bbgate.cli import main
from bbgate.package import package_path_for

from conftest import DIFFERENTIAL, VERIFICATION


def run(args, cwd):
    """Invoke the CLI as if the user were standing in `cwd`.

    The chdir is done here rather than with CliRunner.isolated_filesystem,
    which is deprecated and goes away in Click 9. Every caller passes a
    tmp_path, so the directory is already isolated.
    """
    runner = CliRunner()
    previous = os.getcwd()
    os.chdir(cwd)
    try:
        return runner.invoke(main, args)
    finally:
        os.chdir(previous)


def test_init_creates_a_project(tmp_path):
    result = run(["init"], tmp_path)
    assert result.exit_code == 0
    assert (tmp_path / ".bbgate" / "config.yaml").exists()
    assert (tmp_path / "findings").is_dir()


def test_init_does_not_clobber(tmp_path):
    run(["init"], tmp_path)
    (tmp_path / ".bbgate" / "config.yaml").write_text("findings_dir: mine\n", encoding="utf-8")
    result = run(["init"], tmp_path)
    assert result.exit_code == 0
    assert "mine" in (tmp_path / ".bbgate" / "config.yaml").read_text(encoding="utf-8")


def test_init_with_example_gates_to_hold(tmp_path):
    """The shipped example must start at HOLD, so the walkthrough has somewhere to go."""
    assert run(["init", "--example"], tmp_path).exit_code == 0
    findings = list((tmp_path / "findings").glob("*.md"))
    slugs = [f.stem for f in findings if f.stem.lower() != "readme"]
    assert slugs, "init --example must copy at least one finding"

    result = run(["gate", slugs[0]], tmp_path)
    assert result.exit_code == 1
    assert "HOLD" in result.output


def test_commands_outside_a_project_exit_2(tmp_path):
    result = run(["gate", "anything"], tmp_path)
    assert result.exit_code == 2
    assert "bbgate init" in result.output


def test_gate_exit_codes(tmp_path, project, write_finding, add_manifest):
    ready = write_finding("cli-ready")
    add_manifest(ready, [DIFFERENTIAL, VERIFICATION])
    assert run(["gate", "cli-ready"], tmp_path).exit_code == 0

    held = write_finding("cli-hold", vuln_class="info-disclosure")
    add_manifest(held, [VERIFICATION])
    assert run(["gate", "cli-hold"], tmp_path).exit_code == 1

    dropped = write_finding("cli-drop", impact_tier="theoretical")
    add_manifest(dropped, [DIFFERENTIAL, VERIFICATION])
    assert run(["gate", "cli-drop"], tmp_path).exit_code == 2


def test_gate_json_is_machine_readable(tmp_path, project, write_finding, add_manifest):
    fp = write_finding("cli-json")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    result = run(["gate", "cli-json", "--json"], tmp_path)
    payload = json.loads(result.output)
    assert payload["verdict"] == "READY"
    assert payload["finding"] == "cli-json"
    assert len(payload["checks"]) == 9


def test_gate_warns_that_scope_is_unconfigured(tmp_path, project, write_finding, add_manifest):
    """A permissive default that is invisible would be a trap."""
    fp = write_finding("cli-scope-note")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    output = run(["gate", "cli-scope-note"], tmp_path).output
    assert "scope" in output.lower()


def test_gate_all_exits_with_the_worst_verdict(tmp_path, project, write_finding, add_manifest):
    ready = write_finding("all-ready")
    add_manifest(ready, [DIFFERENTIAL, VERIFICATION])
    dropped = write_finding("all-drop", impact_tier="theoretical")
    add_manifest(dropped, [DIFFERENTIAL, VERIFICATION])
    assert run(["gate", "--all"], tmp_path).exit_code == 2


def test_gate_all_with_a_slug_is_a_usage_error(tmp_path, project, write_finding):
    write_finding("both")
    assert run(["gate", "--all", "both"], tmp_path).exit_code == 2


def test_package_refuses_and_writes_nothing(tmp_path, project, write_finding, add_manifest):
    fp = write_finding("cli-package-hold", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])
    result = run(["package", "cli-package-hold"], tmp_path)
    assert result.exit_code != 0
    assert not package_path_for(fp).exists()


def test_package_writes_on_ready(tmp_path, project, write_finding, add_manifest):
    fp = write_finding("cli-package-ready")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    result = run(["package", "cli-package-ready"], tmp_path)
    assert result.exit_code == 0
    assert package_path_for(fp).exists()


def test_gate_appends_a_log_row(tmp_path, project, write_finding, add_manifest):
    fp = write_finding("cli-logged", vuln_class="info-disclosure")
    add_manifest(fp, [VERIFICATION])
    run(["gate", "cli-logged"], tmp_path)
    run(["gate", "cli-logged"], tmp_path)
    assert project.log_path.exists()
    stats = run(["stats", "--last", "90d"], tmp_path)
    assert stats.exit_code == 0
    assert "check_3" in stats.output


def test_classes_lists_slugs_and_marks_authz(tmp_path, project):
    output = run(["classes"], tmp_path).output
    assert "idor" in output
    assert "ssrf" in output


def test_new_then_gate(tmp_path, project):
    assert run(["new", "cli-new", "--class", "idor"], tmp_path).exit_code == 0
    assert run(["gate", "cli-new"], tmp_path).exit_code == 1


def test_mutators_round_trip(tmp_path, project, write_finding):
    write_finding("cli-mutate")
    assert (
        run(
            [
                "set-impact",
                "cli-mutate",
                "--position",
                "anonymous user",
                "--action",
                "request the export endpoint",
                "--asset",
                "the full customer export",
                "--tier",
                "demonstrated",
            ],
            tmp_path,
        ).exit_code
        == 0
    )
    assert run(["clean-run", "cli-mutate"], tmp_path).exit_code == 0
    assert run(["stamp-ai", "cli-mutate"], tmp_path).exit_code == 0
    assert (
        run(["override-repro", "cli-mutate", "--reason", "step 1 creates the account"], tmp_path
            ).exit_code
        == 0
    )


def test_add_artifact_through_the_cli(tmp_path, project, write_finding):
    write_finding("cli-artifact")
    src = tmp_path / "evidence.har"
    src.write_text("bytes", encoding="utf-8")
    result = run(
        ["add-artifact", "cli-artifact", "--type", "differential_pair", "--path", str(src)],
        tmp_path,
    )
    assert result.exit_code == 0


def test_queue_command_writes_the_file(tmp_path, project, write_finding, add_manifest):
    fp = write_finding("cli-queue")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    assert run(["queue"], tmp_path).exit_code == 0
    assert project.queue_path.exists()
    assert "cli-queue" in project.queue_path.read_text(encoding="utf-8")


def test_claimed_gates_only_self_declared_findings(tmp_path, project, write_finding, add_manifest):
    """The build should break on a contradiction, not on unfinished work.

    Gating every finding is red forever, because most findings are legitimately
    incomplete. Gating the ones whose status says they are sendable is the
    check worth failing CI over.
    """
    incomplete = write_finding("still-working", vuln_class="info-disclosure")
    add_manifest(incomplete, [VERIFICATION])
    assert run(["gate", "--all"], tmp_path).exit_code == 1
    result = run(["gate", "--all", "--claimed"], tmp_path)
    assert result.exit_code == 0, "an unfinished finding is not a CI failure"

    lying = write_finding(
        "says-ready", vuln_class="info-disclosure", status="ready-to-submit"
    )
    add_manifest(lying, [VERIFICATION])
    assert run(["gate", "--all", "--claimed"], tmp_path).exit_code == 1


def test_claimed_requires_all(tmp_path, project, write_finding):
    write_finding("solo")
    assert run(["gate", "--claimed", "solo"], tmp_path).exit_code == 2
