"""The pieces around the gate: config loading, scope resolution, storage, mutators."""
from __future__ import annotations

import pytest
import yaml

from bbgate.config import ConfigError, ProjectNotFound, find_root, load_config
from bbgate.evaluate import evaluate
from bbgate.model import DEFAULT_LOAD_BEARING
from bbgate.mutate import add_artifact, add_clean_run, new_finding, set_impact, stamp_ai
from bbgate.scope import command_resolver, permissive, resolver
from bbgate.store import all_slugs, artifacts_dir, find_finding, read_manifest, sha256_file

from conftest import DIFFERENTIAL, OK, VERIFICATION, make_project

# Config


def test_find_root_walks_up(tmp_path):
    make_project(tmp_path)
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert find_root(nested) == tmp_path


def test_find_root_raises_outside_a_project(tmp_path):
    with pytest.raises(ProjectNotFound):
        find_root(tmp_path)


def test_absent_config_keys_fall_back_to_defaults(tmp_path):
    """A hand-written two line config has to work."""
    (tmp_path / ".bbgate").mkdir()
    (tmp_path / ".bbgate" / "config.yaml").write_text("findings_dir: bugs\n", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.findings_dir == tmp_path / "bugs"
    assert cfg.load_bearing == set(DEFAULT_LOAD_BEARING)
    assert "idor" in cfg.classes
    assert cfg.scope_mode == "none"


def test_empty_config_file_is_valid(tmp_path):
    (tmp_path / ".bbgate").mkdir()
    (tmp_path / ".bbgate" / "config.yaml").write_text("", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.findings_dir == tmp_path / "findings"


def test_load_bearing_is_configurable(tmp_path, write_finding, add_manifest):
    cfg = make_project(tmp_path, load_bearing=["check_1"])
    assert cfg.load_bearing == {"check_1"}


def test_rubric_hint_is_class_specific(project):
    assert project.next_artifact_hint("idor") != project.next_artifact_hint("ssrf")
    assert project.next_artifact_hint("not-a-class")  # falls back rather than returning empty


def test_class_override_file_is_honoured(tmp_path):
    custom = tmp_path / "my-classes.yaml"
    custom.write_text(
        yaml.safe_dump({"classes": {"mine": ["weird-custom-class"]}}), encoding="utf-8"
    )
    cfg = make_project(tmp_path, classes="my-classes.yaml")
    assert cfg.classes == {"weird-custom-class"}


# Scope


def test_permissive_says_why_it_passed(project):
    verdict = permissive("api.example.com")
    assert verdict["verdict"] == "ok"
    assert "no scope engine" in " ".join(verdict["reasons"]).lower()


def test_resolver_defaults_to_permissive(project):
    assert resolver(project) is permissive


def test_resolver_uses_the_configured_command(tmp_path):
    cfg = make_project(tmp_path, scope={"mode": "command", "command": "echo {host}"})
    assert resolver(cfg) is not permissive


def _scope_script(tmp_path, body: str):
    """Write a stand-in scope engine and return a command template invoking it."""
    script = tmp_path / "fake_scope.py"
    script.write_text(body, encoding="utf-8")
    return f"python3 {script} {{host}}"


def test_command_resolver_parses_json(tmp_path):
    command = _scope_script(
        tmp_path,
        'import json, sys\n'
        'print(json.dumps({"host": sys.argv[1], "verdict": "block", '
        '"reasons": ["denylisted"]}))\n',
    )
    assert command_resolver(command)("api.example.com")["verdict"] == "block"


def test_command_resolver_fails_to_unknown_not_ok(tmp_path):
    """A broken scope command must never produce a pass."""
    assert command_resolver("this-command-does-not-exist {host}")("h")["verdict"] == "unknown"

    not_json = _scope_script(tmp_path, "print('this is not json')\n")
    assert command_resolver(not_json)("h")["verdict"] == "unknown"

    no_verdict = _scope_script(tmp_path, 'import json; print(json.dumps({"reasons": []}))\n')
    assert command_resolver(no_verdict)("h")["verdict"] == "unknown"


def test_command_resolver_does_not_let_a_hostname_inject(tmp_path):
    """The host stays one argv element and is never handed to a shell."""
    marker = tmp_path / "pwned"
    command = _scope_script(
        tmp_path,
        'import json, sys\n'
        'print(json.dumps({"verdict": "ok", "reasons": [sys.argv[1]]}))\n',
    )
    hostile = f"evil.com; touch {marker}"
    result = command_resolver(command)(hostile)

    assert not marker.exists(), "the hostname must never reach a shell"
    assert result["reasons"] == [hostile], "it arrives as one argument, unsplit"


# Store


def test_all_slugs_skips_artifacts_and_submissions(project, write_finding, add_manifest):
    fp = write_finding("real-one")
    add_manifest(fp, [DIFFERENTIAL])
    (fp.parent / "real-one.submission.md").write_text("# submission\n", encoding="utf-8")
    assert all_slugs(project) == ["real-one"]


def test_manifest_tolerates_a_missing_file(project, write_finding):
    fp = write_finding("bare")
    assert read_manifest(fp) == []


def test_manifest_row_flags_parse(project, write_finding, add_manifest):
    from conftest import art

    fp = write_finding("flags")
    add_manifest(fp, [art("http_exchange", priv=True), art("poc_html")])
    rows = read_manifest(fp)
    assert rows[0].shows_privileged_data is True
    assert rows[1].shows_privileged_data is False


# Mutators


def test_new_finding_starts_at_hold(project):
    ok, _ = new_finding(project, "fresh-one", vuln_class="idor", target_host="api.example.com")
    assert ok
    verdict = evaluate("fresh-one", project, scope_fn=OK)
    assert verdict.verdict == "HOLD", "a skeleton must not be submittable"


def test_new_finding_refuses_to_overwrite(project):
    new_finding(project, "twice")
    ok, message = new_finding(project, "twice")
    assert not ok and "exists" in message.lower()


def test_set_impact_rejects_an_unknown_tier(project, write_finding):
    write_finding("tiers")
    ok, message = set_impact(
        project, "tiers", position="p", action="a", asset="s", tier="probably"
    )
    assert not ok
    assert "demonstrated" in message  # the valid values are named


def test_precondition_without_an_explicit_tier_becomes_conditional(project, write_finding):
    fp = write_finding("precon")
    set_impact(
        project, "precon", position="p", action="a", asset="s", precondition="victim must click"
    )
    assert yaml.safe_load(fp.read_text().split("---")[1])["impact_tier"] == "conditional"


def test_mutators_preserve_the_body(project, write_finding):
    fp = write_finding("body-safe")
    original = fp.read_text().split("---\n", 2)[2]
    set_impact(project, "body-safe", position="p", action="a", asset="s")
    add_clean_run(project, "body-safe")
    stamp_ai(project, "body-safe")
    assert fp.read_text().split("---\n", 2)[2] == original


def test_add_artifact_copies_hashes_and_records(project, write_finding, tmp_path):
    fp = write_finding("with-art")
    src = tmp_path / "capture.har"
    src.write_text("captured bytes", encoding="utf-8")

    ok, message = add_artifact(project, "with-art", atype="differential_pair", src=str(src))
    assert ok

    rows = read_manifest(fp)
    assert len(rows) == 1
    stored = artifacts_dir(fp) / rows[0].path
    assert stored.exists()
    assert rows[0].sha256 == sha256_file(src)
    assert rows[0].sha256[:12] in message


def test_add_artifact_never_clobbers_a_different_capture(project, write_finding, tmp_path):
    """Two captures sharing a basename must not overwrite each other.

    Overwriting left an earlier manifest row pointing at bytes that no longer
    hash to its recorded sha256, quietly breaking the evidence chain.
    """
    fp = write_finding("collide")
    first = tmp_path / "a" / "screenshot.png"
    second = tmp_path / "b" / "screenshot.png"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("first capture", encoding="utf-8")
    second.write_text("second capture", encoding="utf-8")

    add_artifact(project, "collide", atype="poc_html", src=str(first))
    add_artifact(project, "collide", atype="poc_html", src=str(second))

    rows = read_manifest(fp)
    assert len({r.path for r in rows}) == 2
    for row in rows:
        stored = artifacts_dir(fp) / row.path
        assert sha256_file(stored) == row.sha256


def test_add_artifact_reports_a_missing_source(project, write_finding):
    write_finding("no-src")
    ok, message = add_artifact(project, "no-src", atype="poc_html", src="/nope/missing.har")
    assert not ok and "not found" in message.lower()


def test_full_walk_from_hold_to_ready(project, tmp_path):
    """The sequence the README promises, end to end."""
    new_finding(project, "walk", vuln_class="idor", target_host="api.example.com")
    assert evaluate("walk", project, scope_fn=OK).verdict == "HOLD"

    set_impact(
        project,
        "walk",
        position="free-tier authenticated user",
        action="increment customer_id",
        asset="another customer's personal data",
        tier="demonstrated",
    )
    add_clean_run(project, "walk", from_state="fresh", result="reproduced")

    finding = find_finding(project, "walk")
    text = finding.read_text(encoding="utf-8")
    fm = yaml.safe_load(text.split("---\n")[1])
    fm["repro"] = ["Register account A", "Request account B's object with A's token"]
    finding.write_text(
        "---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n" + text.split("---\n", 2)[2],
        encoding="utf-8",
    )

    stamp_ai(project, "walk", when="2026-06-30T10:00:00")
    for name, atype in (("pair.har", "differential_pair"), ("verify.cast", "terminal_log")):
        src = tmp_path / name
        src.write_text(name, encoding="utf-8")
        add_artifact(
            project, "walk", atype=atype, src=str(src), captured_at="2026-06-30T12:00:00"
        )

    verdict = evaluate("walk", project, scope_fn=OK)
    assert verdict.verdict == "READY", verdict.hold_reason


def test_a_readme_among_findings_is_not_a_finding(project, write_finding, add_manifest):
    """People keep notes next to their findings, and `init --example` ships one.

    Gating documentation prints a permanent HOLD for a file nobody will submit,
    and it makes `gate --all` exit non-zero forever.
    """
    fp = write_finding("real-finding")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    (fp.parent / "README.md").write_text("# how we file findings\n", encoding="utf-8")
    assert all_slugs(project) == ["real-finding"]


def test_evidence_markdown_cannot_shadow_a_finding(project, write_finding, add_manifest):
    """A captured .md named after the finding is evidence, not the finding."""
    fp = write_finding("deep", severity="high/api")
    add_manifest(fp, [DIFFERENTIAL, VERIFICATION])
    decoy = artifacts_dir(fp) / "deep.md"
    decoy.write_text("captured response body", encoding="utf-8")
    assert find_finding(project, "deep") == fp


def test_lock_files_stay_out_of_the_evidence_directory(project, write_finding, tmp_path):
    """Evidence directories hold evidence. The lock lives under .bbgate/locks/."""
    fp = write_finding("locks")
    src = tmp_path / "pair.har"
    src.write_text("bytes", encoding="utf-8")
    ok, _ = add_artifact(project, "locks", atype="differential_pair", src=str(src))
    assert ok
    assert not list(artifacts_dir(fp).glob("*.lock"))
    assert list(project.lock_dir.glob("manifest.tsv.*.lock"))


def test_slug_cannot_leave_the_findings_directory(project, tmp_path):
    """A slug is a filename stem. Separators and dot-dot are refused, not resolved."""
    for bad in ("../escape", "sub/dir", "/abs", ".hidden", "", "a..b"):
        ok, _ = new_finding(project, bad)
        assert not ok, bad
        assert find_finding(project, bad) is None, bad
    assert not (tmp_path / "escape.md").exists()
    ok, _ = new_finding(project, "fine-slug.v2")
    assert ok


@pytest.mark.parametrize("key", ["findings_dir", "queue_path", "log_path"])
def test_config_cannot_point_writes_outside_the_project(tmp_path, key):
    """A cloned repo carries its config. Nothing in it may aim a write elsewhere."""
    outside = tmp_path.parent / "elsewhere"
    (tmp_path / ".bbgate").mkdir()
    (tmp_path / ".bbgate" / "config.yaml").write_text(
        f"{key}: {outside}\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match=key):
        load_config(tmp_path)
    dotdot = tmp_path / ".bbgate" / "config.yaml"
    dotdot.write_text(f"{key}: ../escape\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=key):
        load_config(tmp_path)


def test_read_only_config_paths_may_live_outside(tmp_path):
    """A shared taxonomy kept outside the repo is a normal thing to want."""
    shared = tmp_path.parent / "shared-classes.yaml"
    shared.write_text("classes:\n  mine:\n    - custom\n", encoding="utf-8")
    (tmp_path / ".bbgate").mkdir()
    (tmp_path / ".bbgate" / "config.yaml").write_text(
        f"classes: {shared}\n", encoding="utf-8"
    )
    assert load_config(tmp_path).classes == {"custom"}
