"""Command line entry point."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__, mutate, package, queue, stats
from .config import DATA_DIR, PROJECT_MARKER, Config, ProjectNotFound, load_config
from .evaluate import evaluate
from .model import CHECK_MEANINGS, CHECK_NAMES, DROP, HOLD, READY
from .scope import resolver
from .store import all_slugs, claimed_ready

console = Console()

_VERDICT_STYLE = {READY: "bold green", HOLD: "bold yellow", DROP: "bold red"}

_CONFIG_TEMPLATE = """\
# bbgate project config. Every key is optional and the value shown is the
# default, so deleting a line changes nothing.

findings_dir: findings
queue_path: QUEUE.md
log_path: .bbgate/gate-log.tsv

# Paths to your own class and rubric files. Empty means use the built-in ones.
classes: ""
rubric: ""

# Failing one of these is what stops a submission. The others are advisory.
load_bearing: [check_1, check_3, check_5, check_8]

# Classes where proof needs two principals: a differential pair, or a token you
# minted being accepted.
authz_classes: [idor, bola, bfla, oauth, jwt]

impact_artifact_types: [differential_pair, oob_callback, poc_html, forged_token]
verification_artifact_types: [terminal_log, screen_recording]

# mode: none leaves check_7 permissive. mode: command runs the command once per
# host, substitutes {host}, and reads a verdict JSON from its stdout.
scope:
  mode: none
  command: ""

# Classes a program will not pay for. A finding in one of these is DROPped.
programs: {}
#  example-bbp:
#    excludes: [clickjacking]
"""


def _project() -> Config:
    """Resolve the project or exit 2 with the reason."""
    try:
        return load_config()
    except ProjectNotFound as exc:
        click.echo(str(exc), err=True)
        raise SystemExit(2) from exc


def _finish(ok: bool, message: str) -> None:
    """Print a mutator result and exit on its success flag."""
    console.print(message, style="green" if ok else "red")
    raise SystemExit(0 if ok else 1)


def _print_checks(cfg: Config, verdict) -> None:
    # The name rides beside the id on every line. The id is what config and
    # JSON key on, but "check_8" on its own tells a first-time reader nothing.
    for check in verdict.checks:
        label = f"{check.cid} [dim]{check.name}[/dim]"
        if check.passed:
            console.print(f"  [green]PASS[/green] {label}: {check.reason}")
            continue
        tag = "DROP" if check.fail_route == "drop" else "FAIL"
        color = "red" if check.fail_route == "drop" else "yellow"
        mark = " [dim](load-bearing)[/dim]" if check.cid in cfg.load_bearing else ""
        console.print(f"  [{color}]{tag}[/{color}] {label}{mark}: {check.reason}")


def _print_verdict(cfg: Config, verdict) -> None:
    _print_checks(cfg, verdict)
    # Nothing ran when the finding is missing, so the scope note would be noise.
    if cfg.scope_mode == "none" and verdict.checks:
        console.print(
            "  [dim]note: check_7 passed because no scope engine is configured. "
            "Set the scope: key in .bbgate/config.yaml to make it mean "
            "something.[/dim]"
        )
    style = _VERDICT_STYLE.get(verdict.verdict, "bold")
    console.print(f"\n[{style}]VERDICT: {verdict.verdict}[/{style}]")
    if verdict.verdict == DROP and verdict.drop_reason:
        console.print(f"[red]Reason:[/red] {verdict.drop_reason}")
    if verdict.verdict == HOLD:
        # Only the next artifact is worth repeating here. Every hold reason was
        # already printed as its own failing check line, and echoing the joined
        # string underneath buries the one line the reader has to act on.
        if verdict.next_artifact:
            console.print(f"[yellow]Next artifact:[/yellow] {verdict.next_artifact}")
        else:
            failing = ", ".join(verdict.failed_cids())
            console.print(f"[dim]Failing:[/dim] {failing}")


def _parse_window(text: str) -> int:
    """Turn 90d / 12w / 6m, or a bare number of days, into days."""
    raw = (text or "").strip().lower()
    if not raw:
        raise click.BadParameter("empty window")
    unit, number = raw[-1], raw[:-1]
    scale = {"d": 1, "w": 7, "m": 30}.get(unit)
    if scale is None:
        unit, number, scale = "d", raw, 1
    try:
        count = int(number)
    except ValueError:
        raise click.BadParameter(f"cannot read '{text}' as a window, try 90d") from None
    if count <= 0:
        raise click.BadParameter("window must be positive")
    return count * scale


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Pre-submission gate for bug bounty findings."""


@main.command("init")
@click.option("--example", is_flag=True, default=False,
              help="Also copy the worked example finding into the project.")
def init_cmd(example: bool) -> None:
    """Scaffold a bbgate project in the current directory."""
    root = Path.cwd()
    marker = root / PROJECT_MARKER
    if marker.exists():
        console.print(f"{marker} already exists, leaving it alone.")
        raise SystemExit(0)

    marker.mkdir(parents=True)
    (marker / "config.yaml").write_text(_CONFIG_TEMPLATE, encoding="utf-8")
    (root / "findings").mkdir(exist_ok=True)
    console.print(f"[green]Created[/green] {PROJECT_MARKER}/config.yaml and findings/")

    if example:
        source = DATA_DIR / "example"
        if source.is_dir():
            shutil.copytree(source, root, dirs_exist_ok=True)
            console.print("[green]Copied[/green] the worked example into findings/")
        else:
            console.print("No example ships with this build, skipping.", style="yellow")

    console.print("\nNext:")
    console.print("  bbgate checks                     what the nine checks want, in plain words")
    console.print("  bbgate new my-finding --class idor --host api.example.com")
    console.print("  bbgate gate my-finding")
    console.print("  bbgate queue")
    if example:
        console.print("\nThe example is findings/customer-pii-idor.md. Start with:")
        console.print("  bbgate gate customer-pii-idor")


@main.command("new")
@click.argument("slug")
@click.option("--class", "vuln_class", default="", help="Vulnerability class slug.")
@click.option("--host", "target_host", default="", help="Target host.")
@click.option("--program", default="", help="Program the finding belongs to.")
def new_cmd(slug: str, vuln_class: str, target_host: str, program: str) -> None:
    """Create a finding skeleton."""
    cfg = _project()
    ok, message = mutate.new_finding(
        cfg, slug, vuln_class=vuln_class, target_host=target_host, program=program
    )
    _finish(ok, message)


@main.command("gate")
@click.argument("slug", required=False)
@click.option("--all", "do_all", is_flag=True, default=False,
              help="Gate every finding in the project.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Print the verdict as JSON and nothing else.")
@click.option("--claimed", is_flag=True, default=False,
              help="With --all, gate only findings whose status claims they are ready.")
def gate_cmd(slug: str | None, do_all: bool, as_json: bool, claimed: bool) -> None:
    """Evaluate a finding and print each check, the verdict and what is missing."""
    if do_all and slug:
        raise click.UsageError("give a slug or --all, not both")
    if not do_all and not slug:
        raise click.UsageError("give a slug, or --all to gate everything")
    if claimed and not do_all:
        raise click.UsageError("--claimed only makes sense with --all")

    cfg = _project()
    scope_fn = resolver(cfg)

    if not do_all:
        verdict = evaluate(slug, cfg, scope_fn=scope_fn)
        stats.write_log(cfg, slug, verdict)
        if as_json:
            click.echo(json.dumps(verdict.to_dict(), indent=2))
        else:
            _print_verdict(cfg, verdict)
        raise SystemExit(verdict.exit_code)

    names = claimed_ready(cfg) if claimed else all_slugs(cfg)
    verdicts = []
    for name in names:
        verdict = evaluate(name, cfg, scope_fn=scope_fn)
        stats.write_log(cfg, name, verdict)
        verdicts.append(verdict)

    if as_json:
        click.echo(json.dumps([v.to_dict() for v in verdicts], indent=2))
        raise SystemExit(max([v.exit_code for v in verdicts], default=0))

    if not verdicts:
        if claimed:
            # Nothing claims to be sendable, so there is no disagreement to report.
            console.print("No finding claims to be ready.")
        else:
            console.print("No findings yet. Start one with `bbgate new <slug>`.")
        raise SystemExit(0)

    table = Table(box=None, padding=(0, 2))
    table.add_column("finding")
    table.add_column("verdict")
    table.add_column("next artifact or reason")
    order = {READY: 0, HOLD: 1, DROP: 2}
    for verdict in sorted(verdicts, key=lambda v: (order.get(v.verdict, 9), v.slug)):
        if verdict.verdict == READY:
            detail = ""
        elif verdict.verdict == DROP:
            detail = verdict.drop_reason
        else:
            detail = verdict.next_artifact or verdict.hold_reason
        style = _VERDICT_STYLE.get(verdict.verdict, "bold")
        table.add_row(verdict.slug, f"[{style}]{verdict.verdict}[/{style}]",
                      (detail or "").replace("\n", " "))
    console.print(table)
    if cfg.scope_mode == "none":
        console.print(
            "[dim]note: check_7 passed everywhere because no scope engine is "
            "configured. See the scope: key in .bbgate/config.yaml.[/dim]"
        )
    raise SystemExit(max(v.exit_code for v in verdicts))


@main.command("package")
@click.argument("slug")
def package_cmd(slug: str) -> None:
    """Write the submission markdown, refusing unless the verdict is READY."""
    cfg = _project()
    ok, message, _path = package.build_package(cfg, slug)
    if not ok:
        console.print(message, style="red")
        console.print("[red]Nothing was written.[/red]")
        raise SystemExit(1)
    console.print(message, style="green")
    raise SystemExit(0)


@main.command("set-impact")
@click.argument("slug")
@click.option("--position", required=True, help="Position the attacker starts from.")
@click.option("--action", required=True, help="What the attacker does.")
@click.option("--asset", required=True, help="What that obtains.")
@click.option("--precondition", default="",
              help="Unverified precondition. Non-empty forces the conditional tier.")
@click.option("--tier", default="",
              help="Tier: demonstrated, inferred, conditional or theoretical.")
def set_impact_cmd(slug: str, position: str, action: str, asset: str,
                   precondition: str, tier: str) -> None:
    """Set the impact statement, and the tier it implies."""
    cfg = _project()
    ok, message = mutate.set_impact(
        cfg, slug, position=position, action=action, asset=asset,
        precondition=precondition, tier=tier,
    )
    _finish(ok, message)


@main.command("clean-run")
@click.argument("slug")
@click.option("--from", "from_state", default="fresh", show_default=True,
              help="State the run started from.")
@click.option("--result", default="reproduced", show_default=True,
              help="What the run produced.")
@click.option("--deviation", "deviations", multiple=True,
              help="A deviation from the written repro. Repeatable.")
def clean_run_cmd(slug: str, from_state: str, result: str,
                  deviations: tuple) -> None:
    """Record a reproduction run from a stated starting state."""
    cfg = _project()
    ok, message = mutate.add_clean_run(
        cfg, slug, from_state=from_state, result=result, deviations=list(deviations)
    )
    _finish(ok, message)


@main.command("add-artifact")
@click.argument("slug")
@click.option("--type", "atype", required=True, help="Artifact type.")
@click.option("--path", "src", required=True, help="File to copy in as evidence.")
@click.option("--method", "capture_method", default="manual", show_default=True,
              help="How it was captured.")
@click.option("--shows-privileged-data", is_flag=True, default=False,
              help="The artifact shows data this account should not reach.")
@click.option("--at", "captured_at", default="",
              help="Capture time as an ISO timestamp. Defaults to now.")
def add_artifact_cmd(slug: str, atype: str, src: str, capture_method: str,
                     shows_privileged_data: bool, captured_at: str) -> None:
    """Copy an evidence file in and append its manifest row."""
    cfg = _project()
    ok, message = mutate.add_artifact(
        cfg, slug, atype=atype, src=src, capture_method=capture_method,
        shows_privileged_data=shows_privileged_data, captured_at=captured_at,
    )
    _finish(ok, message)


@main.command("stamp-ai")
@click.argument("slug")
@click.option("--at", "when", default="",
              help="ISO timestamp of the edit. Defaults to now.")
def stamp_ai_cmd(slug: str, when: str) -> None:
    """Record when a model last edited the writeup."""
    cfg = _project()
    ok, message = mutate.stamp_ai(cfg, slug, when=when)
    _finish(ok, message)


@main.command("override-repro")
@click.argument("slug")
@click.option("--reason", required=True, help="Why the repro lint is wrong here.")
def override_repro_cmd(slug: str, reason: str) -> None:
    """Clear the pre-existing-state repro lint, on the record."""
    cfg = _project()
    ok, message = mutate.override_repro(cfg, slug, reason=reason)
    _finish(ok, message)


@main.command("queue")
def queue_cmd() -> None:
    """Regenerate the queue file from the findings on disk."""
    cfg = _project()
    path = queue.write_queue(cfg)
    try:
        shown = path.relative_to(cfg.root)
    except ValueError:
        shown = path
    console.print(f"[green]Wrote[/green] {shown}")


@main.command("stats")
@click.option("--last", default="90d", show_default=True,
              help="Window, such as 90d, 12w, 6m, or a number of days.")
def stats_cmd(last: str) -> None:
    """Show which check kills the most findings."""
    cfg = _project()
    days = _parse_window(last)
    rollup = stats.rollup(cfg, days)
    console.print(f"[bold]Gate stats, last {days}d[/bold]  ({rollup['rows']} runs)")
    if not rollup["rows"]:
        console.print("[dim]No gate runs in that window.[/dim]")
        return

    verdicts = Table(title="Verdicts", box=None, padding=(0, 2))
    verdicts.add_column("verdict")
    verdicts.add_column("count", justify="right")
    for name in (READY, HOLD, DROP):
        if name in rollup["verdicts"]:
            verdicts.add_row(name, str(rollup["verdicts"][name]))
    console.print(verdicts)

    deaths = Table(title="Death by stage", box=None, padding=(0, 2))
    deaths.add_column("check")
    deaths.add_column("times failed", justify="right")
    for cid, count in sorted(rollup["deaths"].items(), key=lambda kv: (-kv[1], kv[0])):
        deaths.add_row(cid, str(count))
    console.print(deaths)


@main.command("checks")
def checks_cmd() -> None:
    """List the nine checks and what each one wants, in plain words."""
    cfg = _project()
    # A list rather than a table: four columns of prose wrap into a stack of
    # three-word lines at eighty columns, and the names get truncated.
    for cid, meaning in CHECK_MEANINGS.items():
        mark = "  [yellow]stops a submission[/yellow]" if cid in cfg.load_bearing else ""
        console.print(f"[bold]{cid}[/bold]  {CHECK_NAMES[cid]}{mark}")
        console.print(f"    {meaning}")
    console.print(
        "\n[dim]A finding that fails a check marked 'stops a submission' is held "
        "no matter what else passes. That set is the load_bearing key in "
        ".bbgate/config.yaml.[/dim]"
    )


@main.command("classes")
def classes_cmd() -> None:
    """List the known vulnerability classes and the bar each one has to clear."""
    cfg = _project()
    if not cfg.classes:
        console.print("No classes are configured.", style="yellow")
        return

    table = Table(box=None, padding=(0, 2))
    table.add_column("class")
    table.add_column("authz")
    table.add_column("demonstrated bar")
    for slug in sorted(cfg.classes):
        entry = cfg.rubric.get(slug)
        authz = "yes" if slug in cfg.authz_classes else ""
        table.add_row(slug, authz, entry.bar if entry else "")
    console.print(table)
    console.print(
        "[dim]authz classes need two-principal proof: a differential_pair, or a "
        "token you minted being accepted.[/dim]"
    )


if __name__ == "__main__":
    main()
