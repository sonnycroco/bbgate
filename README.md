# bbgate

A pre-submission gate for bug bounty findings, built for people who draft
their reports with an AI.

You write the finding as a markdown file. You drop the evidence you captured
beside it. `bbgate gate` reads both and answers with one word: READY, HOLD or
DROP. On HOLD it tells you the exact file to go and capture next. It will not
write a submission until a person has re-run the bug by hand after the last
time a model touched the writeup.

It does not scan, it does not touch the target, and it does not rate severity.
It reads files on your disk and refuses to let a good-looking writeup go out
ahead of its proof.

![bbgate gate holding a finding](docs/gate-hold.svg)

## Who this is for

- **Bug bounty hunters and pentesters who draft with a model.** You do the
  testing, the model tidies the report, and you want something that stops a
  fluent writeup from being sent before you re-checked it.
- **People who run an agent inside their testing workflow.** The tool speaks
  JSON and exit codes, so an agent can be told "gate it, read what is missing,
  ask the human to capture it" and cannot talk its way to READY.
- **Anyone who wants the triage argument to happen before submission.** The
  nine checks are the questions a triager asks. Failing them at your desk is
  cheaper than failing them in the ticket.

It came out of a personal offsec workflow where Claude runs alongside the
testing. That is why the AI loop is the centre of it, not a feature bolted on.

## The idea in one paragraph

Most rejected reports prove a *condition* (the ID is enumerable, the header is
missing, the redirect works) and not a *consequence* (I read another user's
data, I ran a command, I got a token). A model makes that gap worse, because it
writes the consequence fluently whether or not you captured it. bbgate settles
the question by looking at what is on disk. If no evidence file shows the
consequence, the finding holds. If the last human re-run is older than the last
model edit, the finding holds. Neither of those can be argued with, only fixed
by capturing something.

## Words this README uses

| word | meaning here |
|---|---|
| finding | one markdown file with YAML frontmatter, describing one bug |
| artifact | one evidence file you captured (a saved request pair, a callback log, a recording) |
| manifest | `artifacts/manifest.tsv` beside the finding, one row per artifact: type, path, hash, when |
| impact artifact | an artifact type that proves the consequence, not just the bug |
| verification artifact | a terminal log or screen recording of a person re-running the repro |
| differential pair | your request against someone else's object, saved next to the same request being refused |
| negative control | the "refused" half of a differential pair, proving the access was not just open to everyone |
| tier | how strong your impact claim is: demonstrated, inferred, conditional or theoretical |
| load bearing | a check that holds the finding on its own, whatever else passes |
| slug | the finding's filename without `.md`, used as its id on the command line |

## Install

Not on any package index. Install from a checkout:

```
git clone https://github.com/sonnycroco/bbgate
cd bbgate
pip install .
```

`pipx install .` also works if you prefer the CLI isolated. Python 3.9 or newer.

## Five minutes with the example

`bbgate init` creates a project in the current directory. `--example` also
drops in a finished IDOR writeup that is deliberately one step short of
submittable. Everything is written, nothing is captured.

```
mkdir bounty && cd bounty
bbgate init --example
bbgate gate customer-pii-idor
```

It holds, and the first thing it prints is what to go capture:

![capturing the evidence, then the finding clears](docs/gate-ready.svg)

Add the two files it asked for. Any file works for a dry run, the gate records
type, hash and time and never reads the bytes:

```
bbgate add-artifact customer-pii-idor --type differential_pair --path ab.har \
    --method "burp, A's token against B's id plus the 403 control"
bbgate add-artifact customer-pii-idor --type terminal_log --path verify.log \
    --method "asciinema, full repro re-run by hand"
bbgate gate customer-pii-idor        # READY, exit 0
bbgate package customer-pii-idor     # writes findings/customer-pii-idor.submission.md
```

Now let a model tidy the prose, and record that it did:

```
bbgate stamp-ai customer-pii-idor
bbgate package customer-pii-idor     # REFUSED, writes nothing
```

![the submission stops being sendable](docs/refused.svg)

A finding that was READY is not READY any more. What made it trustworthy was a
person re-running it, and that happened before the current text existed.
Re-run it, capture a new terminal log, and it clears again.

`bbgate queue` writes the same verdicts out as a committable list of what you
owe:

![the generated queue](docs/queue.svg)

## Using it with an AI

The risk is not that a model drafts the report. The risk is that the drafting
outruns the last time a person checked anything. So the loop:

1. **You test and you capture.** A model cannot produce a differential pair.
   That comes from you making the request and saving what came back.
2. **The model drafts or tidies the writeup.**
3. **Stamp it:** `bbgate stamp-ai <finding>`. This records `ai_drafted_at`.
4. **You re-run the repro by hand** and capture a `terminal_log` or a
   `screen_recording`.
5. **Gate it.**

Skip step 4 and check_8 fails, so the finding holds no matter how good the
prose got. It costs nothing when you are working honestly. It stops a writeup
nobody has re-checked since a model rewrote it from reaching a triager.

Step 3 is on your honour, and it is the one place the tool takes your word for
something. If you never stamp, check_8 has nothing to compare against and fails
anyway, so the lazy path is still a held finding rather than a false pass.

### Driving it from an agent

`bbgate gate <finding> --json` gives an agent everything it needs to work the
finding without being able to argue with the result:

```json
{"finding": "customer-pii-idor",
 "verdict": "HOLD",
 "failed": ["check_3", "check_4", "check_8"],
 "next_artifact": "capture a differential_pair: A's request against B's object ...",
 "hold_reason": "..."}
```

Trimmed for space: the full object also carries `checks`, every check with its
`id`, `name`, `passed` and `reason`, plus `drop_reason` when the verdict is
DROP.

The agent reads `next_artifact`, asks you to capture that specific thing, and
gates again. Exit codes are `0`, `1` and `2`, so it also works as a plain shell
condition. The verdict is derived from files on every call, which means an
agent cannot reach READY by rewording anything. The only move available is
capturing something that was not there before.

[docs/agent-instructions.md](docs/agent-instructions.md) is a block you can
paste into your agent's instructions file (`CLAUDE.md`, `AGENTS.md`, a system
prompt) so the model stamps after every edit, never runs `package` itself, and
hands capture work back to you. It also has a Claude Code hook that gates every
finding claiming to be ready before the agent is allowed to stop.

One caution that is nothing to do with this tool: think about what you paste
into a model. Findings carry the target's data, and most programs have terms
about where that data goes.

## Commands

| command | what it does |
|---|---|
| `bbgate init [--example]` | create `.bbgate/config.yaml` and `findings/` here, optionally with the worked example |
| `bbgate new <slug> --class <class> --host <host> [--program <p>]` | create a finding skeleton. It starts as a HOLD on purpose |
| `bbgate gate <slug>` | run the nine checks and print each one, the verdict, and what to capture next |
| `bbgate gate --all [--claimed] [--json]` | gate every finding, or only those whose `status` claims they are ready |
| `bbgate package <slug>` | write `<slug>.submission.md` beside the finding. Refuses and writes nothing unless READY |
| `bbgate add-artifact <slug> --type <type> --path <file> [--method ...] [--shows-privileged-data] [--at <iso>]` | copy an evidence file in, hash it, append a manifest row |
| `bbgate set-impact <slug> --position ... --action ... --asset ... [--precondition ...] [--tier ...]` | write the impact statement and the tier it implies |
| `bbgate clean-run <slug> [--from fresh] [--result reproduced] [--deviation ...]` | record a reproduction from a stated starting state |
| `bbgate stamp-ai <slug> [--at <iso>]` | record when a model last edited the writeup |
| `bbgate override-repro <slug> --reason "..."` | clear the pre-existing-state lint on the repro, with the reason stored in the finding |
| `bbgate queue` | regenerate `QUEUE.md` from every finding on disk |
| `bbgate stats [--last 90d]` | which check fails most often, from the gate log |
| `bbgate checks` | the nine checks and what each one wants, in plain words |
| `bbgate classes` | the known vulnerability classes and the bar each has to clear |

Every command runs from anywhere inside the project. The project root is the
directory holding `.bbgate/`, found the way git finds `.git`.

## A finding on disk

```
findings/
  customer-pii-idor.md                  the finding
  customer-pii-idor/
    artifacts/
      manifest.tsv                      one row per evidence file
      ab-differential.har               the evidence itself
      verify.log
  customer-pii-idor.submission.md       written by `package`, only on READY
```

Severity subdirectories (`findings/high/...`) are optional and resolve the
same way. The slug is the filename without `.md`.

### Frontmatter

`bbgate new` writes this skeleton. Every field is read by a check.

```yaml
title: Customer PII readable across accounts via GET /api/v2/customers/{id}
vuln_class: idor                 # a slug from `bbgate classes`. Unknown or empty holds
target_host: api.example.com     # what the scope engine is asked about
program: example-bbp             # matches a key under programs: in config
ai_drafted_at: ""                # set by `stamp-ai`. check_8 compares against it
impact_tier: inferred            # demonstrated | inferred | conditional | theoretical
impact:
  attacker_position: ""          # who you are when you do this
  action: ""                     # what you do
  asset: ""                      # what that gets you
  precondition: ""               # anything unverified the bug depends on. Non-empty forces conditional
repro: []                        # steps someone can follow from a cold start
clean_state_runs: []             # written by `clean-run`
suspected_duplicate: false       # true, or the duplicate's id, holds the finding
repro_override: {}               # written by `override-repro`
```

`status:` is optional. `gate --all --claimed` gates only findings whose status
is `ready-to-submit`, `ready` or `submit`. It is a claim typed by hand, and the
gate exists to contradict it.

`severity:` and `cvss-score:` are optional and copied into the submission
header. The gate does not read them.

### Manifest

`artifacts/manifest.tsv` is tab-separated with a header row. `add-artifact`
writes it, so you rarely touch it by hand.

```
type	path	sha256	captured_at	capture_method	shows_privileged_data
differential_pair	ab-differential.har	3f0a...	2026-08-24T19:02:11	burp	false
terminal_log	verify.log	9c41...	2026-08-24T19:10:40	asciinema	false
```

## Evidence types

| type | what it shows | how people usually make one |
|---|---|---|
| `differential_pair` | you, as user A, acting on user B's object, next to the same request being refused | two saved request/response pairs from Burp, Caido or curl. Save them as a HAR or a single text file, both halves together |
| `oob_callback` | the request came from the target's infrastructure, not yours | the hit log from interactsh, Burp Collaborator or your own listener, with the source IP and the payload id |
| `poc_html` | your payload ran on a real origin and captured a value | the HTML you served, plus the captured value (cookie, token, response body) in the same file or next to it |
| `forged_token` | a credential you minted was accepted for a privileged action | the token you signed and the privileged response the server returned for it |
| `http_exchange` | a request and its response. Counts only when the row is flagged `shows_privileged_data` | one saved request/response holding data your account has no route to |
| `terminal_log` | a person re-ran the repro | an asciinema cast, a `script` capture, or a plain copy of the terminal session |
| `screen_recording` | a person re-ran the repro | OBS, a phone pointed at the screen, anything with a timestamp |
| `screenshot` | nothing | it is recorded, hashed and ignored by every check |

`terminal_log` and `screen_recording` are verification artifacts, used by
check_8. They do not evidence impact. The first five evidence impact and are
used by check_3, and the first and fourth are also the two-principal proof
check_4 wants for access-control classes.

A screenshot counts for nothing, which is the part people argue with. It shows
a rendering of a response you already had: no request, no second principal, no
negative control, nothing tying the image to a position you should not have
held. Anyone can screenshot their own account and crop the username out. If you
disagree, `impact_artifact_types` is config and it is your call.

## The nine checks

`bbgate checks` prints this table from inside a project.

| id | name | passes when | in plain words |
|---|---|---|---|
| check_1 | impact_demonstrated | effective tier is demonstrated | an evidence file shows the consequence, not just the bug |
| check_2 | statement_complete | impact.attacker_position, action and asset all non-empty | you said who the attacker is, what they do, and what they get |
| check_3 | impact_artifact_exists | at least one artifact evidences impact | at least one evidence file proves the impact. A screenshot does not count |
| check_4 | differential_for_authz | if class is an authz class, a differential_pair or forged_token exists | for IDOR and friends, one user reaching another's data next to the same request refused |
| check_5 | clean_state | a run with from_state=fresh, result=reproduced, deviations=[] | someone reproduced it from a fresh account, following the written steps exactly |
| check_6 | repro_self_contained | repro non-empty and no pre-existing-state lint hit | the steps stand on their own, nothing relies on a session left over from earlier testing |
| check_7 | scope_clear | scope ok, class not excluded, not a suspected duplicate | the host is in scope, the program pays for this class, and it is not flagged as a dupe |
| check_8 | human_verified | a verification artifact exists and, if `ai_drafted_at` is set, postdates it | a person re-ran it and recorded that after the last model edit |
| check_9 | confidence_floor | effective tier is demonstrated | same bar as check_1, separately configurable |

`check_1`, `check_3`, `check_5` and `check_8` are load bearing: failing one of
those holds the finding on its own. The rest are advisory, and which set is load
bearing is a config key. An unset or unknown `vuln_class` fails a guard ahead of
everything class-dependent, so mislabelling is not a way around check_4.

## Impact tiers

| tier | meaning | routes to |
|---|---|---|
| demonstrated | an artifact shows the consequence | the only tier that reaches READY |
| inferred | believed, artifact missing | HOLD |
| conditional | depends on an unverified precondition | HOLD |
| theoretical | class present, consequence unproven | DROP |

A non-empty `impact.precondition` forces the tier to `conditional` whatever you
declared, since a finding cannot be demonstrated while it names a precondition
nobody verified. If it does hold, verify it and empty the field.

## Configuration

`.bbgate/config.yaml` marks the project root the way `.git` does. Every key is
optional, so a two-line file is valid.

```yaml
findings_dir: findings          # where findings live, severity subdirs optional
queue_path: QUEUE.md            # where `bbgate queue` writes the owed-work list
log_path: .bbgate/gate-log.tsv  # append-only, one row per gate call
classes: ""                     # your own classes.yaml, empty uses the shipped one
rubric: ""                      # your own rubric.yaml, empty uses the shipped one
load_bearing: [check_1, check_3, check_5, check_8]
authz_classes: [idor, bola, bfla, oauth, jwt]
impact_artifact_types: [differential_pair, oob_callback, poc_html, forged_token]
verification_artifact_types: [terminal_log, screen_recording]
scope:
  mode: none                    # none | command
  command: ""                   # e.g. "myscope {host}", prints verdict JSON on stdout
programs:
  example-bbp:
    excludes: [clickjacking]    # classes this program will not pay for, routes to DROP
```

The rubric says what each class looks like when it is only a condition, what
clears it, and which artifact to go and capture. If your programs draw the line
elsewhere, change it. Class slugs are stable identifiers, so renaming one
orphans the findings that reference it. Program names match case-insensitively.

Scope defaults to permissive: with `mode: none` every host answers ok and the
output says so rather than implying a check happened. To wire in your own, set
`mode: command` with a `{host}` template. The command runs without a shell and
must print JSON:

```json
{"host": "api.example.com", "verdict": "ok", "reasons": ["matched program scope"]}
```

`block` drops the finding, `warn` and `unknown` hold it. A timeout, bad JSON or
a missing binary answers `unknown`, so an engine that broke cannot pass a
finding by failing.

## Exit codes and CI

`0` READY, `1` HOLD, `2` DROP or a usage error. `package` writes nothing and
exits non-zero on anything but READY.

In CI, gate the right set. `gate --all` fails on any HOLD, and most findings in
a working repo are legitimately unfinished, so that build stays red forever and
people learn to ignore it. `gate --all --claimed` gates only findings whose
frontmatter `status` says they are sendable, which turns the build red on a
contradiction instead of on work in progress.

```yaml
- run: pip install .
- run: bbgate gate --all --claimed
```

The case it catches: a finding passes, gets marked ready, then someone runs the
writeup back through a model to tidy it. The verification now predates the
draft, check_8 fails, and the build goes red before anybody sends it.

## What it does not do

It trusts your manifest. Record a screenshot as a `differential_pair` and it
believes you; it checks that evidence of a kind was captured, not that the bytes
say what you claim. It is a discipline tool, not a lie detector.

It never touches a target. No check opens a socket, and the only subprocess it
runs is the scope command you configured.

It does not find bugs, does not rate severity and does not talk to any bug
bounty platform. Use your platform's rubric for severity and paste the
submission file in yourself.

The rubric is one person's judgment about what proof looks like per class, and
yours may land elsewhere. That is why the rubric, the class list and the
artifact type lists are all config.

This is 0.1.0. The check ids and config keys are what I would least like to
change, but they are not frozen.

## Development

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

## License

MIT. Copyright 2026 Sonny Croco.
