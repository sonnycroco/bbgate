# Running bbgate under an agent

Two things to paste. The first is an instructions block for whatever model
drafts your reports. The second is a hook for Claude Code that refuses to let a
session end while a finding claims to be ready and is not.

Both assume `bbgate` is on PATH and the working directory is inside a bbgate
project (a directory with `.bbgate/` at or above it).

## The instructions block

Paste this into the file your agent reads at startup: `CLAUDE.md`, `AGENTS.md`,
`.cursorrules`, a system prompt. Edit the paths to match your layout.

```markdown
## Bug bounty findings and bbgate

Findings live in `findings/<slug>.md`. Evidence lives beside each one in
`findings/<slug>/artifacts/`. `bbgate` decides whether a finding can be sent,
and its verdict is computed from those files every time. You cannot change the
verdict by editing prose.

Rules:

1. After any edit you make to a finding's body or frontmatter, run
   `bbgate stamp-ai <slug>`. Every time, no exceptions. This records that a
   model touched the writeup and it is what lets the human's re-run be trusted.
2. Never run `bbgate package`. A person runs that after reading the finding.
3. Never create, edit or delete anything under `findings/<slug>/artifacts/`,
   and never write to `manifest.tsv`. Evidence is captured by a person.
4. Never set `impact_tier: demonstrated` or `status: ready-to-submit` yourself.
   Those are claims a person makes after the gate agrees.
5. To find out what a finding needs, run `bbgate gate <slug> --json` and read
   `next_artifact` and `failed`. Tell the human exactly what to capture, in
   the words the tool used. Do not paraphrase the artifact type.
6. When `verdict` is `HOLD` and `next_artifact` is empty, the problem is a
   field, not a file: read `hold_reason` and fix the frontmatter, then stamp.
7. When `verdict` is `DROP`, stop working on the finding and report
   `drop_reason` to the human. Do not try to reword it into a HOLD.
8. `bbgate checks` explains every check in plain words. Use it before asking.
```

Rule 1 is the one that matters. A model that stamps after every edit produces
findings the gate can reason about. A model that forgets to stamp produces
findings that hold on check_8 until a person notices, which is the safe
failure, but it wastes their time.

## The Claude Code hook

Claude Code can run a command when the agent tries to end its turn, and a
non-zero exit with a specific code sends the output back to the model instead
of letting it stop. Add this to `.claude/settings.json` in the project:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bbgate gate --all --claimed >&2 || exit 2"
          }
        ]
      }
    ]
  }
}
```

What it does: every time the agent is about to stop, every finding whose
`status` says it is ready gets gated. If any of them is not READY, the hook
exits 2, Claude Code blocks the stop and hands the gate output to the model.
The model then has the failing check and the next artifact in front of it and
can tell you what to capture. Findings that do not claim to be ready are left
alone, so work in progress never trips the hook.

The hook never makes the model do the capturing. It cannot: the artifact has to
come from a person running the request. What the hook removes is the case where
a session ends with a finding marked ready that nobody has re-checked since the
model last edited it.

## Why the agent cannot cheat

Every path an agent might take to READY goes through a file it is told not to
touch, and the gate does not trust the files it is allowed to touch:

- Rewording the impact statement changes nothing. check_3 looks at the
  manifest, not the prose.
- Setting `impact_tier: demonstrated` changes nothing on its own. check_3 and
  check_4 still need the artifact rows.
- Setting `status: ready-to-submit` changes nothing except which findings CI
  gates. It is the claim the gate exists to contradict.
- Editing without stamping leaves the verification older than the text, which
  is what check_8 is for. Stamping honestly and then not re-verifying gives the
  same result. Either way the finding holds.
- Writing a manifest row by hand is the one way to lie to it, and that is a
  person's decision, not a model's. The instructions above say not to. If you
  want it enforced, make `findings/*/artifacts/` read-only to the agent's
  user, or keep evidence in a directory the agent has no permission to write.

The gate does not read artifact bytes. It checks that evidence of the right
kind was recorded, with a hash and a time, by someone who chose to record it.
That is the line: the tool verifies the workflow, the person verifies the bug.
