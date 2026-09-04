# The worked example

`customer-pii-idor.md` is a finished IDOR writeup against a fictional host. It is
deliberately one step short of submittable: the impact statement, the tier, the
repro and the clean-state run are all filled in, but no artifact has been
recorded, so the gate holds it on check_3 (no impact artifact), check_4 (an authz
class with no two-principal proof) and check_8 (no manual verification after the
draft stamp).

That is the normal shape of a finding you are sitting on. The writeup is done and
the evidence is not, which is exactly the state the gate exists to name.

Walk it to READY:

    bbgate gate customer-pii-idor
    # HOLD. Prints the failing checks and the differential_pair to go capture.

    bbgate add-artifact customer-pii-idor \
        --type differential_pair --path ~/captures/ab-differential.har \
        --method "burp, A's token against B's id plus the 403 control"

    bbgate add-artifact customer-pii-idor \
        --type terminal_log --path ~/captures/verify.log \
        --method "asciinema, full repro re-run by hand"

    bbgate gate customer-pii-idor
    # READY, exit 0.

    bbgate package customer-pii-idor
    # Writes customer-pii-idor.submission.md.

Both `--path` arguments are files you supply. The gate records an artifact's
type, sha256 and capture time, and never reads its contents, so any file works
for a dry run. `ai_drafted_at` is already set to a time in the past, which is why
the two captures (stamped now) satisfy check_8. Delete this example whenever you
like, it is a normal finding directory with nothing special about it.
