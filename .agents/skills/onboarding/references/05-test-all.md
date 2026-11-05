# Step 5 — Complete all local gates

Prerequisites: run `python3 .agents/skills/onboarding/scripts/check.py 5`.
Confirm HCP login and registry access from step 2; only the real module/build
gates prove they work. Read [scope and result semantics](../../../../docs/testing.md#exhaustive-local-validation)
and current Makefile/scripts/test_all.py before execution.

Inspect git status. Explain that this is lengthy, downloads dependencies, creates
local images/emulated resources, runs both architectures plus Lambda builds,
and may rewrite files through pre-commit. Ask approval and resolve protection of
unrelated edits; **halt until the user responds**. Then run `make test-all`
from the root with the project tools on PATH. Do not replace it with make check,
a subset, an old report, or a run launched in the background and not observed to finish.

Record the revision, relevant working-tree changes, exact command, exit status,
private log directory, summary.json and JUnit path. Inspect every gate. Preserve
full failure logs privately; share only redacted diagnostics. Fix genuine failures
with permission, or ask the user for missing access/tools and halt. After repairs,
rerun the full aggregate to completion; an earlier failure remains a failed run.

Completion: observed terminal exit zero with no FAIL/blocked gates. Report every
INCOMPLETE gate and skip count as unverified, even with exit zero. The optional
--require-complete policy can remain nonzero because of documented emulator
limits; do not claim fully unskipped coverage or change executor flags to fake it.
If hooks rewrite files, review the diff and rerun until the checked state is clear.

Offer [non-volume-deleting shutdown](../../../../docs/runbooks/contributor-local-setup.md#4-run-all-local-tests-and-checks)
after dependent tests finish; ask before teardown and halt for approval.
Do not use make localstack-down unless volume deletion was requested.
Next: step 6, or report local onboarding complete with live verification pending.
