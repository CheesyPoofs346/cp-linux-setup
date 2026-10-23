# Harder-image generalization implementation plan

**Goal:** Correct or reject synthetic requirements and evidence variations that SH7 did not exercise.

**Architecture:** Keep the deterministic parser and forensic solver. Preserve HTML section boundaries, reject conflicting roles and unrecognized account-role instructions, and parse complete explicit service/account lists. Ambiguous evidence remains a review result. A broad rewrite or more aggressive guesses would enlarge the unverified behavior, so neither is part of this pass.

**Stack:** Existing Python standard library and Bash; no new dependencies or runtime AI.

## Tasks

1. Add contract tests in tests/test_generalization.py for renamed accounts, comma/semicolon service lists, unknown section boundaries, conflicting roles, unsupported role changes, and multiple forensic candidates. Run them against the current source and record failures.
2. Fix only the reproduced extraction failures in lib/readme_extract.py. Preserve existing SH7 and prose fixtures; validators must reject ambiguity. Run the new tests and the existing README/forensic suites.
3. Check forensic ambiguity and explicit path handling with temporary filesystem fixtures. Fix reproduced wrong-answer behavior in lib/forensics_det.py; never fill an answer merely to avoid a pause.
4. Run the full non-root suite and the targeted root safety suite. Revalidate SH7 parsing and all existing forensic answers without resetting or destroying the saved practice evidence. Request a focused source review, commit locally, and refresh the output archive/report with exact coverage limits.

The user's existing request authorizes this practice-project polish and autonomous continuation. No new competition content is needed for these synthetic cases.
