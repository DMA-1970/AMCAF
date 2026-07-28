# AMCAF — working constraints

This repository is the artefact for an MSc dissertation submitting in days. The
dissertation quotes specific scores from this codebase and a run ledger is
being submitted as evidence for them. Treat reproducibility of existing
numbers as sacrosanct.

## Hard constraints

- Do **not** modify anything in `src/engine/` in a way that changes evaluation
  output. No new controls, no widened port sets, no altered pass/fail logic.
  Every currently-reported score must remain reproducible byte-for-byte.
- Do **not** touch any `.docx` or `.xlsx` files.
- Small, atomic commits with descriptive messages. Never amend, rebase,
  squash, or force-push — the linear, timestamped git history is part of the
  academic integrity record.
- If any fix would change a reported score, **stop and ask the user first**
  rather than committing it.
