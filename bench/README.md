# Local benchmark workspace

This directory holds machine-local benchmark inputs and generated outputs. It
is excluded from Git except for this index so measurements, captures and local
configuration do not get committed by accident.

## Common contents

- `runs/` and `matrix/`: generated output from repeated benchmark runs.
- `clients/`: local client builds and related validation artifacts.
- Dated folders: one-off audits, release checks, incident captures and field
  measurements.
- Root scripts and rollout notes: local helpers and working records.

Published procedures and summaries belong in `scripts/` and
`docs/benchmarks/`. Before moving or deleting a local folder, confirm that no
capture is active and that any result worth keeping is summarized in the
tracked documentation. Age alone is not a safe deletion rule for diagnostics.
