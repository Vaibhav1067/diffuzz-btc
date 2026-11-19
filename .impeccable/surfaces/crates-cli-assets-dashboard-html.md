---
version: 1
slug: "crates-cli-assets-dashboard-html"
primary_target: "crates/cli/assets/dashboard.html"
related_targets: []
---

# Results dashboard (`diffuzz dashboard`)

Scope: one generated, self-contained HTML file; visitor mode **Operate** (scan evidence).
Audience: protocol engineers and reviewers checking scale, method and the divergence status.
Constraint: no private finding, case content or private allowlist id may reach the page.
Unresolved: hosting (CI artifact vs docs) left open.

## Direction contract

THESIS: A run's evidence set in the Swiss International Typographic Style: one modular grid,
asymmetric flush-left type, every figure in a column of fixed measure. Refuses the KPI-card
mosaic with donuts and the dark neon metrics board.

OWN-WORLD: Near-white ground, black ink, a full-width black masthead field. Colour has exactly
two jobs: the four implementations (categorical slots 1-4, identical in every chart) and the
critical state (red, only when non-zero). Agreement is set in black and greys. One-pixel
hairlines, no radius on containers, tabular numerals in columns.

STORY: The reader learns how many cases ran across which implementations and versions, sees
that unexplained divergences are zero, then drills into runs, speed, generator coverage,
corpus and sighash results, each traceable to a seed and command.

FIRST VIEWPORT: Black masthead with product name, generation date and machine. Below, a
flush-left statement at display scale: "81,768,448 cases. 0 unexplained divergences." with
the zero in the reserved divergence column. Right column: four implementation keys with
versions. Then the run table begins.

FORM: Swiss data-graphics poster, candidate 6 of 7 (seed:5c15bcd18e04f40b). Signature move:
the reserved divergence column, fixed position in every table, read top to bottom as one
channel. Raises: columns never move, only values (split-flap); 1-device-pixel rules
(centre-rail); one colour per job (terminal wayfinding); fixed implementation colour
language (orienteering).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
