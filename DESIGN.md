---
name: diffuzz-btc
description: Differential-fuzzing evidence set in the Swiss International Typographic Style.
colors:
  plane: "#f9f9f7"
  surface: "#fcfcfb"
  ink: "#0b0b0b"
  ink-2: "#52514e"
  rule: "#e1e0d9"
  rule-strong: "#c3c2b7"
  mast: "#0b0b0b"
  mast-ink: "#fcfcfb"
  mast-ink-2: "#c3c2b7"
  agree-ok: "#2b2a28"
  agree-fail: "#8f8d85"
  known: "#dedcd5"
  known-hatch: "#9b998f"
  critical: "#d03b3b"
  impl-1: "#2a78d6"
  impl-2: "#eb6834"
  impl-3: "#1baf7a"
  impl-4: "#eda100"
  impl-5: "#e87ba4"
  impl-x: "#9b998f"
  plane-dark: "#0d0d0d"
  surface-dark: "#1a1a19"
  ink-dark: "#f0efec"
  ink-2-dark: "#c3c2b7"
  rule-dark: "#2c2c2a"
  rule-strong-dark: "#383835"
  mast-dark: "#000000"
  mast-ink-dark: "#f0efec"
  mast-ink-2-dark: "#a8a79e"
  agree-ok-dark: "#e4e3de"
  agree-fail-dark: "#6f6e68"
  known-dark: "#3a3a37"
  known-hatch-dark: "#8a897f"
  impl-1-dark: "#3987e5"
  impl-2-dark: "#d95926"
  impl-3-dark: "#199e70"
  impl-4-dark: "#c98500"
  impl-5-dark: "#d55181"
typography:
  display:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "clamp(38px, 5.6vw, 80px)"
    fontWeight: 700
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "24px"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "-0.02em"
  lede:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.5
  figure:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 700
    lineHeight: 1.5
    fontFeature: "tnum"
  title:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 700
    lineHeight: 1.5
  body:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
  axis:
    fontFamily: "\"Helvetica Neue\", Helvetica, \"Segoe UI\", Arial, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    fontFeature: "tnum"
  mono:
    fontFamily: "ui-monospace, \"Cascadia Mono\", \"SF Mono\", Consolas, monospace"
    fontSize: "0.86em"
rounded:
  none: "0px"
  mark: "2px"
  tip: "3px"
  bar-end: "4px"
spacing:
  hair: "1px"
  seg-gap: "2px"
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "20px"
  gutter-compact: "20px"
  column-gap: "24px"
  xl: "32px"
  gutter: "40px"
  section: "48px"
  statement: "56px"
  channel: "132px"
  max-width: "1280px"
components:
  masthead:
    backgroundColor: "{colors.mast}"
    textColor: "{colors.mast-ink}"
    height: "64px"
  theme-toggle:
    backgroundColor: "transparent"
    textColor: "{colors.mast-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.mark}"
    padding: "4px 10px"
  theme-toggle-hover:
    backgroundColor: "{colors.mast-ink}"
    textColor: "{colors.mast}"
  table-header:
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    padding: "0 12px 8px 0"
  table-cell:
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    padding: "12px 12px 12px 0"
  channel-cell:
    textColor: "{colors.ink}"
    typography: "{typography.figure}"
    width: "{spacing.channel}"
    padding: "12px 0 12px 16px"
  channel-cell-critical:
    textColor: "{colors.critical}"
    typography: "{typography.figure}"
    width: "{spacing.channel}"
  tab:
    textColor: "{colors.ink-2}"
    padding: "10px 16px 9px"
  tab-selected:
    textColor: "{colors.ink}"
    padding: "10px 16px 9px"
  segment-bar:
    height: "8px"
    rounded: "{rounded.bar-end}"
  tooltip:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.tip}"
    padding: "8px 10px"
  repro-block:
    backgroundColor: "{colors.plane}"
    typography: "{typography.mono}"
    rounded: "{rounded.none}"
    padding: "18px 20px"
---

# Design System: diffuzz-btc

## Overview

**Creative North Star: "The Evidence Poster"**

A run's results set as a Swiss International Typographic Style poster: one modular 12-column grid, flush-left asymmetric type, and every figure in a column of fixed measure. The page is read, not operated. It opens on a single black masthead field and a display-scale statement ("N cases. Unexplained divergences 0."), then descends through ruled tables and bars where columns never move, only their values.

Density is that of a data sheet: hairline-ruled rows, tabular numerals, greys for everything that agrees. Colour is withheld so that it means something. It has exactly two jobs, implementation identity and the critical state, and nothing decorative competes with them. Depth is absent; structure comes from rules, measure and weight.

The world refuses the KPI-card mosaic with donuts and the dark neon metrics board. It is a single self-contained file with no network requests at view time, so the type is a system stack led by Helvetica Neue and no webfont is ever downloaded.

**Key Characteristics:**
- One 12-column grid, 1280px measure, 40px gutters (20px under 900px).
- One black masthead field; everything else is near-white ground and black ink.
- Colour for implementation identity and the critical state only.
- Hairline rules, no container radius, no cards, no decorative shadows or gradients.
- The reserved "Unexplained" channel: the rightmost column of every table, 132px, ruled off on the left.
- One authored motion: verdict bars rule in left to right, once.

## Colors

A near-neutral warm-grey paper-and-ink palette with five categorical identity hues and one red that only appears when something is wrong.

### Primary
- **Signal Red** (critical): the critical state. Used only when an unexplained count is non-zero: the channel figure, the statement's ledger total and the "Unexplained" bar segment. Always paired with the warning-triangle icon in table cells; never used for emphasis, links or headings. The same value serves light, dark and print.

### Secondary (implementation identity)
Categorical slots in a fixed order, assigned by name, never by position in a given run: **slot 1 Core Blue** (impl-1, Bitcoin Core), **slot 2 Signal Orange** (impl-2, btcd), **slot 3 Aqua Green** (impl-3, NBitcoin), **slot 4 Ochre Yellow** (impl-4, libbitcoin), **slot 5 Rose** (impl-5, rust-bitcoin). Any unlisted implementation falls to **Neutral Slot Grey** (impl-x). Each slot has a separate dark-mode step (the `-dark` tokens) from the same validated palette; print forces the light steps. Light-mode aqua and yellow fall below text contrast on the paper, so an identity colour is never the only carrier: swatches sit next to a visible implementation name (keys, bars, corpus rows, sighash headers).

### Neutral
- **Paper Plane** (plane): the page ground outside the body, and the reproduction block's fill.
- **Card-less Surface** (surface): the body ground; also the text colour inside the tooltip and the knockout stroke in the critical icon.
- **Ink** (ink): text, header rules, the channel rule, the statement rule; also the focus ring colour.
- **Second Ink** (ink-2): secondary text, ledes, notes, stamps, axis labels, inactive tabs.
- **Hairline** (rule): row rules and key-list rules; the row hover tint mixes it at 45%.
- **Strong Hairline** (rule-strong): the masthead's bottom rule, empty identity-strip outlines, scrollbar thumb.
- **Masthead Black** (mast), **Masthead Ink** (mast-ink), **Masthead Grey** (mast-ink-2): the one black field and its two text levels.
- **Agreement Black** (agree-ok) and **Agreement Grey** (agree-fail): "all agree: accept" and "all agree: reject" segments. Agreement is never coloured.
- **Allowlist Grey** (known) with **Hatch Grey** (known-hatch): the allowlisted part, filled and hatched. Text selection uses the allowlist grey.

### Named Rules
**The Two Jobs Rule.** Colour identifies an implementation or flags the critical state. Nothing else on the page is coloured: not headings, not links, not agreement, not allowlisted counts.

**The Fixed Slot Rule.** An implementation keeps the same slot on every chart in every report (core, btcd, nbitcoin, libbitcoin, rust-bitcoin = slots 1 to 5). Never reassign slots by sort order or by which implementations a run used.

**The Red Means Non-Zero Rule.** Signal Red appears only when a count is greater than zero, and always with an icon or a visible label. A zero is set in ink with the circled check.

## Typography

**Display Font:** Helvetica Neue (with Helvetica, Segoe UI, Arial, system-ui, sans-serif)
**Body Font:** the same stack
**Label/Mono Font:** ui-monospace (with Cascadia Mono, SF Mono, Consolas, monospace) for seeds, versions, commands and output-type keys

**Character:** One neo-grotesque family in two weights, 400 and 700, doing all the work through size and weight contrast, as the Swiss style prescribes. The system stack is a product constraint (offline single file), not a placeholder.

### Hierarchy
- **Display** (700, clamp(38px, 5.6vw, 80px), 1.02, -0.035em): the statement only. Balanced wrap; proportional numerals so the large count sets tight.
- **Headline** (700, 24px, 1.15, -0.02em): section heads, in columns 1 to 4 beside a column 5 to 11 description.
- **Lede** (400, 17px, 1.5): the statement's supporting paragraph, max 62ch, second ink.
- **Figure** (700, 17px): the channel figure in every table.
- **Title** (700, 15px): sub-heads within a two-column section.
- **Body** (400, 15px, 1.5): table cells and section descriptions (max 68ch). Tables use tabular numerals throughout.
- **Label** (13px): table headers (700, ink), stamps, legends, notes (max 90ch), secondary cells, tooltip text, footer.
- **Axis** (12px, tabular): chart axis ticks and the compact-screen stamp.

### Named Rules
**The Tabular Column Rule.** Every number in a table, bar row, axis or tooltip uses tabular numerals so digits align down the column. Only the display statement uses proportional numerals.

**The Two Weights Rule.** 400 and 700 only. No italics, no uppercase labels, no tracking on small text.

## Layout

A 12-column grid (`repeat(12, minmax(0, 1fr))`, 24px column gap) inside a 1280px maximum width with 40px side gutters, 20px at 900px and below. The masthead is 64px minimum: wordmark in columns 1 to 3, section nav in 4 to 9, stamp and theme toggle right-aligned in 10 to 12. The statement spans all twelve columns, the lede takes columns 1 to 7 and the implementation keys columns 9 to 12. Section heads put the headline in columns 1 to 4 and the description in 5 to 11, baseline-aligned.

Vertical rhythm: statement 56px above, 48px below, closed by an ink rule; sections 48px above, 8px below; 20px between a section head and its content; footer 56px above. Two-up sections split 5fr / 7fr with a 48px gap.

Under 900px: everything stacks to full width; the nav moves to its own row as a horizontally scrolling strip with an edge fade; the stamp moves under it; wide tables scroll inside their container at a minimum of 860px and the channel column becomes sticky on the right edge so it never scrolls away; the p99 column is dropped from throughput.

Print drops the nav, the theme toggle, the tabs and the tooltip, turns the masthead into an ink-ruled header on white, forces light colour steps with exact colour printing, disables the reveal and shows each tabbed section's run note.

### Named Rules
**The Reserved Channel Rule.** The "Unexplained" column is always the rightmost column of every table, always 132px, right-aligned, ruled off on its left with an ink hairline. The statement's ledger total sits in a column of at least the same width with the same rule, so the headline zero reads as the top of that channel.

**The Columns Never Move Rule.** Columns keep their position and measure; only values change. Identity strips keep an empty outlined slot for an absent implementation rather than closing the gap.

## Elevation & Depth

Flat. Depth is carried by rules, weight and the single black masthead field, never by shadows or layered surfaces. The one shadow belongs to the floating tooltip, which genuinely sits above the page.

### Shadow Vocabulary
- **Tooltip lift** (`box-shadow: 0 6px 20px rgba(0,0,0,0.18)`): the pointer/focus tooltip only.

### Named Rules
**The No-Lift Rule.** Tables, bars, keys and the reproduction block sit on the page with no shadow. The tooltip is the only element allowed one.

## Shapes

Square containers, hairline rules. The `--hair` token is 1px, dropping to 0.5px at 2dppx and above so rules stay one device pixel. Tables, sections, the statement and the reproduction block have no radius and no border box; they are separated by a top or bottom rule only (ink for structure, hairline grey for rows). Small radii are reserved for marks: identity swatches and the theme toggle (2px), the tooltip (3px), and the outer ends of bars (4px).

Segmented part-to-whole bars are 8px high with 2px gaps between parts and a 2px minimum part width; only the first and last parts round their outer ends. Throughput bars are 18px high, coverage bars 10px; both are flush at the axis and round only the leading end. Allowlisted parts are hatched: a 1px hatch-grey line every 4px at 135 degrees over the allowlist grey, so they read without colour. In forced-colors mode every bar, swatch and legend mark gets a hairline CanvasText border.

## Components

### Masthead
The one black field. Bold 17px wordmark with a regular grey qualifier, a grey 14px section nav that brightens on hover, a grey 13px stamp with generation date and machine, and the theme toggle. A strong hairline closes it.

### Theme Toggle
- **Shape:** hairline outline in masthead grey, 2px radius, 4px 10px padding, 13px label naming the theme it switches to.
- **Hover:** inverts to masthead ink on black text.
- **State:** `aria-pressed` reflects dark mode; the choice persists locally.

### Tables
- **Header:** 13px bold ink, bottom-aligned, ink hairline below; sortable headers are bare buttons with an arrow that appears only on the sorted column.
- **Rows:** 12px vertical padding, grey hairline below, hover tints the row with the hairline grey at 45%.
- **Numbers:** right-aligned, tabular; secondary detail in 13px second ink beneath or beside.

### Unexplained Channel (signature)
The rightmost cell of every table, 132px, ink rule on its left, 16px left padding, figure type. Zero: ink with a circled-check icon. Non-zero: Signal Red with a warning-triangle icon. Both icons are inline 14px SVGs.

### Segmented Verdict Bar
8px part-to-whole bar, parts in order: agree accept (agreement black), agree reject (agreement grey), allowlisted (hatched), unexplained (red, only if present). Focusable, with an `aria-label` and a tooltip listing each part's count and share. Takes 30% of the table width, at least 120px. Accompanied by a legend of 18 by 8px marks.

### Implementation Keys and Identity Strip
Keys: a ruled list of 10px swatches, bold implementation name and a mono version beneath. Strip: a row of 8px swatches, one fixed slot per implementation, outlined when absent, followed by the count.

### Run Tabs
Underline tabs on an ink hairline: 14px second ink, selected becomes ink, bold, with a 3px ink underline. Arrow keys, Home and End move between runs.

### Horizontal Bars
A grid of name, track, value columns with bold 13px headers on an ink rule and hairline-ruled cells. Throughput bars use the implementation's slot colour; coverage bars are agreement black. A three-tick tabular axis sits below.

### Tooltip
Ink fill, surface text, 13px, 3px radius, max 280px, first line bold as its title. Appears on pointer or focus, closes on Escape, fades and rises 4px over 120ms (expo-out).

### Reproduction Block
Mono 13px commands on the plane fill under an ink rule, 18px 20px padding, 1.6 line height, scrolling horizontally.

### Motion
One authored moment: when the run table first enters the viewport (30% visible), its verdict bars rule in from the left by clip-path, 700ms on `cubic-bezier(0.16, 1, 0.3, 1)`, rows staggered 0, 60, 120 and 180ms. It plays once. Under reduced motion, without IntersectionObserver and in print, the bars are simply present. The tooltip's 120ms fade is a state transition, not a second moment.

## Do's and Don'ts

### Do:
- **Do** place every new figure on the 12-column grid within the 1280px measure.
- **Do** end every table with the 132px "Unexplained" channel, ruled off on the left.
- **Do** colour an implementation only with its fixed slot (core 1, btcd 2, nbitcoin 3, libbitcoin 4, rust-bitcoin 5) and always beside its visible name.
- **Do** show Signal Red only for a non-zero count, always with an icon or label.
- **Do** set agreement in agreement black and grey, and hatch allowlisted parts at 135 degrees.
- **Do** draw structure with the `--hair` token: ink rules for structure, grey hairlines for rows.
- **Do** use tabular numerals in every column of figures.
- **Do** keep segmented bars 8px high with 2px gaps.

### Don't:
- **Don't** use cards, boxed panels or radius on containers.
- **Don't** add shadows to anything but the tooltip.
- **Don't** use decorative gradients; the only gradient functions are the allowlist hatch and the mobile nav's scroll fade.
- **Don't** colour headings, links, agreement or allowlisted counts.
- **Don't** add a second authored animation or replay the bar reveal.
- **Don't** load webfonts, scripts or any network resource; the file must work offline.
- **Don't** move the channel column, or reorder implementation slots by run.
