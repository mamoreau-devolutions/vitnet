---
name: vitnet bounded explorer
description: A local measurement workbench for navigating size evidence.
colors:
  bg: "#f5f6f7"
  panel: "#ffffff"
  ink: "#202b34"
  muted: "#596671"
  rule: "#d8dee3"
  accent: "#1e6178"
  accent-soft: "#edf5f7"
  warning: "#755017"
  warning-bg: "#fff8e8"
  error: "#953132"
  error-bg: "#fff0f0"
  bar: "#4b7b8d"
  bar-other: "#b8c1c8"
typography:
  headline:
    fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "clamp(23px, 2.6vw, 32px)"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.035em"
  title:
    fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "18px"
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif'
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
  identity:
    fontFamily: "ui-monospace, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  control: "4px"
  panel: "5px"
  badge: "20px"
spacing:
  tight: "8px"
  regular: "12px"
  section: "16px"
  page: "24px"
components:
  button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "5px 9px"
  button-hover:
    backgroundColor: "{colors.accent-soft}"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "20px"
---

# Design System: vitnet bounded explorer

## Overview

**Creative North Star: "Measurement workbench"**

This records the shipped explorer, not a new visual identity proposal. The
surface uses restrained system typography, native controls, quiet rules and
compact evidence tables. Measurements lead; the inspector explains a single
selection without creating an accumulating history.

Product truth constrains presentation: ownership, emission and retention must
remain distinct. Unknown measurements and partial results are visible states,
not decorative zeroes.

**Key Characteristics:**
- Dense, readable measurement tables with tabular numeric alignment.
- Independent investigation and evidence-inspector panes.
- Bounded diagrams with accessible text equivalents.
- Local assets, light/dark system themes and visible keyboard focus.

## Colors

The default palette combines cool neutral surfaces with a restrained blue-teal
accent. The frontmatter records the light-theme primitives; the shipped
stylesheet also supplies system-dark overrides.

Accent identifies navigation, selectable evidence and focus. Bar fills measure
within a labelled root; `bar-other` marks unshown remainder, not an inferred
owner. Warning/error palettes communicate uncertainty and failures. Neither
color nor node size encodes a confidence claim on its own.

**The Labelled Budget Rule.** Color never substitutes for the stream, byte
measurement, evidence status or partial-result explanation.

## Typography

System UI fonts carry headings, controls and prose. Producer identities and
structured evidence use the platform monospace stack. Numeric budgets and
table cells use tabular figures. Long identities wrap or show explicitly
bounded previews rather than widening the document.

The hierarchy is compact: one report headline, 18px pane titles, 14px
subheadings/body, and 12px tables/notes. Table headings and generation
annotations use 11px. There is no decorative display face or eyebrow layer.
Icicle labels remain readable on narrow layouts; small white labels on the
default bar fill have a measured 4.649:1 contrast ratio.

## Layout

The main container is at most 1600px wide, with 24px page padding. The workspace
uses a `1.7fr / 1fr` grid; its inspector has a 320px minimum and is sticky on
wide screens. A 16px gap separates independent panes.

At 950px the panes stack and the inspector stops being sticky. At 600px the
page uses `16px 10px` padding, pane padding becomes 14px, and budget metrics
wrap into two columns. The navigation strip scrolls horizontally without
widening the document.

Table containers scroll independently with a 480px height cap. Pages retain
at most 100 rows per table. Chart/graph limits are rendering contracts, not a
reason to make the document infinitely tall or to shrink labels to fit.

## Elevation & Depth

Surfaces are flat. Background tones, one-pixel rules and selected-state fills
establish separation; the implementation uses no drop shadows. The inspector
is a companion pane rather than a floating card layer.

## Shapes

Controls and table/graph containers use 4px corners; panes use 5px corners.
Small mode badges are rounded. Icicle rectangles are square and proportional
within one root. Graph nodes are equal-size bounded labels, not byte-scaled
bubbles.

## Components

### Controls

Buttons, inputs and selects inherit the system font. Controls have a one-pixel
rule, a 34px minimum height and restrained `5px 9px` padding. Hover introduces
the accent-soft surface; focus uses a 3px accent outline with a 3px offset.
Disabled controls remain visible with native semantics and reduced opacity.

### Navigation

The tab strip uses a bottom rule. Its active item has a two-pixel accent
underline and stronger weight. Breadcrumbs navigate stream and partition
scope; they are not an expanding query history.

### Evidence tables

Tables use muted headings, alternating surface roles rather than decorative
stripes, right-aligned tabular numbers and an explicit caption. Selectable
identities are text buttons. Row selection uses accent-soft without removing
the original values or evidence status.

### Inspector

An inspector shows the selected identity, paired values and evidence caveats.
Source paths are inert text. Complete counts and omitted records accompany
bounded previews.

### Diagrams

Icicles provide native keyboard-selectable groups and a corresponding table.
Retention sheets use directional arrows, worker layout and node/edge tables.
Equal-size graph nodes do not inherit bytes from a contributor with a similar
label. The sheet is replaced/reset rather than continuously simulated.

## Do's and Don'ts

### Do:
- **Do** pair every chart with exact values and a text/keyboard equivalent.
- **Do** preserve unknown, overlapping and partial evidence explicitly.
- **Do** bound tables and diagrams independently of the original corpus size.
- **Do** keep native controls, system theme adaptation and visible focus.

### Don't:
- **Don't** encode contributor bytes with graph degree or equal-size nodes.
- **Don't** shrink labels to make a whole application graph appear to fit.
- **Don't** use decorative motion in place of query progress or uncertainty.
- **Don't** turn path/source text into an executable or arbitrary-file action.
