# Binding layout rules

These are not cosmetic preferences — each one is the result of a correction made
while building. Breaking them looks like a bug to anyone who has used the app.

## Graph

- Unselected nodes are white (`var(--card)`) with an accent border. Only the
  selected one is filled with `var(--accent)`.
- Every person card has the same size, the selected one included. Names are
  shortened by frequency in the tree, never truncated.
- Spouses sit at the same height; edges leave the card offset towards their
  marriage diamond — no mirrored arcs, no bracket shape.

## Ancestor chart

- Edges are near-straight with a slight curve. No S-curves, no right angles.
- Cards carry anchors; edges start and end at them. Anchors stay neutral even on
  the selected card, or they merge into its fill.
- The marriage diamond is a rotated square with rounded corners and carries the
  year only — the full date belongs in the detail view.
- Children hang off the marriage diamond, not off a parent, and keep their
  distance from it and from each other.

## Source

The visual reference is the deck `openom Design Spec.dc.html`, which lives
outside this repository — every rule above is the distilled result. Where the
two disagree, this file wins: it was corrected against the running app.

## Names

Names are shortened by frequency in the tree, never truncated. Abbreviating
comes before dropping: `A. M. Wilcke` before `Magdalena Wilcke`. The rule lives
in `nameShortener()` (`apps/app/src/core/queries.js`) for cards and in
`labelChain()` (`apps/app/src/views/fan.js`) for arcs; the fan measures the real path
length and re-measures once the name font has loaded.

## Deletion

Swipe on touch, two-step trash button with a pointer. The switch is the input
kind (`isTouchInput()`), never the window size.

## Adding

The person detail view only shows. Everything that changes the tree lives in the
editor, and every ⊕ offers both routes — create new, or link somebody who is
already there.
