# UI Visual System

## Direction

The operator UI uses a premium dark command-center visual language. The final UI should feel immersive and high-trust, but never theatrical at the cost of comprehension.

## Core rules

- strong spacing and panel rhythm over decorative density
- restrained cyan and amber accents, not rainbow noise
- status and severity must be visually consistent everywhere
- reusable panel and chip patterns are preferred over one-off card styling

## Palette usage

- cyan:
  - active state
  - progress glow
  - live focus
- amber:
  - guarded action
  - waiting state
  - advisory emphasis
- green:
  - healthy
  - complete
  - deployed / validated success
- red:
  - blocked
  - failed
  - critical
- steel blue:
  - unknown
  - reserved future overlay states

## Severity language

- critical: red
- high: orange-red
- medium: amber
- low: green
- info / unknown: steel blue

Severity pills and finding cards must use the same color logic across Mission Control, Findings Theater, and Evidence Replay.

## Reusable UI patterns

- status pills for workflow state
- severity pills for finding severity
- signal cards for good / issues / unknown boards
- panel actions for cross-screen flow
- section notes for operator guidance
- flow strip for persistent lifecycle orientation
- explicit loading, empty, and protected-state surfaces where operator trust matters

## Motion

Allowed:

- active phase pulse
- subtle screen fade
- low-noise glow for active focus

Avoid:

- decorative loops without meaning
- particle-heavy scenes
- motion that competes with text or status
