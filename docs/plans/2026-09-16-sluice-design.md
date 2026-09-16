# Sluice - Design Direction

Date: 2026-09-16
Status: Approved

## Design read

Developer-infrastructure product for engineers who will read the threat model,
with a restrained dark-technical language, built on Next.js + Tailwind v4 +
shadcn/ui, Geist + Geist Mono, and generative particle art as the brand's
visual voice.

## References and how they were used

Two references informed this direction. Neither is to be cloned.

**TokenEx site (landing reference).** Taken: extreme color restraint with a
single accent, generative monochrome particle art carrying the visual identity,
light-weight large sentence-case headlines, hairline grid structure, real
visuals over fake product screenshots. Rejected: the yellow accent, the
dark/light/dark alternation down the page, the mono-free type system, and the
enterprise-compliance tone.

**Gaming dashboard (dashboard reference).** Taken: the three-pane shell, left
nav with command-palette search and grouped sections with the profile pinned
to the bottom, list rows with hover-revealed actions, tabs with count badges,
tonal surface stacking for depth instead of shadows. Rejected: the reliance on
photography for visual energy, and the soft 16px radius scale.

## Decisions

| Decision | Choice | Reason |
|---|---|---|
| Brand accent | Cool blue, not yellow | Amber and red stay free for real warning and danger states. A sluice is a water gate, so the palette earns the name. |
| Radius | Modest unified scale | The two references disagreed. One scale keeps the product coherent across marketing and app. |
| Theming | Dashboard dual, landing dark-locked | Marketing gets one controlled brand moment. The product respects the eyes of people who live in it. |

## Tokens

```
BRAND      #2D7FF9   buttons, links, active nav, focus rings

SEMANTIC   #10B981   connected / healthy
           #F59E0B   expiring / degraded / offline cache
           #EF4444   revoked / danger

DARK       #0A0A0B   base        #131315  panel
           #1A1A1D   card        #26262A  hairline
           #F4F4F5   text        #8A8A93  muted

LIGHT      #FFFFFF   base        #F7F7F8  panel
           #FFFFFF   card        #E4E4E7  hairline
           #18181B   text        #52525B  muted

RADIUS     4 inputs/buttons - 8 cards/panels - 12 modals - 0 rows/dividers
```

**Typography.** Geist and Geist Mono, self-hosted via `next/font`. Geist for
prose and headings. Geist Mono for every key name, token ID, environment name,
install command, and audit timestamp. The mono voice is what makes this read as
a developer tool rather than an enterprise compliance site.

## Surfaces

Three surfaces, three modes. They share tokens, not layout language.

### Landing - Persuade, dark-locked

Dials: variance 7, motion 6, density 3.

Asymmetric split hero, value prop left, generative particle sphere right. The
sphere is a real canvas or WebGL particle field that detonates and scatters,
which is revocation rendered rather than decorated. Below the hero: a quickstart
with a real copyable install block, a threat model teaser that includes what
Sluice does not defend against, the contributor grid via All-Contributors,
sponsors, and a runtime and compliance logo strip.

No fake dashboard screenshots. The revocation demo is a real terminal recording.

### Dashboard - Operate, light and dark

Dials: variance 3, motion 3, density 7.

Three-pane shell. Left nav carries command-palette search, projects with
environments nested beneath the active project, and the profile pinned to the
bottom. Center is a dense secrets table, mono throughout, values masked by
default. Right panel is the live audit stream: events arrive with no refresh,
which puts Convex reactivity in front of the user inside the product itself.

Token rows reveal a revoke action on hover, guarded by typed confirmation.

### Docs - Read, follows system preference

Dials: variance 5, motion 3, density 4.

Two-column with a persistent sidebar and in-page anchors. The threat model page
gets the same design care as the landing hero, because for a security product
the threat model is the pitch.

## Known tension

The dashboard reference draws all of its visual energy from game photography.
Sluice has no images. That texture has to come from mono type, hairline
structure, status color, and genuine data density instead. The result will feel
tighter and more instrument-like than the reference, closer to Linear or Vercel
than to a gaming UI. This is intended.

## Copy rules

These apply to all shipped interface text.

- Zero em-dashes and zero en-dashes anywhere visible. Use a hyphen, a comma, a
  colon, or two sentences.
- One label per intent. Do not mix "Get started" and "Try it free" on one page.
- No invented precision. Do not fake metrics the project cannot claim.
- Icons come from one family only. No hand-rolled SVG icon paths.
