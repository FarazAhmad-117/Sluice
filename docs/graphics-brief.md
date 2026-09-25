# Graphics brief

Three illustrations, one per slot. Nothing else on the site is commissioned
artwork, so these three carry the entire visual argument that Sluice is a
mechanism rather than a pitch.

The authoritative brief for each is the comment block directly above its call
site in the code. This file is the same content in one place, plus the palette,
for working in a design tool.

## Palette

Only these. The site is dark locked and the artwork sits directly on the base
colour with no panel behind it.

| Token | Hex | Use in the artwork |
| --- | --- | --- |
| `--surface-base` | `#050608` | the background it will sit on. Do not paint it. |
| `--brand` | `#2D7FF9` | the signature, and anything that is a cryptographic act |
| `--status-danger` | `#EF4444` | the thing that dies |
| `--status-healthy` | `#10B981` | the things that live |
| `--status-warning` | `#F59E0B` | a limit or a caveat, if one is drawn at all |
| `--hairline-strong` | `rgb(255 255 255 / 0.14)` | everything at rest |
| `--text-primary` | `#F2F3F5` | labels |
| `--text-muted` | `#9CA3AF` | secondary labels |

Export at 2x, transparent background, PNG or SVG.

## 1. The kill switch

**560 x 560 square.** Homepage hero, opposite the copy. Must be legible at
320px wide on a phone.

Three things and nothing else:

1. **Instant.** A signature glyph travels from an admin action to one process
   node, and only *on arrival* does that node fade from solid to hollow. The
   fade must not begin before the glyph lands, or the picture claims the server
   can kill a process on its own, which is the one thing the product does not do.
2. **Selective.** A cluster of process nodes, each holding a token, one marked
   as targeted. Every neighbour is untouched at the end.
3. **Gated on the signature.** The glyph is the cause, drawn as the cause.

The node that dies is `--status-danger`. The signature path is `--brand`. The
survivors are `--hairline-strong` at rest, or `--status-healthy` if they need to
read as alive.

## 2. Two keys meet in the middle

**1200 x 640 landscape.** First section of `/how-it-works`, full width. Must be
legible at 343px wide, or it needs a stacked variant.

One idea: two independent trust roots meeting at a boundary the server cannot
cross.

- A **human path**: a person, through a password, to a lock.
- A **machine path**: a service token splitting into two labelled halves,
  `auth` and `unwrap`.
- Both converge on **one wrapped blob**.
- A box drawn around the server, touching only the outer **closed** shapes.

That last point is the whole claim. If the server box and an open shape
intersect anywhere, the picture says the opposite of the text beside it.

## 3. What the server can see

**1100 x 620 landscape.** `/security`, directly above the plaintext list, full
width.

Two columns, the same shapes in both, and that sameness is the device:

- **Left, what it stores.** Open shapes, readable, labelled as organisation
  names, project slugs, environment names, timestamps and counts.
- **Right, what it never has.** The same shapes as sealed opaque blocks.

Precise enough that a reader can audit the picture against the list underneath
it, item for item. If the drawing shows a shape the list does not name, or omits
one it does, the picture is the claim that is wrong.

No padlock cliche.

## Delivering them

Drop the file into `apps/web/public/graphics/` under the filename in that
folder's README. The call site then takes a `src` and the placeholder box goes.
The brief comment stays where it is.
