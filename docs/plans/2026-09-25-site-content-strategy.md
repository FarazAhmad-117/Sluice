# Sluice Site Content Strategy

Date: 2026-09-25
Status: Approved in outline. One open decision, marked below.

## The correction this document exists to fix

The site was written to recruit contributors. The evidence is in the repo: the
hero CTA said "Clone and run the tests" and the closing CTA said "clone it,
break it, and tell us where it bends". Both are a contributor's job.

**The reader is a senior developer deciding whether to put Sluice in their
project.** Everything on the site serves "should I adopt this", never "should
I contribute to this". Open source is one page, and it exists as evidence that
the project is alive and maintained, not as a recruitment drive.

## Positioning

The homepage leads with the daily `.env` problem, with revocation as the
differentiator immediately beneath it. That is a decision, not a suggestion.

It carries a known cost: leading on daily use puts Sluice against Doppler and
Infisical on convenience, where they are mature and Sluice has shipped nothing.
The mitigation is structural. The scan must read "this replaces my `.env`" and
the next breath must read "and it does something none of them can". A visitor
who only gets the first half is on a feature comparison table losing every row
but one.

The wedge, in the shape Arcjet uses: concede the incumbent's strength, then
name the gap. Everyone can stop issuing a secret. Nobody can take one back from
a running process.

**Do not rebuild the positioning around AI agents**, even though Doppler and
Infisical both did this year. A rogue agent is an excellent example inside the
problem section, because it is the canonical process you need to kill. It is a
poor headline, because the demo that proves the claim is a plain process and
nothing in the product is agent-specific. That gap between what the headline
promises and what the demo shows is exactly what the honesty rules exist to
prevent.

## Pages

| Page | Reader | Its one job |
|---|---|---|
| `/` | A senior developer with a live `.env` problem, arriving skeptical and time-poor | Get two concessions in order: this solves something I deal with, and this does one thing nobody else does |
| `/how-it-works` | The same person, past the hook, wanting the crypto claim to survive detail | Make "zero-knowledge" and "signature-gated revocation" checkable rather than asserted |
| `/security` | The person who gates the decision, actively looking for a reason to say no | Survive their read by being more rigorous than the pitch |
| `/open-source` | The same adopter, checking whether the project is alive | Read as project health, never as a call to contribute |
| `/status` | Someone who clicked the primary CTA before the CLI exists | Land honestly. See the open decision below. |

**Not building:** a pricing page, a blog, or per-audience variants. There is
nothing to sell yet, and one audience does not need voice-segmented landing
pages.

### Global chrome

Nav: logo, How it works, Security, Open source, a small GitHub star chip, "Sign
in" as a plain text link, then the primary CTA button. Every one of the 35
sites studied does sign-in exactly this way: a text link, never a button, never
missing.

The primary CTA is the command itself, `sluice run -- npm start`, styled as a
shell command rather than a generic button label. It appears exactly three
times sitewide: nav, hero, final CTA.

Footer carries Security policy, License, Contributing, the security contact and
Status. CodeRabbit's footer exposes nine products where its nav shows four,
which is how a multi-page site avoids a bloated header, and it is where the
contributor-facing links belong.

## Homepage sections, and what each must prove

1. **Hero.** That this is for me, and that it does something my current tools do
   not. The existing "Pre-release, not third-party audited yet" pill stays, and
   stays *first*, before any claim. State the limit before the pitch, not after.
2. **Problem.** That these are real failure modes, not invented pain. Four
   concrete cases: a secret pasted into Slack because rotating it properly was
   slower; a `.env` that drifted from what is deployed and nobody noticed until
   an outage; an offboarded engineer whose token still works because revoking
   meant waiting for a restart; a script or agent still running with access
   after someone thought they had cut it off.
3. **The wedge and the live demo.** That Sluice does the one thing in that list
   nothing else does, proven by showing it happen. Full spec below.
4. **How it works, three steps.** That the mechanism is simple enough to state
   in three lines and specific enough that simple does not mean vague. Store,
   run, revoke. Links to the deep page.
5. **What is real today.** That this site tells you the bad news before you find
   it. Mid-page, normal reading size, not a footer. Burying it would contradict
   the reason it is there.
6. **Open source proof point.** One line and a link. Not a duplicate of that
   page.
7. **Final CTA.** One honest next action, plus a quieter link to `/security` for
   the reader whose next move is scrutiny rather than action.

**No CTA anywhere between the hero and the final section.** CodeRabbit runs
8,600px and five product sections with nothing but the sticky header.

## The demo

Build the real thing. Not an animation.

Every incumbent fakes their demo because a code review or a dashboard cannot be
run live. Doppler uses Navattic, 1Password uses Reprise, and 1Password is A/B
testing whether that even beats a video. Sluice's differentiator is the one
thing in this category that genuinely can be run in a browser, and faking it
would be the single worst place on the site to break the honesty commitment,
because it is the exact claim a skeptical reader pokes first.

- Spawn a short-lived child process per visitor session, auto-killed after a few
  minutes idle so it cannot become a resource-exhaustion vector. It runs the
  real SDK decision core against a real demo project and prints a heartbeat,
  streamed to the browser, so the terminal on the page is a real tail.
- A "Revoke this token" button wired to the real mutation, performing the real
  signing flow.
- Time from the real server timestamp of the signed notice to the streamed log
  line reporting the signature verified and the process exiting. Display the
  measured delta. **The number must be measured, never hardcoded.**
- Show the raw signed notice underneath, signature bytes real, so a skeptical
  reader can see it is not staged.
- "Run it again" reprovisions, so the demo cannot go stale or be exhausted by
  one visitor.

**Print the number, but do not animate at the real speed.** A kill completing in
tens of milliseconds is below the threshold at which an eye reads an event as an
event: it looks like the page glitched rather than like the product is fast. The
readout carries the truth, the motion carries the legibility, and that stays
honest only while the printed figure is the measured one.

## Graphics to commission

Three, four at most. CodeRabbit's entire homepage runs on two.

1. **The kill switch.** Hero, opposite the copy. A cluster of process nodes each
   holding a token, one marked as targeted. A signature glyph travels from an
   admin action to that node, and *only on arrival* does the node fade from
   solid to hollow. Must communicate: instant, selective (neighbours untouched),
   and gated on the signature arriving before the node dies.
2. **Two keys meet in the middle.** First section of `/how-it-works`. A human
   path through a password to a lock, and a token splitting into a labelled auth
   half and unwrap half, both converging on a wrapped blob, with a box for the
   server that only ever touches the outer closed shapes. Must communicate: two
   independent trust roots meeting at a boundary the server cannot cross.
3. **What the server can see.** On `/security`. Two columns. Left, what it
   stores: open shapes for org names, project slugs, environment names,
   timestamps, counts. Right, what it never has: the same shapes as sealed
   opaque blocks. Must communicate the exact bounded metadata leak, precisely
   enough that a reader can audit the picture against the written claim.
4. **Optional three-icon row** for the homepage steps: a locked box, a terminal
   running the command, a hand triggering a signature that reaches the terminal
   and fades it.

**Do not illustrate the open source page.** Star counts and contributor avatars
are UI, not illustration subjects.

## Where the honesty constraints live as content

Three places, three jobs.

- **The hero pill**, stated before any claim rather than as a caveat after one.
- **The "what is real today" panel**, mid-page, at reading size, carrying the
  three sharpest items: no third-party cryptographic review, no re-key so
  revocation stops delivery but does not undo decryption already pulled, and the
  session token readable by any script on the origin.
- **`/security`**, carrying the full tables close to verbatim from
  `SECURITY.md`, whose voice is already right: plain, specific, no false
  comfort. **This page has no product CTA.** Its only action is reporting a
  vulnerability, and that restraint is part of the credibility.

Any limitation named on `/security` must be repeated unchanged everywhere else
it appears. A visitor who reads three phrasings of "no re-key" will trust none
of them.

## OPEN DECISION: where the primary CTA points

`sluice run -- npm start` is the primary CTA three times on the homepage, for a
command that does not exist yet. Every option fails somehow: a dead link is
worse than no CTA, a signup form collects emails against a product that is not
there, and "coming soon" reads as vaporware on a site whose credibility rests on
not overclaiming.

**The preferred resolution is that the CLI ships before the site does**, which
makes the question disappear. `packages/cli` is being built now. If it slips,
the fallback is a thin `/status` page pointing at a real GitHub watch, since
there is no email delivery infrastructure and inventing one would be its own
overclaim.

Whichever way this resolves, it becomes the most-clicked link on the site.
